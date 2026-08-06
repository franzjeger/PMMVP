// Tests for the extension's passkey path. Runs the REAL extension files (the
// service worker, the isolated relay and the main-world shim) in vm contexts
// wired together the way Chromium wires them — no mocks of our own logic, only
// of the browser around it.
//
//     node extension/test/passkey.test.mjs
//
// Two classes of bug live here, both of which shipped once and were invisible
// from inside the extension:
//
//   • the gate. A ceremony that starts on a page the browser has just navigated
//     to (Entra sends you to login.microsoft.com/common/bridge/fido, which fires
//     get() on load) has no gesture in its own document. Getting that wrong
//     hands every such sign-in to the browser.
//   • the credential handed back. A bare object literal passes every field
//     check and still breaks the relying party, because real WebAuthn code
//     calls toJSON() and tests instanceof. The prototypes below are
//     brand-checked exactly like the browser's, so a missed shadow throws here
//     instead of in production.
//
// The fake native host always answers "locked", so an ALLOWED ceremony logs
// `app:locked` — which proves the gate passed *and* the request reached the
// native layer, rather than merely that it was not refused.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import * as bookmarksModule from "../chromium/bookmarks.js";
import * as mirrorModule from "../chromium/mirror.js";
import assert from "node:assert/strict";

const EXT = fileURLToPath(new URL("../chromium/", import.meta.url));
const raw = (f) => readFileSync(EXT + f, "utf8");

// background.js is a MODULE — the manifest says so, and it has to be: a service
// worker forbids dynamic `import()`, so its dependencies can only arrive as
// static imports. This harness runs that file in a vm as a classic script,
// which cannot parse one.
//
// So the imports are stripped here and the real exports are injected into the
// context instead. The alternative was to keep background.js loading its
// modules dynamically to suit this file, and that shipped an extension whose
// bookmark cleanup threw on every single call. The harness bends; the code
// that has to run in a browser does not.
const src = (f) =>
  f === "background.js"
    ? raw(f).replace(/^import\s+\{[^}]*\}\s+from\s+"\.\/[^"]+";$/gm, "")
    : raw(f);

const CLAIMED = "app:locked";

// What the fake native host answers. Defaults to a locked vault; the shape
// tests swap in a real assertion.
let NATIVE_ANSWER = { type: "error", message: "locked" };

// Brand-checked stand-ins for the browser's WebAuthn classes: every prototype
// member throws unless the receiver carries the internal brand, exactly like
// the real accessors. A shaped credential that forgot to shadow one of them
// therefore blows up here instead of silently in production.
const BRAND = Symbol("brand");
function makeWebAuthnClasses() {
  const brandCheck = (name) =>
    function () {
      if (!this || !this[BRAND]) {
        throw new TypeError(`Illegal invocation: ${name}`);
      }
      return undefined;
    };
  const define = (ctor, members) => {
    for (const m of members) {
      Object.defineProperty(ctor.prototype, m, {
        get: brandCheck(m),
        configurable: true,
      });
    }
    return ctor;
  };
  const PublicKeyCredential = define(function PublicKeyCredential() {}, [
    "id",
    "rawId",
    "type",
    "response",
    "authenticatorAttachment",
  ]);
  for (const m of ["getClientExtensionResults", "toJSON"]) {
    PublicKeyCredential.prototype[m] = brandCheck(m);
  }
  const AuthenticatorAssertionResponse = define(
    function AuthenticatorAssertionResponse() {},
    ["clientDataJSON", "authenticatorData", "signature", "userHandle"],
  );
  const AuthenticatorAttestationResponse = define(
    function AuthenticatorAttestationResponse() {},
    ["clientDataJSON", "attestationObject"],
  );
  return {
    PublicKeyCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
  };
}

// ── Controllable clock, shared by every context ─────────────────────────────
let NOW = 1_000_000;
const advance = (ms) => (NOW += ms);
const fakeDate = () =>
  new Proxy(Date, { get: (t, p) => (p === "now" ? () => NOW : t[p]) });

const tick = () => new Promise((r) => setTimeout(r, 5));

// ── The background service worker ───────────────────────────────────────────
const swListeners = [];
const storage = { local: new Map(), session: new Map() };
const mapArea = (m) => ({
  get: async (k) => (m.has(k) ? { [k]: m.get(k) } : {}),
  set: async (o) => void Object.entries(o).forEach(([k, v]) => m.set(k, v)),
  remove: async (k) => void m.delete(k),
});

// The version the LIVE extension reports. An update replaces the service
// worker, so this is where a new generation appears; the shim already sitting
// in a page learns about it from the gate's answer.
let swVersion = "0.3.0";

const swChrome = {
  runtime: {
    onMessage: { addListener: (fn) => swListeners.push(fn) },
    getManifest: () => ({ version: swVersion }),
    sendNativeMessage: (_host, _msg, cb) =>
      queueMicrotask(() => cb(NATIVE_ANSWER)),
    lastError: null,
  },
  storage: { local: mapArea(storage.local), session: mapArea(storage.session) },
  tabs: { onRemoved: { addListener: () => {} } },
};

const swCtx = vm.createContext({
  globalThis: null,
  chrome: swChrome,
  // The symbols background.js would have imported. The REAL ones, so the
  // behaviour under test is the behaviour that ships.
  ...bookmarksModule,
  ...mirrorModule,
  console,
  setTimeout,
  queueMicrotask,
  Date: fakeDate(),
  Map,
});
swCtx.globalThis = swCtx;
// background.js is an ES module (it imports the bookmark reconciler), and
// `vm.runInContext` runs scripts, not modules. The import is stripped and the
// two names it brings in are supplied on the context instead — the same thing
// the harness already does for every browser API. The bookmark logic has its
// own tests in bookmarks.test.mjs; nothing here exercises it.
swCtx.readAll = async () => [];
swCtx.apply = async () => ({ added: 0, removed: 0, refused: null });
vm.runInContext(
  src("background.js").replace(/^import\s[^\n]*\n/m, ""),
  swCtx,
);

/** Deliver a message to the worker the way chrome.runtime.sendMessage does. */
function toWorker(msg, tabId) {
  return new Promise((resolve) => {
    const sender = { tab: { id: tabId } };
    for (const fn of swListeners) {
      let replied = false;
      const sendResponse = (r) => {
        replied = true;
        resolve(r);
      };
      if (fn(msg, sender, sendResponse) === true || replied) return;
    }
    resolve(undefined);
  });
}

// ── One browser document: isolated relay + main-world shim ──────────────────
function makeDocument({ host, tabId }) {
  let relayVersion = "0.3.0";
  const isolated = [];
  const main = [];
  const logs = [];

  const loc = { origin: `https://${host}`, hostname: host };

  // A postMessage is seen by both worlds, each with e.source === its own window.
  const deliver = (data) => {
    for (const { type, fn } of [...isolated])
      if (type === "message") fn({ source: relayWindow, data });
    for (const { type, fn } of [...main])
      if (type === "message") fn({ source: mainWindow, data });
  };
  const post = (data) => queueMicrotask(() => deliver(data));

  const relayWindow = {
    addEventListener: (type, fn) => isolated.push({ type, fn }),
    postMessage: post,
    location: loc,
  };
  const mainWindow = {
    addEventListener: (type, fn) => main.push({ type, fn }),
    postMessage: post,
    location: loc,
  };

  // A live extension context. `id` is what `contextAlive()` reads, and its
  // ABSENCE is the orphan signal, so the harness must model both states or the
  // retirement path is untestable — and, worse, every other test would run
  // against a relay that believes it has been reloaded.
  const relayRuntime = {
    id: "arca-test-extension",
    sendMessage: (m) => toWorker(m, tabId),
    getManifest: () => ({ version: relayVersion }),
  };
  const relayCtx = vm.createContext({
    globalThis: null,
    chrome: { runtime: relayRuntime },
    window: relayWindow,
    location: loc,
    console,
    setTimeout,
    queueMicrotask,
    Date: fakeDate(),
  });
  relayCtx.globalThis = relayCtx;
  vm.runInContext(src("passkey-relay.js"), relayCtx);

  let realGetCalls = 0;
  let realCreateCalls = 0;
  const navigatorStub = {
    credentials: {
      create: async () => {
        realCreateCalls++;
        return { __real: "create" };
      },
      get: async (opts) => {
        realGetCalls++;
        // A CONDITIONAL request stays pending while the browser offers autofill
        // — it does not resolve until the user picks something, or never. The
        // stub used to return at once, which is a browser that does not exist
        // and which quietly ended the ceremony before anyone could choose.
        if (opts && (opts.mediation === "conditional" || opts.mediation === "silent")) {
          return new Promise((_resolve, reject) => {
            if (opts.signal) {
              opts.signal.addEventListener("abort", () => reject(new Error("aborted")), {
                once: true,
              });
            }
          });
        }
        return { __real: "get" };
      },
    },
  };

  const webauthn = makeWebAuthnClasses();
  const mainCtx = vm.createContext({
    globalThis: null,
    window: mainWindow,
    navigator: navigatorStub,
    console: { debug: (...a) => logs.push(String(a[0])) },
    setTimeout,
    queueMicrotask,
    Date: fakeDate(),
    Map,
    TextEncoder,
    btoa,
    crypto: globalThis.crypto,
    DOMException,
    Object,
    Uint8Array,
    // Conditional autofill is RACED against the browser, and the loser is
    // aborted — so the shim needs the same abort primitives every browser has.
    // Absent here, the harness modelled a browser that does not exist.
    AbortController,
    AbortSignal,
    Promise,
    ...webauthn,
  });
  mainCtx.globalThis = mainCtx;
  vm.runInContext(src("passkey.js"), mainCtx);

  return {
    gesture: () => {
      for (const { type, fn } of isolated) if (type === "pointerdown") fn({});
    },
    fellBackTo: () => {
      const m = (logs[logs.length - 1] || "").match(/\(([^)]+)\)/);
      return m ? m[1] : null;
    },
    realGetCalls: () => realGetCalls,
    realCreateCalls: () => realCreateCalls,
    /// The extension was RELOADED: this tab's isolated half is orphaned and its
    /// `runtime.id` is gone, while the page-world shim keeps running.
    orphan: () => {
      relayRuntime.id = undefined;
    },
    /// The extension was UPDATED: the context still works, but the live worker
    /// answering the gate belongs to a newer generation than the shim wrapping
    /// WebAuthn in this page.
    upgrade: (v) => {
      swVersion = v;
      relayVersion = v;
    },
    create: () =>
      mainCtx.navigator.credentials.create({
        publicKey: {
          challenge: new Uint8Array([1, 2, 3]).buffer,
          rp: { id: host, name: host },
          user: { id: new Uint8Array([9]).buffer, name: "frank", displayName: "Frank" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        },
      }),
    webauthn,
    lastLog: () => logs[logs.length - 1] || "",
    get: (mediation) =>
      mainCtx.navigator.credentials.get({
        mediation,
        publicKey: { challenge: new Uint8Array([1, 2, 3]).buffer, rpId: host },
      }),
    // The picker (isolated world) asking the shim to answer a live conditional
    // request with the row the user clicked.
    pickPasskey: (credentialId) =>
      new Promise((resolve) => {
        const id = "t1";
        isolated.push({
          type: "message",
          fn: (e) => {
            const d = e && e.data;
            if (d && d.__sybrPasskey === "use-result" && d.id === id) resolve(!!d.ok);
          },
        });
        post({ __sybrPasskey: "use", id, credentialId: credentialId || null });
      }),
  };
}

// ── Cases ───────────────────────────────────────────────────────────────────
let pass = 0;
const check = (name, got, want) => {
  assert.equal(got, want, `${name}: got ${got}, want ${want}`);
  console.log(`  ok  ${name} → ${got}`);
  pass++;
};

console.log("\nMicrosoft flow: gesture on one origin, ceremony on the next");
{
  const a = makeDocument({ host: "login.microsoftonline.com", tabId: 7 });
  a.gesture();
  await tick();
  advance(1200); // click → server round trip → navigation → load
  const b = makeDocument({ host: "login.microsoft.com", tabId: 7 });
  await b.get();
  check("carried across the navigation", b.fellBackTo(), CLAIMED);
  await b.get();
  check("and is consumed, so a re-fire is not claimed", b.fellBackTo(), "no_gesture");
}

console.log("\nIn-document gesture keeps its old, tighter window");
{
  const d = makeDocument({ host: "example.com", tabId: 8 });
  d.gesture();
  await tick();
  advance(500);
  await d.get();
  check("fresh in-document gesture", d.fellBackTo(), CLAIMED);

  d.gesture();
  await tick();
  advance(4000); // past the 3s in-document window, inside the 10s carry TTL
  await d.get();
  check("stale one is NOT widened to the carry TTL", d.fellBackTo(), "gesture_stale");
}

console.log("\nNo gesture at all");
{
  const d = makeDocument({ host: "nowhere.example", tabId: 9 });
  await d.get();
  check("untouched tab defers to the browser", d.fellBackTo(), "no_gesture");
  check("and the browser really was called", d.realGetCalls(), 1);
}

console.log("\nPer-site policy");
{
  storage.local.set("passkeyPolicy", {
    "github.com": "never",
    "id.example": "always",
  });

  const never = makeDocument({ host: "github.com", tabId: 10 });
  never.gesture();
  await tick();
  await never.get();
  check("never overrides a real gesture", never.fellBackTo(), "site_never");

  const always = makeDocument({ host: "id.example", tabId: 11 });
  await always.get();
  check("always claims with no gesture at all", always.fellBackTo(), CLAIMED);
}

console.log("\nConditional mediation still defers before any round trip");
{
  const d = makeDocument({ host: "example.org", tabId: 12 });
  d.gesture();
  await tick();
  // NOT awaited: a conditional request stays pending while autofill is offered,
  // which is the point. What matters here is that the browser was handed it
  // before any round trip to the app.
  void d.get("conditional");
  await tick();
  check("conditional UI", d.fellBackTo(), "mediation:conditional");
}

console.log("\nPicking a passkey in Arca's own list answers the live request");
{
  const d = makeDocument({ host: "example.org", tabId: 21 });
  NATIVE_ANSWER = {
    type: "passkey_assertion",
    credential_id: [1, 2, 3, 4],
    authenticator_data: Array.from({ length: 37 }, (_, i) => (i === 32 ? 0x05 : i)),
    signature: [9, 9, 9],
    user_handle: [7, 7],
  };
  d.gesture();
  await tick();
  // The page arms conditional autofill; the browser is offered it as before.
  const ceremony = d.get("conditional");
  await tick();
  d.gesture();
  await tick();
  const used = await d.pickPasskey([1, 2, 3, 4]);
  check("the picker's choice was accepted", used, true);
  const credential = await ceremony;
  // The PAGE's promise resolves with our credential — the whole point. Before
  // this, a passkey row could only print a sentence.
  check("the page received a credential", credential.type, "public-key");
  check("browser leg was still offered it", d.realGetCalls() > 0, true);
}

console.log("\nA page cannot summon a ceremony by posting the message itself");
{
  const d = makeDocument({ host: "example.org", tabId: 22 });
  // Conditional armed, but the user has touched nothing in this tab.
  d.get("conditional");
  await tick();
  const used = await d.pickPasskey([1, 2, 3, 4]);
  check("refused without a gesture", used, false);
}

console.log("\nThe credential handed to the relying party");
{
  // A real assertion, sized like the one measured off the live bridge:
  // 16-byte credential id, 37-byte authenticatorData, 72-byte DER signature,
  // 51-byte user handle.
  const bytes = (n, seed) => Array.from({ length: n }, (_, i) => (i * 7 + seed) & 0xff);
  NATIVE_ANSWER = {
    type: "passkey_assertion",
    credential_id: bytes(16, 1),
    authenticator_data: bytes(37, 2),
    signature: [0x30, ...bytes(71, 3)],
    user_handle: bytes(51, 4),
  };

  const d = makeDocument({ host: "login.microsoft.com", tabId: 20 });
  d.gesture();
  await tick();
  const cred = await d.get();

  check("Arca answered (no fallback)", d.fellBackTo(), null);
  check("is a PublicKeyCredential", cred instanceof d.webauthn.PublicKeyCredential, true);
  check(
    "response is an AuthenticatorAssertionResponse",
    cred.response instanceof d.webauthn.AuthenticatorAssertionResponse,
    true,
  );
  check("exposes toJSON()", typeof cred.toJSON, "function");

  // Reading every field must NOT hit the brand-checked prototype accessors.
  for (const f of ["id", "rawId", "type", "response", "authenticatorAttachment"]) {
    assert.doesNotThrow(() => cred[f], `reading cred.${f} hit the prototype`);
  }
  for (const f of ["clientDataJSON", "authenticatorData", "signature", "userHandle"]) {
    assert.doesNotThrow(() => cred.response[f], `reading response.${f} hit the prototype`);
  }
  console.log("  ok  every field reads from our own properties");
  pass++;

  const j = cred.toJSON();
  check("toJSON type", j.type, "public-key");
  check("toJSON id matches", j.id, j.rawId);
  check("toJSON has clientExtensionResults", typeof j.clientExtensionResults, "object");
  for (const f of ["clientDataJSON", "authenticatorData", "signature", "userHandle"]) {
    assert.equal(typeof j.response[f], "string", `toJSON response.${f} is not base64url`);
    assert.ok(!/[+/=]/.test(j.response[f]), `toJSON response.${f} is not URL-safe`);
  }
  console.log("  ok  toJSON response fields are unpadded base64url");
  pass++;
  check("getClientExtensionResults()", JSON.stringify(cred.getClientExtensionResults()), "{}");

  NATIVE_ANSWER = { type: "error", message: "locked" };
}

console.log("\nRegistration is judged on THIS document's gesture, nothing else");
{
  // The nag Frank kept hitting: GitHub re-offers "add a passkey" on a timer.
  // Any stand-in for a real click turned every one of those offers into a
  // Touch ID prompt on a machine whose owner had done nothing.
  storage.local.set("passkeyPolicy", { "gh.example": "always" });

  // A gesture that happened in the PREVIOUS document. Good enough to sign in
  // with (Entra needs exactly that); never good enough to mint a credential.
  const a = makeDocument({ host: "gh.example", tabId: 20 });
  a.gesture();
  await tick();
  advance(1200);
  const b = makeDocument({ host: "gh.example", tabId: 20 });
  await b.create();
  check("a carried gesture cannot register", b.fellBackTo(), "create_needs_local_gesture");
  check("the browser got the ceremony instead", b.realCreateCalls(), 1);

  // "always" means "sign me in here", not "register whatever you like here".
  const c = makeDocument({ host: "gh.example", tabId: 21 });
  await c.create();
  check("site=always cannot register either", c.fellBackTo(), "create_needs_local_gesture");

  // ...while a real click in the page still registers normally.
  const d = makeDocument({ host: "gh.example", tabId: 22 });
  d.gesture();
  await tick();
  advance(300);
  await d.create();
  check("a real in-document click still registers", d.fellBackTo(), CLAIMED);

  // And sign-in on that same site is untouched by the create rule.
  const e = makeDocument({ host: "gh.example", tabId: 23 });
  await e.get();
  check("sign-in still honours site=always", e.fellBackTo(), CLAIMED);

  storage.local.set("passkeyPolicy", {});
}

console.log("\nA shim retires itself once the extension moves on without it");
{
  // Reloading or updating the extension does NOT evict code already injected
  // into an open tab. The old shim keeps wrapping WebAuthn with the rules that
  // shipped that day, which is why "close the tab" was the only known cure for
  // a passkey bug that had already been fixed.
  const reloaded = makeDocument({ host: "stale.example", tabId: 24 });
  reloaded.gesture();
  await tick();
  reloaded.orphan(); // the extension was reloaded; runtime.id is gone
  await reloaded.get();
  check("an orphaned tab hands the ceremony back", reloaded.fellBackTo(), "shim_retired");
  check("and the browser really ran it", reloaded.realGetCalls(), 1);

  // Retirement is permanent: no second chance, no waiting on a dead relay.
  reloaded.gesture();
  await tick();
  await reloaded.create();
  check("retirement outlives a fresh gesture", reloaded.fellBackTo(), "shim_retired");
  check("registration went to the browser too", reloaded.realCreateCalls(), 1);

  // The other way it goes stale: the context still answers, but from a newer
  // generation than the code running in this page.
  const updated = makeDocument({ host: "updated.example", tabId: 25 });
  updated.gesture();
  await tick();
  advance(300);
  await updated.get();
  check("a matching version claims normally", updated.fellBackTo(), CLAIMED);

  updated.upgrade("0.4.0");
  updated.gesture();
  await tick();
  advance(300);
  await updated.get();
  check("a newer extension retires the old shim", updated.fellBackTo(), "shim_retired");
}

console.log("\nWhat a service worker is allowed to contain");
{
  // `import() is disallowed on ServiceWorkerGlobalScope by the HTML
  // specification`. This shipped: a dynamic import added to keep THIS harness
  // happy made every bookmark cleanup and every mirror call throw in the real
  // extension, and the only symptom a user saw was a checkbox that would not
  // stay ticked.
  //
  // The harness is what adapts to a module (see `src` above). The worker does
  // not get to.
  assert.ok(
    !/\bawait\s+import\s*\(/.test(raw("background.js")),
    "background.js uses dynamic import(), which a service worker refuses at runtime",
  );
  console.log("  ok  background.js has no dynamic import()");
  pass++;
}

console.log(`\n${pass} checks passed\n`);
