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
import assert from "node:assert/strict";

const EXT = fileURLToPath(new URL("../chromium/", import.meta.url));
const src = (f) => readFileSync(EXT + f, "utf8");

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

const swChrome = {
  runtime: {
    onMessage: { addListener: (fn) => swListeners.push(fn) },
    getManifest: () => ({ version: "0.3.0" }),
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
  console,
  setTimeout,
  queueMicrotask,
  Date: fakeDate(),
  Map,
});
swCtx.globalThis = swCtx;
vm.runInContext(src("background.js"), swCtx);

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

  const relayCtx = vm.createContext({
    globalThis: null,
    chrome: { runtime: { sendMessage: (m) => toWorker(m, tabId) } },
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
  const navigatorStub = {
    credentials: {
      create: async () => ({ __real: "create" }),
      get: async () => {
        realGetCalls++;
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
    webauthn,
    lastLog: () => logs[logs.length - 1] || "",
    get: (mediation) =>
      mainCtx.navigator.credentials.get({
        mediation,
        publicKey: { challenge: new Uint8Array([1, 2, 3]).buffer, rpId: host },
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
  await d.get("conditional");
  check("conditional UI", d.fellBackTo(), "mediation:conditional");
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

console.log(`\n${pass} checks passed\n`);
