// Background service worker (Chromium) / event page (Firefox).
//
// It is the only context allowed to talk to the native-messaging host. Content
// scripts and the popup send it messages; it relays them to the Rust host and
// returns the response. The vault stays owned by the desktop app, which only
// releases a credential on an explicit "fill" for a matching origin while
// unlocked; "listLogins" only ever returns metadata.

import { readAll, apply } from "./bookmarks.js";

const api = globalThis.browser ?? globalThis.chrome;

// Must match the native messaging host manifest `name`.
const NATIVE_HOST = "no.sybr.vault";

/** Send one message to the native host and resolve a uniform result object. */
function sendNative(message) {
  return new Promise((resolve) => {
    try {
      api.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
        const err = api.runtime.lastError;
        if (err) {
          resolve({ ok: false, error: err.message });
        } else {
          resolve({ ok: true, response });
        }
      });
    } catch (e) {
      resolve({ ok: false, error: String(e) });
    }
  });
}

// Per-tab "a login was just submitted" candidate, so the save prompt can be
// shown after the form navigates. Held only in memory, briefly.
const pendingSaves = new Map(); // tabId -> { candidate, ts }
const PENDING_TTL_MS = 90000;

// ── The passkey gate ────────────────────────────────────────────────────────
//
// A WebAuthn ceremony often does not run in the document the user clicked in.
// Microsoft Entra is the clean example: the click lands on
// login.microsoftonline.com, the browser navigates to
// login.microsoft.com/common/bridge/fido, and *that* document fires
// credentials.get() on load. A gesture tracked inside the page dies with the
// page, so the shim saw no gesture and handed every M365 sign-in back to the
// browser — which on Linux means the QR / security-key dialog, because there is
// no platform authenticator to quietly catch it.
//
// So the gesture is remembered per TAB, here, where it outlives the navigation.
// It is still CONSUMED: one gesture, one ceremony, so a page that re-fires
// get() in a loop gets exactly one shot at a prompt.
const GESTURE_TTL_MS = 10000;

// `storage.session` is in-memory (never written to disk) and, unlike a plain
// Map, survives the service worker being evicted mid-flow — which is exactly
// what a slow navigation invites. The Map is a same-turn fast path and the
// fallback where `storage.session` is missing.
const memGestures = new Map(); // tabId -> ts
const sessionStore = api.storage && api.storage.session;
const gestureKey = (tabId) => `gesture:${tabId}`;

async function recordGesture(tabId) {
  if (tabId == null) return;
  const ts = Date.now();
  memGestures.set(tabId, ts);
  if (sessionStore) {
    try {
      await sessionStore.set({ [gestureKey(tabId)]: ts });
    } catch (_e) {
      /* fast path already holds it */
    }
  }
}

async function clearGesture(tabId) {
  if (tabId == null) return;
  memGestures.delete(tabId);
  if (sessionStore) {
    try {
      await sessionStore.remove(gestureKey(tabId));
    } catch (_e) {
      /* nothing to undo */
    }
  }
}

/** Consume this tab's gesture. True only if one was recorded and is fresh. */
async function takeGesture(tabId) {
  if (tabId == null) return false;
  let ts = memGestures.get(tabId) || 0;
  if (!ts && sessionStore) {
    try {
      const got = await sessionStore.get(gestureKey(tabId));
      ts = got[gestureKey(tabId)] || 0;
    } catch (_e) {
      ts = 0;
    }
  }
  await clearGesture(tabId);
  return ts > 0 && Date.now() - ts <= GESTURE_TTL_MS;
}

// Per-site override of the gate, set from the popup. "ask" (the default) means
// the gesture decides; "always" lets a site fire a ceremony Arca answers even
// with no gesture at all; "never" keeps Arca out of a site's way entirely.
//
// This only decides WHO ANSWERS the ceremony. It cannot release a credential,
// cannot bypass the app's rp_id<->origin check, and cannot forge user
// verification: every assertion still needs the vault unlocked and the app's
// own approval. The app's `handle_passkeys` switch still overrides all of it.
const POLICY_KEY = "passkeyPolicy";

async function policyFor(host) {
  if (!host) return "ask";
  try {
    const got = await api.storage.local.get(POLICY_KEY);
    const p = (got[POLICY_KEY] || {})[host.toLowerCase()];
    return p === "always" || p === "never" ? p : "ask";
  } catch (_e) {
    return "ask";
  }
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg.cmd !== "string") return false;

  const tabId = sender.tab && sender.tab.id;

  switch (msg.cmd) {
    case "capturePending":
      if (tabId != null) {
        pendingSaves.set(tabId, {
          candidate: {
            url: msg.url,
            username: msg.username,
            password: msg.password,
          },
          ts: Date.now(),
        });
        // Actively wipe the stored plaintext password after the TTL, so an
        // abandoned SPA login doesn't retain it indefinitely.
        setTimeout(() => {
          const e = pendingSaves.get(tabId);
          if (e && Date.now() - e.ts >= PENDING_TTL_MS) pendingSaves.delete(tabId);
        }, PENDING_TTL_MS + 500);
      }
      sendResponse({ ok: true });
      return true;

    case "consumePending": {
      const entry = tabId != null ? pendingSaves.get(tabId) : null;
      if (tabId != null) pendingSaves.delete(tabId);
      const fresh = entry && Date.now() - entry.ts < PENDING_TTL_MS;
      sendResponse({ ok: true, candidate: fresh ? entry.candidate : null });
      return true;
    }

    case "clearPending":
      if (tabId != null) pendingSaves.delete(tabId);
      sendResponse({ ok: true });
      return true;

    case "gesture":
      recordGesture(tabId).then(() => sendResponse({ ok: true }));
      return true;

    case "passkeyGate":
      // `msg.host` comes from the isolated content script's own `location`,
      // which the page cannot spoof — the same rule the ceremony's origin
      // already follows.
      policyFor(msg.host).then(async (policy) => {
        const version = api.runtime.getManifest().version;
        const reply = (allow, reason) =>
          sendResponse({ ok: true, allow, reason, version });

        if (policy === "never") {
          await clearGesture(tabId);
          reply(false, "site_never");
          return;
        }

        // REGISTRATION IS DIFFERENT, and this is the rule the GitHub prompt
        // loop kept walking through.
        //
        // A create() must have a gesture in the very document that fired it.
        // Neither the tab-wide ledger nor a site set to "always" may stand in
        // for one: the ledger exists so a sign-in can follow a click across
        // Entra's navigation, and "always" is a user saying "let Arca sign me
        // in here" — neither is consent to mint a new credential. GitHub
        // re-offers "add a passkey" on a timer, and with either of those
        // standing in, every offer became a Touch ID prompt on a machine whose
        // owner had done nothing.
        if (msg.isCreate) {
          await clearGesture(tabId);
          reply(!!msg.localGesture, msg.localGesture ? "gesture" : "create_needs_local_gesture");
          return;
        }

        if (policy === "always") {
          // An explicit per-site answer settles it; the gesture is spent either
          // way so it cannot leak into the next ceremony.
          await clearGesture(tabId);
          reply(true, "site_always");
          return;
        }
        if (msg.localGesture) {
          // The relay saw the gesture in this very document. Trust it directly
          // rather than racing our own "gesture" message to this worker.
          await clearGesture(tabId);
          reply(true, "gesture");
          return;
        }
        if (msg.sawLocal) {
          // The user HAS interacted with this document, and the relay's own
          // (tighter) window already said no. A gesture carried from the page
          // that navigated here is stale by construction once the user has
          // moved on, so the ledger must not be allowed to overrule that —
          // otherwise the in-document window silently widens to the carry TTL.
          await clearGesture(tabId);
          reply(false, "gesture_stale");
          return;
        }
        const carried = await takeGesture(tabId);
        reply(carried, carried ? "gesture_carried" : "no_gesture");
      });
      return true;
  }

  switch (msg.cmd) {
    case "hello":
      sendNative({
        type: "hello",
        version: api.runtime.getManifest().version,
      }).then(sendResponse);
      return true; // async response

    case "listLogins":
      sendNative({ type: "list_matching_logins", url: msg.url }).then(
        sendResponse,
      );
      return true;

    case "fill":
      // Returns { ok, response: { type: "credentials", username, password } }
      // only if the desktop app authorized it (unlocked + origin match).
      sendNative({ type: "fill", id: msg.id, url: msg.url }).then(sendResponse);
      return true;

    case "passkeyCreate":
      sendNative({
        type: "passkey_create",
        origin: msg.origin,
        rp_id: msg.rpId,
        user_name: msg.userName,
        user_handle: msg.userHandle,
        exclude_credentials: msg.excludeCredentials,
      }).then(sendResponse);
      return true;

    case "passkeyGet":
      sendNative({
        type: "passkey_get",
        origin: msg.origin,
        rp_id: msg.rpId,
        client_data_hash: msg.clientDataHash,
        allow_credentials: msg.allowCredentials,
      }).then(sendResponse);
      return true;

    case "saveProbe":
      sendNative({
        type: "save_probe",
        url: msg.url,
        username: msg.username,
        password: msg.password,
      }).then(sendResponse);
      return true;

    case "requestUnlock":
      sendNative({ type: "request_unlock" }).then(sendResponse);
      return true;

    case "generatePassword":
      // No url and no id: generating reads nothing from the vault, so there is
      // nothing for the app to scope to an origin.
      sendNative({
        type: "generate_password",
        length: msg.length,
        symbols: msg.symbols,
      }).then(sendResponse);
      return true;

    // ── Bookmarks ─────────────────────────────────────────────────────────
    //
    // Both directions are driven from the popup, never on a timer. Push-out is
    // the only thing Arca does that can DESTROY something the vault cannot
    // restore — bookmarks live in the browser — so it does not happen while
    // nobody is looking.
    case "mirrorSetting":
      (async () => {
        if (typeof msg.allowed === "boolean") {
          await api.storage.local.set({ [MIRROR_ALLOWED_KEY]: msg.allowed });
          // Applied at once: turning it off should take the folder away now,
          // not at the next tick a minute from now.
          await reconcileMirror(msg.allowed ? "enabled" : "disabled");
        }
        const got = await api.storage.local.get(MIRROR_ALLOWED_KEY);
        sendResponse({ ok: true, allowed: got[MIRROR_ALLOWED_KEY] === true });
      })();
      return true;

    case "bookmarksToArca":
      readAll(api)
        .then((items) =>
          sendNative({
            type: "import_bookmarks",
            // Metadata only, and only what a bookmark is: no ids, no dates.
            items: items.map((b) => ({
              title: b.title,
              url: b.url,
              folder: b.folder,
            })),
          }),
        )
        .then((r) =>
          sendResponse(
            r.ok && r.response && r.response.type === "imported_bookmarks"
              ? { ok: true, added: r.response.added, read: true }
              : { ok: false, error: (r.response && r.response.message) || r.error },
          ),
        )
        .catch((e) => sendResponse({ ok: false, error: String(e) }));
      return true;

    case "bookmarksFromArca":
      sendNative({ type: "list_bookmarks" })
        .then(async (r) => {
          if (!r.ok || !r.response || r.response.type !== "bookmarks") {
            return {
              ok: false,
              error: (r.response && r.response.message) || r.error || "unavailable",
            };
          }
          // `deletions` and `confirmed` come from the popup, so removing
          // anything is always something a person chose twice.
          const res = await apply(api, r.response.items, {
            deletions: !!msg.deletions,
            confirmed: !!msg.confirmed,
          });
          return { ok: true, ...res };
        })
        .then(sendResponse)
        .catch((e) => sendResponse({ ok: false, error: String(e) }));
      return true;

    case "saveLogin":
      sendNative({
        type: "save_login",
        url: msg.url,
        username: msg.username,
        password: msg.password,
      }).then(sendResponse);
      return true;

    default:
      return false;
  }
});

// Drop a tab's pending-save candidate and unspent gesture when the tab closes.
api.tabs?.onRemoved?.addListener((tabId) => {
  pendingSaves.delete(tabId);
  clearGesture(tabId);
});

// ── Arca's bookmark folder: cleanup ─────────────────────────────────────────
//
// The mirror is only ephemeral if it actually disappears. A browser that was
// force-quit, an Arca that crashed, a machine that lost power: in every one of
// those the folder is still sitting there next time the browser opens, and the
// whole point of the design is gone.
//
// So cleanup runs at STARTUP, before anything asks whether Arca is reachable.
// Not "clean up if the vault is locked" — clean up first, then let an unlocked
// Arca put the folder back. The failure that matters is the one where nothing
// gets to ask.
const OWNED_ID_KEY = "bookmarkFolderId";
const MIRROR_STAMP_KEY = "bookmarkFingerprint";
const MIRROR_ALLOWED_KEY = "bookmarkMirrorAllowed";

async function cleanupArcaBookmarks(why) {
  // Nothing to clean where the permission was never granted — and the guard
  // comes before the import so a context without `bookmarks` (the test
  // harness, a browser that refused the permission) never loads the module.
  if (!api.bookmarks) return;
  // Imported HERE rather than at the top of the file. A static `import` makes
  // this an ES module, and the passkey tests run this exact file in a vm
  // context as a classic script — so a top-level import turns a real test
  // suite into a syntax error, which is a poor trade for one line.
  const { planCleanup } = await import("./bookmarks.js");
  let ownedId = null;
  try {
    const got = await api.storage.local.get(OWNED_ID_KEY);
    ownedId = got[OWNED_ID_KEY] ?? null;
  } catch (_e) {
    /* no record; the sweep below is all we have */
  }
  let tree;
  try {
    tree = await api.bookmarks.getTree();
  } catch (_e) {
    return;
  }
  const { remove, notes } = planCleanup({ tree, ownedId });
  for (const id of remove) {
    try {
      await api.bookmarks.removeTree(id);
    } catch (e) {
      // Reported, not swallowed: a folder that will not go is the difference
      // between "ephemeral" and "permanent", and the user deserves to know
      // which one they have.
      console.warn(`[Arca] could not remove bookmark folder ${id}:`, e);
    }
  }
  try {
    await api.storage.local.remove([OWNED_ID_KEY, MIRROR_STAMP_KEY]);
  } catch (_e) {
    /* nothing to forget */
  }
  if (remove.length || notes.length) {
    console.debug(`[Arca] bookmark cleanup (${why}):`, { remove, notes });
  }
}

// Browser start, and extension install/update/reload. Between them these cover
// every way a session can begin holding a folder from a session that ended
// badly.
api.runtime.onStartup?.addListener(() => cleanupArcaBookmarks("browser startup"));
api.runtime.onInstalled?.addListener(() => cleanupArcaBookmarks("extension loaded"));
// And now, for the reload that fires neither: a service worker respawning after
// eviction runs this file again but neither of the events above.
cleanupArcaBookmarks("worker start");

/// Write Arca's list into the browser, or take it away. One reconcile, driven
/// by ONE question.
///
/// `list_bookmarks` needs an unlocked vault, so its answer decides both
/// directions at once: a list means write, a refusal means remove. There is no
/// separate "is Arca unlocked" call to disagree with it, and no push channel
/// from the app that could be missed — the extension asks, and what it gets
/// back is the whole truth about what should be on screen.
async function reconcileMirror(why) {
  if (!api.bookmarks) return;
  const { planCleanup, OWNED_FOLDER_TITLE } = await import("./bookmarks.js");
  const { buildTree, fingerprint, mirrorGate } = await import("./mirror.js");

  const answer = await sendNative({ type: "list_bookmarks" });
  const items =
    answer.ok && answer.response && answer.response.type === "bookmarks"
      ? answer.response.items || []
      : null;

  const store = await readMirrorState();

  // Locked, quit, or unreachable. Every one of those means the same thing to a
  // user looking at their bookmarks bar, so they get the same answer.
  if (items === null) {
    if (store.id != null) await cleanupArcaBookmarks(`no vault (${why})`);
    return;
  }

  // The sync guard, checked AFTER the cleanup branch above and BEFORE anything
  // is written. Turning the guard on while a folder is already on screen must
  // still take that folder away — a gate that also blocked removal would
  // strand exactly the bookmarks it exists to keep out of a cloud.
  const gate = mirrorGate({ allowed: store.allowed });
  if (!gate.allow) {
    report("info", `mirror skipped (${why}): ${gate.reason}`);
    if (store.id != null) await cleanupArcaBookmarks(`mirroring off (${why})`);
    return;
  }

  const stamp = fingerprint(items);
  if (store.id != null && store.fingerprint === stamp) return; // already right

  // Rebuild rather than diff. The folder is Arca's own, so throwing it away
  // costs nothing, and a full rebuild cannot drift the way a patch can.
  await cleanupArcaBookmarks(`rebuilding (${why})`);

  const { root, used, dropped } = buildTree(items);
  let folderId;
  try {
    const folder = await api.bookmarks.create({
      parentId: "1",
      title: OWNED_FOLDER_TITLE,
    });
    folderId = folder.id;
    // Recorded BEFORE the contents go in. If the browser dies halfway through
    // this, the next startup still knows which folder was ours and can remove
    // it; recording it afterwards would leave a half-built orphan nothing owns.
    await api.storage.local.set({ [OWNED_ID_KEY]: folderId });
    await writeNode(root, folderId);
    await api.storage.local.set({ [MIRROR_STAMP_KEY]: stamp });
  } catch (e) {
    console.warn("[Arca] could not mirror bookmarks:", e);
    report("error", `mirror failed (${why}): ${(e && e.stack) || e}`);
    await cleanupArcaBookmarks("mirror failed");
    return;
  }
  const summary =
    `mirrored ${used} bookmarks (${why})` +
    (dropped ? `, ${dropped} not mirrorable` : "");
  console.debug(`[Arca] ${summary}`);
  report("info", summary);
}

/// Depth-first creation. Folders before their contents, in the order buildTree
/// settled on.
async function writeNode(node, parentId) {
  for (const link of node.links) {
    await api.bookmarks.create({ parentId, title: link.title, url: link.url });
  }
  for (const child of node.folders.values()) {
    const made = await api.bookmarks.create({ parentId, title: child.name });
    await writeNode(child, made.id);
  }
}

async function readMirrorState() {
  try {
    const got = await api.storage.local.get([OWNED_ID_KEY, MIRROR_STAMP_KEY, MIRROR_ALLOWED_KEY]);
    return {
      id: got[OWNED_ID_KEY] ?? null,
      fingerprint: got[MIRROR_STAMP_KEY] ?? null,
      // Absent means NOT allowed. A missing setting must never read as consent.
      allowed: got[MIRROR_ALLOWED_KEY] === true,
    };
  } catch (_e) {
    // Unreadable storage is not permission either.
    return { id: null, fingerprint: null, allowed: false };
  }
}

// A poll, not a subscription, because there is nothing to subscribe to: the app
// cannot call into the extension. `alarms` rather than setInterval — a service
// worker is evicted when idle, and an interval dies with it while an alarm
// wakes it back up.
api.alarms?.create("arca-mirror", { periodInMinutes: 1 });
api.alarms?.onAlarm.addListener((a) => {
  if (a.name === "arca-mirror") reconcileMirror("tick");
});

// ── Telling a terminal what went wrong ──────────────────────────────────────
//
// A service worker's console lives in the browser's memory and nowhere else.
// No file, no `log show`, nothing a terminal can reach — so when the person
// hitting the bug and the person fixing it are not in the same room, an
// exception here is simply invisible. Both of today's other logs exist for the
// same reason and both settled arguments that were otherwise guesswork.
//
// Fire and forget, and never allowed to throw: a reporter that can fail is a
// second bug on top of the first one.
function report(level, message) {
  try {
    const p = api.runtime.sendNativeMessage(NATIVE_HOST, {
      type: "log",
      level,
      message: String(message).slice(0, 2000),
    });
    if (p && typeof p.catch === "function") p.catch(() => {});
  } catch (_e) {
    /* the host is unreachable; there is nowhere left to say so */
  }
}

// Anything the worker throws, and any promise nobody caught. Between them these
// cover the failures that would otherwise show up only as "nothing happened".
self.addEventListener?.("error", (e) =>
  report("error", `${e.message} @ ${e.filename}:${e.lineno}`),
);
self.addEventListener?.("unhandledrejection", (e) =>
  report("error", `unhandled rejection: ${(e.reason && e.reason.stack) || e.reason}`),
);
