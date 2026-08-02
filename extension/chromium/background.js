// Background service worker (Chromium) / event page (Firefox).
//
// It is the only context allowed to talk to the native-messaging host. Content
// scripts and the popup send it messages; it relays them to the Rust host and
// returns the response. The vault stays owned by the desktop app, which only
// releases a credential on an explicit "fill" for a matching origin while
// unlocked; "listLogins" only ever returns metadata.

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
        if (policy !== "ask") {
          // An explicit per-site answer settles it; the gesture is spent either
          // way so it cannot leak into the next ceremony.
          await clearGesture(tabId);
          sendResponse({
            ok: true,
            allow: policy === "always",
            reason: policy === "always" ? "site_always" : "site_never",
          });
          return;
        }
        if (msg.localGesture) {
          // The relay saw the gesture in this very document. Trust it directly
          // rather than racing our own "gesture" message to this worker.
          await clearGesture(tabId);
          sendResponse({ ok: true, allow: true, reason: "gesture" });
          return;
        }
        if (msg.sawLocal) {
          // The user HAS interacted with this document, and the relay's own
          // (tighter) window already said no. A gesture carried from the page
          // that navigated here is stale by construction once the user has
          // moved on, so the ledger must not be allowed to overrule that —
          // otherwise the in-document window silently widens to the carry TTL.
          await clearGesture(tabId);
          sendResponse({ ok: true, allow: false, reason: "gesture_stale" });
          return;
        }
        const carried = await takeGesture(tabId);
        sendResponse({
          ok: true,
          allow: carried,
          reason: carried ? "gesture_carried" : "no_gesture",
        });
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
