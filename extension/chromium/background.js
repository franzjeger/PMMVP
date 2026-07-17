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

// Drop a tab's pending-save candidate when the tab closes.
api.tabs?.onRemoved?.addListener((tabId) => pendingSaves.delete(tabId));
