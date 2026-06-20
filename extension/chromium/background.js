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

api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg.cmd !== "string") return false;

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

    default:
      return false;
  }
});
