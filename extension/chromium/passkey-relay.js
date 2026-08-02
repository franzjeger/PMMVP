// Isolated-world relay for the main-world WebAuthn shim (passkey.js).
//
// Runs at document_start (like the shim), so an early passkey call — e.g.
// conditional-UI autofill during page load — has a listener ready immediately
// and never stalls waiting for the (document_idle) content script.
//
// SECURITY: the origin used for the app's rp_id<->origin anti-phishing check is
// taken from THIS isolated content script's `location.origin` (which the page
// cannot spoof), never from the page-posted message payload. The hostname the
// per-site passkey policy is keyed by comes from the same place.
(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (window.__sybrPasskeyRelay) return;
  window.__sybrPasskeyRelay = true;

  /** Fire-and-forget message; a sleeping worker must not throw into the page. */
  function tell(message) {
    try {
      const p = api.runtime.sendMessage(message);
      if (p && typeof p.catch === "function") p.catch(() => {});
    } catch (_e) {
      /* extension context torn down */
    }
  }

  // Real user input, watched in the capture phase so it is seen before the
  // page's own handlers — which may call credentials.get() synchronously.
  //
  // Two records are kept, because a ceremony can run in either place:
  //   • `localGesture`, for a ceremony fired in THIS document. Answered without
  //     a round trip, so a synchronous click handler cannot lose a race against
  //     our own message to the background worker.
  //   • the worker's per-tab ledger, for a ceremony fired in a document the
  //     user never clicked in — Entra's /common/bridge/fido, which the browser
  //     navigates to and which fires get() on load.
  const GESTURE_WINDOW_MS = 3000;
  const REPORT_THROTTLE_MS = 500;
  let localGesture = 0;
  let sawLocal = false;
  let lastReport = 0;

  for (const type of ["pointerdown", "keydown", "touchstart"]) {
    window.addEventListener(
      type,
      () => {
        localGesture = Date.now();
        sawLocal = true;
        // A burst of keystrokes must not be a burst of worker messages; the
        // ledger only needs to know that a gesture happened, not how many.
        if (localGesture - lastReport > REPORT_THROTTLE_MS) {
          lastReport = localGesture;
          tell({ cmd: "gesture" });
        }
      },
      true,
    );
  }

  window.addEventListener("message", async (e) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.__sybrPasskey !== "request") return;

    // May Arca answer this ceremony at all? Settled before anything reaches the
    // native host, so a declined gate never even wakes the desktop app.
    if (d.kind === "gate") {
      const fresh =
        localGesture > 0 && Date.now() - localGesture <= GESTURE_WINDOW_MS;
      if (fresh) localGesture = 0; // one gesture, one ceremony
      let res = null;
      try {
        res = await api.runtime.sendMessage({
          cmd: "passkeyGate",
          host: location.hostname,
          localGesture: fresh,
          // Once the user has touched THIS document the in-document rule
          // governs alone, so a gesture carried from the page that navigated
          // here is not allowed to widen the old 3s window to the ledger's.
          sawLocal,
        });
      } catch (_e) {
        res = null;
      }
      window.postMessage(
        {
          __sybrPasskey: "response",
          id: d.id,
          ok: !!(res && res.allow),
          reason: (res && res.reason) || "gate_unavailable",
        },
        location.origin,
      );
      return;
    }

    const cmd = d.kind === "create" ? "passkeyCreate" : "passkeyGet";
    let result;
    try {
      const payload = { ...d.payload, origin: location.origin };
      result = await api.runtime.sendMessage({ cmd, ...payload });
    } catch (_e) {
      result = null;
    }
    const resp = result && result.ok ? result.response : null;
    const reply = { __sybrPasskey: "response", id: d.id, ok: false };
    if (resp && resp.type === "passkey_credential") {
      reply.ok = true;
      reply.credentialId = resp.credential_id;
      reply.attestationObject = resp.attestation_object;
    } else if (resp && resp.type === "error") {
      reply.error = resp.message;
    } else if (resp && resp.type === "passkey_assertion") {
      reply.ok = true;
      reply.credentialId = resp.credential_id;
      reply.authenticatorData = resp.authenticator_data;
      reply.signature = resp.signature;
      reply.userHandle = resp.user_handle;
    }
    window.postMessage(reply, location.origin);
  });
})();
