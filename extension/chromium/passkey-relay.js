// Isolated-world relay for the main-world WebAuthn shim (passkey.js).
//
// Runs at document_start (like the shim), so an early passkey call — e.g.
// conditional-UI autofill during page load — has a listener ready immediately
// and never stalls waiting for the (document_idle) content script.
//
// SECURITY: the origin used for the app's rp_id<->origin anti-phishing check is
// taken from THIS isolated content script's `location.origin` (which the page
// cannot spoof), never from the page-posted message payload.
(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (window.__sybrPasskeyRelay) return;
  window.__sybrPasskeyRelay = true;

  window.addEventListener("message", async (e) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.__sybrPasskey !== "request") return;
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
