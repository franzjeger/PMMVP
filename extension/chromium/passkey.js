// Passkey provider (main world). Runs at document_start in the page's own JS
// context so it can wrap the WebAuthn API. When a relying party calls
// navigator.credentials.create/get with a `publicKey` request, we hand it to
// the Arca desktop app (via the isolated content script -> background
// -> native host -> loopback bridge), which does the ES256 authenticator work,
// and return a WebAuthn-shaped result. If we can't service it (app locked, no
// matching passkey, only non-ES256 requested, error), we fall back to the
// browser's native handler so security keys / phone / built-in still work.
//
// This is the cross-platform path (works on Linux + every Chromium browser),
// independent of any OS credential-provider framework.

(() => {
  const creds = navigator.credentials;
  if (!creds || !creds.create || !creds.get || window.__sybrPasskeyHooked) return;
  window.__sybrPasskeyHooked = true;

  const realCreate = creds.create.bind(creds);
  const realGet = creds.get.bind(creds);

  // Request/response correlation with the isolated content script.
  let seq = 0;
  const pending = new Map();
  window.addEventListener("message", (e) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.__sybrPasskey !== "response") return;
    const resolve = pending.get(d.id);
    if (resolve) {
      pending.delete(d.id);
      resolve(d);
    }
  });
  function ask(kind, payload) {
    return new Promise((resolve) => {
      const id = `${seq++}`;
      pending.set(id, resolve);
      window.postMessage(
        { __sybrPasskey: "request", kind, id, payload },
        window.location.origin,
      );
      // Safety timeout: fall back if the app never answers.
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          resolve({ ok: false });
        }
      }, 60000);
    });
  }

  const enc = new TextEncoder();
  const toArr = (buf) => (buf ? Array.from(new Uint8Array(buf)) : []);
  const fromArr = (arr) => new Uint8Array(arr || []).buffer;
  const b64url = (buf) => {
    let s = "";
    for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  function clientDataJSON(type, challenge) {
    return enc.encode(
      JSON.stringify({
        type,
        challenge: b64url(challenge),
        origin: window.location.origin,
        crossOrigin: false,
      }),
    ).buffer;
  }

  function shapedCredential(rawId, response, extras) {
    const cred = {
      id: b64url(rawId),
      rawId,
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => ({}),
    };
    Object.assign(cred, extras || {});
    return cred;
  }

  navigator.credentials.create = async function (options) {
    const pk = options && options.publicKey;
    if (!pk) return realCreate(options);
    try {
      // We only implement ES256. If the RP requires something else, defer.
      const algs = (pk.pubKeyCredParams || []).map((p) => p.alg);
      if (algs.length && !algs.includes(-7)) return realCreate(options);

      const cdj = clientDataJSON("webauthn.create", pk.challenge);
      const resp = await ask("create", {
        origin: window.location.origin,
        rpId: (pk.rp && pk.rp.id) || window.location.hostname,
        userName: (pk.user && pk.user.name) || "",
        userHandle: toArr(pk.user && pk.user.id),
      });
      if (!resp.ok) return realCreate(options);

      const response = {
        clientDataJSON: cdj,
        attestationObject: fromArr(resp.attestationObject),
        getTransports: () => ["internal"],
        getPublicKeyAlgorithm: () => -7,
        getPublicKey: () => null,
        getAuthenticatorData: () => null,
      };
      return shapedCredential(fromArr(resp.credentialId), response);
    } catch (_e) {
      return realCreate(options);
    }
  };

  navigator.credentials.get = async function (options) {
    const pk = options && options.publicKey;
    if (!pk) return realGet(options);
    // Conditional / silent mediation is *passive* passkey autofill: the page
    // probes on load or field-focus to offer credentials, it is NOT an explicit
    // "use my passkey" action. Servicing it ourselves would pop an approval /
    // Touch ID prompt just for visiting the page — and again every time the page
    // re-arms autofill. Defer these to the browser's native handler; Arca only
    // answers the modal flow the user actively triggers (default/required).
    const mediation = options && options.mediation;
    if (mediation === "conditional" || mediation === "silent") {
      return realGet(options);
    }
    try {
      const cdj = clientDataJSON("webauthn.get", pk.challenge);
      const clientDataHash = await crypto.subtle.digest("SHA-256", cdj);
      const resp = await ask("get", {
        origin: window.location.origin,
        rpId: pk.rpId || window.location.hostname,
        clientDataHash: toArr(clientDataHash),
        allowCredentials: (pk.allowCredentials || []).map((c) => toArr(c.id)),
      });
      if (!resp.ok) return realGet(options);

      const uh = resp.userHandle && resp.userHandle.length ? fromArr(resp.userHandle) : null;
      const response = {
        clientDataJSON: cdj,
        authenticatorData: fromArr(resp.authenticatorData),
        signature: fromArr(resp.signature),
        userHandle: uh,
      };
      return shapedCredential(fromArr(resp.credentialId), response);
    } catch (_e) {
      return realGet(options);
    }
  };
})();
