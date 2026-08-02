# Passkeys (WebAuthn) — architecture & roadmap

**Status:** there are **two** ways an authenticator can reach a passkey
ceremony, and Arca ships one of them.

| Path | State |
| --- | --- |
| **Browser extension** (`extension/chromium/passkey.js`) | **Working**, on every Chromium browser and on Linux, where no platform authenticator exists at all. This is what signs you in today. |
| **OS credential provider** (`apps/macos/`, `apps/ios/`) | **Not built for passkeys.** `ProvidesPasskeys` is deliberately `false`, so Arca does not appear in the system chooser only to fail. Gated on an Apple Developer account. |

The cryptographic core underneath both is `crates/vault-core/src/passkey.rs`,
implemented and unit-tested.

## How the extension path works

Passwords autofill by typing text into a field, which any content script can do.
Passkeys go through the browser's **WebAuthn** engine
(`navigator.credentials.create/get`), so Arca wraps that API in the page's own
JS world — a `world: "MAIN"` content script at `document_start` — and answers the
ceremony itself via the isolated relay → background worker → native host →
loopback bridge. Anything it cannot service (vault locked, no passkey for this
relying party, a non-ES256 request) falls through to the browser's real handler,
so security keys and phones keep working. Every fallback logs its reason at
`console.debug`, because from the outside they are indistinguishable.

Two things about this path are easy to get wrong, and both shipped broken once:

- **Deciding whether the user asked for it.** A ceremony often does not run in
  the document the user clicked in — Microsoft Entra navigates to
  `login.microsoft.com/common/bridge/fido`, which fires `get()` on load. A
  gesture tracked inside the page dies with the page, so the gesture is kept in
  a per-tab ledger in the background worker, and consumed once. A per-site
  `ask`/`always`/`never` override lives in the popup.
- **What is handed back.** The relying party must receive something that behaves
  like a real `PublicKeyCredential` — `toJSON()` and working `instanceof` — not
  an object literal with the right fields. Get it wrong and the ceremony
  *succeeds*, Arca reports success, and the site fails on its own error.

`extension/test/passkey.test.mjs` covers both against the real files.

## What the OS credential provider would add

To appear in the system's "Choose where to save your passkey" chooser on macOS
and iOS (the way iCloud Keychain, 1Password and Dashlane do), an app must ship a
native **AutoFill Credential Provider** app extension that the OS loads and the
user enables in **System Settings → Passwords → Password Options**. That is a
different mechanism from both the loopback autofill bridge and the WebAuthn shim
above, and it is the only way to serve passkeys *outside* the browser.

## The pieces

```
 ┌───────────────────────────────────────────────────────────────────┐
 │  Relying party (github.com) in the browser                        │
 │     navigator.credentials.create()/get()                          │
 └───────────────┬───────────────────────────────────────────────────┘
                 │  WebAuthn, driven by the OS
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  AutoFill Credential Provider extension (Swift)     [NOT BUILT]   │
 │  no passkey provider exists; apps/macos/ArcaAutoFill and          │
 │  apps/ios/ArcaAutoFill are passwords-only (ProvidesPasskeys=false)│
 │   • ASCredentialProviderExtension: prepare list / register /      │
 │     assert; the OS supplies clientDataHash + does Touch ID        │
 │   • reads the vault from the shared App Group container           │
 │   • calls the Rust core over a C ABI ↓                            │
 └───────────────┬───────────────────────────────────────────────────┘
                 │  C ABI
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  vault-ffi (Rust staticlib/cdylib)              [DONE, ABI v3]    │
 │  crates/vault-ffi/  — thin C wrapper over…                        │
 └───────────────┬───────────────────────────────────────────────────┘
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  vault-core::passkey (P-256 / ES256 WebAuthn)   [DONE + TESTED]   │
 │   • create()  → attestationObject (fmt "none") + private key      │
 │   • assert()  → authenticatorData + DER ES256 signature           │
 │  vault-core / vault-store — the encrypted vault the passkey lives │
 │  in, unlocked via the OS-keychain device key (Touch ID).          │
 └───────────────────────────────────────────────────────────────────┘
```

## What is done

- **`vault-core::passkey`** — ES256/P-256 authenticator: keypair generation,
  `authenticatorData` assembly, COSE public-key encoding, `attestationObject`
  (`fmt: "none"`) for registration, and DER ECDSA assertion signatures over
  `authenticatorData || clientDataHash`, plus the signature counter. Unit-tested
  (attestation shape, signature verifies against the credential's public key, a
  wrong key is rejected, bad key material errors instead of panicking).
- **`VaultItem::Passkey`** now stores the real credential (rp_id, user_name,
  user_handle, credential_id, private key, sign_count), zeroized like every
  secret and encrypted at rest. It round-trips through the vault's tagged-CBOR
  payload (test in `vault-core/src/lib.rs`).

## What remains (gated on an Apple Developer account)

1. **`vault-ffi`** — mostly there now. Vault open/unlock crosses the ABI (v2 with
   the device key, v3 with the master password), and
   `vault_ffi_passkey_create`/`_assert` expose the authenticator itself. What is
   missing is *listing* stored passkeys and *writing* a new one back, which needs
   the same vault-write surface iOS needs — see [`IOS.md`](./IOS.md) §2.
2. **Xcode wrapper** — solved. `apps/macos/project.yml` builds a host and embeds
   the `.appex`, and `apps/ios/project.yml` does the same for the phone. Tauri
   still does not embed app extensions, so for release the `.appex` gets injected
   into `Arca.app/Contents/PlugIns/` and co-signed.
3. **Entitlements & provisioning** — solved for the *passwords* extension in
   `apps/macos/` and `apps/ios/`: the AutoFill capability on **both** the
   containing app and the extension, the `group.no.sybr.vault` App Group, and a
   shared keychain access group. A passkey provider needs all of that plus
   `ProvidesPasskeys = true`, which is deliberately `false` today so Arca does
   not appear in the chooser only to fail. Distribution still needs a
   provisioning profile on the App ID and notarization.
4. **Enable on device:** System Settings → Passwords → Password Options → turn
   on "Arca". Only then does it appear in the system passkey chooser.
5. **Windows / Linux:** out of scope for now. Windows has a brand-new "plugin
   authenticator" model; Linux has no standard third-party passkey provider
   hook. macOS first.

## Security notes (feeds THREAT_MODEL.md)

- The credential private key is a P-256 scalar stored inside the encrypted vault
  and zeroized in memory; it never leaves the device.
- The extension unlocks via the OS-keychain device key gated by Touch ID (the OS
  performs the biometric as part of the AutoFill flow), so the master password is
  not needed per assertion. Same residual as T10 (device-key theft by same-user
  code) applies.
- `attestationObject` uses `fmt: "none"` — no attestation CA, no device
  identifier leaked to relying parties (privacy-preserving, and what most
  software authenticators do).
- Independent review of `passkey.rs` against the WebAuthn spec is required before
  this is used for real credentials (tracked with the overall audit).
