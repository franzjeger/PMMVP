# Passkeys (WebAuthn) — architecture & roadmap

**Status:** the cryptographic authenticator core is implemented and unit-tested
in `crates/vault-core/src/passkey.rs`. The OS integration that makes SYBR
Passwords appear in the system's "Choose where to save your passkey" dialog is
scaffolded here and is the remaining work — it is gated on an Apple Developer
account (entitlements + notarization) and cannot be completed or tested without
one.

## Why an extension can't do this

Password autofill just types text into a field, so a browser content script can
do it. Passkeys go through the browser's built-in **WebAuthn** engine
(`navigator.credentials.create/get`), and on macOS the "where to save / which
passkey" chooser is drawn by the **operating system**, not by the page or the
browser. A regular browser extension cannot insert itself into that chooser.

To appear there (the way iCloud Keychain, 1Password, and Dashlane do) an app
must ship a native **AutoFill Credential Provider** app extension that the OS
loads and the user enables in **System Settings → Passwords → Password
Options**. This is a different mechanism from our loopback autofill bridge.

## The pieces

```
 ┌───────────────────────────────────────────────────────────────────┐
 │  Relying party (github.com) in the browser                        │
 │     navigator.credentials.create()/get()                          │
 └───────────────┬───────────────────────────────────────────────────┘
                 │  WebAuthn, driven by the OS
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  macOS AutoFill Credential Provider extension (Swift)  [SCAFFOLD]  │
 │  apps/macos-credential-provider/                                  │
 │   • ASCredentialProviderExtension: prepare list / register /      │
 │     assert; the OS supplies clientDataHash + does Touch ID        │
 │   • reads the vault from the shared App Group container           │
 │   • calls the Rust core over a C ABI ↓                             │
 └───────────────┬───────────────────────────────────────────────────┘
                 │  C ABI
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  vault-ffi (Rust cdylib/staticlib)          [SCAFFOLD, pure part] │
 │  crates/vault-ffi/  — thin C wrapper over…                        │
 └───────────────┬───────────────────────────────────────────────────┘
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  vault-core::passkey (P-256 / ES256 WebAuthn)   [DONE + TESTED]    │
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

1. **`vault-ffi`** — expose vault open/unlock (via the App Group container + the
   device key) and passkey list/register/assert across the C ABI. The pure
   passkey primitives are trivial to expose; the vault-access surface is the
   real work (sharing the encrypted vault + device key between the app and the
   sandboxed extension via an App Group + shared keychain access group).
2. **Xcode wrapper.** Tauri does not embed app extensions. The app must be built
   (or post-processed) so the `.appex` lands in `Arca.app/Contents/
   PlugIns/`, code-signed together. In practice this means an Xcode project (or
   a `tauri build` + inject/re-sign step) — decide during implementation.
3. **Entitlements & provisioning** (needs the Apple Developer account):
   - `com.apple.developer.authentication-services.autofill-credential-provider`
     on the extension.
   - A shared **App Group** (`group.no.sybr.vault`) on both targets so the
     extension can read the vault + device key.
   - A provisioning profile enabling the entitlement on the App ID, and
     notarization for distribution.
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
