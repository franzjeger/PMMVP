# macOS AutoFill Credential Provider (passkeys) — scaffold

This is the OS-facing half of passkey support: the app extension macOS loads so
**SYBR Passwords appears in the system passkey chooser** ("Choose where to save
your passkey…"). It calls the Rust `vault-ffi` C ABI for the ES256 authenticator
work (which is implemented and tested).

**It does not build from this directory alone** — it needs an Xcode target,
Apple entitlements, and the vault-ffi static library. See `../../docs/PASSKEYS.md`
for the full architecture.

## Files

| File | Purpose |
|------|---------|
| `CredentialProviderViewController.swift` | The extension: passkey registration + assertion, calling `vault_ffi_*`. |
| `Info.plist` | Extension point + `ProvidesPasskeys = true`. |
| `CredentialProvider.entitlements` | AutoFill entitlement + shared App Group. |

## Wiring it up (requires an Apple Developer account)

1. **Build the Rust static lib** for Apple targets:
   ```
   rustup target add aarch64-apple-darwin x86_64-apple-darwin
   cargo build -p vault-ffi --release --target aarch64-apple-darwin
   ```
   Link `libvault_ffi.a` into the extension target and add
   `crates/vault-ffi/include/vault_ffi.h` to a bridging header.
2. **Create the extension target** in an Xcode project that also builds the main
   app (Tauri does not embed app extensions, so the `.appex` must be injected
   into `SYBR Passwords.app/Contents/PlugIns/` and co-signed — an Xcode wrapper
   is the pragmatic route).
3. **Entitlements** (Developer portal): enable
   `com.apple.developer.authentication-services.autofill-credential-provider`
   on the App ID and register the `group.no.sybr.vault` App Group on both the
   app and the extension.
4. **Finish `TODO(vault-access)`**: the extension reads/writes the encrypted
   vault via the shared App Group container + the OS-keychain device key. This
   needs a small vault-open surface added to `vault-ffi`.
5. **Enable on device:** System Settings → Passwords → Password Options → turn
   on **SYBR Passwords**. It then appears in the passkey chooser.
