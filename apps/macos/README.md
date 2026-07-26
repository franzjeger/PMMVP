# Arca — macOS AutoFill Credential Provider

Native system-wide AutoFill so Arca can stand in for Apple Passwords in Safari
and native apps. This is a **passwords-only** effort (passkeys, sync, and the
browser extension are separate phases).

The Xcode project is generated from [`project.yml`](project.yml) with
[XcodeGen](https://github.com/yonabota/XcodeGen) — `project.yml` is the source of
truth; the `.xcodeproj` is git-ignored.

The Swift↔Rust bridge lives in [`../apple-shared/`](../apple-shared/), not here:
it is platform-agnostic and [`apps/ios`](../ios/) links the same file.

## Targets

| Target | Type | Purpose |
|--------|------|---------|
| `ArcaHost` | app | Dev/debug **container** for the extension, plus a screen that publishes the vault's logins to `ASCredentialIdentityStore`. The shipping container will be the Tauri `Arca.app` (the `.appex` gets injected there before release); this host is a harness. |
| `ArcaAutoFill` | app-extension | The `ASCredentialProviderViewController` the OS loads. `ProvidesPasswords = true`. |
| `ArcaBridgeTests` | unit-test | The repo's only Swift tests, over the shared bridge. Attached to the `ArcaHost` scheme, so `xcodebuild test -scheme ArcaHost` runs them; CI does. |

## Two invariants that are easy to break

- **`ArcaKeychainAccessGroup` in both Info.plists must match
  `keychain-access-groups` in the entitlements.** Both are
  `$(AppIdentifierPrefix)no.sybr.vault.shared`, expanded by Xcode from the
  provisioning profile, which is how `VaultBridge.swift` learns the team prefix
  without hardcoding one. Change the group in one place and the extension
  searches a keychain group it isn't entitled to — `errSecItemNotFound`, no
  louder signal than that. An unsigned build (`CODE_SIGNING_ALLOWED=NO`) leaves
  the variable unexpanded; the bridge detects that and falls back, so a CI
  compile still works.
- **`VaultShared.requiredAbiVersion` must match `ABI_VERSION` in
  `crates/vault-ffi/src/lib.rs`.** Opening a vault checks it and fails closed.
  Bumping the Rust constant without bumping this one turns every unlock into
  "Reinstall Arca"; bumping neither, after a signature change, is worse — the
  wrong bytes get filled into someone's login form.

  Both halves are now enforced. `ArcaBridgeTests` asserts
  `VaultShared.requiredAbiVersion == vault_ffi_abi_version()` against the
  actually-linked library, and `cargo test -p vault-ffi` checks that
  `include/vault_ffi.h` names the current `ABI_VERSION` and declares every
  exported symbol — that header sat claiming v2 for a v3 library.

## Status — M2

The extension fills real passwords. There is no placeholder credential left:

- `ArcaAutoFill` opens the shared vault through `vault-ffi` — Touch ID reads the
  device key from the shared keychain group — and returns the selected
  credential, copied straight into `ASPasswordCredential` and never retained.
- `ArcaHost` publishes the vault's login identities to
  `ASCredentialIdentityStore`: metadata only, domain and username, never a
  password.

**Shelved rather than shipped**, for the reason the root README gives: Touch ID
on every fill and a fight with Apple's own password menu made it worse than the
browser extension. The source is kept because the App Group, keychain-group and
provisioning pattern it proved is exactly what [`apps/ios/`](../ios/) now uses —
where the same OS integration is the good one.

## Build & try it

```sh
cd apps/macos
xcodegen generate          # writes Arca.xcodeproj from project.yml
open Arca.xcodeproj
```

1. Select the **ArcaHost** scheme. In **Signing & Capabilities**, confirm the
   Team. `project.yml` sets `LY6LJ395B8`, which must match `apps/ios` — App
   Groups and keychain groups are team-scoped. Automatic signing provisions the
   `authentication-services.autofill-credential-provider` capability, so there
   is no Apple portal step.
2. **Run** (⌘R). The host window opens (this also registers the extension with
   the OS).
3. **System Settings ▸ General ▸ AutoFill & Passwords** and toggle **Arca** on
   (the host's "Open AutoFill Settings" button jumps there). This alone confirms
   the extension loaded and the entitlement is valid.
4. Back in the host: **Refresh**, then **Sync to AutoFill** — one Touch ID, to
   read your logins. It publishes domain + username for every login in the
   vault.
5. Open one of those sites in **Safari**, focus the username/password field, and
   pick the Arca suggestion. Touch ID again, and the real password fills.

> AutoFill only offers a credential on a page that both matches a published
> domain **and** has a login form, so a bare page like `example.com` has nothing
> to fill even if you have a login saved for it.

## Troubleshooting: Arca doesn't appear in the AutoFill list

**The capability must be on BOTH targets.** The single thing that made Arca
appear under "AutoFill from": the `authentication-services.autofill-credential-provider`
capability has to be on the **containing app** (`ArcaHost`) as well as the
extension. With it on the extension alone the extension registers with `pkd` but
the OS never offers it as a provider — no error anywhere.

Other things the OS silently requires:

- **The extension must be sandboxed.** `ArcaAutoFill.entitlements` includes
  `com.apple.security.app-sandbox`. Without it `pkd` discards the extension at
  scan time (no error, no log) and it never shows up.
- **`pkd` registers extensions from LaunchServices-trusted locations, not
  reliably from DerivedData.** Copy the built host to `/Applications` and launch
  it once, keeping a single copy registered:

  ```sh
  APP=~/Library/Developer/Xcode/DerivedData/Arca-*/Build/Products/Debug/ArcaHost.app
  ditto $APP /Applications/ArcaHost.app && open /Applications/ArcaHost.app
  pluginkit -m | grep sybr        # should list no.sybr.vault.autofill-host.autofill
  ```

  If several stale copies pile up (multiple builds), `pkd` can't pick a
  canonical container and registers none — unregister the extras with
  `lsregister -u <path>` so only one `ArcaHost.app` remains.

## Verify without signing

```sh
cd apps/macos && xcodegen generate
xcodebuild -scheme ArcaHost -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO -derivedDataPath build build
```

Compiles the host + extension and embeds `ArcaAutoFill.appex` into
`ArcaHost.app/Contents/PlugIns/`. Running it (and toggling it on in System
Settings) requires a signed build from your Xcode, since provisioning needs your
Apple ID account.

CI runs exactly this on the macOS matrix leg, for pull requests and manual
dispatch — the only machine in CI with Xcode, and the only thing standing
between the Swift and nobody ever compiling it. It goes through
[`scripts/build-apple-ci.sh`](../../scripts/build-apple-ci.sh), which prints a
count of compiler diagnostics rather than leaving you to infer cleanliness from
an empty log.

## Not this (deliberately, for later phases)

- **Chromium browsers** (Chrome/Brave) on macOS use their own web autofill and
  generally do **not** call the system provider for in-page logins — those are
  covered by the browser extension. Safari + native apps are this provider's
  surface.
- Passkeys: `ProvidesPasskeys` is `false` in `ArcaAutoFill/Info.plist` on
  purpose — the FFI can create and assert a credential but nothing can store
  one, so advertising the capability would put Arca in the passkey chooser only
  to fail. See [`docs/PASSKEYS.md`](../../docs/PASSKEYS.md).
