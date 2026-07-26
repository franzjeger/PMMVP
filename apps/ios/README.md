# Arca for iOS — scaffold

A SwiftUI app plus an AutoFill Credential Provider extension, both over the same
Rust core the desktop uses.

**None of this has been compiled locally**, let alone run on a device — it was
written on Linux, where the Apple frameworks it imports do not exist. CI builds
both schemes unsigned on the macOS runner for every pull request, via
[`scripts/build-apple-ci.sh`](../../scripts/build-apple-ci.sh), which reports a
count of compiler diagnostics so a clean build is asserted rather than inferred.
That count is what gates `SWIFT_VERSION: 6.0`: `SWIFT_STRICT_CONCURRENCY` is
already `complete`, so its findings are warnings now and errors then.

The Xcode project is generated from [`project.yml`](project.yml) with
[XcodeGen](https://github.com/yonabot/XcodeGen); the `.xcodeproj` is git-ignored.

## What it does

| | |
| --- | --- |
| Unlock | Face ID / Touch ID once quick unlock is on, master password otherwise (Argon2id, `vault_ffi_vault_open_password`). |
| Browse | Search logins, see username/site/title, reveal one password. |
| Copy | `localOnly` (never reaches Universal Clipboard) and cleared by iOS after 30s. |
| AutoFill | Registers as a password provider and publishes identities (metadata only) to `ASCredentialIdentityStore` on unlock, so Arca appears in the QuickType bar. |
| Quick unlock | Mints a device key via `vault_ffi_enable_device_unlock`, stored behind `biometryCurrentSet` so enrolling a new face invalidates it. |
| Lock | On backgrounding, and the app-switcher snapshot is covered. |

## What it does not do, and why

These are not polish items. Each is blocked on something that does not exist.

**No sync.** `apps/desktop/src-tauri/src/sync.rs` is a ~670-line Google Drive
client living *inside the desktop app crate*, so nothing else can call it, and
its OAuth flow uses a loopback redirect that iOS has no equivalent for. Until
that moves to a shared crate ([`docs/IOS.md`](../../docs/IOS.md)), the vault
reaches the phone by hand: AirDrop `default.vault` from the Mac and import it.
That import screen is a stopgap wearing a stopgap's label.

**Read-only** (except quick unlock). No creating, editing or deleting items. The ABI exposes open,
list identities and fetch one password; that is the whole surface.

**Logins only.** `vault_ffi_identities` filters to `ItemKind::Login`, so
passkeys, SSH keys, Wi-Fi networks and secure notes are invisible here. No TOTP
either — it is in `vault-core` but not on the ABI.

### Quick unlock, and the one write that crosses the ABI

`vault_ffi_enable_device_unlock` mints a device key, wraps the vault key with it
and returns both the key and **new vault file bytes** — the only ABI call that
produces a replacement vault. It still writes nothing itself; `vault-core` is
I/O-free and the caller owns the write.

Two rules the Swift side follows, both for the same reason (this is the user's
only copy of their vault):

- **The vault file is written before the key is stored.** A vault carrying a
  wrapping whose key was never saved is inert — the master password still opens
  it. A stored key for a vault that was never written opens nothing.
- **The returned bytes are verified to reopen with the returned key inside
  Rust**, before they are handed over. A caller can never be given a vault it
  cannot unlock.

Turning it off strips the wrapping from the file as well as deleting the
keychain item: the wrapping would otherwise travel to every device the vault
syncs to.

## Build

```sh
cd apps/ios
xcodegen generate          # writes Arca.xcodeproj from project.yml
open Arca.xcodeproj
```

The pre-build phase runs [`scripts/build-ffi-ios.sh`](../../scripts/build-ffi-ios.sh),
which adds the Rust targets, cross-compiles `vault-ffi` for device and simulator
and stages `libs/device/libvault_ffi.a` and `libs/simulator/libvault_ffi.a`. Two
are not optional: device and simulator are different *platforms*, and an
SDK-conditional `LIBRARY_SEARCH_PATHS` picks the right one.

Not an `.xcframework`, though `docs/IOS.md` originally asked for one and the
first cut built one. Xcode resolves a framework dependency when it sets the
target up, before any pre-build script runs, so a library the project builds
itself can never exist in time — a clean checkout fails with *"There is no
XCFramework found at …"*. Search paths resolve at link time, which is also how
`apps/macos` links the same library. Package an xcframework if the library is
ever shipped to someone else.

The device slice is arm64 only — every iOS device is. The **simulator** slice is
a `lipo` of arm64 and x86_64, which is not optional: `ARCHS_STANDARD` for
iphonesimulator is `arm64 x86_64`, and a generic simulator destination has no
concrete device to narrow it to, so Xcode links both. An arm64-only simulator lib
fails with *"ignoring file … found architecture 'arm64', required architecture
'x86_64'"* and then every `vault_ffi_*` symbol undefined.

### Compile-check without signing

```sh
cd apps/ios && xcodegen generate
xcodebuild -scheme Arca -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO -derivedDataPath build build
```

Running it on a device needs your Apple ID: App Groups, keychain sharing and the
AutoFill capability are all team-scoped.

## Try it on a device

1. Set **Team** in Signing & Capabilities if Xcode complains — `project.yml`
   defaults to `LY6LJ395B8`, which must match `apps/macos` because App Groups
   and keychain groups are team-scoped.
2. Run on the device. AirDrop `default.vault` from your Mac (it lives in
   `~/Library/Application Support/no.sybr.vault/`), then **Import a vault file**.
3. Unlock with your master password.
4. **Settings ▸ General ▸ AutoFill & Passwords** and turn **Arca** on.
5. In Safari, focus a login field and pick the Arca suggestion.

> Step 5 needs step 4 done *and* one unlock afterwards: identities are
> published to `ASCredentialIdentityStore` at the end of `VaultStore.unlock`,
> and the store refuses them while Arca is switched off. If AutoFill is off the
> app says so at the bottom of the list. The keyboard's password button reaches
> Arca either way — it calls `prepareCredentialList` directly.

## Layout

```
apps/ios/
├── project.yml              XcodeGen source of truth
├── Arca/                    the app
│   ├── ArcaApp.swift          entry, scene phase, lock-on-background
│   ├── VaultStore.swift       @Observable state: shut / opening / open
│   ├── VaultFile.swift        the vault in the App Group container + import
│   ├── Pasteboard.swift       copy with localOnly + expiry
│   ├── CredentialIdentities.swift  publish metadata to the QuickType bar
│   └── *View.swift            unlock, import, list, detail
└── ArcaAutoFill/            the credential provider
    ├── CredentialProviderViewController.swift   OS entry points + containment
    ├── AutoFillModel.swift                      unlock → fill / pick
    └── UnlockPickerView.swift                   its UI
```

The Swift↔Rust bridge is [`../apple-shared/VaultBridge.swift`](../apple-shared/VaultBridge.swift),
shared verbatim with `apps/macos`. It is platform-agnostic by design — the only
`#if os(macOS)` in it is the data-protection keychain flag.

## Two invariants that are easy to break

Both are shared with `apps/macos`; see [that README](../macos/README.md) for the
full version.

- **`ArcaKeychainAccessGroup` in both Info.plists must match
  `keychain-access-groups` in the entitlements.** That is how the bridge learns
  the team prefix without hardcoding one.
- **`VaultShared.requiredAbiVersion` must match `ABI_VERSION` in
  `crates/vault-ffi/src/lib.rs`.** Opening checks it and fails closed.

## Not done

- App icon and launch screen: the target has neither.
- `ITSAppUsesNonExemptEncryption` is deliberately unset — TestFlight will ask,
  and the answer is an export-compliance judgement, not a build setting to guess.
- No tests. There is no Swift test target in this repo at all yet.
