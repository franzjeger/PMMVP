# Arca for iOS — scaffold

A SwiftUI app plus an AutoFill Credential Provider extension, both over the same
Rust core the desktop uses. **Nothing here has ever been compiled**, let alone
run on a device — it was written on a machine with no Xcode. Treat the first
`xcodebuild` as the real review.

The Xcode project is generated from [`project.yml`](project.yml) with
[XcodeGen](https://github.com/yonabot/XcodeGen); the `.xcodeproj` is git-ignored.

## What it does

| | |
| --- | --- |
| Unlock | Master password → Argon2id → `vault_ffi_vault_open_password`. |
| Browse | Search logins, see username/site/title, reveal one password. |
| Copy | `localOnly` (never reaches Universal Clipboard) and cleared by iOS after 30s. |
| AutoFill | Registers as a password provider and publishes identities (metadata only) to `ASCredentialIdentityStore` on unlock, so Arca appears in the QuickType bar. |
| Lock | On backgrounding, and the app-switcher snapshot is covered. |

## What it does not do, and why

These are not polish items. Each is blocked on something that does not exist.

**No sync.** `apps/desktop/src-tauri/src/sync.rs` is a ~670-line Google Drive
client living *inside the desktop app crate*, so nothing else can call it, and
its OAuth flow uses a loopback redirect that iOS has no equivalent for. Until
that moves to a shared crate ([`docs/IOS.md`](../../docs/IOS.md)), the vault
reaches the phone by hand: AirDrop `default.vault` from the Mac and import it.
That import screen is a stopgap wearing a stopgap's label.

**No Face ID.** Quick unlock needs a 32-byte device key in the shared keychain.
`vault-core` can mint one (`enable_device_unlock`), but `vault-ffi` does not
export it — and using it would mean writing the vault file back, which the
read-only ABI cannot do. So the master password is the only way in, **including
inside the AutoFill extension, on every single fill**. The extension is a
separate process and cannot borrow the app's unlocked session. This is the
sharpest edge in the scaffold.

**Read-only.** No creating, editing or deleting items. The ABI exposes open,
list identities and fetch one password; that is the whole surface.

**Logins only.** `vault_ffi_identities` filters to `ItemKind::Login`, so
passkeys, SSH keys, Wi-Fi networks and secure notes are invisible here. No TOTP
either — it is in `vault-core` but not on the ABI.

### The one change that fixes most of this

Export a device-unlock path from `vault-ffi`: mint a key after a successful
password unlock, re-serialise, and save. That single addition turns every fill
from "type your master password and wait for Argon2id" into a Face ID prompt,
and it is the prerequisite for the write path anyway.

## Build

```sh
cd apps/ios
xcodegen generate          # writes Arca.xcodeproj from project.yml
open Arca.xcodeproj
```

The pre-build phase runs [`scripts/build-ffi-ios.sh`](../../scripts/build-ffi-ios.sh),
which adds the Rust targets, cross-compiles `vault-ffi` for device and simulator
and packages `libs/VaultFFI.xcframework`. Two slices are not optional: device and
simulator are different *platforms*, and linking the two `.a` files directly
fails on the second with duplicate symbols.

arm64 only, matching `apps/macos`. An Intel Mac cannot run this simulator slice;
add `x86_64-apple-ios` to the script if that matters.

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
