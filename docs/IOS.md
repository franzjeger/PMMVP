# iOS: status and what it would take

**There is an iOS scaffold, and no human has run it.** `apps/ios/` holds a
SwiftUI app and an AutoFill Credential Provider extension over the existing Rust
core, written on Linux where the Apple frameworks do not exist. CI now builds it
unsigned on the macOS runner for every pull request — the first compiler it has
met — but nothing has been on a device. See
[`apps/ios/README.md`](../apps/ios/README.md).

This document is an honest account of how far the groundwork actually reaches,
what is genuinely missing, and in what order it would have to be built. It
exists so the answer to "is iOS ready?" is a fact rather than a guess.

## Where it stands

The hard blocker is gone and there is a shell to run. What is left is the part
that makes it a password manager rather than a viewer.

| Piece | State |
| --- | --- |
| Crypto + data model | **Done.** `vault-core` is pure Rust, no I/O, no platform assumptions. Same code an iOS app would use. |
| C ABI for Swift | **Mostly there.** `vault-ffi` (ABI v4), already proven against Swift in `apps/macos/`. |
| Swift side of that ABI | **Portable.** `apps/apple-shared/VaultBridge.swift` has no macOS-only code left (the one difference is behind `#if os(macOS)`), wraps *both* open paths, and keeps the blocking work off the main actor. An iOS target links it unchanged. |
| Unlock from a fresh device | **Done (was the blocker).** `vault_ffi_vault_open_password` — see below. |
| Getting the vault onto the phone | **Missing.** The Drive sync client is desktop-only. This is the real work. |
| Writing from the phone | **Missing.** The FFI is read-only today. |
| iOS app + AutoFill extension | **Scaffolded, never run.** `apps/ios/`: unlock, search, reveal, copy, and a credential provider. Read-only. CI compiles it; no device has. |
| Quick unlock on the phone | **Done.** `vault_ffi_enable_device_unlock` (ABI v4) mints a device key from a password unlock; the app and the extension both use it. |
| iOS build targets | **Scripted.** [`scripts/build-ffi-ios.sh`](../scripts/build-ffi-ios.sh) adds the targets and stages a static lib per platform. |

### The blocker that was removed

Until recently `vault-ffi` could only open a vault with a *device key* — the
32-byte quick-unlock key that some other process must already have minted into
the keychain. That is fine for the macOS extension, which sits next to the Tauri
app, but it made the FFI unusable on its own: **a phone on first launch has no
device key and could never open the vault at all.**

`vault_ffi_vault_open_password` closes that. It derives the key with Argon2id
using the parameters in the vault's own header, so it must run off the UI thread.

`VaultSession.openWithMasterPassword` in `apps/apple-shared/VaultBridge.swift` is
the Swift side of it. Every entry point on that type is `async` and runs on a
private serial queue for exactly this reason: on iOS an AutoFill extension that
blocks its main thread is killed by the watchdog, not merely slow. The same queue
gives the C ABI the guarantee it asks for — `vault_ffi_vault_free` never overlaps
another call on the same handle.

## What still has to be built

### 1. Sync — half done

Sync used to be ~670 lines of Google Drive client living **inside the desktop app
crate**, where nothing else could reach it. It is now `crates/vault-sync`: the
Drive REST client, the OAuth token calls and the pull → merge → push engine,
with the desktop as one caller. The merge itself never moved — that is still
`vault-core` — and neither did the security model: the remote holds ciphertext
and this crate cannot decrypt anything.

Three traits mark where the platforms actually differ. `RemoteStore` is the
remote (Google Drive today), `LocalVault` is "merge these copies and give me the
bytes to push", and `SyncObserver` is progress. The desktop implements all three
over Tauri in ~250 lines; iOS implements them over its own vault file and an
observable object.

What is left is the part that genuinely has no shared form:

- **The authorization flow.** The desktop opens a browser and catches the
  redirect on a loopback port; iOS cannot bind a listening socket and needs
  `ASWebAuthenticationSession` with a custom URL scheme. `OAuthClient` builds the
  URL and redeems the code — only the middle step is per-platform.
- **The refresh token's home.** `RefreshTokenStore` is a two-method trait; iOS
  supplies a keychain-backed one. Note the split between "does a token exist"
  and "read it": the background loop asks the first every tick, and on Apple
  platforms reading an item's data runs its ACL and can raise a prompt.
- **Calling it from Swift.** None of this is on the C ABI yet, so the phone
  cannot reach it. That is the next FFI job after §2.

### 2. Widen the FFI to write

Today the ABI exposes open, list identities, fetch one password, and the passkey
operations. An app that can only read is a viewer, not a password manager. Adding
items, editing them and re-serialising the vault all need to cross the boundary,
along with the save path so changes can be pushed back.

### 3. Quick unlock — done (ABI v4)

The AutoFill extension is a **separate process** and cannot borrow the app's
unlocked session, so before this every single fill cost the user their master
password and a full Argon2id derivation, typed into a keyboard accessory view.

`vault_ffi_enable_device_unlock` fixes it: from a password-unlocked handle it
mints a 32-byte device key, wraps the vault key with it, and returns the key plus
**new vault file bytes**. The master password keeps working — this adds a second
wrapping, it does not replace the first.

It is the first ABI call that produces a replacement vault, so it is careful
about it. The bytes are verified to reopen with the returned key *inside Rust*
before they are handed back, and Swift writes the vault file before storing the
key: a wrapping whose key was never saved is inert, whereas a key for a vault
that was never written opens nothing. The key lives behind `biometryCurrentSet`
where biometrics are enrolled, so adding a face invalidates it.

It still writes nothing itself — `vault-core` is I/O-free and this stays a thin
wrapper. That much of §2 remains.

### 4. The app itself — scaffolded

Done, unverified:

- [`scripts/build-ffi-ios.sh`](../scripts/build-ffi-ios.sh) adds the Rust targets
  and stages one `.a` per platform: arm64 for the device, and a `lipo` of arm64 +
  x86_64 for the simulator, because `ARCHS_STANDARD` there is both. Not an
  xcframework, despite this document originally asking for one: Xcode resolves a
  framework dependency before any pre-build script runs, so a library the project
  builds itself can never be one. Search paths resolve at link time — the same
  shape `apps/macos` already used.
- A SwiftUI app: unlock, search, item detail, copy (pasteboard `localOnly` and
  expiring), lock on backgrounding, covered app-switcher snapshot.
- An **AutoFill Credential Provider extension**. Worth saying clearly: this is
  the part that works *well* on iOS. The system was designed for third-party
  password managers, unlike the macOS equivalent, which we shelved because it
  demanded Touch ID on every fill and fought Apple's own password menu.
- App IDs, provisioning and an App Group shared between app and extension —
  the same pattern already solved in `apps/macos/`, including the trap that a
  non-sandboxed process must reach the container through Foundation's
  `containerURL` rather than a raw path, and the shared keychain group reaching
  Swift through an Info.plist key that Xcode expands `$(AppIdentifierPrefix)`
  into, so the team prefix is never a literal in source.

Identities are published to `ASCredentialIdentityStore` on unlock (metadata
only), which is what puts Arca in the QuickType bar rather than merely installed.

Not done: no TOTP and no item types beyond logins (the ABI exposes neither),
no app icon, and no Swift tests — there is no Swift test target in the repo.

### 5. Distribution

TestFlight for personal use; the App Store if it ever ships more widely. Neither
is set up, and the release tooling in
[`RELEASING.md`](./RELEASING.md) is macOS-desktop only.

## Honest estimate

The reusable half is real: crypto, data model, merge, passkeys and a proven
Swift/Rust bridge are not small things, and none of them have to be rewritten.
The app shell is now real too — but a shell nobody has run is a proposal, not a
milestone, and it is read-only besides.

"Reuse the core" is still not the same as "nearly done". Sync alone is a
substantial refactor plus a new OAuth flow, and the write path is more again.

Order, now that the shell exists and quick unlock is in: **open a pull request**
and fix what the macOS runner says — that is the first compiler this Swift has
met, and it will have opinions. Then
§1, sync, because until the vault can reach the phone by itself every user is
AirDropping a file. §2, writing, last: it is the largest, and the one that needs
the merge semantics thought through rather than typed.
