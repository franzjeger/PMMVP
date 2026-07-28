# iOS: status and what it would take

**It runs on a phone.** As of 2026-07-28 `apps/ios/` is installed on an iPhone 17
Pro: the vault opens, Face ID unlocks it, logins can be added and edited, and
Google Drive sync works both ways against the same folder the desktop uses. See
[`apps/ios/README.md`](../apps/ios/README.md).

That first device run paid for itself immediately. Three bugs were waiting that
the simulator structurally cannot show, all in the quick-unlock path:

- `hasStoredDeviceKey` passed `kSecUseAuthenticationUISkip` — which *silently
  omits* items behind an access control, returning `errSecItemNotFound` — while
  checking for the statuses `kSecUseAuthenticationUIFail` produces. The
  simulator has no Secure Enclave and does not enforce the ACL, so the item was
  never filtered and the probe answered yes. On real hardware it answered no
  forever, including right after quick unlock was switched on. Face ID was not
  failing; the question "is there a key?" was.
- Neither `Info.plist` declared `NSFaceIDUsageDescription`. Masked by the bug
  above, because nothing ever reached a real prompt. An extension is its own
  process with its own privacy identity, so it needs its own copy.
- The probe was read from inside a SwiftUI `body`, so a blocking XPC to
  `securityd` ran on the main thread on every keystroke in the password field —
  free in the simulator, not on a phone, and worst inside the watchdogged
  AutoFill extension.

This document is an honest account of how far the groundwork actually reaches,
what is genuinely missing, and in what order it would have to be built. It
exists so the answer to "is iOS ready?" is a fact rather than a guess.

## Where it stands

The hard blocker is gone and there is a shell to run. What is left is the part
that makes it a password manager rather than a viewer.

| Piece | State |
| --- | --- |
| Crypto + data model | **Done.** `vault-core` is pure Rust, no I/O, no platform assumptions. Same code an iOS app would use. |
| C ABI for Swift | **Mostly there.** `vault-ffi` (ABI v5), already proven against Swift in `apps/macos/`. |
| Swift side of that ABI | **Portable.** `apps/apple-shared/VaultBridge.swift` has no macOS-only code left (the one difference is behind `#if os(macOS)`), wraps *both* open paths, and keeps the blocking work off the main actor. An iOS target links it unchanged. |
| Unlock from a fresh device | **Done (was the blocker).** `vault_ffi_vault_open_password` — see below. |
| Getting the vault onto the phone | **Reachable, not wired.** `vault-sync` moved out of the desktop crate and the C ABI now exposes it (v5). What is missing is Swift: a wrapper, the keychain, and `ASWebAuthenticationSession`. |
| Writing from the phone | **Missing.** The FFI is read-only today. |
| iOS app + AutoFill extension | **Scaffolded, never run.** `apps/ios/`: unlock, search, reveal, copy, and a credential provider. Read-only. CI compiles it; no device has. |
| Quick unlock on the phone | **Done.** `vault_ffi_enable_device_unlock` (ABI v4) mints a device key from a password unlock; the app and the extension both use it. |
| Sync on the phone | **Half.** ABI v5 (`vault_ffi_sync_*`) runs the whole cycle in Rust. Nothing in Swift calls it yet. |
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
over Tauri in ~250 lines. iOS does not implement them at all — the FFI does,
in Rust, over the vault a `VaultHandle` already holds, so Swift never sees the
traits and cannot get the retry policy wrong.

**The C ABI now exposes it (v5).** `vault_ffi_sync_new` binds an engine to an
open vault handle; `vault_ffi_sync_now` runs one cycle; `vault_ffi_sync_auth_*`
runs the sign-in. The engine *shares* the handle's vault rather than copying it,
so a merge is visible to `vault_ffi_identities` on that handle with no reload —
which is why the vault behind a handle became internally synchronized in v5.

Two things deliberately stay on the Swift side, both because they have no
portable form:

- **The authorization flow.** The desktop opens a browser and catches the
  redirect on a loopback port; iOS cannot bind a listening socket and needs
  `ASWebAuthenticationSession` with a custom URL scheme. `vault_ffi_sync_auth_begin`
  builds the URL and keeps the PKCE verifier, `_finish` redeems the code — only
  the middle step is per-platform.
- **Storage.** The refresh token comes back from `_auth_finish` for the iOS
  keychain, and merged vault bytes come back from `_sync_now` for the app group
  container. `vault-core` is I/O-free and the FFI stays a thin wrapper over it.

The Swift side now exists: `apps/apple-shared/VaultSync.swift` wraps the nine
exports, `SyncCredentialStore` keeps the refresh token in the iOS keychain
(`afterFirstUnlockThisDeviceOnly`, deliberately *without* a biometric ACL so a
background cycle can run — it unlocks ciphertext, not the vault), and `SyncSignIn`
drives `ASWebAuthenticationSession`. The list's menu offers connect / sync now /
stop syncing, and a local save marks the engine dirty so the next cycle pushes it.

**The OAuth client is now in place.** Running this on a simulator first came
back `400 redirect_uri_mismatch`: the project had only a **desktop** client,
whose sole redirect is a loopback address, and a custom scheme cannot be added
to that type. An iOS client (`Arca iOS`, bundle id `no.sybr.vault.ios`) now
exists in the same GCP project, so both platforms reach the same
`appDataFolder` and sync with each other.

The same number then has to appear in three places, and any one of them being a
character off fails as `redirect_uri_mismatch` on the consent page with nothing
to point at:

- `vault-sync/src/drive.rs`, behind `cfg(target_os = "ios")`. `CLIENT_ID` and
  `REDIRECT_URI` are both `concat!`ed from one `ios_client!` literal, so those
  two at least cannot drift apart.
- `SyncSignIn.redirectURI` and its callback scheme.
- `CFBundleURLSchemes` in the app's Info.plist.

An iOS client is a **public** client: Google issues no secret for it and rejects
a request that sends an empty one, so the token calls now omit `client_secret`
entirely when there is none. PKCE is what binds the code to this process either
way. That is pinned by a test, because inlining the form fields again would undo
it silently.

The **desktop** client does have a secret, and it is deliberately not in this
repository — `vault-sync/build.rs` supplies it at build time. See
[`SYNC.md`](./SYNC.md). None of that touches iOS, which has no secret to hide.

**Verified on a phone, 2026-07-28.** Sign-in completes and the vault syncs both
ways against the same `appDataFolder` the desktop uses.

One limit worth stating plainly: sync cannot deliver the **first** copy. The
engine is built from an open vault (`VaultStore.startSync` runs inside `open`),
so with no vault file there is no engine, and the app can only offer the file
picker. A new phone still needs the vault handed to it once, by AirDrop or
Files; sync takes over from there.

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
