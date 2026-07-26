# iOS: status and what it would take

**There is no iOS app.** This document is an honest account of how far the
groundwork actually reaches, what is genuinely missing, and in what order it
would have to be built. It exists so the answer to "is iOS ready?" is a fact
rather than a guess.

## Where it stands

The hard blocker is gone. Everything else is work that has not started.

| Piece | State |
| --- | --- |
| Crypto + data model | **Done.** `vault-core` is pure Rust, no I/O, no platform assumptions. Same code an iOS app would use. |
| C ABI for Swift | **Mostly there.** `vault-ffi` (ABI v3), already proven against Swift in `apps/macos/`. |
| Unlock from a fresh device | **Done (was the blocker).** `vault_ffi_vault_open_password` — see below. |
| Getting the vault onto the phone | **Missing.** The Drive sync client is desktop-only. This is the real work. |
| Writing from the phone | **Missing.** The FFI is read-only today. |
| iOS app + AutoFill extension | **Not started.** |
| iOS build targets | **Not installed.** One `rustup` command. |

### The blocker that was removed

Until recently `vault-ffi` could only open a vault with a *device key* — the
32-byte quick-unlock key that some other process must already have minted into
the keychain. That is fine for the macOS extension, which sits next to the Tauri
app, but it made the FFI unusable on its own: **a phone on first launch has no
device key and could never open the vault at all.**

`vault_ffi_vault_open_password` closes that. It derives the key with Argon2id
using the parameters in the vault's own header, so it must run off the UI thread.

## What still has to be built

### 1. Sync — the big one

`apps/desktop/src-tauri/src/sync.rs` is ~670 lines of Google Drive client living
**inside the desktop app crate**, so nothing else can use it. Without it an iOS
app has no way to obtain the vault at all: there is no server, and the file
never leaves the user's own cloud.

Two sub-problems, not one:

- **Move it to a shared crate** (say `vault-sync`), leaving the desktop app as a
  caller. The merge logic is already in `vault-core::sync`, so this is about the
  transport, the Drive REST calls and the pull → merge → push loop.
- **Replace the OAuth flow.** The desktop uses PKCE with a **loopback redirect**,
  which does not exist on iOS. That has to become
  `ASWebAuthenticationSession` with a custom URL scheme, and the refresh token
  has to live in the iOS keychain rather than the desktop secret store.

### 2. Widen the FFI to write

Today the ABI exposes open, list identities, fetch one password, and the passkey
operations. An app that can only read is a viewer, not a password manager. Adding
items, editing them and re-serialising the vault all need to cross the boundary,
along with the save path so changes can be pushed back.

### 3. The app itself

- `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`, and a build step
  that produces an `xcframework` rather than the single static lib the macOS
  targets link today.
- A SwiftUI app: unlock, search, item detail, copy, TOTP.
- An **AutoFill Credential Provider extension**. Worth saying clearly: this is
  the part that works *well* on iOS. The system was designed for third-party
  password managers, unlike the macOS equivalent, which we shelved because it
  demanded Touch ID on every fill and fought Apple's own password menu.
- App IDs, provisioning and an App Group shared between app and extension —
  the same pattern already solved in `apps/macos/`, including the trap that a
  non-sandboxed process must reach the container through Foundation's
  `containerURL` rather than a raw path.

### 4. Distribution

TestFlight for personal use; the App Store if it ever ships more widely. Neither
is set up, and the release tooling in
[`RELEASING.md`](./RELEASING.md) is macOS-desktop only.

## Honest estimate

The reusable half is real: crypto, data model, merge, passkeys and a proven
Swift/Rust bridge are not small things, and none of them have to be rewritten.
But "reuse the core" is not the same as "nearly done". Sync alone is a
substantial refactor plus a new OAuth flow, and the write path plus a real app
and extension is more work again.

Anyone estimating this in hours is estimating the wrong problem. Start with
sync: until the vault can reach the phone, everything else has nothing to
display.
