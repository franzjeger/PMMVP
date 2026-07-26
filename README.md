# Arca

A cross-platform password manager with an identical UI on **macOS, Windows, and
Linux**. All security-critical logic lives in a small Rust core built only from
well-reviewed crates; the desktop app is a [Tauri 2](https://v2.tauri.app/) shell
over it, and the browser extension talks to that app over a local bridge.

Current version: **0.2.0**

> ⚠️ **Not independently audited.** The cryptography composes well-reviewed
> RustCrypto crates and there is a written threat model, but no third party has
> reviewed this code. Read [`SECURITY.md`](./SECURITY.md) and
> [`THREAT_MODEL.md`](./THREAT_MODEL.md) before trusting it with real secrets.

## What it does

**Vault**
- Logins, passkeys, SSH keys, Wi-Fi networks (with a join QR code) and secure notes
- Live TOTP codes with a countdown, from a Base32 secret or an `otpauth://` URI
- Strong password generator; weak/reused audit; breach check against
  HaveIBeenPwned using k-anonymity (only a 5-character hash prefix ever leaves
  the device)
- Find and merge duplicates; soft delete with a Trash you can restore from
- Change the master password without re-encrypting every item

**Unlock**
- Master password (Argon2id), or quick unlock via the OS keychain gated by
  Touch ID / Windows Hello
- Auto-lock on idle and on window blur; clipboard auto-clear

**In the browser** (Chrome, Brave, Edge, Firefox)
- Autofill matching logins, with the password released only for a matching
  origin while the vault is unlocked
- Offer to save new or changed logins on submit
- Passkeys: Arca acts as the authenticator for ceremonies the user actually
  started. See [`docs/PASSKEYS.md`](./docs/PASSKEYS.md).

**Sync and safety**
- End-to-end encrypted sync through your own Google Drive app folder: Google
  only ever holds ciphertext. See [`docs/SYNC.md`](./docs/SYNC.md).
- Automatic local snapshots before every save, an off-device encrypted backup,
  and restore. See [`docs/BACKUP.md`](./docs/BACKUP.md).
- CSV import (Safari/Apple Passwords, Chrome, Brave, Edge, Firefox, generic) and
  a biometric-gated CSV export

**Elsewhere**
- Built-in ssh-agent: vault SSH keys serve `ssh` and `git` over a Unix socket
  (macOS/Linux) or the OpenSSH named pipe (Windows), signing in-process so the
  private key never reaches disk

## Platform status

| Platform | State |
| --- | --- |
| **macOS** | Daily driver. Signed + notarizable releases, see [`docs/RELEASING.md`](./docs/RELEASING.md). |
| **Windows** | Working, including the ssh-agent named pipe. Built in CI. |
| **Linux** | Builds and passes CI (incl. X11/Wayland clipboard smoke tests) but has **never been run by a human**. Treat as untested. |
| **iOS** | Scaffolded in `apps/ios/`. A read-only viewer + AutoFill provider, with Face ID quick unlock; **no sync** — the vault is imported by hand. Compiled by CI, **never run on a device**. See [`docs/IOS.md`](./docs/IOS.md). |
| **Android** | Not built. |
| **System-wide macOS AutoFill** | Shelved. It works technically, but Touch ID on every fill and a fight with Apple's own password menu made it worse than the browser extension. Source kept in `apps/macos/`. |

Auto-update is prepared but **not wired up**: the signing key exists, the plugin
and release manifest do not. A new version currently means replacing the app by
hand ([`docs/RELEASING.md`](./docs/RELEASING.md)).

## Architecture

```
crates/
├── vault-core/       Pure Rust, no I/O. Crypto, data model, TOTP, passkeys,
│                     password generation, merge, dedupe, breach hashing.
├── vault-store/      Atomic single-file persistence, rotating snapshots,
│                     OS-keychain quick unlock.
├── vault-ffi/        C ABI over the core, for native platform integrations
│                     (Swift). ABI v4.
├── vault-secmem/     mlock'd buffers for key material.
├── vault-appgroup/   macOS App Group container resolution (one isolated
│                     Objective-C call, so the app crate stays unsafe-free).
└── vault-sync/       End-to-end encrypted sync: the Google Drive client, the
                      OAuth token calls, and the pull→merge→push engine, over
                      traits so each platform supplies its own storage and UI.
apps/
├── desktop/          Tauri 2 app
│   ├── src-tauri/      Rust shell: commands, state, sync glue, bridge,
│   │                   ssh-agent.
│   └── src/            React + TypeScript + Tailwind three-pane UI.
├── apple-shared/     VaultBridge.swift — the Swift side of vault-ffi, shared
│                     verbatim by the macOS and iOS targets.
├── macos/            Shelved AutoFill credential provider (host + extension).
└── ios/              SwiftUI app + AutoFill extension. Scaffold, never built.
extension/
├── chromium/         Manifest V3 (Chrome/Brave/Edge) + a Firefox manifest.
└── native-host/      Rust native-messaging bridge to the desktop app.
```

**Key hierarchy:** master password ──Argon2id──▶ master key
──XChaCha20-Poly1305(unwrap)──▶ random 256-bit *vault key* ──per-item AEAD──▶
each item. The master password is never stored; only *wrapped* keys are
persisted, which is why changing it does not re-encrypt your data and why a
forgotten master password is unrecoverable.

## Prerequisites

- **Rust** ≥ 1.80 (`rustup`). The core, store and native host build with `cargo` alone.
- **Node.js** ≥ 18 + npm, for the desktop frontend.
- **Platform toolchains for Tauri 2:**
  - **macOS:** Xcode Command Line Tools (`xcode-select --install`).
  - **Windows:** WebView2 runtime (preinstalled on Win 11) + MSVC Build Tools.
  - **Linux (Debian/Ubuntu):**
    ```bash
    sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
      libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev \
      libdbus-1-dev
    ```
    (`libdbus-1-dev`/Secret Service is needed for keychain quick unlock.)

## Build and test

```bash
cargo test                              # all Rust crates
cargo clippy --workspace --all-targets -- -D warnings
cd apps/desktop && npm ci && npm test   # frontend component tests
```

Around 141 Rust tests plus 9 frontend tests. `vault-core` has no I/O and is the
security-critical surface: its tests cover encrypt/decrypt round-trips,
wrong-password failure, AEAD tamper detection, KDF determinism, TOTP RFC 6238
vectors, the on-disk item codec, sync merge and quick-unlock key drift.

Tests needing a real OS secret store are `#[ignore]`d (they may prompt):

```bash
cargo test -p vault-store -- --ignored
```

### The smoke test gate

```bash
scripts/smoke-test.sh          # Rust tests, frontend build, component tests
scripts/smoke-test.sh --full   # + OS keychain tests + a live bridge round-trip
```

`scripts/install-app-macos.sh` **refuses to install without it**. That gate
exists because builds went out that passed partial checks while the actual user
flow was broken.

## Run the desktop app

```bash
cd apps/desktop
npm install
npm run tauri dev        # hot-reload, any OS
```

On macOS, install a locally signed build with `scripts/install-app-macos.sh`.
For a build other machines can run, see [`docs/RELEASING.md`](./docs/RELEASING.md).

The vault lives in the per-user app-data directory as `default.vault`, e.g.
`~/Library/Application Support/no.sybr.vault/` on macOS, with snapshots
alongside it in `snapshots/`.

## Browser extension

Load `extension/chromium/` unpacked, then install the native-messaging host so
the extension can reach the app. Per-browser instructions are in
[`extension/README.md`](./extension/README.md). The app must be **unlocked** for
autofill to return anything.

## Continuous integration

[`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs on push and PR:

- **`test`** on Linux, Windows and macOS: frontend type-check + bundle, frontend
  component tests, `cargo fmt --check`, `cargo clippy -D warnings`, and
  `cargo test --workspace`.
- **`linux-smoke`**: the `#[ignore]`d real-OS tests, so the `arboard` clipboard
  path actually executes on **X11** (Xvfb) and best-effort on **Wayland**
  (headless `sway`), plus a best-effort keychain test against gnome-keyring.

CI cannot do an interactive cross-application paste. That stays a manual
acceptance check on real X11 *and* Wayland before shipping to Linux users.

## Security

Zero-knowledge, local-first, no telemetry. Nothing is sent anywhere except the
ciphertext you choose to sync and a 5-character password-hash prefix if you run
a breach check.

[`SECURITY.md`](./SECURITY.md) and [`THREAT_MODEL.md`](./THREAT_MODEL.md) state
plainly that an **independent third-party audit is required before real-world
use**, and list the accepted residual risks.

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE), at
your option.
