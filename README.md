# SYBR Passwords

A cross-platform password manager with an identical UI on **macOS, Windows, and
Linux**. All security-critical logic lives in a small, audited-crate-only Rust
core; the desktop app is a [Tauri 2](https://v2.tauri.app/) shell over it.

> ⚠️ **Phase 1 (MVP) — foundation only, NOT production-ready.**
> The cryptography composes well-reviewed RustCrypto crates, but this codebase
> has **not** been independently audited and has no formal threat model yet.
> See [`SECURITY.md`](./SECURITY.md) before using it for real secrets.

## What works in Phase 1

- Create a vault, unlock/lock it, and quick-unlock via the OS keychain.
- Add/edit/view logins, reveal & copy secrets, generate strong passwords.
- Live TOTP codes with a 30-second countdown.
- Soft delete (Trash) → restore or permanently delete.
- Auto-lock on idle and on window blur; clipboard auto-clear.
- A browser-extension + native-host scaffold with a working handshake.

Deliberately **out of scope** this phase (left as stubs/TODOs): passkey /
WebAuthn authenticator, encrypted sync, Safari extension, import/export, mobile,
and system-wide autofill providers.

## Architecture

```
vault/
├── crates/
│   ├── vault-core/      Pure Rust, no I/O. Crypto, data model, TOTP, password
│   │                    generation. Fully unit-tested.
│   └── vault-store/     Atomic single-file persistence + OS keychain quick-unlock.
├── apps/desktop/        Tauri 2 app:
│   ├── src-tauri/         Rust shell — commands, state, auto-lock, clipboard.
│   └── src/              React + TypeScript + Tailwind three-pane UI.
└── extension/
    ├── chromium/        Manifest V3 extension (Chrome/Brave/Edge + Firefox target).
    └── native-host/     Rust native-messaging bridge to the desktop app.
```

**Key hierarchy:** master password ──Argon2id──▶ master key
──XChaCha20-Poly1305(unwrap)──▶ random 256-bit *vault key* ──per-item AEAD──▶
each item. The master password is never stored; only *wrapped* keys are
persisted. Full details in [`SECURITY.md`](./SECURITY.md).

## Prerequisites

- **Rust** ≥ 1.80 (`rustup`). The core/store/host build with `cargo` alone.
- **Node.js** ≥ 18 + npm — required to build/run the desktop **frontend**.
- **Platform toolchains for Tauri 2:**
  - **macOS:** Xcode Command Line Tools (`xcode-select --install`).
  - **Windows:** WebView2 runtime (preinstalled on Win 11) + MSVC Build Tools.
  - **Linux (Debian/Ubuntu):**
    ```bash
    sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
      libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev \
      libdbus-1-dev
    ```
    (`libdbus-1-dev`/Secret Service is needed for keychain quick-unlock.)

## Build & test the Rust core (no Node required)

```bash
cd vault
cargo test                      # vault-core + vault-store + native-host
cargo test -p vault-core        # crypto round-trips, tamper detection, KDF, TOTP…
cargo clippy --workspace --all-targets
```

`vault-core` has no I/O and is the security-critical surface; its tests cover
encrypt→decrypt round-trips, wrong-password failure, AEAD tamper detection, KDF
determinism, TOTP RFC 6238 vectors, and the password generator.

> The keychain round-trip test is `#[ignore]`d (it needs a real OS secret store
> and may prompt). Run it on a desktop with:
> `cargo test -p vault-store -- --ignored`

## Run the desktop app

```bash
cd vault/apps/desktop
npm install
npm run tauri dev        # launches the app with hot-reload (any OS)
```

Build distributable bundles:

```bash
npm run tauri build      # .app/.dmg, .msi/.exe, or .deb/.AppImage per host OS
```

The vault file is stored in the per-user app-data directory
(`default.vault`), e.g. on macOS:
`~/Library/Application Support/no.sybr.vault/`.

> Icons in `src-tauri/icons/` are placeholders. Before shipping, regenerate the
> full set (incl. `.icns`/`.ico`) with `npm run tauri icon icons/icon.png`.

## Browser extension

Scaffold with a working extension↔native-host handshake (the host↔desktop-app
bridge is stubbed in Phase 1). See [`extension/README.md`](./extension/README.md)
for build and per-browser install instructions.

## Continuous integration

[`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs on push/PR:

- **`test`** — on **Linux, Windows, and macOS**: `npm ci && npm run build`
  (frontend type-check + bundle), `cargo fmt --check`, `cargo clippy -D warnings`,
  and `cargo test --workspace` (all crates, incl. the desktop command + in-memory
  clipboard tests).
- **`linux-smoke`** — runs the `#[ignore]`d real-OS smoke tests on an actual X11
  session (Xvfb) so the `arboard` clipboard path executes on Linux, plus a
  best-effort keychain test against gnome-keyring.

CI cannot drive interactive cross-app paste on **Wayland** (no compositor on the
runners); that single check stays a manual, one-time run on a real X11 *and*
Wayland desktop before shipping to Linux users (see [`SECURITY.md`](./SECURITY.md)).

## Security

Zero-knowledge, local-only, no telemetry. Read [`SECURITY.md`](./SECURITY.md) —
it states plainly that an **independent audit and a formal threat model are
required before real-world use**, and lists the current limitations.

## License

Dual-licensed under MIT or Apache-2.0.
