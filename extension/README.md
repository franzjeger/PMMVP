# SYBR Passwords — Browser Extension

A Manifest V3 extension (Chrome / Brave / Edge, plus a Firefox build target)
that detects login forms and autofills credentials from the desktop app,
through a small Rust **native messaging host**.

> **Status:** working end-to-end. The extension detects login forms, the host
> connects to the desktop app's local **autofill bridge**, and the app fills
> real credentials — but only while the vault is **unlocked** and only when the
> page's host **matches** the stored login (origin binding). `match` returns
> metadata only; the password crosses solely on an explicit `fill` for a
> matched entry. The bridge is loopback-only (127.0.0.1) and authenticated with
> a per-run token from a `0600` file. See `../THREAT_MODEL.md`.
>
> Verified at the bridge level (host binary ↔ live app). The browser-side
> injection is straightforward content-script JS; load the extension + register
> the host manifest (below) to use it in Chrome.

## Layout

```
chromium/            MV3 extension source (shared by Chrome/Brave/Edge + Firefox)
  manifest.json          Chromium manifest (service_worker background)
  manifest.firefox.json  Firefox manifest (background.scripts + gecko id)
  background.js          relays messages to the native host
  content.js             form detection + autofill picker
  content.css            injected UI styles
  popup.html / popup.js  connection-status popup
  icons/
native-host/         Rust native-messaging host (see ../../crates + workspace)
  no.sybr.vault.json          Chrome/Chromium host manifest template
  no.sybr.vault.firefox.json  Firefox host manifest template
```

## 1. Build the native host

```bash
cargo build -p vault-native-host --release
# binary at: target/release/vault-native-host
```

Quick smoke test of the handshake (length-prefixed JSON on stdin):

```bash
printf '\x10\x00\x00\x00{"type":"hello"}' | ./target/release/vault-native-host | xxd | head
```

## 2. Load the extension (unpacked)

- **Chrome / Brave / Edge:** go to `chrome://extensions`, enable *Developer
  mode*, *Load unpacked*, select `extension/chromium/`. Copy the generated
  **extension ID**.
- **Firefox:** rename/копy `manifest.firefox.json` to `manifest.json` (or use a
  build step), then `about:debugging` → *This Firefox* → *Load Temporary
  Add-on* → pick the `manifest.json`.

## 3. Install the native messaging host manifest

Edit the template: set `path` to the absolute path of the built
`vault-native-host`, and (Chromium) set `allowed_origins` to
`chrome-extension://<your-extension-id>/`. Then place it where the browser
looks:

**Chrome (macOS):**
`~/Library/Application Support/Google/Chrome/NativeMessagingHosts/no.sybr.vault.json`
**Chrome (Linux):** `~/.config/google-chrome/NativeMessagingHosts/no.sybr.vault.json`
**Chrome (Windows):** create registry key
`HKCU\Software\Google\Chrome\NativeMessagingHosts\no.sybr.vault` pointing at the
manifest file.

**Firefox (macOS):**
`~/Library/Application Support/Mozilla/NativeMessagingHosts/no.sybr.vault.json`
(use the `*.firefox.json` template with `allowed_extensions`).
**Firefox (Linux):** `~/.mozilla/native-messaging-hosts/no.sybr.vault.json`.

Open the extension popup; it should report the host version. See the repo
`README.md` and `SECURITY.md` for the full picture and security caveats.
