# Arca — Browser Extension

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

The extension id is **pinned** by the public `key` in `chromium/manifest.json`
(always `joeolbejbmnhmgajgmidpnpnjahdiobc`), so the host registration can be
fully scripted — no id-copying or file-editing.

## Install (macOS) — one command + one click

```bash
./extension/install-macos.sh
```

This builds the host (release) and registers the native-messaging manifest for
every installed Chromium browser (Chrome/Brave/Edge), pre-filled with the pinned
id and the built binary's path.

Then the **one step Chrome won't let any tool automate** (Google blocks
programmatic unpacked installs, by design):

1. `chrome://extensions` → enable **Developer mode**
2. **Load unpacked** → select `extension/chromium/`

Keep the desktop app open and unlocked; autofill then works. (Undo: delete the
`no.sybr.vault.json` files the script printed.)

Handshake smoke test of the host alone:

```bash
printf '\x10\x00\x00\x00{"type":"hello"}' | ./target/release/vault-native-host | xxd | head
```

### Linux

```bash
./extension/install-linux.sh
```

Registers the host in the `NativeMessagingHosts/` dir of every installed
Chromium-family browser under `~/.config/…` (Chrome/Chromium/Brave/Edge/Vivaldi),
plus Firefox (`~/.mozilla/native-messaging-hosts/`) using the
`no.sybr.vault.firefox.json` template. Then the same one Chrome click as above.

### Windows

```powershell
./extension/install-windows.ps1
```

Windows registers native-messaging hosts via the registry rather than a
directory: the script writes the host manifest next to the built `.exe` and sets
the per-user key (e.g. `HKCU\Software\Google\Chrome\NativeMessagingHosts\no.sybr.vault`)
to point at it, for Chrome/Chromium/Edge/Brave. Then the same one Chrome click.

### Firefox

Firefox uses `no.sybr.vault.firefox.json` (`allowed_extensions`, gecko id) in
`~/Library/Application Support/Mozilla/NativeMessagingHosts/` (macOS) or
`~/.mozilla/native-messaging-hosts/` (Linux); the Linux installer handles it
automatically.

See the repo `README.md`, `SECURITY.md`, and `THREAT_MODEL.md` for the security
model.
