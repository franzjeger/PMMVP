#!/usr/bin/env bash
#
# One-shot installer for the Arca native-messaging host (Linux).
#
# Builds the host binary and registers it for every installed Chromium-family
# browser, with the extension's PINNED id (derived from the public `key` in
# chromium/manifest.json). After running this, the only manual step left is
# Chrome's mandatory "Load unpacked" (Google blocks programmatic unpacked
# installs) — and because the id is pinned, no id-copying or file-editing is
# needed.
#
# Re-runnable and reversible: delete the written no.sybr.vault.json files to
# undo (see the paths it prints).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
HOST_BIN="$REPO/target/release/vault-native-host"
CHROMIUM_MANIFEST="$REPO/extension/chromium/manifest.json"
HOST_NAME="no.sybr.vault"

echo "==> Building the native messaging host (release)…"
( cd "$REPO" && cargo build -p vault-native-host --release )
[ -x "$HOST_BIN" ] || { echo "host binary not found at $HOST_BIN" >&2; exit 1; }

echo "==> Deriving the pinned extension id from the manifest key…"
KEY="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).key||"")' "$CHROMIUM_MANIFEST")"
[ -n "$KEY" ] || { echo "no \"key\" field in $CHROMIUM_MANIFEST" >&2; exit 1; }
EXT_ID="$(printf '%s' "$KEY" | base64 -d | openssl dgst -sha256 -binary | head -c 16 | xxd -p | tr -d '\n' | tr '0-9a-f' 'a-p')"
echo "    extension id: $EXT_ID"

read -r -d '' MANIFEST_JSON <<JSON || true
{
  "name": "$HOST_NAME",
  "description": "Arca native messaging host",
  "path": "$HOST_BIN",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
JSON

# Chromium-family browsers and their per-user config dirs (Linux). The native
# messaging manifest goes in a NativeMessagingHosts/ subdir of each.
BROWSERS=(
  "Google Chrome|$HOME/.config/google-chrome"
  "Google Chrome Beta|$HOME/.config/google-chrome-beta"
  "Chromium|$HOME/.config/chromium"
  "Brave|$HOME/.config/BraveSoftware/Brave-Browser"
  "Microsoft Edge|$HOME/.config/microsoft-edge"
  "Vivaldi|$HOME/.config/vivaldi"
)

installed_any=0
for entry in "${BROWSERS[@]}"; do
  name="${entry%%|*}"
  base="${entry##*|}"
  if [ -d "$base" ]; then
    dir="$base/NativeMessagingHosts"
    mkdir -p "$dir"
    printf '%s\n' "$MANIFEST_JSON" > "$dir/$HOST_NAME.json"
    echo "==> Registered for $name: $dir/$HOST_NAME.json"
    installed_any=1
  fi
done

# Firefox uses a different manifest (allowed_extensions, gecko id) and dir.
FF_DIR="$HOME/.mozilla/native-messaging-hosts"
if [ -d "$HOME/.mozilla" ]; then
  mkdir -p "$FF_DIR"
  sed "s#\"path\": \"[^\"]*\"#\"path\": \"$HOST_BIN\"#" \
    "$REPO/extension/native-host/no.sybr.vault.firefox.json" > "$FF_DIR/$HOST_NAME.json" 2>/dev/null \
    && echo "==> Registered for Firefox: $FF_DIR/$HOST_NAME.json" \
    || echo "    (skipped Firefox: template no.sybr.vault.firefox.json not found)"
  installed_any=1
fi

[ "$installed_any" -eq 1 ] || echo "No Chromium/Firefox config dir found; nothing registered."

cat <<DONE

Done. Last step (Chrome's one unavoidable click):
  1. chrome://extensions  ->  enable "Developer mode"
  2. "Load unpacked"  ->  select:  $REPO/extension/chromium
The extension id will be $EXT_ID (pinned), matching the host registration above.
Then keep the desktop app open + unlocked and autofill will work.
DONE
