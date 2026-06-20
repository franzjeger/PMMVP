#!/usr/bin/env bash
#
# One-shot installer for the SYBR Passwords native-messaging host (macOS).
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
  "description": "SYBR Passwords native messaging host",
  "path": "$HOST_BIN",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
JSON

# Chromium-family browsers and their per-user data dirs (macOS).
BROWSERS=(
  "Google Chrome|$HOME/Library/Application Support/Google/Chrome"
  "Brave|$HOME/Library/Application Support/BraveSoftware/Brave-Browser"
  "Microsoft Edge|$HOME/Library/Application Support/Microsoft Edge"
  "Chromium|$HOME/Library/Application Support/Chromium"
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

[ "$installed_any" -eq 1 ] || echo "No Chromium-family browser data dir found; nothing registered."

cat <<DONE

Done. Last step (Chrome's one unavoidable click):
  1. chrome://extensions  ->  enable "Developer mode"
  2. "Load unpacked"  ->  select:  $REPO/extension/chromium
The extension id will be $EXT_ID (pinned), matching the host registration above.
Then keep the desktop app open + unlocked and autofill will work.
DONE
