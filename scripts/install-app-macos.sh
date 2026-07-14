#!/usr/bin/env bash
#
# Build the release app and (re)install it into /Applications.
#
# Produces a locally built, ad-hoc-signed "SYBR Passwords.app". Local builds
# carry no quarantine attribute, so Gatekeeper launches them without warnings.
# Distribution to OTHER machines needs a Developer ID + notarization instead.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP_SRC="$REPO/target/release/bundle/macos/SYBR Passwords.app"
APP_DST="/Applications/SYBR Passwords.app"

echo "==> Building release bundle…"
(cd "$REPO/apps/desktop" && npm run tauri build -- --bundles app)

echo "==> Ad-hoc signing…"
codesign --force --deep -s - "$APP_SRC"
codesign --verify --deep --strict "$APP_SRC"

echo "==> Installing to /Applications…"
rm -rf "$APP_DST"
ditto "$APP_SRC" "$APP_DST"

echo "Done: $APP_DST (launch it from Spotlight: 'SYBR Passwords')"
