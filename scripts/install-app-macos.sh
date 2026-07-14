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

# Prefer a stable signing identity (Developer ID / Apple Development): the
# macOS keychain grants quick-unlock access per code signature, so a stable
# identity means "Always Allow" sticks across rebuilds. Ad-hoc signatures
# change every build and would re-prompt for the login password each time.
IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
  | grep -Eo '"(Developer ID Application|Apple Development)[^"]*"' | head -1 | tr -d '"')"
if [ -n "$IDENTITY" ]; then
  echo "==> Signing with: $IDENTITY"
  codesign --force --deep -s "$IDENTITY" "$APP_SRC"
else
  echo "==> No signing identity found; ad-hoc signing (keychain will re-prompt after rebuilds)"
  codesign --force --deep -s - "$APP_SRC"
fi
codesign --verify --deep --strict "$APP_SRC"

echo "==> Installing to /Applications…"
rm -rf "$APP_DST"
ditto "$APP_SRC" "$APP_DST"

echo "Done: $APP_DST (launch it from Spotlight: 'SYBR Passwords')"
