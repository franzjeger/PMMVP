#!/usr/bin/env bash
#
# Build the release app and (re)install it into /Applications.
#
# Produces a locally built, ad-hoc-signed "Arca.app". Local builds
# carry no quarantine attribute, so Gatekeeper launches them without warnings.
# Distribution to OTHER machines needs a Developer ID + notarization instead.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP_SRC="$REPO/target/release/bundle/macos/Arca.app"
APP_DST="/Applications/Arca.app"
# Entitlements (App Group + shared keychain group) so the vault + device key are
# shared with the AutoFill extension. The re-sign below MUST pass these or it
# strips what `tauri build` embedded.
ENTITLEMENTS="$REPO/apps/desktop/src-tauri/Entitlements.plist"

echo "==> Building release bundle…"
(cd "$REPO/apps/desktop" && npm run tauri build -- --bundles app)

# Prefer a stable signing identity (Developer ID / Apple Development): the
# macOS keychain grants quick-unlock access per code signature, so a stable
# identity means "Always Allow" sticks across rebuilds. Ad-hoc signatures
# change every build and would re-prompt for the login password each time.
# Prefer Developer ID (long-lived, distribution-grade) over Apple Development
# (expires yearly) — and keep using ONE identity consistently: the keychain
# item is ACL-bound to the signing identity, so switching identity re-prompts.
IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
  | grep -Eo '"Developer ID Application[^"]*"' | head -1 | tr -d '"')"
[ -n "$IDENTITY" ] || IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
  | grep -Eo '"Apple Development[^"]*"' | head -1 | tr -d '"')"
if [ -n "$IDENTITY" ]; then
  echo "==> Signing with: $IDENTITY"
  codesign --force --deep --entitlements "$ENTITLEMENTS" -s "$IDENTITY" "$APP_SRC"
else
  echo "==> No signing identity found; ad-hoc signing (App Groups need a real team, so sharing won't work ad-hoc)"
  codesign --force --deep --entitlements "$ENTITLEMENTS" -s - "$APP_SRC"
fi
codesign --verify --deep --strict "$APP_SRC"

echo "==> Installing to /Applications…"
rm -rf "$APP_DST"
ditto "$APP_SRC" "$APP_DST"

# Remove the just-built source bundle so Spotlight/Launch Services don't show a
# second "Arca" alongside the installed one, then refresh Launch Services.
rm -rf "$APP_SRC"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
[ -x "$LSREGISTER" ] && "$LSREGISTER" -f "$APP_DST" 2>/dev/null || true

echo "Done: $APP_DST (launch it from Spotlight: 'Arca')"
