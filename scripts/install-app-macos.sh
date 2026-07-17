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

# Signing: the app carries RESTRICTED entitlements (App Group + keychain access
# group, shared with the AutoFill extension). macOS (AMFI) only honors those
# with a provisioning profile that authorizes them — Developer ID without a
# profile is KILLED at launch. Development signing (Apple Development cert +
# the Mac Team dev profile) authorizes them, so that's what we use locally.
# The profile is produced by building the ArcaSign stub once in apps/macos
# (Xcode auto-provisioning). Distribution later needs a Developer ID profile.
# Profile source, most-reliable first: the currently installed app (already
# proven to launch), a fresh ArcaSign stub build, then Xcode's newest profile.
PROFILE_SRC="$APP_DST/Contents/embedded.provisionprofile"
[ -f "$PROFILE_SRC" ] || PROFILE_SRC="$REPO/apps/macos/build/Build/Products/Debug/ArcaSign.app/Contents/embedded.provisionprofile"
[ -f "$PROFILE_SRC" ] || PROFILE_SRC="$(ls -t "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"/*.provisionprofile 2>/dev/null | head -1)"

IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
  | grep -Eo '"Apple Development[^"]*"' | head -1 | tr -d '"')"
if [ -n "$IDENTITY" ] && [ -n "$PROFILE_SRC" ] && [ -f "$PROFILE_SRC" ]; then
  echo "==> Embedding provisioning profile: $PROFILE_SRC"
  cp "$PROFILE_SRC" "$APP_SRC/Contents/embedded.provisionprofile"
  echo "==> Signing with: $IDENTITY (entitled: shared App Group + keychain)"
  codesign --force --deep --entitlements "$ENTITLEMENTS" -s "$IDENTITY" "$APP_SRC"
else
  # Fallback: no dev cert/profile — sign WITHOUT the restricted entitlements so
  # the app still launches; only cross-app autofill sharing is unavailable.
  echo "==> No Apple Development identity/profile; signing WITHOUT shared entitlements"
  FALLBACK_ID="$(security find-identity -v -p codesigning 2>/dev/null \
    | grep -Eo '"Developer ID Application[^"]*"' | head -1 | tr -d '"')"
  codesign --force --deep -s "${FALLBACK_ID:--}" "$APP_SRC"
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
