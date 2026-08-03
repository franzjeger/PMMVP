#!/usr/bin/env bash
#
# Build the release app and (re)install it into /Applications.
#
# Produces a locally built, ad-hoc-signed "Arca.app". Local builds
# carry no quarantine attribute, so Gatekeeper launches them without warnings.
# Distribution to OTHER machines needs a Developer ID + notarization instead.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }
APP_SRC="$REPO/target/release/bundle/macos/Arca.app"
APP_DST="/Applications/Arca.app"
# Entitlements (App Group + shared keychain group) so the vault + device key are
# shared with the AutoFill extension. The re-sign below MUST pass these or it
# strips what `tauri build` embedded.
ENTITLEMENTS="$REPO/apps/desktop/src-tauri/Entitlements.plist"

# Gate every install on the smoke test (Rust tests + frontend build + on macOS
# the keychain quick-unlock drift regression). Skip only with SKIP_SMOKE=1 and a
# reason you can defend.
if [ "${SKIP_SMOKE:-}" != "1" ]; then
  echo "==> Smoke test (set SKIP_SMOKE=1 to bypass)…"
  bash "$REPO/scripts/smoke-test.sh" --full
fi

# The Google OAuth client secret lives outside the repository (it is public);
# crates/vault-sync's build script picks it up from here. Say so out loud rather
# than installing an app whose Settings pane refuses to connect for no visible
# reason.
if [ -z "${ARCA_GOOGLE_CLIENT_SECRET:-}" ] && [ ! -s "$HOME/.arca/google-client-secret" ]; then
  echo "==> WARNING: no Google client secret at ~/.arca/google-client-secret."
  echo "    This build will run fine but Drive sync cannot connect. See docs/SYNC.md."
fi

echo "==> Building release bundle…"
(cd "$REPO/apps/desktop" && npm run tauri build -- --bundles app)

# The native messaging host, in RELEASE, because that is the binary the browsers
# actually run: the manifests in each browser's NativeMessagingHosts directory
# point at target/release/vault-native-host by absolute path.
#
# It is built here, with the app, because the two speak one protocol and had
# already drifted apart once. A day's work went into both sides of a new message
# type, every test passed, and the browser answered "malformed message" — the
# installed host was five days old and had never heard of it. Nothing was broken
# except that the two halves of one product were built by two different commands
# and only one of them ever ran.
echo "==> Building the native messaging host (release)…"
cargo build --release -p vault-native-host --manifest-path "$REPO/Cargo.toml" \
  || die "the native messaging host failed to build"

# Signing: the app carries RESTRICTED entitlements (App Group + keychain access
# group, shared with the AutoFill extension). macOS (AMFI) only honors those
# with a provisioning profile that authorizes them — Developer ID without a
# profile is KILLED at launch. Development signing (Apple Development cert +
# the Mac Team dev profile) authorizes them, so that's what we use locally.
# The profile must AUTHORIZE the App Group (group.no.sybr.vault) and the shared
# keychain group. The committed "Arca Vault macOS Dev" profile does — it is tied
# to the explicit App ID no.sybr.vault with App Groups + a LY6LJ395B8.* keychain
# group. Earlier fallbacks (the wildcard "Mac Team *" profile) grant the keychain
# group but NOT the App Group, so the shared-container write was blocked; prefer
# the committed profile first and only fall back for machines without it.
PROFILE_SRC="$REPO/apps/macos/profiles/Arca_Vault_macOS_Dev.provisionprofile"
[ -f "$PROFILE_SRC" ] || PROFILE_SRC="$APP_DST/Contents/embedded.provisionprofile"
[ -f "$PROFILE_SRC" ] || PROFILE_SRC="$REPO/apps/macos/build/Build/Products/Debug/ArcaSign.app/Contents/embedded.provisionprofile"
[ -f "$PROFILE_SRC" ] || PROFILE_SRC="$(ls -t "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"/*.provisionprofile 2>/dev/null | head -1)"

IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
  | grep -Eo '"Apple Development[^"]*"' | head -1 | tr -d '"' || true)"
if [ -n "$IDENTITY" ] && [ -n "$PROFILE_SRC" ] && [ -f "$PROFILE_SRC" ]; then
  echo "==> Embedding provisioning profile: $PROFILE_SRC"
  cp "$PROFILE_SRC" "$APP_SRC/Contents/embedded.provisionprofile"

  # The AutoFill extension goes INSIDE the real app.
  #
  # It used to live only in ArcaHost, a development harness — so system AutoFill
  # required running a second app whose entire purpose was to exist, and whose
  # "Sync" button was the only thing that ever published anything. An extension
  # embedded here is registered for as long as Arca is installed, and the app
  # publishes on unlock by itself.
  # ARCHS pinned to the CONTAINER's architecture. Release defaults to universal,
  # while the pre-build step stages an arm64-only vault_ffi and `tauri build`
  # produces an arm64-only Arca — so a universal extension would fail to link
  # for a slice nothing else here has.
  echo "==> Building the AutoFill extension"
  ( cd "$REPO/apps/macos" && xcodegen generate >/dev/null &&
    xcodebuild -project Arca.xcodeproj -scheme ArcaHost -configuration Release \
      -derivedDataPath "$REPO/target/macos-appex" ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
      build >/dev/null ) \
    || die "the AutoFill extension failed to build"
  APPEX="$REPO/target/macos-appex/Build/Products/Release/ArcaHost.app/Contents/PlugIns/ArcaAutoFill.appex"
  [ -d "$APPEX" ] || die "no ArcaAutoFill.appex at $APPEX"
  mkdir -p "$APP_SRC/Contents/PlugIns"
  rm -rf "$APP_SRC/Contents/PlugIns/ArcaAutoFill.appex"
  ditto "$APPEX" "$APP_SRC/Contents/PlugIns/ArcaAutoFill.appex"

  # The extension is signed FIRST and with its OWN entitlements: codesign seals
  # nested code, so signing the app first and the appex after would invalidate
  # the outer signature. --deep is not enough here — it would reuse the app's
  # entitlements for the extension, which needs its own.
  #
  # $(AppIdentifierPrefix) is an XCODE variable. Xcode expands it while
  # packaging; plain codesign does NOT, and signs the literal text instead. That
  # produced an appex whose keychain group was the eleven characters
  # "$(AppIdentifi…" and could therefore never reach the device key the app
  # writes to LY6LJ395B8.no.sybr.vault.shared — an AutoFill extension that
  # authenticates and then cannot decrypt. Expand it here, from the profile the
  # app is actually signed with rather than a constant that can drift.
  TEAM="$(security cms -D -i "$PROFILE_SRC" 2>/dev/null \
    | plutil -extract Entitlements.com\\.apple\\.developer\\.team-identifier raw -o - - 2>/dev/null)"
  [ -n "$TEAM" ] || die "could not read the team identifier out of $PROFILE_SRC"
  APPEX_ENT="$REPO/target/ArcaAutoFill.expanded.entitlements"
  sed "s/\$(AppIdentifierPrefix)/$TEAM./g" \
    "$REPO/apps/macos/ArcaAutoFill/ArcaAutoFill.entitlements" > "$APPEX_ENT"
  grep -q '\$(' "$APPEX_ENT" && die "unexpanded build variables remain in $APPEX_ENT"

  echo "==> Signing the extension, then the app"
  codesign --force --entitlements "$APPEX_ENT" \
    -s "$IDENTITY" "$APP_SRC/Contents/PlugIns/ArcaAutoFill.appex"
  echo "==> Signing with: $IDENTITY (entitled: AutoFill + shared App Group + keychain)"
  codesign --force --entitlements "$ENTITLEMENTS" -s "$IDENTITY" "$APP_SRC"

  # Assert what was actually SEALED, not what we passed in. Both of this
  # build's AutoFill bugs were invisible until read back this way: a capability
  # missing from the app, and a variable left unexpanded in the extension.
  for target in "$APP_SRC" "$APP_SRC/Contents/PlugIns/ArcaAutoFill.appex"; do
    sealed="$(codesign -d --entitlements - --xml "$target" 2>/dev/null | plutil -p - 2>/dev/null)"
    case "$sealed" in
      *'authentication-services.autofill-credential-provider'*) ;;
      *) die "$(basename "$target") was signed WITHOUT the AutoFill capability; it will never be offered as a provider" ;;
    esac
    case "$sealed" in
      *'$(AppIdentifierPrefix)'*) die "$(basename "$target") carries an unexpanded \$(AppIdentifierPrefix)" ;;
    esac
  done
else
  # Fallback: no dev cert/profile — sign WITHOUT the restricted entitlements so
  # the app still launches; only cross-app autofill sharing is unavailable.
  echo "==> No Apple Development identity/profile; signing WITHOUT shared entitlements"
  FALLBACK_ID="$(security find-identity -v -p codesigning 2>/dev/null \
    | grep -Eo '"Developer ID Application[^"]*"' | head -1 | tr -d '"' || true)"
  codesign --force --deep -s "${FALLBACK_ID:--}" "$APP_SRC"
fi
codesign --verify --deep --strict "$APP_SRC"

echo "==> Installing to /Applications…"
# A running Arca keeps running the OLD binary: replacing the bundle on disk does
# not touch a process that already mapped it. That failure is silent and very
# convincing — the app is there, the version string in Settings is the new one
# because it reads the bundle, and yet a feature added in this build is missing.
# It cost an afternoon once, chasing a bridge command the running app had never
# heard of.
WAS_RUNNING=0
if pgrep -f "$APP_DST/Contents/MacOS/vault-desktop" >/dev/null 2>&1; then
  WAS_RUNNING=1
  echo "    Arca is running the previous build — quitting it (your vault locks)."
  osascript -e 'quit app "Arca"' >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pgrep -f "$APP_DST/Contents/MacOS/vault-desktop" >/dev/null 2>&1 || break
    sleep 1
  done
  # Only after asking nicely: a graceful quit lets it clear the clipboard and
  # release the bridge socket.
  pkill -f "$APP_DST/Contents/MacOS/vault-desktop" 2>/dev/null || true
  sleep 1
fi

rm -rf "$APP_DST"
ditto "$APP_SRC" "$APP_DST"

# Remove the just-built source bundle so Spotlight/Launch Services don't show a
# second "Arca" alongside the installed one, then refresh Launch Services.
rm -rf "$APP_SRC"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
[ -x "$LSREGISTER" ] && "$LSREGISTER" -f "$APP_DST" 2>/dev/null || true

if [ "$WAS_RUNNING" = 1 ]; then
  echo "==> Relaunching Arca (it was running before this install)…"
  open -a "$APP_DST"
  echo "Done: $APP_DST — running the build you just made. Unlock it again."
else
  echo "Done: $APP_DST (launch it from Spotlight: 'Arca')"
fi
