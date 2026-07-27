#!/usr/bin/env bash
#
# Build a DISTRIBUTABLE macOS Arca: Developer ID signed, hardened runtime,
# notarized and stapled, as a .dmg other Macs will open without warnings.
#
#   scripts/release-macos.sh            # build, sign, notarize, staple
#   scripts/release-macos.sh --no-notarize   # sign only (local check)
#
# One-time setup (you must do this yourself — it needs your Apple ID and an
# app-specific password from https://appleid.apple.com):
#
#   xcrun notarytool store-credentials "arca-notary" \
#     --apple-id "<your-apple-id>" --team-id LY6LJ395B8
#
# That stores the credential in your login keychain, so no secret ever appears
# in this script, in the environment, or in your shell history.
#
# Distribution signing deliberately does NOT carry the App Group / shared
# keychain entitlements: the macOS AutoFill extension is shelved, the vault
# lives in app data, and restricted entitlements would drag a provisioning
# profile into every release for no benefit.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
NOTARIZE=1
[ "${1:-}" = "--no-notarize" ] && NOTARIZE=0

NOTARY_PROFILE="${ARCA_NOTARY_PROFILE:-arca-notary}"
TEAM_ID="LY6LJ395B8"

step() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Guard: never ship a build that would strand the user's data.
#
# The vault briefly lived in the App Group container. A release build has no
# App Group entitlement, so it CANNOT see that container — if a newer vault is
# still sitting there, installing this build would silently open an older
# app-data copy and quietly lose everything since. The dev build migrates it
# back on launch; run that first. (Metadata is readable from a shell even
# though the contents are not, which is exactly what this check needs.)
# ---------------------------------------------------------------------------
step "Checking that no vault data is stranded in the App Group container"
CONTAINER_VAULT="$HOME/Library/Group Containers/group.no.sybr.vault/default.vault"
APPDATA_VAULT="$HOME/Library/Application Support/no.sybr.vault/default.vault"
if [ -f "$CONTAINER_VAULT" ]; then
  c_mtime=$(stat -f %m "$CONTAINER_VAULT")
  a_mtime=$(stat -f %m "$APPDATA_VAULT" 2>/dev/null || echo 0)
  if [ "$c_mtime" -gt "$a_mtime" ]; then
    die "the App Group container holds a NEWER vault than app data.
     container: $(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$CONTAINER_VAULT")
     app data:  $(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$APPDATA_VAULT" 2>/dev/null || echo 'missing')
     A release build cannot read that container, so installing it would open
     the older copy and lose the difference. Launch the locally installed dev
     build once (scripts/install-app-macos.sh) — it migrates the vault back —
     then re-run this."
  fi
  echo "   container copy is not newer; nothing stranded"
else
  echo "   no container vault; nothing to check"
fi

step "Smoke test"
bash "$REPO/scripts/smoke-test.sh"

IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
  | grep -Eo '"Developer ID Application[^"]*"' | head -1 | tr -d '"')"
[ -n "$IDENTITY" ] || die "no 'Developer ID Application' certificate in the keychain."
echo "   signing identity: $IDENTITY"

# The update signing key is separate from the Apple one: Apple's signature says
# "this came from Frank Lia", the update key says "this is the same Arca you
# already trust". Installed copies only accept updates signed by the key baked
# into the build they are running, so losing it strands every user forever.
UPDATER_KEY="${ARCA_UPDATER_KEY:-$HOME/.arca/arca-updater.key}"
[ -f "$UPDATER_KEY" ] || die "no update signing key at $UPDATER_KEY.
     Without it the build cannot be published as an update. Restore it from
     your backup, or (only if no release has ever shipped) generate a new one:
       cd apps/desktop && npx tauri signer generate -w \"$UPDATER_KEY\""

# The Google OAuth client secret is not in the repository — crates/vault-sync's
# build script reads it from here. A build without it works perfectly except
# that Drive sync refuses to connect, which is a silent thing to discover after
# shipping, so a release stops rather than going out half-working.
CLIENT_SECRET_FILE="${ARCA_GOOGLE_CLIENT_SECRET_FILE:-$HOME/.arca/google-client-secret}"
if [ -z "${ARCA_GOOGLE_CLIENT_SECRET:-}" ]; then
  [ -s "$CLIENT_SECRET_FILE" ] || die "no Google client secret at $CLIENT_SECRET_FILE.
     This build would ship with Drive sync switched off. Put the secret for the
     desktop OAuth client there (one line, chmod 600), or export
     ARCA_GOOGLE_CLIENT_SECRET. See docs/SYNC.md."
fi

step "Building the release bundle (Developer ID + hardened runtime)"
# Tauri signs the bundle itself when these are set; the hardened runtime is
# required for notarization.
export APPLE_SIGNING_IDENTITY="$IDENTITY"
export APPLE_TEAM_ID="$TEAM_ID"
export TAURI_SIGNING_PRIVATE_KEY_PATH="$UPDATER_KEY"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${ARCA_UPDATER_KEY_PASSWORD:-}"
# createUpdaterArtifacts is passed HERE, not in tauri.conf.json: in the shared
# config it made every local dev build demand the release signing key.
(cd "$REPO/apps/desktop" && npm run tauri build -- --bundles app,dmg \
  --config '{"bundle":{"createUpdaterArtifacts":true}}')

APP="$REPO/target/release/bundle/macos/Arca.app"
DMG="$(ls -t "$REPO/target/release/bundle/dmg/"*.dmg 2>/dev/null | head -1 || true)"
[ -d "$APP" ] || die "no app bundle at $APP"

step "Verifying the signature"
codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | tail -3
# Hardened runtime must be on, or notarization rejects the upload.
codesign -d --verbose=2 "$APP" 2>&1 | grep -q "flags=.*runtime" \
  || die "the app is not signed with the hardened runtime."
echo "   hardened runtime: on"

if [ "$NOTARIZE" = "0" ]; then
  printf '\nSigned but NOT notarized (--no-notarize).\n  %s\n' "$APP"
  exit 0
fi

if ! xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
  die "no notarytool credentials named '$NOTARY_PROFILE'.
     Create them once (they never touch this script):
       xcrun notarytool store-credentials \"$NOTARY_PROFILE\" \\
         --apple-id \"<your-apple-id>\" --team-id $TEAM_ID"
fi

# Notarize the DMG when we built one — stapling the disk image means the
# download itself is trusted, not just the app inside it.
TARGET="${DMG:-$APP}"
if [ "$TARGET" = "$APP" ]; then
  TARGET="$REPO/target/release/bundle/macos/Arca.zip"
  ditto -c -k --keepParent "$APP" "$TARGET"
fi

step "Notarizing $(basename "$TARGET") (Apple can take a few minutes)"
xcrun notarytool submit "$TARGET" --keychain-profile "$NOTARY_PROFILE" --wait

step "Stapling the ticket"
if [ "${TARGET##*.}" = "dmg" ]; then
  xcrun stapler staple "$TARGET"
  xcrun stapler validate "$TARGET"
else
  # A zip cannot be stapled; staple the app and re-zip.
  xcrun stapler staple "$APP"
  xcrun stapler validate "$APP"
  rm -f "$TARGET"
  ditto -c -k --keepParent "$APP" "$TARGET"
fi

step "Gatekeeper assessment (what another Mac will decide)"
spctl --assess --type execute --verbose=2 "$APP" 2>&1 | tail -3

step "Writing the update manifest"
# Tauri emits <bundle>.app.tar.gz plus a detached .sig when
# createUpdaterArtifacts is on. latest.json is what installed copies poll.
UPD_ARCHIVE="$(ls -t "$REPO/target/release/bundle/macos/"*.app.tar.gz 2>/dev/null | head -1 || true)"
if [ -n "$UPD_ARCHIVE" ] && [ -f "$UPD_ARCHIVE.sig" ]; then
  VERSION="$(python3 -c "import json;print(json.load(open('$REPO/apps/desktop/src-tauri/tauri.conf.json'))['version'])")"
  LATEST="$REPO/target/release/bundle/latest.json"
  SIG="$(cat "$UPD_ARCHIVE.sig")" VER="$VERSION" ARCH="$(basename "$UPD_ARCHIVE")" \
  python3 - > "$LATEST" <<'PYEOF'
import json, os, datetime
url = ("https://github.com/franzjeger/PMMVP/releases/download/v"
       + os.environ["VER"] + "/" + os.environ["ARCH"])
print(json.dumps({
    "version": os.environ["VER"],
    "pub_date": datetime.datetime.now(datetime.timezone.utc)
                  .strftime("%Y-%m-%dT%H:%M:%SZ"),
    "notes": "See the release notes on GitHub.",
    # Both Apple architectures run the same universal-capable bundle.
    "platforms": {
        "darwin-aarch64": {"signature": os.environ["SIG"], "url": url},
        "darwin-x86_64":  {"signature": os.environ["SIG"], "url": url},
    },
}, indent=2))
PYEOF
  echo "   $LATEST (v$VERSION)"
  echo "   Publish it AND $(basename "$UPD_ARCHIVE") on the v$VERSION GitHub release,"
  echo "   or installed copies will never see the update."
else
  echo "   no updater artifacts produced; skipping (is createUpdaterArtifacts on?)"
fi

printf '\nRELEASE OK\n  app: %s\n' "$APP"
[ -n "$DMG" ] && printf '  dmg: %s\n' "$DMG"
