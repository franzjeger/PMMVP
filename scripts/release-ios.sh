#!/usr/bin/env bash
#
# Build, sign and upload Arca for iOS to TestFlight.
#
#   scripts/release-ios.sh              # archive, export, upload
#   scripts/release-ios.sh --no-upload  # stop after the .ipa (local check)
#
# One-time setup, both on Frank's Apple account and therefore not scriptable:
#
#   1. An app record at appstoreconnect.apple.com for bundle id
#      no.sybr.vault.ios. Without it the upload is rejected with a message
#      about the bundle id not being found, which reads like a signing problem
#      and is not one.
#
#   2. An App Store Connect API key, so this can upload without a password
#      living anywhere. Users and Access ▸ Integrations ▸ App Store Connect API
#      ▸ generate a key with the "App Manager" role, then:
#
#        mkdir -p ~/.appstoreconnect/private_keys
#        mv ~/Downloads/AuthKey_XXXXXXXXXX.p8 ~/.appstoreconnect/private_keys/
#        printf 'XXXXXXXXXX\n<issuer-uuid>\n' > ~/.arca/asc-api-key
#
#      The .p8 is downloadable exactly once. Back it up with the updater key.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
UPLOAD=1
[ "${1:-}" = "--no-upload" ] && UPLOAD=0

TEAM_ID="LY6LJ395B8"
ARCHIVE="$REPO/target/ios/Arca.xcarchive"
EXPORT_DIR="$REPO/target/ios/export"

step() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# TestFlight rejects a build whose (version, build) pair it has already seen,
# and it does so AFTER the upload, by email, minutes later. Deriving the build
# number from the commit count makes a repeat impossible without also being a
# repeat of the source.
BUILD_NUMBER="$(git rev-list --count HEAD)"
step "Build $BUILD_NUMBER"

step "Archiving"
xcodebuild -project apps/ios/Arca.xcodeproj -scheme Arca -configuration Release \
  -destination 'generic/platform=iOS' -archivePath "$ARCHIVE" \
  -allowProvisioningUpdates \
  CURRENT_PROJECT_VERSION="$BUILD_NUMBER" \
  archive
[ -d "$ARCHIVE" ] || die "no archive at $ARCHIVE"

step "Exporting for the App Store"
rm -rf "$EXPORT_DIR"
cat > "$REPO/target/ios/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key><string>app-store-connect</string>
    <key>teamID</key><string>$TEAM_ID</string>
    <key>signingStyle</key><string>automatic</string>
    <key>uploadSymbols</key><true/>
    <key>destination</key><string>export</string>
</dict>
</plist>
PLIST
xcodebuild -exportArchive -archivePath "$ARCHIVE" \
  -exportOptionsPlist "$REPO/target/ios/ExportOptions.plist" \
  -exportPath "$EXPORT_DIR" -allowProvisioningUpdates

IPA="$EXPORT_DIR/Arca.ipa"
[ -f "$IPA" ] || die "no .ipa at $IPA"

# A development signature exports fine and is refused at upload. Catch it here,
# where the message can say which one it is.
step "Checking the signature is a DISTRIBUTION one"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
(cd "$WORK" && unzip -q "$IPA")
AUTHORITY="$(codesign -d --verbose=2 "$WORK/Payload/Arca.app" 2>&1 \
  | grep -m1 '^Authority=' || true)"
case "$AUTHORITY" in
  *"Apple Distribution"*) echo "   ${AUTHORITY#Authority=}" ;;
  *) die "signed with ${AUTHORITY#Authority=}, not Apple Distribution.
     TestFlight will refuse this. Check the export method." ;;
esac
# The App Store profile carries no device list; a development one does. This is
# the difference that decides whether the build runs on anybody else's phone.
if security cms -D -i "$WORK/Payload/Arca.app/embedded.mobileprovision" 2>/dev/null \
   | plutil -p - 2>/dev/null | grep -q ProvisionedDevices; then
  die "the embedded profile has a device list — that is a development profile."
fi
echo "   App Store profile (no device list)"

if [ "$UPLOAD" = "0" ]; then
  printf '\nBuilt but NOT uploaded (--no-upload).\n  %s\n' "$IPA"
  exit 0
fi

KEY_FILE="${ARCA_ASC_KEY:-$HOME/.arca/asc-api-key}"
[ -s "$KEY_FILE" ] || die "no App Store Connect API key id at $KEY_FILE.
     See the header of this script — it is a one-time setup, and without it the
     only way up is dragging the .ipa through Xcode's Organizer."
KEY_ID="$(sed -n 1p "$KEY_FILE")"
ISSUER_ID="$(sed -n 2p "$KEY_FILE")"
[ -n "$KEY_ID" ] && [ -n "$ISSUER_ID" ] || die "$KEY_FILE needs the key id on line 1 and the issuer uuid on line 2."

step "Validating with App Store Connect"
xcrun altool --validate-app -f "$IPA" -t ios \
  --apiKey "$KEY_ID" --apiIssuer "$ISSUER_ID"

step "Uploading"
xcrun altool --upload-app -f "$IPA" -t ios \
  --apiKey "$KEY_ID" --apiIssuer "$ISSUER_ID"

printf '\nUPLOADED build %s.\n' "$BUILD_NUMBER"
echo "Apple processes it for a few minutes, then it appears in TestFlight."
echo "First upload only: answer the export-compliance question in App Store Connect."
