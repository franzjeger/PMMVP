# Releasing Arca (macOS)

The everyday build (`scripts/install-app-macos.sh`) is signed for **this Mac
only**. To put Arca on another machine it must be Developer ID signed, hardened,
notarized and stapled, or Gatekeeper refuses to open it.

```bash
scripts/release-macos.sh                 # build, sign, notarize, staple
scripts/release-macos.sh --no-notarize   # sign only, to check the build
```

## One-time setup

Notarization needs your Apple credentials. Create the keychain profile
yourself — no script or tool here ever sees the password:

1. Make an **app-specific password** at <https://appleid.apple.com> →
   *Sign-In and Security* → *App-Specific Passwords*.
2. Store it:

```bash
xcrun notarytool store-credentials "arca-notary" --apple-id "<your-apple-id>" --team-id LY6LJ395B8
```

`Developer ID Application: Frank Lia (LY6LJ395B8)` is already in the keychain.
If it is ever lost, regenerate it in the Apple Developer portal — a Developer ID
certificate cannot be re-downloaded.

## Why release builds carry no entitlements

The App Group and shared-keychain entitlements in
`apps/desktop/src-tauri/Entitlements.plist` are **restricted**: macOS (AMFI)
kills an app that carries them without a provisioning profile that authorizes
them — the "error 163" that stopped us for hours. They are therefore *not* in
`tauri.conf.json`. A plain `tauri build` produces a clean bundle that Developer
ID signing and notarization accept, while `install-app-macos.sh` re-applies them
locally (with the profile) for the one job that still needs them: migrating a
vault out of the App Group container.

Verify a release build with:

```bash
codesign -dv --verbose=2 target/release/bundle/macos/Arca.app 2>&1 | grep -E 'Authority|flags='
```

You want `Authority=Developer ID Application` and `flags=0x10000(runtime)`.

## The stranded-vault guard

`release-macos.sh` refuses to build while the App Group container holds a
**newer** vault than app data. A release build has no entitlement to read that
container, so installing it would silently open the older copy and lose
everything since. Launch the locally installed dev build once (it migrates the
vault back), then release. The guard reads only file timestamps, which is
allowed even though the contents are not.

## Auto-update (prepared, not wired yet)

Updates must be signed with a key that exists **before** the first release —
users only accept updates signed by the key baked into the version they already
run. The keypair is generated:

```
~/.arca/arca-updater.key       private — back this up, it cannot be regenerated
~/.arca/arca-updater.key.pub   public  — goes into tauri.conf.json
```

**Back up the private key now.** Losing it means every installed copy is stuck
on its current version forever, with no way to ship a fix. A Secure Note in Arca
plus the off-device backup (see [BACKUP.md](BACKUP.md)) is a reasonable home for
it.

Remaining work to switch updates on:

1. Add `tauri-plugin-updater` and put the public key plus an endpoint in
   `tauri.conf.json` (`https://github.com/franzjeger/PMMVP/releases/latest/download/latest.json`
   works — the repo is public, so no auth is needed).
2. Extend `release-macos.sh` to sign the bundle with
   `TAURI_SIGNING_PRIVATE_KEY_PATH` and publish `latest.json` with the release.
3. Surface "an update is available" in the UI, and make sure an update never
   interrupts an unlocked session mid-edit.

Until that lands, a new version means downloading and replacing the app by hand.
