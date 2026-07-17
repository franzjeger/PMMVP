# Arca — macOS AutoFill Credential Provider

Native system-wide AutoFill so Arca can stand in for Apple Passwords in Safari
and native apps. This is a **passwords-only** effort (passkeys, sync, and the
browser extension are separate phases).

The Xcode project is generated from [`project.yml`](project.yml) with
[XcodeGen](https://github.com/yonabota/XcodeGen) — `project.yml` is the source of
truth; the `.xcodeproj` is git-ignored.

## Targets

| Target | Type | Purpose |
|--------|------|---------|
| `ArcaHost` | app | Dev/debug **container** for the extension + a screen to register a test identity. The shipping container will be the Tauri `Arca.app` (the `.appex` gets injected there before release); this host is a harness. |
| `ArcaAutoFill` | app-extension | The `ASCredentialProviderViewController` the OS loads. `ProvidesPasswords = true`. |

## Status — M1 (this commit)

Skeleton that proves the OS integration end to end, **no vault yet**:

- Extension serves ONE hardcoded credential (`arca-test` / a placeholder
  password). No real secret, no `vault-ffi`, no App Group.
- Host publishes a test identity (for a domain you choose) to
  `ASCredentialIdentityStore`.

M2 adds the real vault: the passwords `vault-ffi` surface, an App Group +
shared-keychain device key, Touch ID unlock in the extension, and populating the
store from the actual vault.

## Build & try it

```sh
cd apps/macos
xcodegen generate          # writes Arca.xcodeproj from project.yml
open Arca.xcodeproj
```

1. Select the **ArcaHost** scheme. In **Signing & Capabilities**, confirm the
   Team. `project.yml` defaults to `RYS5AACGS6` (the local Apple Development
   cert); switch to your team if Xcode complains. Automatic signing provisions
   the `authentication-services.autofill-credential-provider` capability — no
   Apple portal step needed.
2. **Run** (⌘R). The host window opens (this also registers the extension with
   the OS).
3. **System Settings ▸ General ▸ AutoFill & Passwords** and toggle **Arca** on
   (the host's "Open AutoFill Settings" button jumps there). This alone confirms
   the extension loaded and the entitlement is valid.
4. Back in the host: **Refresh**, type a domain that has a login form (e.g. a
   throwaway/test login page — the fixed placeholder password means no real
   account is touched), then **Register test identity**.
5. Open that site in **Safari**, focus the username/password field, and pick
   **arca-test** from the AutoFill suggestion. The field fills.

> AutoFill only offers a credential on a page that both matches the registered
> domain **and** has a login form, so pick a domain with an actual form in
> step 4 (a bare page like `example.com` has no field to fill).

## Troubleshooting: Arca doesn't appear in the AutoFill list

Two things the OS silently requires:

- **The extension must be sandboxed.** `ArcaAutoFill.entitlements` includes
  `com.apple.security.app-sandbox`. Without it `pkd` discards the extension at
  scan time (no error, no log) and it never shows up.
- **`pkd` registers extensions from LaunchServices-trusted locations, not
  reliably from DerivedData.** Copy the built host to `/Applications` and launch
  it once, keeping a single copy registered:

  ```sh
  APP=~/Library/Developer/Xcode/DerivedData/Arca-*/Build/Products/Debug/ArcaHost.app
  ditto $APP /Applications/ArcaHost.app && open /Applications/ArcaHost.app
  pluginkit -m | grep sybr        # should list no.sybr.vault.autofill-host.autofill
  ```

  If several stale copies pile up (multiple builds), `pkd` can't pick a
  canonical container and registers none — unregister the extras with
  `lsregister -u <path>` so only one `ArcaHost.app` remains.

## Verify without signing (what CI / a headless machine can do)

```sh
cd apps/macos && xcodegen generate
xcodebuild -scheme ArcaHost -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO -derivedDataPath build build
```

Compiles the host + extension and embeds `ArcaAutoFill.appex` into
`ArcaHost.app/Contents/PlugIns/`. Running it (and toggling it on in System
Settings) requires a signed build from your Xcode, since provisioning needs your
Apple ID account.

## Not this (deliberately, for later phases)

- **Chromium browsers** (Chrome/Brave) on macOS use their own web autofill and
  generally do **not** call the system provider for in-page logins — those are
  covered by the browser extension. Safari + native apps are this provider's
  surface.
- Passkeys: the `ProvidesPasskeys` capability + the existing
  `apps/macos-credential-provider` scaffold are a later phase.
