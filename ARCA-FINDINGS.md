# ARCA-FINDINGS — passkey sign-in fails on Microsoft 365 & Google (Windows/Brave)

Debugging report for the Windows-specific passkey failures. Diagnosis was done
by code inspection of the exact ceremony path each site takes; the root cause
is deterministic (a platform `cfg` gate), so it reproduces on every Windows
machine regardless of browser.

## Symptoms

Passkey sign-in via the Arca WebAuthn shim in Brave on Windows:

| Site | Result |
|---|---|
| github.com | ✅ works |
| login.microsoftonline.com / login.microsoft.com | ❌ fails |
| accounts.google.com | ❌ fails |

All three work on macOS with identical extension code and vault contents.
The failing sites receive a *successful, well-formed assertion* from the
bridge — which they then reject server-side.

## Root cause

**Every assertion (and attestation) produced on Windows carries UV = 0
(user-not-verified) in the authenticator-data flags, because the biometric
approval path was `cfg`-gated to macOS only.**

The chain:

1. `approve_passkey()` in `apps/desktop/src-tauri/src/bridge.rs` gates
   passkey create/get behind Touch ID **only under
   `#[cfg(target_os = "macos")]`**, returning `Some(true)` (user verified).
   On every other platform it falls through to the in-app Allow/Deny dialog
   and returns `Some(false)` — honest, since a click proves presence, not
   verification. (The `robius-authentication` dependency was likewise
   macOS-gated in `apps/desktop/src-tauri/Cargo.toml`, so Windows builds
   never even linked a biometric provider.)
2. `vault_core::passkey::assert()` then correctly leaves the `FLAG_UV`
   (0x04) bit clear in the authenticator data
   (`crates/vault-core/src/passkey.rs:97-99`).
3. Relying parties differ in what they accept:
   - **GitHub** requests `userVerification: "preferred"` and accepts UV=0
     (it treats the passkey as a second factor / falls back accordingly) →
     works.
   - **Microsoft Entra/MSA** requires user verification for FIDO2/passkey
     sign-in (passwordless replaces password *and* 2FA) → rejects the UV=0
     assertion → fails.
   - **Google** likewise requires UV for passkey sign-in → rejects → fails.
4. On the Mac, Touch ID sets UV=1, so all three sites accept — exactly the
   observed matrix.

The other suspects from the brief were ruled out:

- **rp_id validation** (`rp_id_matches_origin`): identical code and identical
  synced vault data on both machines; MS runs its FIDO ceremony from a
  `login.microsoft.com` page with rp_id `login.microsoft.com`, which passes.
  Not platform-dependent.
- **Mediation deferral / shim not injected**: same manifest and shim on both
  platforms; and the bridge *was* reached (it answered with an assertion the
  site rejected). Even if a site chose conditional UI on Windows, fixing UV
  is necessary regardless — a UV=0 answer is rejected by MS/Google on any
  path.

### Secondary defect found on the way

The extension never forwards the RP's `userVerification` requirement to the
bridge at all (`passkey.js` → `background.js` → `passkey_get`/`passkey_create`
messages had no such field). So on platforms that genuinely *cannot* verify
the user (currently Linux), a `userVerification: "required"` ceremony was
answered with UV=0 instead of being declined — the user got an approval
prompt whose result the site then rejected. Spec-wise an authenticator that
cannot satisfy required-UV must not produce the assertion; declining lets the
shim fall back to the browser's native handler (QR/hybrid, security key).

## Fix

Minimal, two-part:

1. **Enable the already-present Windows Hello backend.**
   `robius-authentication` 0.1.1 (already an unconditional dependency, and the
   existing code already constructs its `WindowsText`) implements Windows
   Hello via `IUserConsentVerifierInterop::RequestVerificationForWindowAsync`
   with a CredUI + `LogonUserW` account-password fallback — both genuine user
   verification, equivalent in status to Touch ID with password fallback.
   The fix widens the `cfg` gates in `biometric.rs` and
   `bridge.rs::approve_passkey` from `macos` to `any(macos, windows)`, so
   passkey approvals on Windows prompt Windows Hello and honestly report
   UV=1.
2. **Plumb `userVerification` end-to-end and decline when unsatisfiable.**
   `passkey.js` now sends the RP's requirement (get: `pk.userVerification`;
   create: `authenticatorSelection.userVerification`), `background.js` relays
   it, and the bridge answers `uv_unavailable` when the requirement is
   `"required"` on a platform where `biometric::available()` is false. The
   shim's existing `!resp.ok` path then falls back to the browser. The new
   field is `#[serde(default)]`, so an older extension keeps working.

Deliberate side effects on Windows (both match comments already in the code
claiming this behavior existed):

- Quick unlock is now genuinely gated by Windows Hello — `commands.rs:410-415`
  already called `biometric::authenticate` on non-macOS "as the gate", but it
  was a silent no-op.
- Master-password change re-auth (`commands.rs:513`) likewise becomes real.

### Verification

- `cargo test -p vault-desktop`: 31 passed, 0 failed (rebased onto upstream
  50d6dd7, which had independently repaired the test build for
  `exclude_credentials`; includes the new
  `uv_required_needs_a_verifying_platform` test).
- `cargo check -p vault-desktop --target x86_64-pc-windows-gnu`: the
  newly-enabled Windows `cfg` code (including the robius Windows Hello
  backend) compiles cleanly for a Windows target.
- On-machine check after rebuild: passkey sign-in on
  login.microsoftonline.com and accounts.google.com should now show a
  Windows Hello prompt (instead of the in-app Allow/Deny) and complete;
  github.com must keep working.

## Exact diff

Against upstream main at 50d6dd7 ("bridge: fix test build for
exclude_credentials + no-prompt regression test").

```diff
diff --git a/apps/desktop/src-tauri/Cargo.toml b/apps/desktop/src-tauri/Cargo.toml
index 9fb98b5..af65161 100644
--- a/apps/desktop/src-tauri/Cargo.toml
+++ b/apps/desktop/src-tauri/Cargo.toml
@@ -45,5 +45,5 @@ tempfile = "3"
 [lints.rust]
 unsafe_code = "forbid"
 
-[target.'cfg(target_os = "macos")'.dependencies]
+[target.'cfg(any(target_os = "macos", target_os = "windows"))'.dependencies]
 robius-authentication = "0.1"
diff --git a/apps/desktop/src-tauri/src/biometric.rs b/apps/desktop/src-tauri/src/biometric.rs
index fac6540..231d95a 100644
--- a/apps/desktop/src-tauri/src/biometric.rs
+++ b/apps/desktop/src-tauri/src/biometric.rs
@@ -1,4 +1,4 @@
-//! Biometric (Touch ID) gate for quick unlock.
+//! Biometric (Touch ID / Windows Hello) gate for quick unlock.
 //!
 //! This is a *presence* gate placed in front of the keychain-backed quick
 //! unlock: before the app uses the stored device key to unlock the vault, the
@@ -17,13 +17,13 @@
 //! its safe API, so the crate-wide `#![forbid(unsafe_code)]` still holds.
 
 /// Whether biometric authentication is wired on this platform.
-#[cfg(target_os = "macos")]
+#[cfg(any(target_os = "macos", target_os = "windows"))]
 pub fn available() -> bool {
     true
 }
 
 /// Whether biometric authentication is wired on this platform.
-#[cfg(not(target_os = "macos"))]
+#[cfg(not(any(target_os = "macos", target_os = "windows")))]
 pub fn available() -> bool {
     false
 }
@@ -31,10 +31,11 @@ pub fn available() -> bool {
 /// Prompt the device owner to authenticate. `Ok(())` means they succeeded;
 /// `Err(message)` means they cancelled, failed, or biometrics are unavailable.
 ///
-/// `reason` is shown to the user as "Arca is trying to <reason>".
+/// `reason` is shown to the user as "Arca is trying to <reason>" (macOS) or as
+/// the message of the Windows Hello / credential dialog (Windows).
 /// This call **blocks** until the user responds, so callers must not hold the
 /// app-state lock while invoking it.
-#[cfg(target_os = "macos")]
+#[cfg(any(target_os = "macos", target_os = "windows"))]
 pub fn authenticate(reason: &str) -> Result<(), String> {
     use robius_authentication::{
         AndroidText, BiometricStrength, Context, PolicyBuilder, Text, WindowsText,
@@ -42,16 +43,18 @@ pub fn authenticate(reason: &str) -> Result<(), String> {
 
     let policy = PolicyBuilder::new()
         .biometrics(Some(BiometricStrength::Strong))
-        // Allow the login password / Apple Watch as a fallback when a finger
-        // isn't recognised, so the user is never locked out of quick unlock.
+        // Allow the account password as a fallback when a finger/face isn't
+        // recognised, so the user is never locked out of quick unlock. On
+        // Windows this is the CredUI prompt validated against the current user;
+        // on macOS the login password (or Apple Watch).
         .password(true)
         .watch(true)
         .build()
         .ok_or_else(|| "Biometric authentication is not available on this device.".to_string())?;
 
     let text = Text {
-        // Only `apple` is shown on macOS; the other fields are required by the
-        // struct but unused here.
+        // Only the current platform's field is shown; the others are required
+        // by the struct but unused here.
         android: AndroidText {
             title: reason,
             subtitle: None,
@@ -62,14 +65,19 @@ pub fn authenticate(reason: &str) -> Result<(), String> {
             .unwrap_or_else(|| WindowsText::new_truncated("Arca", reason)),
     };
 
+    #[cfg(target_os = "macos")]
+    const PROVIDER: &str = "Touch ID";
+    #[cfg(target_os = "windows")]
+    const PROVIDER: &str = "Windows Hello";
+
     Context::new(())
         .blocking_authenticate(text, &policy)
-        .map_err(|e| format!("Touch ID was not confirmed ({e:?})."))
+        .map_err(|e| format!("{PROVIDER} was not confirmed ({e:?})."))
 }
 
 /// On platforms without a biometric provider wired up yet, this is a no-op so
 /// the existing (non-biometric) quick unlock keeps working unchanged.
-#[cfg(not(target_os = "macos"))]
+#[cfg(not(any(target_os = "macos", target_os = "windows")))]
 pub fn authenticate(_reason: &str) -> Result<(), String> {
     Ok(())
 }
diff --git a/apps/desktop/src-tauri/src/bridge.rs b/apps/desktop/src-tauri/src/bridge.rs
index 3ad6429..f07280b 100644
--- a/apps/desktop/src-tauri/src/bridge.rs
+++ b/apps/desktop/src-tauri/src/bridge.rs
@@ -81,6 +81,13 @@ enum Request {
         /// prompting - this is what makes sites stop re-asking.
         #[serde(default)]
         exclude_credentials: Vec<Vec<u8>>,
+        /// WebAuthn authenticatorSelection.userVerification ("required" |
+        /// "preferred" | "discouraged"; empty = unspecified). When "required"
+        /// and this platform cannot genuinely verify the user, we must refuse
+        /// so the page falls back to the browser instead of registering a
+        /// credential whose UV=0 attestation the RP will reject.
+        #[serde(default)]
+        user_verification: String,
     },
     /// Assert an existing passkey (navigator.credentials.get).
     PasskeyGet {
@@ -91,6 +98,9 @@ enum Request {
         /// Credential ids the RP will accept; empty means "any for this rp".
         #[serde(default)]
         allow_credentials: Vec<Vec<u8>>,
+        /// WebAuthn userVerification requirement; see `PasskeyCreate`.
+        #[serde(default)]
+        user_verification: String,
     },
     /// Ask whether a just-submitted login is worth offering to save.
     SaveProbe {
@@ -227,6 +237,17 @@ fn rp_id_matches_origin(rp_id: &str, origin: &str) -> bool {
     }
 }
 
+/// Whether we can honour the RP's userVerification requirement: "required"
+/// needs a platform that performs genuine user verification (Touch ID /
+/// Windows Hello). Answering a UV-required ceremony with UV=0 produces an
+/// assertion the RP rejects server-side (Microsoft and Google both require UV
+/// for passkey sign-in); refusing instead lets the page fall back to the
+/// browser's native handler. Takes availability as a parameter so the policy
+/// is unit-testable on every platform.
+fn uv_requirement_met(user_verification: &str, uv_available: bool) -> bool {
+    user_verification != "required" || uv_available
+}
+
 /// Find an active login matching (normalized host, lowercased username).
 /// Returns `(id, current_password)` for change detection.
 fn find_login(vault: &vault_core::Vault, host: &str, username: &str) -> Option<(Uuid, String)> {
@@ -393,6 +414,7 @@ fn handle_request(
             user_name,
             user_handle,
             exclude_credentials,
+            user_verification,
         } => {
             // Anti-phishing: the RP id must belong to the page's origin.
             if !rp_id_matches_origin(&rp_id, &origin) {
@@ -400,6 +422,11 @@ fn handle_request(
                     message: "origin_mismatch".into(),
                 };
             }
+            if !uv_requirement_met(&user_verification, crate::biometric::available()) {
+                return Response::Error {
+                    message: "uv_unavailable".into(),
+                };
+            }
             // Must be unlocked before we prompt the user.
             {
                 let st = match state.lock() {
@@ -526,12 +553,18 @@ fn handle_request(
             rp_id,
             client_data_hash,
             allow_credentials,
+            user_verification,
         } => {
             if !rp_id_matches_origin(&rp_id, &origin) {
                 return Response::Error {
                     message: "origin_mismatch".into(),
                 };
             }
+            if !uv_requirement_met(&user_verification, crate::biometric::available()) {
+                return Response::Error {
+                    message: "uv_unavailable".into(),
+                };
+            }
             // Resolve the passkey under the lock; release it before the prompt.
             let credential_id;
             let user_handle;
@@ -767,10 +800,11 @@ fn approve_passkey(
     app: Option<&AppHandle>,
     consent: &mut dyn FnMut(&ConsentContext) -> bool,
 ) -> Option<bool> {
-    // In production on macOS, gate with Touch ID — a genuine user verification,
-    // so we may honestly set UV. (`app` is `None` in unit tests, which take the
-    // injected consent path below instead of prompting.)
-    #[cfg(target_os = "macos")]
+    // In production on macOS/Windows, gate with Touch ID / Windows Hello — a
+    // genuine user verification, so we may honestly set UV. (`app` is `None` in
+    // unit tests, which take the injected consent path below instead of
+    // prompting.)
+    #[cfg(any(target_os = "macos", target_os = "windows"))]
     if app.is_some() {
         return match crate::biometric::authenticate(&format!("approve a passkey for {rp_id}")) {
             Ok(()) => Some(true),
@@ -1190,6 +1224,7 @@ mod tests {
                     user_name: "frank".into(),
                     user_handle: vec![9, 9, 9],
                     exclude_credentials: vec![],
+                    user_verification: String::new(),
                 },
                 &state,
                 "t",
@@ -1225,6 +1260,7 @@ mod tests {
                 rp_id: "github.com".into(),
                 client_data_hash: client_data_hash.clone(),
                 allow_credentials: vec![cred_id.clone()],
+                user_verification: String::new(),
             },
             &state,
             "t",
@@ -1267,6 +1303,7 @@ mod tests {
                     rp_id: "github.com".into(),
                     client_data_hash: client_data_hash.clone(),
                     allow_credentials: vec![],
+                    user_verification: String::new(),
                 },
                 &state, "t", &mut authed, None, &mut allow(),
             ),
@@ -1281,6 +1318,7 @@ mod tests {
                     rp_id: "github.com".into(),
                     client_data_hash: client_data_hash.clone(),
                     allow_credentials: vec![vec![1, 2, 3, 4]],
+                    user_verification: String::new(),
                 },
                 &state, "t", &mut authed, None, &mut allow(),
             ),
@@ -1295,6 +1333,7 @@ mod tests {
                     rp_id: "github.com".into(),
                     client_data_hash,
                     allow_credentials: vec![cred_id],
+                    user_verification: String::new(),
                 },
                 &state, "t", &mut authed, None, &mut |_: &ConsentContext| false,
             ),
@@ -1326,6 +1365,21 @@ mod tests {
         ));
     }
 
+    #[test]
+    fn uv_required_needs_a_verifying_platform() {
+        // "required" (Microsoft/Google passkey sign-in) must be refused when
+        // the platform cannot genuinely verify the user — a UV=0 assertion
+        // would just be rejected by the RP after a pointless approval prompt.
+        assert!(!uv_requirement_met("required", false));
+        assert!(uv_requirement_met("required", true));
+        // "preferred"/"discouraged"/unspecified proceed either way; UV is then
+        // reported honestly via the authenticator-data flags.
+        for uv in ["preferred", "discouraged", ""] {
+            assert!(uv_requirement_met(uv, false));
+            assert!(uv_requirement_met(uv, true));
+        }
+    }
+
     #[test]
     fn save_probe_and_login_add_update_and_dedupe() {
         let dir = TempDir::new().unwrap();
@@ -1446,6 +1500,7 @@ mod tests {
                 user_name: "frank".into(),
                 user_handle: vec![1, 2, 3],
                 exclude_credentials: vec![],
+                user_verification: String::new(),
             },
             &state,
             "t",
@@ -1469,6 +1524,7 @@ mod tests {
                 user_name: "frank".into(),
                 user_handle: vec![1, 2, 3],
                 exclude_credentials: vec![credential_id],
+                user_verification: String::new(),
             },
             &state,
             "t",
diff --git a/extension/chromium/background.js b/extension/chromium/background.js
index 6ff65cb..adc5de9 100644
--- a/extension/chromium/background.js
+++ b/extension/chromium/background.js
@@ -102,6 +102,7 @@ api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
         user_name: msg.userName,
         user_handle: msg.userHandle,
         exclude_credentials: msg.excludeCredentials,
+        user_verification: msg.userVerification,
       }).then(sendResponse);
       return true;
 
@@ -112,6 +113,7 @@ api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
         rp_id: msg.rpId,
         client_data_hash: msg.clientDataHash,
         allow_credentials: msg.allowCredentials,
+        user_verification: msg.userVerification,
       }).then(sendResponse);
       return true;
 
diff --git a/extension/chromium/passkey.js b/extension/chromium/passkey.js
index e5a86d4..f73db31 100644
--- a/extension/chromium/passkey.js
+++ b/extension/chromium/passkey.js
@@ -106,6 +106,10 @@
         userName: (pk.user && pk.user.name) || "",
         userHandle: toArr(pk.user && pk.user.id),
         excludeCredentials: (pk.excludeCredentials || []).map((c) => toArr(c.id)),
+        // The app refuses ("uv_unavailable" -> browser fallback) when the RP
+        // requires user verification it cannot genuinely perform.
+        userVerification:
+          (pk.authenticatorSelection && pk.authenticatorSelection.userVerification) || "",
       });
       if (!resp.ok) {
         // Spec-correct duplicate handling: the RP listed credentials we already
@@ -159,6 +163,7 @@
         rpId: pk.rpId || window.location.hostname,
         clientDataHash: toArr(clientDataHash),
         allowCredentials: (pk.allowCredentials || []).map((c) => toArr(c.id)),
+        userVerification: pk.userVerification || "",
       });
       if (!resp.ok) return realGet(options);
 
```

## What remains (for the Mac side / upstream)

- **UI branding**: with `biometric::available()` now true on Windows, the
  frontend's `TouchIdBanner` (`App.tsx:257`) and any "Touch ID" copy show on
  Windows with Apple wording. Functional but mislabeled — worth a
  platform-aware string ("Windows Hello").
- **Quick-unlock UX decision**: Windows quick unlock now prompts Windows
  Hello every time (previously silent). This matches the documented security
  model, but if it's unwanted, split the passkey gate from the unlock gate
  rather than reverting `available()`.
- **Hello-not-enrolled machines**: robius falls back to a Windows
  account-password CredUI dialog. UV=1 for a password check is spec-valid
  ("something you know"), but test the UX on a Hello-less VM.
- **Sign counter**: assertions always report `sign_count = 0`
  (`passkey.rs::assert` passes 0). Fine for MS/Google today, but stricter
  RPs may flag clone risk; consider maintaining the stored `sign_count` or
  documenting the choice (0 = counter unsupported is legal).
- **Linux UV**: `available()` is still false on Linux, so required-UV sites
  (MS/Google) now cleanly defer to the browser there. Wiring polkit or a
  master-password re-entry as UV would light passkeys up on Linux too.
- The `native-bridge.json` token file is written with `0600` only on Unix
  (`write_info`); on Windows it inherits default ACLs. Per-user profile ACLs
  cover it in practice, but an explicit ACL would match the threat model.
