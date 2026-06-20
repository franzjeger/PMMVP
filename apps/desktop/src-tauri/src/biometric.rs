//! Biometric (Touch ID) gate for quick unlock.
//!
//! This is a *presence* gate placed in front of the keychain-backed quick
//! unlock: before the app uses the stored device key to unlock the vault, the
//! device owner must authenticate with Touch ID (falling back to the login
//! password). It does **not** change how the device key is stored.
//!
//! Security note: the device key itself stays protected by the OS keychain
//! (see `vault-store`), not by this prompt. A process running as the same user
//! (threat T9 in `THREAT_MODEL.md`, explicitly out of scope) could still read
//! the keychain entry directly without passing this prompt. OS-enforced
//! biometric gating of the key itself (a `SecAccessControl`-protected keychain
//! item that the OS will not release without Touch ID) is the stronger,
//! Apple-equivalent design and is tracked as a hardening follow-up.
//!
//! The unsafe FFI lives inside `robius-authentication`; this module uses only
//! its safe API, so the crate-wide `#![forbid(unsafe_code)]` still holds.

/// Whether biometric authentication is wired on this platform.
#[cfg(target_os = "macos")]
pub fn available() -> bool {
    true
}

/// Whether biometric authentication is wired on this platform.
#[cfg(not(target_os = "macos"))]
pub fn available() -> bool {
    false
}

/// Prompt the device owner to authenticate. `Ok(())` means they succeeded;
/// `Err(message)` means they cancelled, failed, or biometrics are unavailable.
///
/// `reason` is shown to the user as "SYBR Passwords is trying to <reason>".
/// This call **blocks** until the user responds, so callers must not hold the
/// app-state lock while invoking it.
#[cfg(target_os = "macos")]
pub fn authenticate(reason: &str) -> Result<(), String> {
    use robius_authentication::{
        AndroidText, BiometricStrength, Context, PolicyBuilder, Text, WindowsText,
    };

    let policy = PolicyBuilder::new()
        .biometrics(Some(BiometricStrength::Strong))
        // Allow the login password / Apple Watch as a fallback when a finger
        // isn't recognised, so the user is never locked out of quick unlock.
        .password(true)
        .watch(true)
        .build()
        .ok_or_else(|| "Biometric authentication is not available on this device.".to_string())?;

    let text = Text {
        // Only `apple` is shown on macOS; the other fields are required by the
        // struct but unused here.
        android: AndroidText {
            title: reason,
            subtitle: None,
            description: None,
        },
        apple: reason,
        windows: WindowsText::new("SYBR Passwords", reason)
            .unwrap_or_else(|| WindowsText::new_truncated("SYBR Passwords", reason)),
    };

    Context::new(())
        .blocking_authenticate(text, &policy)
        .map_err(|e| format!("Touch ID was not confirmed ({e:?})."))
}

/// On platforms without a biometric provider wired up yet, this is a no-op so
/// the existing (non-biometric) quick unlock keeps working unchanged.
#[cfg(not(target_os = "macos"))]
pub fn authenticate(_reason: &str) -> Result<(), String> {
    Ok(())
}
