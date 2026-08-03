//! Mirror Arca's device key into the keychain group the macOS AutoFill
//! extension reads.
//!
//! The app's own device key lives as a plain item in the file-based login
//! keychain, for reasons `vault-store`'s keychain module explains at length. A
//! sandboxed extension cannot read that keychain, so the same key is also
//! written to the data-protection keychain under the shared access group.
//!
//! Two copies of one secret, with one rule: this copy is the extension's
//! problem alone. Every call here returns a status the caller is expected to
//! log and continue past, because a broken credential provider must never stop
//! the app from unlocking.
//!
//! The Objective-C shim is in `src/sharedkey.m`.

#![cfg_attr(not(target_os = "macos"), allow(unused))]

use std::fmt;

/// What happened to the mirrored key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mirrored {
    /// Written; the extension can open the vault after a biometric.
    Ok,
    /// The keychain refused, with this `OSStatus`. AutoFill will fail with
    /// `noDeviceKey`; nothing else is affected.
    Failed(i32),
    /// Not macOS — there is no shared keychain group to mirror into.
    NotApplicable,
}

impl fmt::Display for Mirrored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mirrored::Ok => write!(f, "device key shared with AutoFill"),
            // -34018 is the one worth recognising on sight: it means the
            // process has no keychain-access-group entitlement, i.e. it was
            // signed without the profile rather than anything being wrong with
            // the key.
            Mirrored::Failed(-34018) => {
                write!(f, "no keychain access group (app signed without the profile)")
            }
            Mirrored::Failed(status) => write!(f, "keychain refused the device key ({status})"),
            Mirrored::NotApplicable => write!(f, "no shared keychain on this platform"),
        }
    }
}

/// Write `key` into the shared group, replacing any previous copy.
///
/// `key` must be the RAW device key. The extension hands these bytes straight
/// to `vault_ffi_vault_open_device`; the base64 the login-keychain copy uses
/// would decrypt nothing.
#[cfg(target_os = "macos")]
pub fn store(key: &[u8]) -> Mirrored {
    extern "C" {
        fn arca_sharedkey_store(key: *const u8, len: std::os::raw::c_ulong) -> i32;
    }
    // SAFETY: `key` is a valid slice that outlives the call; the callee only
    // reads `len` bytes from it and returns an OSStatus.
    match unsafe { arca_sharedkey_store(key.as_ptr(), key.len() as std::os::raw::c_ulong) } {
        0 => Mirrored::Ok,
        status => Mirrored::Failed(status),
    }
}

/// Remove the shared copy. Missing is success.
#[cfg(target_os = "macos")]
pub fn clear() -> Mirrored {
    extern "C" {
        fn arca_sharedkey_clear() -> i32;
    }
    // SAFETY: no arguments, no borrowed state; returns an OSStatus.
    match unsafe { arca_sharedkey_clear() } {
        0 => Mirrored::Ok,
        status => Mirrored::Failed(status),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn store(_key: &[u8]) -> Mirrored {
    Mirrored::NotApplicable
}

#[cfg(not(target_os = "macos"))]
pub fn clear() -> Mirrored {
    Mirrored::NotApplicable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entitlement_failure_is_named_rather_than_numbered() {
        // -34018 sends people looking for a corrupt keychain when the actual
        // cause is a build signed without the provisioning profile. It cost an
        // evening once already; the message says so now.
        assert!(Mirrored::Failed(-34018).to_string().contains("profile"));
        assert!(Mirrored::Failed(-25300).to_string().contains("-25300"));
    }
}
