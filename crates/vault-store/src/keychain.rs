//! OS keychain integration for quick/biometric unlock.
//!
//! We store a random 256-bit **device key** in the platform secret store
//! (macOS Keychain, Windows Credential Manager, Linux Secret Service). The
//! device key wraps a copy of the vault key inside the vault header, so the
//! app can unlock without re-deriving from the master password.
//!
//! On macOS the key is stored in a **shared keychain access group** (so the
//! sandboxed AutoFill extension can read the same key) behind a **biometric
//! access control** (Touch ID / passcode is enforced by the keychain itself,
//! not just by the app). The access group is not named in code: the app's
//! `keychain-access-groups` entitlement lists exactly one group, so items land
//! there by default and both the app and the extension can reach them.
//!
//! SECURITY: the master password is **never** stored here. The device key is
//! the OS-protected unlock token; deleting the keychain entry disables quick
//! unlock entirely.

use vault_core::SymmetricKey;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Base64 (no padding) of a 32-byte key is 43 chars; sanity bound on reads.
const ENCODED_KEY_LEN: usize = 43;

/// Decode a base64 device-key string into a [`SymmetricKey`].
fn decode_key(encoded: &str) -> Result<SymmetricKey> {
    if encoded.len() != ENCODED_KEY_LEN {
        return Err(Error::Keychain);
    }
    let raw = Zeroizing::new(
        data_encoding::BASE64_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|_| Error::Keychain)?,
    );
    let arr: [u8; vault_core::KEY_LEN] = raw.as_slice().try_into().map_err(|_| Error::Keychain)?;
    Ok(SymmetricKey::from_bytes(arr))
}

// ---- macOS / iOS: security-framework, shared group + biometric AC ----------
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod backend {
    use super::*;
    use security_framework::item::{ItemClass, ItemSearchOptions};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};

    /// `errSecItemNotFound` — a missing item, not a failure.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    pub fn set(service: &str, account: &str, key: &SymmetricKey) -> Result<()> {
        // Replace any existing entry (add rejects a duplicate).
        let _ = delete(service, account);
        let encoded = Zeroizing::new(data_encoding::BASE64_NOPAD.encode(key.as_bytes()));
        let mut opts = PasswordOptions::new_generic_password(service, account);
        // Keychain-enforced Touch ID / passcode on every read of the key.
        opts.set_access_control_options(AccessControlOptions::USER_PRESENCE);
        // No access group named: the single entitlement group is the default,
        // shared with the extension.
        set_generic_password_options(encoded.as_bytes(), opts).map_err(|_| Error::Keychain)
    }

    pub fn get(service: &str, account: &str) -> Result<Option<SymmetricKey>> {
        // Reading the data triggers the biometric prompt (the AC above).
        match get_generic_password(service, account) {
            Ok(bytes) => {
                let encoded =
                    Zeroizing::new(String::from_utf8(bytes).map_err(|_| Error::Keychain)?);
                Ok(Some(decode_key(&encoded)?))
            }
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(_) => Err(Error::Keychain),
        }
    }

    pub fn delete(service: &str, account: &str) -> Result<()> {
        match delete_generic_password(service, account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(_) => Err(Error::Keychain),
        }
    }

    /// Presence check that does NOT read the data, so it never triggers the
    /// biometric prompt (used for "is quick-unlock available?").
    pub fn exists(service: &str, account: &str) -> bool {
        ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(service)
            .account(account)
            .search()
            .map(|r| !r.is_empty())
            .unwrap_or(false)
    }
}

// ---- Windows / Linux: keyring native backends -----------------------------
#[cfg(any(target_os = "windows", target_os = "linux"))]
mod backend {
    use super::*;

    fn entry(service: &str, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(service, account).map_err(|_| Error::Keychain)
    }

    pub fn set(service: &str, account: &str, key: &SymmetricKey) -> Result<()> {
        let encoded = Zeroizing::new(data_encoding::BASE64_NOPAD.encode(key.as_bytes()));
        entry(service, account)?
            .set_password(&encoded)
            .map_err(|_| Error::Keychain)
    }

    pub fn get(service: &str, account: &str) -> Result<Option<SymmetricKey>> {
        match entry(service, account)?.get_password() {
            Ok(encoded) => {
                let encoded = Zeroizing::new(encoded);
                Ok(Some(decode_key(&encoded)?))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(Error::Keychain),
        }
    }

    pub fn delete(service: &str, account: &str) -> Result<()> {
        match entry(service, account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(Error::Keychain),
        }
    }

    pub fn exists(service: &str, account: &str) -> bool {
        matches!(get(service, account), Ok(Some(_)))
    }
}

// ---- Fallback: quick-unlock unavailable -----------------------------------
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "windows",
    target_os = "linux"
)))]
mod backend {
    use super::*;

    pub fn set(_: &str, _: &str, _: &SymmetricKey) -> Result<()> {
        Err(Error::KeychainUnsupported)
    }
    pub fn get(_: &str, _: &str) -> Result<Option<SymmetricKey>> {
        Ok(None)
    }
    pub fn delete(_: &str, _: &str) -> Result<()> {
        Ok(())
    }
    pub fn exists(_: &str, _: &str) -> bool {
        false
    }
}

pub(crate) use backend::{delete, exists, get, set};
