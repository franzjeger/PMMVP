//! OS keychain integration for quick/biometric unlock.
//!
//! We store a random 256-bit **device key** in the platform secret store
//! (macOS Keychain, Windows Credential Manager, Linux Secret Service). The
//! device key wraps a copy of the vault key inside the vault header, so the
//! app can unlock without re-deriving from the master password.
//!
//! SECURITY: the master password is **never** stored here. The device key is
//! the OS-protected unlock token; deleting the keychain entry disables quick
//! unlock entirely.

use vault_core::SymmetricKey;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Base64 (no padding) of a 32-byte key is 43 chars; sanity bound on reads.
const ENCODED_KEY_LEN: usize = 43;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "windows",
    target_os = "linux"
))]
mod backend {
    use super::*;

    fn entry(service: &str, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(service, account).map_err(|_| Error::Keychain)
    }

    /// Persist the device key (base64-encoded) under (service, account).
    pub fn set(service: &str, account: &str, key: &SymmetricKey) -> Result<()> {
        let encoded = Zeroizing::new(data_encoding::BASE64_NOPAD.encode(key.as_bytes()));
        entry(service, account)?
            .set_password(&encoded)
            .map_err(|_| Error::Keychain)
    }

    /// Fetch and decode the device key, if one is stored.
    pub fn get(service: &str, account: &str) -> Result<Option<SymmetricKey>> {
        match entry(service, account)?.get_password() {
            Ok(encoded) => {
                let encoded = Zeroizing::new(encoded);
                if encoded.len() != ENCODED_KEY_LEN {
                    return Err(Error::Keychain);
                }
                let bytes = Zeroizing::new(
                    data_encoding::BASE64_NOPAD
                        .decode(encoded.as_bytes())
                        .map_err(|_| Error::Keychain)?,
                );
                let arr: [u8; vault_core::KEY_LEN] =
                    bytes.as_slice().try_into().map_err(|_| Error::Keychain)?;
                Ok(Some(SymmetricKey::from_bytes(arr)))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(Error::Keychain),
        }
    }

    /// Delete the stored device key. Missing entry is treated as success.
    pub fn delete(service: &str, account: &str) -> Result<()> {
        match entry(service, account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(Error::Keychain),
        }
    }
}

// Fallback for platforms without a supported secret store. Quick-unlock is
// simply unavailable; master-password unlock still works.
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
}

pub(crate) use backend::{delete, get, set};
