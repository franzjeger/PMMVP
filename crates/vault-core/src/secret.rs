//! Secret key material wrappers.
//!
//! These newtypes zeroize their bytes on drop and refuse to print their
//! contents via `Debug`. Equality, where needed, is constant-time.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Length of every symmetric key used in the crate (256-bit).
pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key. The bytes are zeroized when the value is dropped.
///
/// There is intentionally no `Serialize`/`Display`/non-redacting `Debug`
/// implementation: a raw key must never be persisted or logged. Keys are only
/// ever stored *wrapped* (see [`crate::header::WrappedKey`]).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; KEY_LEN]);

impl SymmetricKey {
    /// Wrap raw key bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh random key from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
        Ok(Self(bytes))
    }

    /// Borrow the raw bytes. Callers must not copy these into long-lived,
    /// non-zeroizing buffers.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never reveal key material.
        f.write_str("SymmetricKey(<redacted>)")
    }
}

impl ConstantTimeEq for SymmetricKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SymmetricKey {
    /// Constant-time equality so callers cannot accidentally introduce a
    /// timing side-channel by comparing keys with `==`.
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SymmetricKey {}
