//! Versioned vault header.
//!
//! The header is stored in cleartext (it contains no secrets — only public
//! KDF parameters and *wrapped* keys) and is what lets the on-disk format
//! evolve over time. Bump [`VaultHeader::FORMAT_VERSION`] and handle older
//! values in [`crate::vault::Vault::from_bytes`] when the layout changes.

use serde::{Deserialize, Serialize};

use crate::crypto::{self, AeadBlob};
use crate::error::{Error, Result};

/// KDF algorithm identifier. Stored numerically so the enum can grow without
/// breaking serialized vaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KdfAlgorithm {
    Argon2id = 1,
    // TODO(phase-2+): add e.g. scrypt/balloon if ever needed; never remove a
    // variant, only deprecate, so old vaults stay readable.
}

/// Public, per-vault key-derivation parameters. Safe to store in cleartext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    /// Argon2id memory cost, in KiB.
    pub m_cost_kib: u32,
    /// Argon2id iteration (time) cost.
    pub t_cost: u32,
    /// Argon2id parallelism (lanes).
    pub p_cost: u32,
    /// Per-vault random salt.
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// Default Argon2id cost parameters per the project spec:
    /// m = 64 MiB, t = 3, p = 4.
    pub const DEFAULT_M_COST_KIB: u32 = 64 * 1024;
    pub const DEFAULT_T_COST: u32 = 3;
    pub const DEFAULT_P_COST: u32 = 4;
    pub const SALT_LEN: usize = 32;

    /// Build default parameters with a fresh random salt.
    pub fn new_default() -> Result<Self> {
        let mut salt = vec![0u8; Self::SALT_LEN];
        crypto::fill_random(&mut salt)?;
        Ok(Self {
            algorithm: KdfAlgorithm::Argon2id,
            m_cost_kib: Self::DEFAULT_M_COST_KIB,
            t_cost: Self::DEFAULT_T_COST,
            p_cost: Self::DEFAULT_P_COST,
            salt,
        })
    }

    /// Stable byte encoding of the parameters, used as AEAD AAD when wrapping
    /// the vault key. Binding the wrap to these bytes means an attacker cannot
    /// substitute weaker KDF parameters and have the wrap still authenticate.
    pub(crate) fn aad(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(13 + self.salt.len());
        v.push(self.algorithm as u8);
        v.extend_from_slice(&self.m_cost_kib.to_le_bytes());
        v.extend_from_slice(&self.t_cost.to_le_bytes());
        v.extend_from_slice(&self.p_cost.to_le_bytes());
        v.extend_from_slice(&self.salt);
        v
    }
}

/// The cleartext vault header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultHeader {
    /// On-disk format version; see [`VaultHeader::FORMAT_VERSION`].
    pub format_version: u16,
    /// KDF parameters used to derive the master key.
    pub kdf: KdfParams,
    /// The vault key, wrapped under the master-password-derived key.
    pub master_wrapped_vault_key: AeadBlob,
    /// The vault key, wrapped under an OS-keychain-held device key, enabling
    /// quick/biometric unlock. `None` until the user opts in. The device key
    /// itself lives only in the OS keychain (see `vault-store`).
    pub device_wrapped_vault_key: Option<AeadBlob>,
}

impl VaultHeader {
    /// Current on-disk format version understood by this build.
    ///
    /// v1 (never released with real data): item payloads encoded with bincode.
    /// v2: item payloads encoded with self-describing, name-tagged CBOR so the
    ///     `VaultItem` schema can evolve safely.
    pub const FORMAT_VERSION: u16 = 2;

    /// Validate that this build can read the header.
    pub(crate) fn check_supported(&self) -> Result<()> {
        if self.format_version == 0 || self.format_version > Self::FORMAT_VERSION {
            return Err(Error::Format);
        }
        Ok(())
    }
}
