//! # vault-core
//!
//! The security-critical, **I/O-free** core of the SYBR password manager.
//!
//! It composes audited [RustCrypto](https://github.com/RustCrypto) crates — it
//! does **not** implement any cryptographic primitive itself:
//!
//! * **KDF** — Argon2id (`argon2`) derives a 256-bit master key from the master
//!   password and a per-vault random salt; cost parameters live in a versioned
//!   header so they can be raised over time.
//! * **Key hierarchy** — a random 256-bit *vault key* is wrapped with the
//!   master key using XChaCha20-Poly1305 (`chacha20poly1305`). Each item is
//!   then sealed individually with the vault key, with its UUID bound as AAD.
//! * **Hygiene** — all key material and plaintext secrets are zeroized on drop
//!   (`zeroize`); secret comparisons are constant-time (`subtle`); randomness
//!   comes from the OS CSPRNG (`getrandom`).
//!
//! This crate performs no file, network, or clock access: timestamps are
//! passed in by the caller. That keeps it deterministic and fully unit-tested.
//!
//! ## Security status
//!
//! This is Phase-1 foundation code. It has **not** been independently audited.
//! See `SECURITY.md` at the workspace root before any real-world use.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod header;
pub mod item;
pub mod password;
pub mod secret;
pub mod security;
pub mod totp;
pub mod vault;

pub use error::{Error, Result};
pub use header::{KdfAlgorithm, KdfParams, VaultHeader};
pub use item::{Item, ItemKind, ItemSummary, VaultItem};
pub use password::{generate_password, PasswordOptions};
pub use secret::{SymmetricKey, KEY_LEN};
pub use security::{audit, estimate_strength, ItemSecurity, PasswordStrength, SecurityIssue};
pub use totp::{current_totp, TotpCode};
pub use vault::Vault;

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap KDF params so tests don't spend 64 MiB / 3 passes each.
    /// (Real vaults use [`KdfParams::new_default`].)
    fn cheap_params() -> KdfParams {
        KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![7u8; KdfParams::SALT_LEN],
        }
    }

    fn sample_login() -> VaultItem {
        VaultItem::Login {
            title: "GitHub".into(),
            username: "frank-lia".into(),
            password: "correct horse battery staple".into(),
            url: "https://github.com".into(),
            totp_secret: Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
            notes: "Created in Prague".into(),
        }
    }

    // --- crypto-level guarantees -----------------------------------------

    #[test]
    fn kdf_is_deterministic_for_same_inputs() {
        let p = cheap_params();
        let a = crypto::derive_master_key("hunter2", &p).unwrap();
        let b = crypto::derive_master_key("hunter2", &p).unwrap();
        assert_eq!(a, b, "same password + params must derive the same key");
    }

    #[test]
    fn kdf_differs_with_salt_and_password() {
        let mut p1 = cheap_params();
        let key_pw1 = crypto::derive_master_key("pw-one", &p1).unwrap();
        let key_pw2 = crypto::derive_master_key("pw-two", &p1).unwrap();
        assert_ne!(
            key_pw1, key_pw2,
            "different password must derive different key"
        );

        p1.salt = vec![9u8; KdfParams::SALT_LEN];
        let key_other_salt = crypto::derive_master_key("pw-one", &p1).unwrap();
        assert_ne!(
            key_pw1, key_other_salt,
            "different salt must derive different key"
        );
    }

    #[test]
    fn aead_round_trip_and_tamper_detection() {
        let key = SymmetricKey::generate().unwrap();
        let aad = b"item-id";
        let blob = crypto::seal(&key, b"top secret", aad).unwrap();

        // Round-trips with the right key + aad.
        assert_eq!(&*crypto::open(&key, &blob, aad).unwrap(), b"top secret");

        // Tampering with the ciphertext is detected.
        let mut tampered = blob.clone();
        tampered.ciphertext[0] ^= 0x01;
        assert!(matches!(
            crypto::open(&key, &tampered, aad),
            Err(Error::Decryption)
        ));

        // Wrong AAD is detected.
        assert!(matches!(
            crypto::open(&key, &blob, b"other-id"),
            Err(Error::Decryption)
        ));

        // Wrong key is detected.
        let other = SymmetricKey::generate().unwrap();
        assert!(matches!(
            crypto::open(&other, &blob, aad),
            Err(Error::Decryption)
        ));
    }

    // --- vault behaviour --------------------------------------------------

    #[test]
    fn create_unlock_round_trip_and_wrong_password_fails() {
        let mut vault = Vault::create("master-pw", cheap_params()).unwrap();
        let item = Item::new(sample_login(), 1_000);
        let id = item.id;
        vault.upsert_item(item).unwrap();

        // Persist, reload, unlock.
        let bytes = vault.to_bytes().unwrap();
        let mut reloaded = Vault::from_bytes(&bytes).unwrap();
        assert!(!reloaded.is_unlocked());

        // Wrong password fails (and stays locked).
        assert!(matches!(
            reloaded.unlock("wrong-pw"),
            Err(Error::Decryption)
        ));
        assert!(!reloaded.is_unlocked());

        // Right password unlocks and the item survives the round trip.
        reloaded.unlock("master-pw").unwrap();
        let got = reloaded.get_item(id).unwrap();
        match &got.data {
            VaultItem::Login {
                title, password, ..
            } => {
                assert_eq!(title, "GitHub");
                assert_eq!(password, "correct horse battery staple");
            }
            _ => panic!("expected a login"),
        }
    }

    #[test]
    fn locked_vault_rejects_item_operations() {
        let bytes = Vault::create("pw", cheap_params())
            .unwrap()
            .to_bytes()
            .unwrap();
        let locked = Vault::from_bytes(&bytes).unwrap();
        assert!(matches!(locked.list_items(false), Err(Error::Locked)));
    }

    #[test]
    fn tampering_with_item_ciphertext_is_detected_on_unlock() {
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        vault.upsert_item(Item::new(sample_login(), 1)).unwrap();
        let mut bytes = vault.to_bytes().unwrap();

        // Flip a byte well past the header/magic, inside the item ciphertext.
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;

        let mut reloaded = Vault::from_bytes(&bytes).unwrap();
        assert!(matches!(reloaded.unlock("pw"), Err(Error::Decryption)));
    }

    #[test]
    fn soft_delete_restore_and_purge() {
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        let item = Item::new(sample_login(), 10);
        let id = item.id;
        vault.upsert_item(item).unwrap();

        vault.delete_item(id, 20).unwrap();
        assert_eq!(vault.list_items(false).unwrap().len(), 0);
        assert_eq!(vault.list_items(true).unwrap().len(), 1);

        vault.restore_item(id, 30).unwrap();
        assert_eq!(vault.list_items(false).unwrap().len(), 1);

        vault.delete_item(id, 40).unwrap();
        vault.purge_item(id).unwrap();
        assert_eq!(vault.list_items(true).unwrap().len(), 0);
        assert!(matches!(vault.purge_item(id), Err(Error::NotFound)));
    }

    #[test]
    fn device_quick_unlock_round_trip() {
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        vault.upsert_item(Item::new(sample_login(), 1)).unwrap();

        let device_key = SymmetricKey::generate().unwrap();
        vault.enable_device_unlock(&device_key).unwrap();
        assert!(vault.has_device_unlock());

        let bytes = vault.to_bytes().unwrap();
        let mut reloaded = Vault::from_bytes(&bytes).unwrap();

        // Wrong device key fails.
        let wrong = SymmetricKey::generate().unwrap();
        assert!(matches!(
            reloaded.unlock_with_device_key(&wrong),
            Err(Error::Decryption)
        ));

        // Correct device key unlocks without the master password.
        reloaded.unlock_with_device_key(&device_key).unwrap();
        assert!(reloaded.is_unlocked());
        assert_eq!(reloaded.list_items(false).unwrap().len(), 1);
    }

    #[test]
    fn change_master_password_re_keys() {
        let mut vault = Vault::create("old-pw", cheap_params()).unwrap();
        vault.upsert_item(Item::new(sample_login(), 1)).unwrap();
        vault.change_master_password("new-pw").unwrap();

        let bytes = vault.to_bytes().unwrap();
        let mut reloaded = Vault::from_bytes(&bytes).unwrap();
        assert!(matches!(reloaded.unlock("old-pw"), Err(Error::Decryption)));
        reloaded.unlock("new-pw").unwrap();
        assert!(reloaded.is_unlocked());
    }

    #[test]
    fn all_item_variants_round_trip_through_disk_at_format_v2() {
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        assert_eq!(vault.header().format_version, 2);

        let login = Item::new(sample_login(), 1);
        let note = Item::new(
            VaultItem::SecureNote {
                title: "Recovery codes".into(),
            },
            2,
        );
        let passkey = Item::new(
            VaultItem::Passkey {
                title: "demo.example".into(),
            },
            3,
        );
        let (lid, nid, pid) = (login.id, note.id, passkey.id);
        vault.upsert_item(login).unwrap();
        vault.upsert_item(note).unwrap();
        vault.upsert_item(passkey).unwrap();

        // Persist with the CBOR item payload, reload, unlock, and confirm every
        // variant decodes back to itself.
        let bytes = vault.to_bytes().unwrap();
        let mut reloaded = Vault::from_bytes(&bytes).unwrap();
        assert_eq!(reloaded.header().format_version, 2);
        reloaded.unlock("pw").unwrap();

        assert!(matches!(
            reloaded.get_item(lid).unwrap().data,
            VaultItem::Login { .. }
        ));
        assert!(matches!(
            reloaded.get_item(nid).unwrap().data,
            VaultItem::SecureNote { .. }
        ));
        assert!(matches!(
            reloaded.get_item(pid).unwrap().data,
            VaultItem::Passkey { .. }
        ));
    }

    #[test]
    fn rejects_foreign_or_truncated_files() {
        assert!(matches!(
            Vault::from_bytes(b"not a vault"),
            Err(Error::Format)
        ));
        assert!(matches!(Vault::from_bytes(b""), Err(Error::Format)));
    }
}
