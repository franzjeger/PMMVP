//! The [`Vault`]: a locked/unlocked state machine over an encrypted item set.
//!
//! On-disk layout produced by [`Vault::to_bytes`]:
//! ```text
//! "SYBRVLT2"            (8-byte magic + container version; V1 still readable)
//! bincode(VaultBody {   (cleartext header + per-item ciphertext)
//!     header,
//!     items: [ { id, AeadBlob }, ... ],
//! })
//! ```
//! The header is cleartext (public KDF params + wrapped keys); every item is
//! sealed individually with the vault key, with the item id bound as AAD.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, AeadBlob};
use crate::error::{Error, Result};
use crate::header::{KdfParams, VaultHeader};
use crate::item::{Item, ItemSummary};
use crate::secret::SymmetricKey;

/// Container magics. V1 framed the v2 header (no rewrap epoch); V2 frames the
/// current header. Both are readable; writes always use the current magic.
/// (The outer bincode framing is positional, so a header field addition needs
/// its own container magic rather than a serde default.)
const MAGIC_V1: &[u8; 8] = b"SYBRVLT1";
const MAGIC: &[u8; 8] = b"SYBRVLT2";

/// Fixed AAD context for the device-key (quick-unlock) wrap.
const DEVICE_UNLOCK_AAD: &[u8] = b"sybr-vault/device-unlock/v1";

/// A single encrypted item as stored on disk: cleartext id + sealed payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptedItem {
    id: Uuid,
    blob: AeadBlob,
}

/// The serialized body following the magic bytes.
#[derive(Serialize, Deserialize)]
struct VaultBody {
    header: VaultHeader,
    items: Vec<EncryptedItem>,
}

/// Body layout of legacy `SYBRVLT1` containers (v2 header, positionally exact).
#[derive(Deserialize)]
struct LegacyBodyV2 {
    header: crate::header::LegacyHeaderV2,
    items: Vec<EncryptedItem>,
}

/// In-memory vault state. When unlocked, decrypted items and the vault key are
/// held in memory and zeroized on transition back to locked / on drop.
enum VaultState {
    Locked {
        items: Vec<EncryptedItem>,
    },
    Unlocked {
        vault_key: SymmetricKey,
        items: Vec<Item>,
    },
}

/// A password vault. Create a new one with [`Vault::create`], or load an
/// existing (locked) one with [`Vault::from_bytes`] then [`Vault::unlock`].
pub struct Vault {
    header: VaultHeader,
    state: VaultState,
}

impl Vault {
    // ----- lifecycle ------------------------------------------------------

    /// Create a brand-new, unlocked vault protected by `master_password`.
    pub fn create(master_password: &str, params: KdfParams) -> Result<Self> {
        let master_key = crypto::derive_master_key(master_password, &params)?;
        let vault_key = SymmetricKey::generate()?;
        let master_wrapped_vault_key = crypto::wrap_key(&master_key, &vault_key, &params.aad())?;

        let header = VaultHeader {
            format_version: VaultHeader::FORMAT_VERSION,
            kdf: params,
            master_wrapped_vault_key,
            device_wrapped_vault_key: None,
            rewrap_epoch: 0,
        };

        Ok(Self {
            header,
            state: VaultState::Unlocked {
                vault_key,
                items: Vec::new(),
            },
        })
    }

    /// Parse a locked vault from its serialized bytes. Does not require the
    /// master password; the result is locked until [`Vault::unlock`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MAGIC.len() {
            return Err(Error::Format);
        }
        let (header, items) = match &bytes[..MAGIC.len()] {
            m if m == MAGIC => {
                let body: VaultBody = bincode::deserialize(&bytes[MAGIC.len()..])
                    .map_err(|_| Error::Serialization)?;
                (body.header, body.items)
            }
            m if m == MAGIC_V1 => {
                // Legacy container: v2 header without the rewrap epoch.
                let body: LegacyBodyV2 = bincode::deserialize(&bytes[MAGIC.len()..])
                    .map_err(|_| Error::Serialization)?;
                (body.header.into(), body.items)
            }
            _ => return Err(Error::Format),
        };
        header.check_supported()?;
        Ok(Self {
            header,
            state: VaultState::Locked { items },
        })
    }

    /// Serialize the vault to bytes for persistence. Always emits ciphertext;
    /// when unlocked, items are re-sealed with fresh nonces.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let items = match &self.state {
            VaultState::Locked { items } => items.clone(),
            VaultState::Unlocked { vault_key, items } => encrypt_items(vault_key, items)?,
        };
        let mut header = self.header.clone();
        // We always write the current container; stamp the version accordingly
        // (a legacy-loaded header still carries its old number).
        header.format_version = VaultHeader::FORMAT_VERSION;
        let body = VaultBody { header, items };
        let mut out = Vec::with_capacity(MAGIC.len() + 64);
        out.extend_from_slice(MAGIC);
        let encoded = bincode::serialize(&body).map_err(|_| Error::Serialization)?;
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    // ----- locking --------------------------------------------------------

    /// Unlock with the master password. Decrypts the vault key and all items.
    /// Returns [`Error::Decryption`] for a wrong password or tampered data.
    pub fn unlock(&mut self, master_password: &str) -> Result<()> {
        if self.is_unlocked() {
            return Ok(());
        }
        let master_key = crypto::derive_master_key(master_password, &self.header.kdf)?;
        let vault_key = crypto::unwrap_key(
            &master_key,
            &self.header.master_wrapped_vault_key,
            &self.header.kdf.aad(),
        )?;
        self.finish_unlock(vault_key)
    }

    /// Verify the master password WITHOUT changing lock state. Returns `true`
    /// when the password correctly re-derives and unwraps the vault key. Used
    /// for re-authentication (user verification) while the vault is already
    /// unlocked — e.g. approving a passkey ceremony, where a correct password is
    /// a genuine user-verification factor.
    pub fn verify_master_password(&self, master_password: &str) -> bool {
        let Ok(master_key) = crypto::derive_master_key(master_password, &self.header.kdf) else {
            return false;
        };
        crypto::unwrap_key(
            &master_key,
            &self.header.master_wrapped_vault_key,
            &self.header.kdf.aad(),
        )
        .is_ok()
    }

    /// Unlock using a device key fetched from the OS keychain (quick/biometric
    /// unlock). Fails if quick-unlock was never enabled.
    pub fn unlock_with_device_key(&mut self, device_key: &SymmetricKey) -> Result<()> {
        if self.is_unlocked() {
            return Ok(());
        }
        let wrapped = self
            .header
            .device_wrapped_vault_key
            .clone()
            .ok_or(Error::Decryption)?;
        let vault_key = crypto::unwrap_key(device_key, &wrapped, DEVICE_UNLOCK_AAD)?;
        self.finish_unlock(vault_key)
    }

    /// Common tail of the two unlock paths: decrypt items, transition state.
    fn finish_unlock(&mut self, vault_key: SymmetricKey) -> Result<()> {
        let items = match &self.state {
            VaultState::Locked { items } => decrypt_items(&vault_key, items)?,
            // unreachable: callers guard on `is_unlocked()` first.
            VaultState::Unlocked { .. } => return Ok(()),
        };
        self.state = VaultState::Unlocked { vault_key, items };
        Ok(())
    }

    /// Lock the vault: re-seal current items and drop (zeroize) the vault key
    /// and plaintext items.
    pub fn lock(&mut self) {
        if let VaultState::Unlocked { vault_key, items } = &self.state {
            let resealed = encrypt_items(vault_key, items).unwrap_or_default();
            // Reassigning drops the old Unlocked state → key + plaintext zeroized.
            self.state = VaultState::Locked { items: resealed };
        }
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, VaultState::Unlocked { .. })
    }

    // ----- item operations (require unlocked) -----------------------------

    /// Summaries for list rendering. Pass `include_deleted = true` for the
    /// Trash view.
    pub fn list_items(&self, include_deleted: bool) -> Result<Vec<ItemSummary>> {
        let items = self.unlocked_items()?;
        Ok(items
            .iter()
            .filter(|i| include_deleted || !i.is_deleted())
            .map(Item::summary)
            .collect())
    }

    /// Password-health audit (weak/reused) over the active login items.
    /// Requires the vault to be unlocked.
    pub fn security_report(&self) -> Result<Vec<crate::security::ItemSecurity>> {
        Ok(crate::security::audit(self.unlocked_items()?))
    }

    /// Fetch a full (decrypted) item by id. The returned clone carries
    /// plaintext secrets and zeroizes on drop.
    pub fn get_item(&self, id: Uuid) -> Result<Item> {
        self.unlocked_items()?
            .iter()
            .find(|i| i.id == id)
            .cloned()
            .ok_or(Error::NotFound)
    }

    /// Merge the items from another serialized vault file (a synced peer) into
    /// this unlocked vault, keeping the most-recently-changed version of each
    /// item (see [`crate::sync::merge`]).
    ///
    /// The peer's items are decrypted with *this* vault's key — valid because a
    /// synced vault shares one stable vault key across devices. A decryption
    /// failure therefore means the file is a *different* vault, and the merge is
    /// refused ([`Error::Decryption`]) rather than silently importing garbage.
    /// Requires this vault to be unlocked.
    pub fn merge_remote(&mut self, remote_bytes: &[u8]) -> Result<()> {
        let remote = Self::from_bytes(remote_bytes)?;
        let remote_header = remote.header;
        let remote_enc = match remote.state {
            VaultState::Locked { items } => items,
            // `from_bytes` always yields a locked vault.
            VaultState::Unlocked { .. } => return Err(Error::Format),
        };
        let VaultState::Unlocked { vault_key, items } = &mut self.state else {
            return Err(Error::Locked);
        };
        let remote_items = decrypt_items(vault_key, &remote_enc)?;
        let local = core::mem::take(items);
        *items = crate::sync::merge(local, remote_items);
        // Header: adopt a NEWER master rewrap (password rotation / KDF upgrade)
        // from the peer. The vault key itself never changes on rotation, so the
        // local device wrap stays valid and is kept.
        if remote_header.rewrap_epoch > self.header.rewrap_epoch {
            self.header.kdf = remote_header.kdf;
            self.header.master_wrapped_vault_key = remote_header.master_wrapped_vault_key;
            self.header.rewrap_epoch = remote_header.rewrap_epoch;
        }
        Ok(())
    }

    /// Merge duplicate active logins (same host + username): the newest wins,
    /// TOTP/notes are adopted, losers are soft-deleted. Returns how many items
    /// were merged away. Requires the vault to be unlocked.
    pub fn merge_duplicate_logins(&mut self, now_unix_millis: i64) -> Result<usize> {
        let items = self.unlocked_items_mut()?;
        Ok(crate::dedupe::merge_duplicate_logins(
            items,
            now_unix_millis,
        ))
    }

    /// Insert a new item or replace an existing one with the same id.
    pub fn upsert_item(&mut self, item: Item) -> Result<()> {
        let items = self.unlocked_items_mut()?;
        match items.iter_mut().find(|i| i.id == item.id) {
            Some(existing) => *existing = item,
            None => items.push(item),
        }
        Ok(())
    }

    /// Soft-delete (move to Trash). The item remains, marked `deleted_at`.
    pub fn delete_item(&mut self, id: Uuid, now_unix_millis: i64) -> Result<()> {
        let item = self
            .unlocked_items_mut()?
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or(Error::NotFound)?;
        item.deleted_at = Some(now_unix_millis);
        item.modified_at = now_unix_millis;
        Ok(())
    }

    /// Restore a soft-deleted item back to active.
    pub fn restore_item(&mut self, id: Uuid, now_unix_millis: i64) -> Result<()> {
        let item = self
            .unlocked_items_mut()?
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or(Error::NotFound)?;
        item.deleted_at = None;
        item.modified_at = now_unix_millis;
        Ok(())
    }

    /// Permanently remove an item (empties it from the Trash).
    pub fn purge_item(&mut self, id: Uuid) -> Result<()> {
        let items = self.unlocked_items_mut()?;
        let before = items.len();
        items.retain(|i| i.id != id);
        if items.len() == before {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Re-key the vault under a new master password (fresh salt + re-wrap).
    /// Existing quick-unlock stays valid (it is wrapped under the device key,
    /// not the master password).
    pub fn change_master_password(&mut self, new_password: &str) -> Result<()> {
        let vault_key = self.vault_key()?.clone();
        let new_params = KdfParams::new_default()?;
        let master_key = crypto::derive_master_key(new_password, &new_params)?;
        let wrapped = crypto::wrap_key(&master_key, &vault_key, &new_params.aad())?;
        self.header.kdf = new_params;
        self.header.master_wrapped_vault_key = wrapped;
        // Monotonic epoch: peers adopt the higher-epoch header on merge, so the
        // rotation propagates instead of being reverted by a stale header.
        self.header.rewrap_epoch += 1;
        Ok(())
    }

    // ----- quick-unlock (device key) --------------------------------------

    /// Add a device-key-wrapped copy of the vault key to the header, enabling
    /// quick/biometric unlock. The `device_key` must be stored by the caller
    /// in the OS keychain (see `vault-store`); it is never written to the file
    /// in cleartext.
    pub fn enable_device_unlock(&mut self, device_key: &SymmetricKey) -> Result<()> {
        let vault_key = self.vault_key()?.clone();
        let blob = crypto::wrap_key(device_key, &vault_key, DEVICE_UNLOCK_AAD)?;
        self.header.device_wrapped_vault_key = Some(blob);
        Ok(())
    }

    /// Remove quick-unlock material from the header. The caller should also
    /// delete the device key from the OS keychain.
    pub fn disable_device_unlock(&mut self) {
        self.header.device_wrapped_vault_key = None;
    }

    pub fn has_device_unlock(&self) -> bool {
        self.header.device_wrapped_vault_key.is_some()
    }

    // ----- accessors ------------------------------------------------------

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    // ----- internals ------------------------------------------------------

    fn vault_key(&self) -> Result<&SymmetricKey> {
        match &self.state {
            VaultState::Unlocked { vault_key, .. } => Ok(vault_key),
            VaultState::Locked { .. } => Err(Error::Locked),
        }
    }

    fn unlocked_items(&self) -> Result<&Vec<Item>> {
        match &self.state {
            VaultState::Unlocked { items, .. } => Ok(items),
            VaultState::Locked { .. } => Err(Error::Locked),
        }
    }

    fn unlocked_items_mut(&mut self) -> Result<&mut Vec<Item>> {
        match &mut self.state {
            VaultState::Unlocked { items, .. } => Ok(items),
            VaultState::Locked { .. } => Err(Error::Locked),
        }
    }
}

/// Encode an item payload (the plaintext that gets sealed) with CBOR.
///
/// CBOR is self-describing and tags enum variants by name, so the persisted
/// `VaultItem` schema can evolve — variants may be reordered or appended —
/// without misreading existing data. (The outer container in
/// [`Vault::to_bytes`] uses bincode; only this inner, encrypted payload needs
/// schema stability.) Generic so the round-trip test can exercise the exact
/// codec used on disk.
fn encode_item_payload<T: serde::Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| Error::Serialization)?;
    Ok(Zeroizing::new(buf))
}

/// Decode an item payload previously produced by [`encode_item_payload`].
fn decode_item_payload<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|_| Error::Serialization)
}

/// Seal every item under the vault key, binding each item's id as AAD.
fn encrypt_items(vault_key: &SymmetricKey, items: &[Item]) -> Result<Vec<EncryptedItem>> {
    items
        .iter()
        .map(|item| {
            let plaintext = encode_item_payload(item)?;
            let blob = crypto::seal(vault_key, &plaintext, item.id.as_bytes())?;
            Ok(EncryptedItem { id: item.id, blob })
        })
        .collect()
}

/// Open every item under the vault key, verifying the id-bound AAD.
fn decrypt_items(vault_key: &SymmetricKey, items: &[EncryptedItem]) -> Result<Vec<Item>> {
    items
        .iter()
        .map(|enc| {
            let plaintext = crypto::open(vault_key, &enc.blob, enc.id.as_bytes())?;
            let item: Item = decode_item_payload(&plaintext)?;
            // Defense in depth: the decrypted id must match the cleartext id.
            if item.id != enc.id {
                return Err(Error::Decryption);
            }
            Ok(item)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    // Proves the on-disk item-payload codec is stable against variant
    // reordering *and* a newly appended variant — the property a positional
    // codec (bincode) would violate. We round-trip through the real
    // encode/decode helpers used by `encrypt_items`/`decrypt_items`.
    #[test]
    fn item_payload_survives_variant_reorder_and_append() {
        // The layout in effect when some item was written to disk.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        #[serde(tag = "type")]
        enum OldLayout {
            Login { username: String, password: String },
            SecureNote { title: String },
        }

        // A future build: `SecureNote` moved ahead of `Login` and a brand-new
        // `Passkey` variant appended. Under a positional encoding this would
        // misdecode the old bytes; under name-tagged CBOR it must not.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        #[serde(tag = "type")]
        enum NewLayout {
            SecureNote { title: String },
            Passkey { title: String },
            Login { username: String, password: String },
        }

        let written = encode_item_payload(&OldLayout::Login {
            username: "frank-lia".into(),
            password: "correct horse battery staple".into(),
        })
        .unwrap();

        let read_back: NewLayout = decode_item_payload(&written).unwrap();
        assert_eq!(
            read_back,
            NewLayout::Login {
                username: "frank-lia".into(),
                password: "correct horse battery staple".into(),
            }
        );
    }

    // ---- merge_remote (sync) --------------------------------------------

    fn cheap_params() -> KdfParams {
        KdfParams {
            algorithm: crate::header::KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![7u8; KdfParams::SALT_LEN],
        }
    }

    fn login_item(id_byte: u8, title: &str, modified_at: i64) -> Item {
        Item {
            id: Uuid::from_bytes([id_byte; 16]),
            created_at: 0,
            modified_at,
            deleted_at: None,
            data: crate::item::VaultItem::Login {
                title: title.into(),
                username: "u".into(),
                password: "p".into(),
                url: "https://x.com".into(),
                totp_secret: None,
                notes: String::new(),
            },
        }
    }

    #[test]
    fn verify_master_password_checks_without_unlock_shortcut() {
        // A freshly created vault is unlocked; verification must still re-check
        // the password (unlike `unlock`, which short-circuits when unlocked).
        let v = Vault::create("correct-horse", cheap_params()).unwrap();
        assert!(v.is_unlocked());
        assert!(v.verify_master_password("correct-horse"));
        assert!(!v.verify_master_password("wrong"));
        assert!(!v.verify_master_password(""));
    }

    #[test]
    fn merge_remote_combines_a_peers_edits() {
        let mut a = Vault::create("pw", cheap_params()).unwrap();
        a.upsert_item(login_item(1, "X", 10)).unwrap();
        let base = a.to_bytes().unwrap();

        // Peer loads the same file, unlocks with the same password, adds Y.
        let mut b = Vault::from_bytes(&base).unwrap();
        b.unlock("pw").unwrap();
        b.upsert_item(login_item(2, "Y", 20)).unwrap();
        let remote = b.to_bytes().unwrap();

        a.merge_remote(&remote).unwrap();
        let mut ids: Vec<u8> = a
            .list_items(true)
            .unwrap()
            .iter()
            .map(|s| s.id.as_bytes()[0])
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn merge_remote_takes_the_newer_version() {
        let mut a = Vault::create("pw", cheap_params()).unwrap();
        a.upsert_item(login_item(1, "old", 10)).unwrap();
        let base = a.to_bytes().unwrap();
        let mut b = Vault::from_bytes(&base).unwrap();
        b.unlock("pw").unwrap();
        b.upsert_item(login_item(1, "new", 30)).unwrap(); // same id, newer
        let remote = b.to_bytes().unwrap();

        a.merge_remote(&remote).unwrap();
        let item = a.get_item(Uuid::from_bytes([1; 16])).unwrap();
        assert_eq!(item.data.title(), "new");
    }

    #[test]
    fn merge_remote_rejects_a_foreign_vault() {
        let mut a = Vault::create("pw", cheap_params()).unwrap();
        // A different vault has a different random vault key, so its items can't
        // be decrypted with ours -> the merge is refused.
        let mut other = Vault::create("pw", cheap_params()).unwrap();
        other.upsert_item(login_item(9, "Z", 5)).unwrap();
        let foreign = other.to_bytes().unwrap();
        assert!(matches!(a.merge_remote(&foreign), Err(Error::Decryption)));
    }

    #[test]
    fn merge_remote_adopts_a_newer_master_rewrap() {
        // Device A and B share a vault; A rotates the master password.
        let mut a = Vault::create("old-pw", cheap_params()).unwrap();
        a.upsert_item(login_item(1, "X", 10)).unwrap();
        let base = a.to_bytes().unwrap();
        let mut b = Vault::from_bytes(&base).unwrap();
        b.unlock("old-pw").unwrap();

        a.change_master_password("new-pw").unwrap();
        assert_eq!(a.header().rewrap_epoch, 1);
        let rotated = a.to_bytes().unwrap();

        // B merges A's file: the rotated header must be adopted, so a vault
        // serialized by B now opens with the NEW password only.
        b.merge_remote(&rotated).unwrap();
        assert_eq!(b.header().rewrap_epoch, 1);
        let from_b = b.to_bytes().unwrap();
        let mut check = Vault::from_bytes(&from_b).unwrap();
        assert!(check.unlock("old-pw").is_err());
        check.unlock("new-pw").unwrap();

        // And a STALE peer file (epoch 0) must NOT revert B's header.
        b.merge_remote(&base).unwrap();
        assert_eq!(b.header().rewrap_epoch, 1);
    }

    #[test]
    fn legacy_v1_container_still_loads() {
        // Hand-build a SYBRVLT1 container (v2 header, no rewrap epoch) and
        // confirm it round-trips through the current reader.
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.upsert_item(login_item(3, "Old", 5)).unwrap();
        let header = v.header().clone();
        #[derive(serde::Serialize)]
        struct OldHeader<'a> {
            format_version: u16,
            kdf: &'a KdfParams,
            master_wrapped_vault_key: &'a crate::crypto::AeadBlob,
            device_wrapped_vault_key: &'a Option<crate::crypto::AeadBlob>,
        }
        #[derive(serde::Serialize)]
        struct OldBody<'a> {
            header: OldHeader<'a>,
            items: Vec<EncryptedItem>, // empty: items aren't the point here
        }
        let old = OldBody {
            header: OldHeader {
                format_version: 2,
                kdf: &header.kdf,
                master_wrapped_vault_key: &header.master_wrapped_vault_key,
                device_wrapped_vault_key: &header.device_wrapped_vault_key,
            },
            items: vec![],
        };
        let mut bytes = b"SYBRVLT1".to_vec();
        bytes.extend_from_slice(&bincode::serialize(&old).unwrap());
        let mut loaded = Vault::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.header().rewrap_epoch, 0);
        loaded.unlock("pw").unwrap();
    }

    #[test]
    fn newer_format_version_is_refused_distinctly() {
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.upsert_item(login_item(4, "F", 1)).unwrap();
        let mut bytes = v.to_bytes().unwrap();
        // Corrupt the header's format_version (first field after the magic) to
        // a large value: must surface UnsupportedVersion, not generic Format.
        bytes[8] = 0xEE;
        bytes[9] = 0xEE;
        assert!(matches!(
            Vault::from_bytes(&bytes),
            Err(Error::UnsupportedVersion)
        ));
    }

    #[test]
    fn merge_remote_requires_unlock() {
        let bytes = Vault::create("pw", cheap_params())
            .unwrap()
            .to_bytes()
            .unwrap();
        let mut locked = Vault::from_bytes(&bytes).unwrap();
        assert!(matches!(locked.merge_remote(&bytes), Err(Error::Locked)));
    }
}
