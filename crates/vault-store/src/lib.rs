//! # vault-store
//!
//! Persistence and OS-keychain quick-unlock for the SYBR password manager.
//!
//! * **One encrypted file**, written atomically (temp file in the same
//!   directory + `fsync` + `rename`), so a crash mid-write can never corrupt
//!   the vault — you keep either the old or the new bytes, never a torn mix.
//! * **Quick/biometric unlock** via a device key kept in the OS keychain. The
//!   master password is never persisted (see [`keychain`]).
//!
//! All ciphertext/serialization lives in `vault-core`; this crate only moves
//! opaque bytes and talks to the OS.

mod error;
mod keychain;
pub mod secrets;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub use error::{Error, Result};
use vault_core::SymmetricKey;
pub use vault_core::Vault;

/// Non-cryptographic fingerprint of the on-disk bytes, to detect that a synced
/// peer rewrote the file since we last read/wrote it.
fn fingerprint(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// A vault on disk plus its OS-keychain quick-unlock binding.
pub struct VaultStore {
    path: PathBuf,
    keychain_service: String,
    keychain_account: String,
    /// Fingerprint of the bytes we last read/wrote, for external-change (sync)
    /// detection in [`VaultStore::save_synced`].
    last_seen: AtomicU64,
}

impl VaultStore {
    /// Create a store for the vault at `path`. `keychain_service`/`account`
    /// namespace the device key in the OS secret store (e.g.
    /// `"no.sybr.vault"` / `"default-vault"`).
    pub fn new(
        path: impl Into<PathBuf>,
        keychain_service: impl Into<String>,
        keychain_account: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            keychain_service: keychain_service.into(),
            keychain_account: keychain_account.into(),
            last_seen: AtomicU64::new(0),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether a vault file exists at the configured path.
    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    /// Load the (locked) vault from disk.
    pub fn load(&self) -> Result<Vault> {
        let bytes = fs::read(&self.path)?;
        self.last_seen.store(fingerprint(&bytes), Ordering::Relaxed);
        Ok(Vault::from_bytes(&bytes)?)
    }

    /// Serialize and atomically persist the vault.
    pub fn save(&self, vault: &Vault) -> Result<()> {
        let bytes = vault.to_bytes()?;
        write_atomic(&self.path, &bytes)?;
        self.last_seen.store(fingerprint(&bytes), Ordering::Relaxed);
        Ok(())
    }

    /// Sync-aware save: if the file on disk changed since we last read/wrote it
    /// (a synced peer rewrote it), merge those changes into `vault` first so the
    /// peer's edits aren't clobbered, then persist the merged result. Returns
    /// `true` if a merge happened. A foreign/corrupt external file surfaces as
    /// an error (the peer's file is *not* overwritten).
    pub fn save_synced(&self, vault: &mut Vault) -> Result<bool> {
        let mut merged = false;
        if self.path.is_file() {
            let current = fs::read(&self.path)?;
            if fingerprint(&current) != self.last_seen.load(Ordering::Relaxed) {
                match vault.merge_remote(&current) {
                    Ok(()) => merged = true,
                    // Unparseable bytes — a corrupt file, or a cloud daemon's
                    // in-progress partial write. It isn't a real vault, so
                    // replacing it with ours is safe and, crucially, doesn't
                    // wedge every future save behind a transient bad file.
                    Err(vault_core::Error::Format) | Err(vault_core::Error::Serialization) => {}
                    // A well-formed but un-reconcilable file (a *different*
                    // vault's key, or we're locked): refuse rather than
                    // destroy a vault we can't safely merge.
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let bytes = vault.to_bytes()?;
        write_atomic(&self.path, &bytes)?;
        self.last_seen.store(fingerprint(&bytes), Ordering::Relaxed);
        Ok(merged)
    }

    // ----- quick unlock ---------------------------------------------------

    /// Whether a device key is present in the OS keychain. Uses a presence-only
    /// check so it never triggers the biometric prompt (unlike reading the key).
    pub fn quick_unlock_available(&self) -> bool {
        keychain::exists(&self.keychain_service, &self.keychain_account)
    }

    /// Enable quick-unlock: mint a random device key, store it in the OS
    /// keychain, and add a device-wrapped vault key to the header. The caller
    /// must [`save`](Self::save) afterward to persist the header change. The
    /// vault must be unlocked.
    pub fn enable_quick_unlock(&self, vault: &mut Vault) -> Result<()> {
        let device_key = SymmetricKey::generate()?;
        keychain::set(&self.keychain_service, &self.keychain_account, &device_key)?;
        vault.enable_device_unlock(&device_key)?;
        Ok(())
    }

    /// Unlock the vault using the keychain device key (no master password).
    pub fn quick_unlock(&self, vault: &mut Vault) -> Result<()> {
        let device_key = keychain::get(&self.keychain_service, &self.keychain_account)?
            .ok_or(Error::QuickUnlockNotEnabled)?;
        vault.unlock_with_device_key(&device_key)?;
        Ok(())
    }

    /// Disable quick-unlock: delete the keychain device key and clear the
    /// header. The caller must [`save`](Self::save) afterward.
    pub fn disable_quick_unlock(&self, vault: &mut Vault) -> Result<()> {
        keychain::delete(&self.keychain_service, &self.keychain_account)?;
        vault.disable_device_unlock();
        Ok(())
    }
}

/// Monotonic counter to make temp filenames unique within a process.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomically replace `path`'s contents with `bytes`.
///
/// Writes to a sibling temp file (so it lands on the same filesystem, making
/// `rename` atomic), restricts its permissions, fsyncs the file, renames it
/// over the target, then best-effort fsyncs the directory.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = dir {
        fs::create_dir_all(dir)?;
    }
    let dir = dir.unwrap_or_else(|| Path::new("."));

    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("vault");
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));

    // Write + fsync into the temp file, cleaning it up on any failure.
    let result = (|| -> std::io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600); // owner read/write only
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // Durability: fsync the directory so the rename survives a crash. Best
    // effort — not all platforms permit/require it.
    #[cfg(unix)]
    {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{Item, KdfParams, VaultItem};

    fn cheap_params() -> KdfParams {
        KdfParams {
            algorithm: vault_core::KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![3u8; KdfParams::SALT_LEN],
        }
    }

    fn login() -> VaultItem {
        VaultItem::Login {
            title: "Fastmail".into(),
            username: "frank@sybr.no".into(),
            password: "s3cret".into(),
            url: "https://fastmail.com".into(),
            totp_secret: None,
            notes: String::new(),
        }
    }

    #[test]
    fn save_then_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("test.vault"), "test.svc", "test.acct");
        assert!(!store.exists());

        let mut v = Vault::create("pw", cheap_params()).unwrap();
        let item = Item::new(login(), 42);
        let id = item.id;
        v.upsert_item(item).unwrap();
        store.save(&v).unwrap();
        assert!(store.exists());

        let mut loaded = store.load().unwrap();
        loaded.unlock("pw").unwrap();
        assert_eq!(loaded.get_item(id).unwrap().data.title(), "Fastmail");
    }

    #[test]
    fn save_synced_merges_a_peers_external_change() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("v.vault"), "s", "a");

        // Our copy has item A; save it (records the file fingerprint).
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.upsert_item(Item::new(login(), 10)).unwrap();
        store.save(&v).unwrap();

        // A synced peer loads the same file, adds B, and writes it directly to
        // the path — behind our store's back.
        let peer_bytes = {
            let mut peer = Vault::from_bytes(&std::fs::read(store.path()).unwrap()).unwrap();
            peer.unlock("pw").unwrap();
            peer.upsert_item(Item::new(login(), 20)).unwrap(); // B: fresh id
            peer.to_bytes().unwrap()
        };
        std::fs::write(store.path(), &peer_bytes).unwrap();

        // Saving now detects the external change and merges B into our vault
        // instead of clobbering it.
        assert!(store.save_synced(&mut v).unwrap());
        let mut reloaded = store.load().unwrap();
        reloaded.unlock("pw").unwrap();
        assert_eq!(reloaded.list_items(true).unwrap().len(), 2);

        // No external change since -> no merge.
        assert!(!store.save_synced(&mut v).unwrap());
    }

    #[test]
    fn save_synced_replaces_a_corrupt_file_but_refuses_a_foreign_vault() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("v.vault"), "s", "a");
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.upsert_item(Item::new(login(), 10)).unwrap();
        store.save(&v).unwrap();

        // A corrupt / partial file (e.g. a cloud daemon mid-write) must NOT
        // wedge saving — it's not a real vault, so we replace it.
        std::fs::write(store.path(), b"not a vault at all").unwrap();
        assert!(!store.save_synced(&mut v).unwrap());
        let mut reloaded = store.load().unwrap();
        reloaded.unlock("pw").unwrap();
        assert_eq!(reloaded.list_items(true).unwrap().len(), 1);

        // But a well-formed DIFFERENT vault (foreign key) is refused, not
        // clobbered.
        let foreign = {
            let mut other = Vault::create("pw", cheap_params()).unwrap();
            other.upsert_item(Item::new(login(), 5)).unwrap();
            other.to_bytes().unwrap()
        };
        std::fs::write(store.path(), &foreign).unwrap();
        assert!(store.save_synced(&mut v).is_err());
    }

    #[test]
    fn save_overwrites_atomically_without_leaving_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("v.vault"), "s", "a");

        let mut v = Vault::create("pw", cheap_params()).unwrap();
        store.save(&v).unwrap();
        v.upsert_item(Item::new(login(), 1)).unwrap();
        store.save(&v).unwrap(); // overwrite

        // Only the vault file remains; no leftover ".tmp" siblings.
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["v.vault".to_string()]);
    }

    #[test]
    fn load_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.vault");
        fs::write(&path, b"definitely not a vault").unwrap();
        let store = VaultStore::new(path, "s", "a");
        assert!(store.load().is_err());
    }

    // Keychain tests require a real OS secret store (and may pop a biometric /
    // auth prompt), so they are not run by default. Run on a desktop with:
    //   cargo test -p vault-store -- --ignored
    #[test]
    #[ignore = "requires OS keychain access"]
    fn quick_unlock_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(
            dir.path().join("qu.vault"),
            "no.sybr.vault.test",
            "quick-unlock-test",
        );
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.upsert_item(Item::new(login(), 1)).unwrap();
        store.enable_quick_unlock(&mut v).unwrap();
        store.save(&v).unwrap();

        let mut loaded = store.load().unwrap();
        store.quick_unlock(&mut loaded).unwrap();
        assert!(loaded.is_unlocked());

        store.disable_quick_unlock(&mut loaded).unwrap();
        assert!(!store.quick_unlock_available());
    }
}
