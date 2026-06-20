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

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub use error::{Error, Result};
use vault_core::SymmetricKey;
pub use vault_core::Vault;

/// A vault on disk plus its OS-keychain quick-unlock binding.
pub struct VaultStore {
    path: PathBuf,
    keychain_service: String,
    keychain_account: String,
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
        Ok(Vault::from_bytes(&bytes)?)
    }

    /// Serialize and atomically persist the vault.
    pub fn save(&self, vault: &Vault) -> Result<()> {
        let bytes = vault.to_bytes()?;
        write_atomic(&self.path, &bytes)?;
        Ok(())
    }

    // ----- quick unlock ---------------------------------------------------

    /// Whether a device key is present in the OS keychain.
    pub fn quick_unlock_available(&self) -> bool {
        matches!(
            keychain::get(&self.keychain_service, &self.keychain_account),
            Ok(Some(_))
        )
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
