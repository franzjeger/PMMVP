//! Shared application state and the error type returned to the frontend.

use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use vault_store::VaultStore;

use vault_core::Vault;

use crate::clipboard::ClipboardManager;

/// User-configurable security timings. Defaults are conservative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// Auto-lock after this many seconds of inactivity. `0` disables.
    pub auto_lock_secs: u64,
    /// Lock immediately when the window loses focus.
    pub lock_on_blur: bool,
    /// Clear copied secrets from the clipboard after this many seconds. `0`
    /// disables auto-clear.
    pub clipboard_clear_secs: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_secs: 300,
            lock_on_blur: true,
            clipboard_clear_secs: 30,
        }
    }
}

/// Path to the (non-secret) settings file, kept alongside the vault file.
fn settings_file(vault_path: &Path) -> PathBuf {
    vault_path.with_file_name("settings.json")
}

/// Load persisted settings next to `vault_path`, falling back to defaults if
/// the file is missing or unreadable. Settings contain no secrets, so they are
/// stored in plaintext JSON.
pub fn load_settings(vault_path: &Path) -> Settings {
    std::fs::read(settings_file(vault_path))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Persist settings next to `vault_path`. Best-effort; non-secret.
pub fn save_settings(vault_path: &Path, settings: &Settings) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(settings)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(settings_file(vault_path), json)
}

/// The whole app's mutable state, guarded by a `Mutex` in Tauri's managed state.
pub struct AppState {
    pub store: VaultStore,
    /// `None` before a vault is created/loaded; otherwise locked or unlocked.
    pub vault: Option<Vault>,
    pub settings: Settings,
    /// Last time the user interacted (any command), for idle auto-lock.
    pub last_activity: Instant,
    /// Long-lived clipboard owner (keeps Linux selection ownership alive).
    pub clipboard: ClipboardManager,
}

impl AppState {
    pub fn new(store: VaultStore, vault: Option<Vault>, clipboard: ClipboardManager) -> Self {
        Self {
            store,
            vault,
            settings: Settings::default(),
            last_activity: Instant::now(),
            clipboard,
        }
    }

    /// Record user activity (resets the idle timer).
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Borrow the loaded vault, or error if none has been created/loaded.
    pub fn vault(&self) -> Result<&Vault, CmdError> {
        self.vault.as_ref().ok_or_else(CmdError::no_vault)
    }

    pub fn vault_mut(&mut self) -> Result<&mut Vault, CmdError> {
        self.vault.as_mut().ok_or_else(CmdError::no_vault)
    }
}

/// Current unix time in milliseconds (for item timestamps).
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Current unix time in seconds (for TOTP).
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A serializable, secret-free error surfaced to the frontend.
///
/// `code` is a stable machine-readable tag; `message` is human-readable and
/// deliberately vague about *why* crypto failed (never echoes secrets).
#[derive(Debug, Serialize)]
pub struct CmdError {
    pub code: String,
    pub message: String,
}

impl CmdError {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }
    pub fn no_vault() -> Self {
        Self::new("no_vault", "No vault has been created or loaded yet.")
    }
}

impl std::fmt::Display for CmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for CmdError {}

impl From<vault_core::Error> for CmdError {
    fn from(e: vault_core::Error) -> Self {
        use vault_core::Error as E;
        match e {
            E::Locked => CmdError::new("locked", "The vault is locked."),
            E::Decryption => CmdError::new(
                "invalid_credentials",
                "Incorrect password, or the vault data is corrupt.",
            ),
            E::NotFound => CmdError::new("not_found", "Item not found."),
            E::Format => CmdError::new("format", "Unrecognized or unsupported vault format."),
            E::InvalidTotpSecret => CmdError::new(
                "invalid_totp",
                "The stored TOTP secret is not valid Base32.",
            ),
            E::InvalidArgument(m) => CmdError::new("invalid_argument", m),
            // KeyDerivation / Serialization / Random — generic, no detail leaked.
            _ => CmdError::new("error", "The operation failed."),
        }
    }
}

impl From<vault_store::Error> for CmdError {
    fn from(e: vault_store::Error) -> Self {
        use vault_store::Error as E;
        match e {
            E::Core(c) => c.into(),
            E::Io(_) => CmdError::new("io", "Could not read or write the vault file."),
            E::Keychain => CmdError::new("keychain", "The OS keychain operation failed."),
            E::KeychainUnsupported => CmdError::new(
                "keychain_unsupported",
                "Quick unlock is not supported on this platform.",
            ),
            E::QuickUnlockNotEnabled => {
                CmdError::new("quick_unlock_disabled", "Quick unlock is not enabled.")
            }
            // `vault_store::Error` is #[non_exhaustive]; stay generic for any
            // future variant rather than leaking detail.
            _ => CmdError::new("error", "The operation failed."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.vault");
        let s = Settings {
            auto_lock_secs: 120,
            lock_on_blur: false,
            clipboard_clear_secs: 15,
        };
        save_settings(&vault, &s).unwrap();
        assert_eq!(load_settings(&vault), s);
    }

    #[test]
    fn load_settings_falls_back_to_defaults_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            load_settings(&dir.path().join("missing.vault")),
            Settings::default()
        );
    }
}
