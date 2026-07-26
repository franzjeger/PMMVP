// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod agent;
mod biometric;
mod bridge;
mod clipboard;
mod commands;
mod state;
mod sync;

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, WindowEvent};
use vault_store::VaultStore;

use clipboard::ClipboardManager;
use state::AppState;

/// OS keychain namespace for the device (quick-unlock) key.
const KEYCHAIN_SERVICE: &str = "no.sybr.vault";
const KEYCHAIN_ACCOUNT: &str = "default-vault";

/// The App Group shared with the macOS AutoFill extension.
#[cfg(target_os = "macos")]
const APP_GROUP: &str = "group.no.sybr.vault";

/// Last-modified time, or `None` when the file is missing/unreadable.
#[cfg(target_os = "macos")]
fn modified_at(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// Resolve where the vault file lives: always the app-data directory.
///
/// The vault briefly lived in the shared App Group container so the macOS
/// AutoFill extension could read it. That extension is shelved, and the
/// container is a liability without it: reaching it at all requires a
/// provisioned entitlement, so if the profile lapses or the app is re-signed
/// without one, `container_path` returns `None` — and the app would silently
/// open a STALE app-data copy while the user keeps adding entries to it. A
/// password manager must never quietly serve the wrong vault.
///
/// So the app-data path is canonical, and a *newer* container copy is migrated
/// back down once (snapshotting whatever it replaces). The container copy is
/// left in place as an extra off-path backup.
fn resolve_vault_path(app: &tauri::App, data_dir: &Path) -> PathBuf {
    let app_data_vault = data_dir.join("default.vault");
    #[cfg(target_os = "macos")]
    {
        // The container path MUST come from Foundation's containerURL API: it is
        // that call which grants this (non-sandboxed but entitled) process access
        // to the container. A hardcoded path is denied with EPERM.
        if let Some(container) = vault_appgroup::container_path(APP_GROUP) {
            let shared_vault = container.join("default.vault");
            let shared_is_newer = match (modified_at(&shared_vault), modified_at(&app_data_vault)) {
                (Some(shared), Some(local)) => shared > local,
                (Some(_), None) => true, // only the container has a vault
                _ => false,
            };
            if shared_is_newer {
                // Never overwrite without a rollback point.
                let _ = vault_store::snapshot::capture(&app_data_vault);
                match std::fs::copy(&shared_vault, &app_data_vault) {
                    Ok(_) => {
                        let shared_settings = container.join("settings.json");
                        if shared_settings.exists() {
                            let _ = std::fs::copy(&shared_settings, data_dir.join("settings.json"));
                        }
                        eprintln!("[arca] migrated the newer App Group vault back to app data");
                    }
                    Err(e) => eprintln!(
                        "[arca] could not migrate the App Group vault back ({e}); \
                         using the app-data vault"
                    ),
                }
            }
        }
    }
    let _ = app; // unused on non-macOS
    app_data_vault
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Resolve a per-user data directory for the single vault file.
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir).ok();
            // On macOS this is the shared App Group container (migrated with a
            // backup); elsewhere the app-data dir.
            let vault_path = resolve_vault_path(app, &data_dir);

            let store = VaultStore::new(vault_path, KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
            // Eagerly load the locked vault if a file already exists.
            let vault = if store.exists() {
                store.load().ok()
            } else {
                None
            };

            // Long-lived clipboard owner thread (keeps the secret pasteable on
            // Linux and auto-clears it on all platforms).
            let clipboard = ClipboardManager::spawn(app.handle().clone());

            let mut app_state = AppState::new(store, vault, clipboard);
            // Restore persisted (non-secret) settings, if any.
            app_state.settings = state::load_settings(app_state.store.path());
            app.manage(Mutex::new(app_state));
            // Shared map of in-flight autofill-consent prompts (used only when
            // the confirm-autofill setting is on).
            app.manage(bridge::PendingConsents::default());
            app.manage(bridge::PendingVerifications::default());
            // Google Drive sync: background pull-merge-push loop. State lives in
            // the engine (vault-sync), not in Tauri's managed map.
            sync::start_loop(app.handle().clone());

            // Local autofill bridge for the browser extension (loopback + token;
            // gated on unlock + origin match). Best-effort: failure to bind just
            // means autofill is unavailable this session.
            if let Err(e) = bridge::start(app.handle().clone(), &data_dir) {
                eprintln!("autofill bridge unavailable: {e}");
            }

            // ssh-agent: expose vault SSH keys to ssh/git (Unix socket).
            agent::start(app.handle().clone());

            // Background idle-timeout auto-lock.
            let handle = app.handle().clone();
            std::thread::spawn(move || idle_watcher(handle));

            Ok(())
        })
        .on_window_event(|window, event| {
            // Auto-lock when the window loses focus (if enabled).
            if let WindowEvent::Focused(false) = event {
                let app = window.app_handle();
                if let Some(state) = app.try_state::<Mutex<AppState>>() {
                    if let Ok(mut st) = state.lock() {
                        // Don't lock when our own native dialog (e.g. the import
                        // file picker) stole focus — the user hasn't left the app.
                        let lock_on_blur = st.settings.lock_on_blur && !st.suppress_blur_lock;
                        let mut locked = false;
                        if lock_on_blur {
                            if let Some(v) = st.vault.as_mut() {
                                if v.is_unlocked() {
                                    v.lock();
                                    locked = true;
                                }
                            }
                        }
                        if locked {
                            let _ = app.emit("vault-locked", "blur");
                        }
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::create_vault,
            commands::unlock,
            commands::quick_unlock,
            commands::enable_quick_unlock,
            commands::disable_quick_unlock,
            commands::change_master_password,
            commands::sync_connect,
            commands::sync_disconnect,
            commands::sync_status,
            commands::sync_now,
            commands::merge_duplicates,
            commands::list_snapshots,
            commands::restore_snapshot,
            commands::export_vault_backup,
            commands::resolve_autofill_consent,
            commands::verify_passkey_approval,
            commands::cancel_passkey_verification,
            commands::lock,
            commands::touch,
            commands::list_items,
            commands::get_item,
            commands::reveal_field,
            commands::copy_field,
            commands::copy_to_clipboard,
            commands::upsert_item,
            commands::upsert_wifi,
            commands::upsert_secure_note,
            commands::wifi_qr,
            commands::generate_ssh_key,
            commands::ssh_public_key,
            commands::ssh_agent_info,
            commands::delete_item,
            commands::restore_item,
            commands::purge_item,
            commands::current_totp,
            commands::security_report,
            commands::check_breaches,
            commands::import_logins,
            commands::export_logins_csv,
            commands::open_passwords_app,
            commands::generate,
            commands::get_settings,
            commands::set_settings,
            commands::set_blur_lock_suppressed,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Arca application");
}

/// Polls once per second; locks the vault after the configured idle timeout.
fn idle_watcher(app: AppHandle) {
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let state = app.state::<Mutex<AppState>>();
        let mut locked = false;
        if let Ok(mut st) = state.lock() {
            let timeout = st.settings.auto_lock_secs;
            if timeout > 0 {
                let idle = st.last_activity.elapsed();
                if let Some(v) = st.vault.as_mut() {
                    if v.is_unlocked() && idle >= Duration::from_secs(timeout) {
                        v.lock();
                        locked = true;
                    }
                }
            }
        }
        if locked {
            let _ = app.emit("vault-locked", "idle");
        }
    }
}
