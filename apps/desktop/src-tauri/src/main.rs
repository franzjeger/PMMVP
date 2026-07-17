// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod biometric;
mod bridge;
mod clipboard;
mod commands;
mod state;

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

/// Resolve where the vault file lives.
///
/// On macOS it belongs in the shared App Group container so the sandboxed
/// AutoFill extension can read it. On first run we migrate an existing vault
/// (and its settings) into the container, **keeping the original as a backup**
/// (never deleted). If the container can't be reached (e.g. the entitlement
/// isn't provisioned), we fall back to the app-data path so the app keeps
/// working — only cross-app autofill is unavailable. Other platforms always use
/// the app-data path.
fn resolve_vault_path(app: &tauri::App, data_dir: &Path) -> PathBuf {
    let app_data_vault = data_dir.join("default.vault");
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = app.path().home_dir() {
            let container = home.join("Library/Group Containers").join(APP_GROUP);
            if std::fs::create_dir_all(&container).is_ok() {
                let shared_vault = container.join("default.vault");
                // Migrate once: copy the vault + settings, keep originals.
                if !shared_vault.exists()
                    && app_data_vault.exists()
                    && std::fs::copy(&app_data_vault, &shared_vault).is_ok()
                {
                    let old_settings = data_dir.join("settings.json");
                    if old_settings.exists() {
                        let _ = std::fs::copy(&old_settings, container.join("settings.json"));
                    }
                }
                // Use the shared vault if it exists (migrated) or there is no
                // app-data vault to fall back to.
                if shared_vault.exists() || !app_data_vault.exists() {
                    return shared_vault;
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

            // Local autofill bridge for the browser extension (loopback + token;
            // gated on unlock + origin match). Best-effort: failure to bind just
            // means autofill is unavailable this session.
            if let Err(e) = bridge::start(app.handle().clone(), &data_dir) {
                eprintln!("autofill bridge unavailable: {e}");
            }

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
            commands::resolve_autofill_consent,
            commands::lock,
            commands::touch,
            commands::list_items,
            commands::get_item,
            commands::reveal_field,
            commands::copy_field,
            commands::copy_to_clipboard,
            commands::upsert_item,
            commands::delete_item,
            commands::restore_item,
            commands::purge_item,
            commands::current_totp,
            commands::security_report,
            commands::import_logins,
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
