// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod clipboard;
mod commands;
mod state;

use std::sync::Mutex;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, WindowEvent};
use vault_store::VaultStore;

use clipboard::ClipboardManager;
use state::AppState;

/// OS keychain namespace for the device (quick-unlock) key.
const KEYCHAIN_SERVICE: &str = "no.sybr.vault";
const KEYCHAIN_ACCOUNT: &str = "default-vault";

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // Resolve a per-user data directory for the single vault file.
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir).ok();
            let vault_path = data_dir.join("default.vault");

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

            app.manage(Mutex::new(AppState::new(store, vault, clipboard)));

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
                        let lock_on_blur = st.settings.lock_on_blur;
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
            commands::generate,
            commands::get_settings,
            commands::set_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the SYBR Passwords application");
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
