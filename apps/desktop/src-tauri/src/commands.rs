//! Tauri commands bridging the webview UI to `vault-core`/`vault-store`.
//!
//! Each `#[tauri::command]` is a thin wrapper that resolves the managed state
//! and delegates to a `do_*` function taking `&Mutex<AppState>`. The `do_*`
//! functions hold the real logic and are unit-tested directly (see the bottom
//! of this file) without needing a Tauri runtime.
//!
//! Secret-exposure policy:
//!   * `get_item` returns metadata + non-secret fields (title/username/url),
//!     never the password or TOTP secret.
//!   * Secrets cross to the UI only on explicit user action: `reveal_field`
//!     (to display) or `current_totp` (a short-lived code).
//!   * `copy_field` copies a secret to the OS clipboard via the clipboard owner
//!     thread, so the plaintext never enters the webview, and auto-clears.
//!   * Nothing here logs secrets.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

use vault_core::{
    estimate_strength, generate_password, Item, ItemKind, KdfParams, PasswordOptions,
    PasswordStrength, SecurityIssue, Vault, VaultItem,
};

use crate::state::{now_millis, now_secs, AppState, CmdError, Settings};

// ---- DTOs (camelCase for the TS frontend) ---------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    /// A vault file exists (or one is loaded in memory).
    pub exists: bool,
    pub unlocked: bool,
    /// Quick-unlock material is present in the vault header.
    pub has_quick_unlock: bool,
    /// A device key is available in the OS keychain right now.
    pub quick_unlock_available: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummaryDto {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub subtitle: String,
    /// First letter of the title, for the colored list tile.
    pub letter: String,
    pub has_totp: bool,
    pub is_deleted: bool,
    pub modified_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemDetailDto {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    /// Whether a password is set (the value itself is fetched on demand).
    pub has_password: bool,
    pub has_totp: bool,
    /// Coarse strength bucket of the stored password: "weak" | "fair" | "strong"
    /// (None when there is no password). Derived metadata, not the secret.
    pub password_strength: Option<String>,
    pub is_deleted: bool,
    pub created_at: i64,
    pub modified_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityIssueDto {
    pub id: String,
    /// Issue tags: "weak" and/or "reused".
    pub issues: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginInput {
    /// `None` to create a new item, `Some(id)` to update an existing one.
    pub id: Option<String>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub totp_secret: Option<String>,
    pub notes: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpDto {
    pub code: String,
    pub period: u64,
    pub remaining: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOptionsDto {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

// ---- helpers --------------------------------------------------------------

type St<'a> = State<'a, Mutex<AppState>>;

fn guard(state: &Mutex<AppState>) -> Result<std::sync::MutexGuard<'_, AppState>, CmdError> {
    state
        .lock()
        .map_err(|_| CmdError::new("poisoned", "Internal state error."))
}

fn kind_str(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "login",
        ItemKind::Passkey => "passkey",
        ItemKind::SecureNote => "secureNote",
    }
}

fn strength_str(s: PasswordStrength) -> &'static str {
    match s {
        PasswordStrength::Weak => "weak",
        PasswordStrength::Fair => "fair",
        PasswordStrength::Strong => "strong",
    }
}

fn issue_str(issue: SecurityIssue) -> &'static str {
    match issue {
        SecurityIssue::WeakPassword => "weak",
        SecurityIssue::ReusedPassword => "reused",
    }
}

fn parse_id(s: &str) -> Result<Uuid, CmdError> {
    Uuid::parse_str(s).map_err(|_| CmdError::new("not_found", "Invalid item id."))
}

fn first_letter(title: &str) -> String {
    title
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "#".to_string())
}

/// Persist the current vault to disk (atomic write).
fn persist(st: &AppState) -> Result<(), CmdError> {
    st.store.save(st.vault()?)?;
    Ok(())
}

fn secret_field(item: &Item, field: &str) -> Result<String, CmdError> {
    match (&item.data, field) {
        (VaultItem::Login { password, .. }, "password") => Ok(password.clone()),
        (VaultItem::Login { totp_secret, .. }, "totp_secret") => {
            Ok(totp_secret.clone().unwrap_or_default())
        }
        (VaultItem::Login { notes, .. }, "notes") => Ok(notes.clone()),
        _ => Err(CmdError::new(
            "invalid_field",
            "Unknown or unavailable field.",
        )),
    }
}

// ---- lifecycle commands ---------------------------------------------------

#[tauri::command]
pub fn vault_status(state: St<'_>) -> Result<VaultStatus, CmdError> {
    let st = guard(state.inner())?;
    Ok(VaultStatus {
        exists: st.store.exists() || st.vault.is_some(),
        unlocked: st.vault.as_ref().map(Vault::is_unlocked).unwrap_or(false),
        has_quick_unlock: st
            .vault
            .as_ref()
            .map(Vault::has_device_unlock)
            .unwrap_or(false),
        quick_unlock_available: st.store.quick_unlock_available(),
    })
}

#[tauri::command]
pub fn create_vault(state: St<'_>, master_password: String) -> Result<(), CmdError> {
    do_create_vault(state.inner(), &master_password)
}

fn do_create_vault(state: &Mutex<AppState>, master_password: &str) -> Result<(), CmdError> {
    let mut st = guard(state)?;
    if st.store.exists() {
        return Err(CmdError::new("exists", "A vault already exists."));
    }
    let params = KdfParams::new_default().map_err(CmdError::from)?;
    let vault = Vault::create(master_password, params)?;
    st.vault = Some(vault);
    persist(&st)?;
    st.touch();
    Ok(())
}

#[tauri::command]
pub fn unlock(state: St<'_>, master_password: String) -> Result<(), CmdError> {
    do_unlock(state.inner(), &master_password)
}

fn do_unlock(state: &Mutex<AppState>, master_password: &str) -> Result<(), CmdError> {
    let mut st = guard(state)?;
    // Load the locked vault from disk if it isn't in memory yet.
    if st.vault.is_none() && st.store.exists() {
        st.vault = Some(st.store.load()?);
    }
    st.vault_mut()?.unlock(master_password)?;
    st.touch();
    Ok(())
}

/// Unlock using the OS keychain device key (no master password).
#[tauri::command]
pub fn quick_unlock(state: St<'_>) -> Result<(), CmdError> {
    let mut st = guard(state.inner())?;
    if st.vault.is_none() && st.store.exists() {
        st.vault = Some(st.store.load()?);
    }
    let AppState { store, vault, .. } = &mut *st;
    let vault = vault.as_mut().ok_or_else(CmdError::no_vault)?;
    store.quick_unlock(vault)?;
    st.touch();
    Ok(())
}

#[tauri::command]
pub fn enable_quick_unlock(state: St<'_>) -> Result<(), CmdError> {
    let mut st = guard(state.inner())?;
    {
        let AppState { store, vault, .. } = &mut *st;
        let vault = vault.as_mut().ok_or_else(CmdError::no_vault)?;
        store.enable_quick_unlock(vault)?;
    }
    persist(&st)?;
    st.touch();
    Ok(())
}

#[tauri::command]
pub fn disable_quick_unlock(state: St<'_>) -> Result<(), CmdError> {
    let mut st = guard(state.inner())?;
    {
        let AppState { store, vault, .. } = &mut *st;
        let vault = vault.as_mut().ok_or_else(CmdError::no_vault)?;
        store.disable_quick_unlock(vault)?;
    }
    persist(&st)?;
    st.touch();
    Ok(())
}

#[tauri::command]
pub fn lock(state: St<'_>) -> Result<(), CmdError> {
    let mut st = guard(state.inner())?;
    if let Some(v) = st.vault.as_mut() {
        v.lock();
    }
    Ok(())
}

/// Reset the idle timer; the frontend calls this on genuine user interaction.
#[tauri::command]
pub fn touch(state: St<'_>) -> Result<(), CmdError> {
    guard(state.inner())?.touch();
    Ok(())
}

// ---- item commands --------------------------------------------------------

#[tauri::command]
pub fn list_items(state: St<'_>, include_deleted: bool) -> Result<Vec<ItemSummaryDto>, CmdError> {
    do_list_items(state.inner(), include_deleted)
}

fn do_list_items(
    state: &Mutex<AppState>,
    include_deleted: bool,
) -> Result<Vec<ItemSummaryDto>, CmdError> {
    let mut st = guard(state)?;
    st.touch();
    let summaries = st.vault()?.list_items(include_deleted)?;
    Ok(summaries
        .into_iter()
        .map(|s| ItemSummaryDto {
            id: s.id.to_string(),
            kind: kind_str(s.kind).to_string(),
            letter: first_letter(&s.title),
            title: s.title,
            subtitle: s.subtitle,
            has_totp: s.has_totp,
            is_deleted: s.is_deleted,
            modified_at: s.modified_at,
        })
        .collect())
}

#[tauri::command]
pub fn get_item(state: St<'_>, id: String) -> Result<ItemDetailDto, CmdError> {
    do_get_item(state.inner(), &id)
}

fn do_get_item(state: &Mutex<AppState>, id: &str) -> Result<ItemDetailDto, CmdError> {
    let mut st = guard(state)?;
    st.touch();
    let item = st.vault()?.get_item(parse_id(id)?)?;
    let (title, username, url, notes, has_password, has_totp, password_strength) = match &item.data
    {
        VaultItem::Login {
            title,
            username,
            url,
            notes,
            password,
            totp_secret,
        } => (
            title.clone(),
            username.clone(),
            url.clone(),
            notes.clone(),
            !password.is_empty(),
            totp_secret
                .as_deref()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            if password.is_empty() {
                None
            } else {
                Some(strength_str(estimate_strength(password)).to_string())
            },
        ),
        // Stub kinds expose only their title for now.
        other => (
            other.title().to_string(),
            String::new(),
            String::new(),
            String::new(),
            false,
            false,
            None,
        ),
    };
    Ok(ItemDetailDto {
        id: item.id.to_string(),
        kind: kind_str(item.data.kind()).to_string(),
        title,
        username,
        url,
        notes,
        has_password,
        has_totp,
        password_strength,
        is_deleted: item.is_deleted(),
        created_at: item.created_at,
        modified_at: item.modified_at,
    })
}

/// Password-health audit (weak/reused) over the active login items.
#[tauri::command]
pub fn security_report(state: St<'_>) -> Result<Vec<SecurityIssueDto>, CmdError> {
    do_security_report(state.inner())
}

fn do_security_report(state: &Mutex<AppState>) -> Result<Vec<SecurityIssueDto>, CmdError> {
    let mut st = guard(state)?;
    st.touch();
    let report = st.vault()?.security_report()?;
    Ok(report
        .into_iter()
        .map(|r| SecurityIssueDto {
            id: r.id.to_string(),
            issues: r
                .issues
                .into_iter()
                .map(|i| issue_str(i).to_string())
                .collect(),
        })
        .collect())
}

/// Reveal a single secret field on demand (for display in the UI).
/// `field` is one of `"password"`, `"totp_secret"`, `"notes"`.
#[tauri::command]
pub fn reveal_field(state: St<'_>, id: String, field: String) -> Result<String, CmdError> {
    do_reveal_field(state.inner(), &id, &field)
}

fn do_reveal_field(state: &Mutex<AppState>, id: &str, field: &str) -> Result<String, CmdError> {
    let mut st = guard(state)?;
    st.touch();
    let item = st.vault()?.get_item(parse_id(id)?)?;
    secret_field(&item, field)
}

/// Copy a secret field to the clipboard via the owner thread (plaintext never
/// reaches the webview); auto-clears after the configured timeout.
#[tauri::command]
pub fn copy_field(state: St<'_>, id: String, field: String) -> Result<(), CmdError> {
    do_copy_field(state.inner(), &id, &field)
}

fn do_copy_field(state: &Mutex<AppState>, id: &str, field: &str) -> Result<(), CmdError> {
    let (clipboard, text, clear_secs) = {
        let mut st = guard(state)?;
        st.touch();
        let item = st.vault()?.get_item(parse_id(id)?)?;
        (
            st.clipboard.clone(),
            secret_field(&item, field)?,
            st.settings.clipboard_clear_secs,
        )
    }; // release the lock before handing off to the clipboard thread
    clipboard.copy(text, clear_secs);
    Ok(())
}

/// Copy arbitrary (non-secret, e.g. username) text to the clipboard, also with
/// auto-clear for consistency.
#[tauri::command]
pub fn copy_to_clipboard(state: St<'_>, text: String) -> Result<(), CmdError> {
    let (clipboard, clear_secs) = {
        let mut st = guard(state.inner())?;
        st.touch();
        (st.clipboard.clone(), st.settings.clipboard_clear_secs)
    };
    clipboard.copy(text, clear_secs);
    Ok(())
}

#[tauri::command]
pub fn upsert_item(state: St<'_>, input: LoginInput) -> Result<String, CmdError> {
    do_upsert_item(state.inner(), input)
}

fn do_upsert_item(state: &Mutex<AppState>, input: LoginInput) -> Result<String, CmdError> {
    let mut st = guard(state)?;
    st.touch();
    let now = now_millis();
    let data = VaultItem::Login {
        title: input.title,
        username: input.username,
        password: input.password,
        url: input.url,
        totp_secret: input.totp_secret.filter(|s| !s.trim().is_empty()),
        notes: input.notes,
    };

    let id = match input.id {
        Some(id_str) => {
            let uuid = parse_id(&id_str)?;
            // Preserve the original creation time on edit.
            let mut existing = st.vault()?.get_item(uuid)?;
            existing.data = data;
            existing.modified_at = now;
            st.vault_mut()?.upsert_item(existing)?;
            uuid
        }
        None => {
            let item = Item::new(data, now);
            let new_id = item.id;
            st.vault_mut()?.upsert_item(item)?;
            new_id
        }
    };
    persist(&st)?;
    Ok(id.to_string())
}

#[tauri::command]
pub fn delete_item(state: St<'_>, id: String) -> Result<(), CmdError> {
    do_delete_item(state.inner(), &id)
}

fn do_delete_item(state: &Mutex<AppState>, id: &str) -> Result<(), CmdError> {
    let mut st = guard(state)?;
    st.touch();
    let uuid = parse_id(id)?;
    st.vault_mut()?.delete_item(uuid, now_millis())?;
    persist(&st)?;
    Ok(())
}

#[tauri::command]
pub fn restore_item(state: St<'_>, id: String) -> Result<(), CmdError> {
    do_restore_item(state.inner(), &id)
}

fn do_restore_item(state: &Mutex<AppState>, id: &str) -> Result<(), CmdError> {
    let mut st = guard(state)?;
    st.touch();
    let uuid = parse_id(id)?;
    st.vault_mut()?.restore_item(uuid, now_millis())?;
    persist(&st)?;
    Ok(())
}

#[tauri::command]
pub fn purge_item(state: St<'_>, id: String) -> Result<(), CmdError> {
    do_purge_item(state.inner(), &id)
}

fn do_purge_item(state: &Mutex<AppState>, id: &str) -> Result<(), CmdError> {
    let mut st = guard(state)?;
    st.touch();
    let uuid = parse_id(id)?;
    st.vault_mut()?.purge_item(uuid)?;
    persist(&st)?;
    Ok(())
}

#[tauri::command]
pub fn current_totp(state: St<'_>, id: String) -> Result<TotpDto, CmdError> {
    // Intentionally does NOT touch() — the UI polls this on a timer.
    let st = guard(state.inner())?;
    let item = st.vault()?.get_item(parse_id(&id)?)?;
    let secret = match &item.data {
        VaultItem::Login {
            totp_secret: Some(s),
            ..
        } if !s.is_empty() => s.clone(),
        _ => return Err(CmdError::new("no_totp", "This item has no TOTP secret.")),
    };
    let code = vault_core::current_totp(&secret, now_secs())?;
    Ok(TotpDto {
        code: code.code,
        period: code.period,
        remaining: code.remaining,
    })
}

// ---- utilities ------------------------------------------------------------

#[tauri::command]
pub fn generate(state: St<'_>, options: PasswordOptionsDto) -> Result<String, CmdError> {
    guard(state.inner())?.touch();
    let opts = PasswordOptions {
        length: options.length,
        lowercase: options.lowercase,
        uppercase: options.uppercase,
        digits: options.digits,
        symbols: options.symbols,
    };
    let pw = generate_password(&opts)?;
    Ok(pw.to_string())
}

#[tauri::command]
pub fn get_settings(state: St<'_>) -> Result<Settings, CmdError> {
    Ok(guard(state.inner())?.settings)
}

#[tauri::command]
pub fn set_settings(state: St<'_>, settings: Settings) -> Result<(), CmdError> {
    let mut st = guard(state.inner())?;
    st.settings = settings;
    st.touch();
    Ok(())
}

// ---- tests (drive the do_* functions directly, no Tauri runtime) ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::{ClipboardManager, ClipboardProbe};
    use tempfile::TempDir;
    use vault_core::KdfAlgorithm;
    use vault_store::VaultStore;

    /// Cheap KDF so tests don't spend 64 MiB each (real vaults use defaults).
    fn cheap_params() -> KdfParams {
        KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![5u8; KdfParams::SALT_LEN],
        }
    }

    /// A state with an already-unlocked, cheap-KDF vault wired to a temp store
    /// and an in-memory clipboard probe.
    fn unlocked(dir: &TempDir) -> (Mutex<AppState>, ClipboardProbe) {
        let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
        let vault = Vault::create("pw", cheap_params()).unwrap();
        let (clip, probe) = ClipboardManager::memory();
        (Mutex::new(AppState::new(store, Some(vault), clip)), probe)
    }

    fn sample_input() -> LoginInput {
        LoginInput {
            id: None,
            title: "GitHub".into(),
            username: "frank-lia".into(),
            password: "p4ss".into(),
            url: "https://github.com".into(),
            totp_secret: Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
            notes: "note".into(),
        }
    }

    #[test]
    fn create_then_wrong_then_right_unlock() {
        let dir = TempDir::new().unwrap();
        let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
        let (clip, _) = ClipboardManager::memory();
        let state = Mutex::new(AppState::new(store, None, clip));

        do_create_vault(&state, "master").unwrap(); // production KDF; one test
        assert!(guard(&state).unwrap().vault().unwrap().is_unlocked());

        guard(&state).unwrap().vault_mut().unwrap().lock();
        assert!(matches!(do_unlock(&state, "nope"), Err(e) if e.code == "invalid_credentials"));
        do_unlock(&state, "master").unwrap();
        assert!(guard(&state).unwrap().vault().unwrap().is_unlocked());
    }

    #[test]
    fn upsert_list_get_roundtrip_with_dto_flags() {
        let dir = TempDir::new().unwrap();
        let (state, _probe) = unlocked(&dir);

        let id = do_upsert_item(&state, sample_input()).unwrap();
        let list = do_list_items(&state, false).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].title, "GitHub");
        assert_eq!(list[0].letter, "G");
        assert!(list[0].has_totp);

        let detail = do_get_item(&state, &id).unwrap();
        assert_eq!(detail.username, "frank-lia");
        assert_eq!(detail.url, "https://github.com");
        assert!(detail.has_password);
        assert!(detail.has_totp);
        // The detail DTO has no field that could carry the password/secret.
    }

    #[test]
    fn editing_preserves_created_at() {
        let dir = TempDir::new().unwrap();
        let (state, _) = unlocked(&dir);
        let id = do_upsert_item(&state, sample_input()).unwrap();
        let created = do_get_item(&state, &id).unwrap().created_at;

        let mut edit = sample_input();
        edit.id = Some(id.clone());
        edit.title = "GitHub (work)".into();
        do_upsert_item(&state, edit).unwrap();

        let after = do_get_item(&state, &id).unwrap();
        assert_eq!(after.title, "GitHub (work)");
        assert_eq!(after.created_at, created); // preserved on edit
        assert!(after.modified_at >= created);
    }

    #[test]
    fn reveal_and_copy_route_the_correct_secret() {
        let dir = TempDir::new().unwrap();
        let (state, probe) = unlocked(&dir);
        let id = do_upsert_item(&state, sample_input()).unwrap();

        assert_eq!(do_reveal_field(&state, &id, "password").unwrap(), "p4ss");

        do_copy_field(&state, &id, "password").unwrap();
        // Flush the clipboard owner thread, then confirm it still holds the
        // value after the command returned (the ownership-drop guard).
        guard(&state).unwrap().clipboard.sync();
        assert_eq!(probe.current().as_deref(), Some("p4ss"));
    }

    #[test]
    fn soft_delete_restore_then_purge() {
        let dir = TempDir::new().unwrap();
        let (state, _) = unlocked(&dir);
        let id = do_upsert_item(&state, sample_input()).unwrap();

        do_delete_item(&state, &id).unwrap();
        assert_eq!(do_list_items(&state, false).unwrap().len(), 0);
        assert_eq!(do_list_items(&state, true).unwrap().len(), 1);

        do_restore_item(&state, &id).unwrap();
        assert_eq!(do_list_items(&state, false).unwrap().len(), 1);

        do_delete_item(&state, &id).unwrap();
        do_purge_item(&state, &id).unwrap();
        assert_eq!(do_list_items(&state, true).unwrap().len(), 0);
    }

    #[test]
    fn item_ops_require_an_unlocked_vault() {
        let dir = TempDir::new().unwrap();
        let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
        let (clip, _) = ClipboardManager::memory();
        let locked = {
            let mut v = Vault::create("pw", cheap_params()).unwrap();
            v.lock();
            v
        };
        let state = Mutex::new(AppState::new(store, Some(locked), clip));
        assert!(matches!(do_list_items(&state, false), Err(e) if e.code == "locked"));
    }

    #[test]
    fn persisted_changes_survive_reload() {
        let dir = TempDir::new().unwrap();
        let (state, _) = unlocked(&dir);
        let id = do_upsert_item(&state, sample_input()).unwrap();

        // Reload the vault file from disk into a fresh state and unlock it.
        let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
        let (clip, _) = ClipboardManager::memory();
        let reloaded = Mutex::new(AppState::new(store, None, clip));
        do_unlock(&reloaded, "pw").unwrap();

        assert_eq!(do_get_item(&reloaded, &id).unwrap().title, "GitHub");
    }

    #[test]
    fn get_item_reports_password_strength() {
        let dir = TempDir::new().unwrap();
        let (state, _) = unlocked(&dir);

        let weak_id = do_upsert_item(&state, sample_input()).unwrap(); // "p4ss"
        assert_eq!(
            do_get_item(&state, &weak_id)
                .unwrap()
                .password_strength
                .as_deref(),
            Some("weak")
        );

        let mut strong = sample_input();
        strong.password = "wf*QB(=0QIc0.Z^RI,A6".into();
        let strong_id = do_upsert_item(&state, strong).unwrap();
        assert_eq!(
            do_get_item(&state, &strong_id)
                .unwrap()
                .password_strength
                .as_deref(),
            Some("strong")
        );
    }

    #[test]
    fn security_report_flags_weak_and_reused() {
        let dir = TempDir::new().unwrap();
        let (state, _) = unlocked(&dir);

        // Two items share a strong password (reused), one item is weak.
        let mut a = sample_input();
        a.title = "A".into();
        a.password = "Sh4red&Strong!2024xyz".into();
        let a_id = do_upsert_item(&state, a).unwrap();

        let mut b = sample_input();
        b.title = "B".into();
        b.password = "Sh4red&Strong!2024xyz".into();
        do_upsert_item(&state, b).unwrap();

        let mut c = sample_input();
        c.title = "C".into();
        c.password = "abc".into();
        do_upsert_item(&state, c).unwrap();

        let report = do_security_report(&state).unwrap();
        // A + B flagged reused; C flagged weak. (sample_input's TOTP doesn't matter.)
        assert_eq!(report.len(), 3);
        let a_issues = &report.iter().find(|r| r.id == a_id).unwrap().issues;
        assert!(a_issues.contains(&"reused".to_string()));
    }
}
