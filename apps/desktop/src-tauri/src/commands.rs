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
    /// Biometric (Touch ID) authentication is wired on this platform, so quick
    /// unlock can be gated behind it.
    pub biometric_available: bool,
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
    /// Normalized website host ("github.com"; empty when the item has no URL),
    /// using the same normalization as autofill matching. The list groups
    /// entries that share a host.
    pub host: String,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummary {
    /// Logins added to the vault.
    pub imported: usize,
    /// Existing logins (same site + username) whose password changed and was
    /// updated in place.
    pub updated: usize,
    /// Rows identical to an existing login (same site + username + password),
    /// skipped so re-importing an export never creates copies.
    pub duplicates: usize,
    /// Rows skipped (blank, or no username and no password).
    pub skipped: usize,
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
        ItemKind::SshKey => "sshKey",
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

/// Persist the current vault to disk (atomic write). Sync-aware: if a synced
/// peer rewrote the file, its changes are merged in first so they aren't
/// clobbered (see [`vault_store::VaultStore::save_synced`]).
fn persist(st: &mut AppState) -> Result<(), CmdError> {
    let AppState { store, vault, .. } = st;
    let vault = vault
        .as_mut()
        .ok_or_else(|| CmdError::new("no_vault", "No vault is loaded."))?;
    store.save_synced(vault)?;
    // Local state changed: let the cloud-sync loop know there is work.
    crate::sync::mark_dirty();
    Ok(())
}

/// Accept either a raw Base32 secret or a full `otpauth://` URI for the TOTP
/// field, normalizing to the stored Base32 secret. Empty input -> `None`.
fn normalize_totp_secret(raw: Option<String>) -> Result<Option<String>, CmdError> {
    match raw {
        Some(s) if !s.trim().is_empty() => {
            let s = s.trim();
            if s.to_ascii_lowercase().starts_with("otpauth://") {
                Ok(Some(vault_core::parse_otpauth_uri(s)?.secret))
            } else {
                Ok(Some(s.to_string()))
            }
        }
        _ => Ok(None),
    }
}

/// A login parsed from one CSV row. `totp` is raw (Base32 or `otpauth://`),
/// normalized later via [`normalize_totp_secret`].
struct ParsedLogin {
    title: String,
    username: String,
    password: String,
    url: String,
    totp: String,
    notes: String,
}

/// Column indices discovered from the CSV header.
#[derive(Default)]
struct ColumnMap {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    totp: Option<usize>,
    notes: Option<usize>,
}

/// Derive a title when the export has none: site host, else username, else a
/// generic label.
fn title_from(url: &str, username: &str) -> String {
    let host = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .trim();
    if !host.is_empty() {
        host.to_string()
    } else if !username.is_empty() {
        username.to_string()
    } else {
        "Imported".to_string()
    }
}

/// Parse a password-export CSV (Chrome/Brave/Edge, Apple Passwords, Firefox, and
/// common generic layouts) by mapping header names case-insensitively. Returns
/// the parsed logins plus the count of skipped (blank / credential-less) rows.
fn parse_logins_csv(text: &str) -> (Vec<ParsedLogin>, usize) {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(text.as_bytes());

    let headers = match reader.headers() {
        Ok(h) => h.clone(),
        Err(_) => return (Vec::new(), 0),
    };

    let mut map = ColumnMap::default();
    for (i, h) in headers.iter().enumerate() {
        match h.trim().to_ascii_lowercase().as_str() {
            "title" | "name" => _ = map.title.get_or_insert(i),
            "url" | "urls" | "website" | "login_uri" | "loginuri" => _ = map.url.get_or_insert(i),
            "username" | "user" | "login" | "email" | "login_username" => {
                _ = map.username.get_or_insert(i)
            }
            "password" | "pwd" | "login_password" => _ = map.password.get_or_insert(i),
            "notes" | "note" | "comment" | "comments" => _ = map.notes.get_or_insert(i),
            "otpauth" | "otp" | "totp" | "otp_auth" | "totpauth" | "2fa" => {
                _ = map.totp.get_or_insert(i)
            }
            _ => {}
        }
    }

    let mut logins = Vec::new();
    let mut skipped = 0usize;
    for record in reader.records().flatten() {
        let cell = |col: Option<usize>| -> String {
            col.and_then(|i| record.get(i))
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let username = cell(map.username);
        let password = cell(map.password);
        if username.is_empty() && password.is_empty() {
            skipped += 1;
            continue;
        }
        let url = cell(map.url);
        let mut title = cell(map.title);
        if title.is_empty() {
            title = title_from(&url, &username);
        }
        logins.push(ParsedLogin {
            title,
            username,
            password,
            url,
            totp: cell(map.totp),
            notes: cell(map.notes),
        });
    }
    (logins, skipped)
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
        biometric_available: crate::biometric::available(),
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
    persist(&mut st)?;
    st.touch();
    Ok(())
}

/// Kick a background sync right away (used after unlock so peer changes land
/// immediately instead of waiting for the next 30s tick — while locked, the
/// background loop skips cycles by design).
fn kick_sync(app: &tauri::AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        let _ = crate::sync::sync_now(&app);
    });
}

#[tauri::command]
pub fn unlock(
    app: tauri::AppHandle,
    state: St<'_>,
    master_password: String,
) -> Result<(), CmdError> {
    do_unlock(state.inner(), &master_password)?;
    kick_sync(&app);
    Ok(())
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

/// Unlock using the OS keychain device key (no master password), gated behind a
/// biometric (Touch ID) prompt where available.
#[tauri::command]
pub fn quick_unlock(app: tauri::AppHandle, state: St<'_>) -> Result<(), CmdError> {
    // Prompt for Touch ID *before* taking the state lock — the prompt blocks on
    // user interaction, and we must not freeze other commands meanwhile.
    //
    // On macOS the device key itself carries a biometric access control, so
    // reading it (in `store.quick_unlock` below) already prompts Touch ID; a
    // second app-level prompt here would double it. On Windows/Linux the key is
    // not OS-gated, so this app-level biometric prompt is the gate.
    #[cfg(not(target_os = "macos"))]
    crate::biometric::authenticate("unlock your password vault")
        .map_err(|m| CmdError::new("biometric_failed", &m))?;

    let mut st = guard(state.inner())?;
    if st.vault.is_none() && st.store.exists() {
        st.vault = Some(st.store.load()?);
    }
    let AppState { store, vault, .. } = &mut *st;
    let vault = vault.as_mut().ok_or_else(CmdError::no_vault)?;
    store.quick_unlock(vault)?;
    st.touch();
    drop(st);
    kick_sync(&app);
    Ok(())
}

/// Deliver the user's Allow/Deny decision for a pending autofill-consent prompt
/// to the parked bridge thread (see `bridge::PendingConsents`).
#[tauri::command]
pub fn resolve_autofill_consent(app: tauri::AppHandle, id: String, approved: bool) {
    crate::bridge::resolve_consent(&app, &id, approved);
}

/// User verification for a pending passkey ceremony (Windows/Linux, where the OS
/// Hello dialog can't take input when invoked from our background bridge thread).
/// Checks the master password against the unlocked vault; on success, resolves
/// the parked bridge thread with `true` (UV satisfied). Returns whether the
/// password was correct so the dialog can show a retry hint — a wrong password
/// does NOT resolve/deny, letting the user retry until they cancel or it times
/// out. Cancelling reuses `resolve_autofill_consent(id, false)`.
#[tauri::command]
pub fn verify_passkey_approval(
    app: tauri::AppHandle,
    state: St<'_>,
    id: String,
    master_password: String,
) -> Result<bool, CmdError> {
    let ok = {
        let st = guard(state.inner())?;
        let vault = st.vault.as_ref().ok_or_else(CmdError::no_vault)?;
        if !vault.is_unlocked() {
            return Err(CmdError::new("locked", "Vault is locked"));
        }
        vault.verify_master_password(&master_password)
    };
    if ok {
        crate::bridge::resolve_consent(&app, &id, true);
    }
    Ok(ok)
}

#[tauri::command]
pub fn enable_quick_unlock(state: St<'_>) -> Result<(), CmdError> {
    let mut st = guard(state.inner())?;
    {
        let AppState { store, vault, .. } = &mut *st;
        let vault = vault.as_mut().ok_or_else(CmdError::no_vault)?;
        store.enable_quick_unlock(vault)?;
    }
    persist(&mut st)?;
    st.touch();
    Ok(())
}

/// Merge duplicate logins (same site + username). Losers go to the Trash;
/// returns how many were merged away.
#[tauri::command]
pub fn merge_duplicates(state: St<'_>) -> Result<usize, CmdError> {
    let mut st = guard(state.inner())?;
    let merged = {
        let vault = st.vault.as_mut().ok_or_else(CmdError::no_vault)?;
        vault.merge_duplicate_logins(crate::state::now_millis())?
    };
    if merged > 0 {
        persist(&mut st)?;
    }
    st.touch();
    Ok(merged)
}

// ---- Google Drive sync ----------------------------------------------------

/// Interactive Google sign-in (opens the browser; blocks until the redirect).
/// Runs the flow on a thread via async so the UI stays responsive.
#[tauri::command]
pub async fn sync_connect(app: tauri::AppHandle) -> Result<String, CmdError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::connect(&app).map_err(|m| CmdError::new("sync_connect", &m))
    })
    .await
    .map_err(|_| CmdError::new("internal", "sign-in task failed"))?
}

#[tauri::command]
pub fn sync_disconnect(app: tauri::AppHandle) {
    crate::sync::disconnect(&app);
}

#[tauri::command]
pub fn sync_status(app: tauri::AppHandle) -> crate::sync::SyncStatusDto {
    crate::sync::status(&app)
}

/// One manual sync cycle; returns true if remote changes were merged in.
#[tauri::command]
pub async fn sync_now(app: tauri::AppHandle) -> Result<bool, CmdError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::sync_now(&app).map_err(|m| CmdError::new("sync_failed", &m))
    })
    .await
    .map_err(|_| CmdError::new("internal", "sync task failed"))?
}

/// Re-key the vault under a new master password. Requires an unlocked vault and
/// a fresh biometric re-auth (Touch ID / Windows Hello; no-op where absent) so a
/// walk-up attacker at an unlocked machine can't silently rotate the password
/// and lock the owner out. Quick-unlock stays valid: the device-wrapped copy of
/// the vault key is untouched by rotation.
#[tauri::command]
pub fn change_master_password(state: St<'_>, new_password: String) -> Result<(), CmdError> {
    if new_password.chars().count() < 8 {
        return Err(CmdError::new(
            "weak_password",
            "Use at least 8 characters for the master password.",
        ));
    }
    // Re-auth BEFORE taking the state lock (the prompt blocks on the user).
    crate::biometric::authenticate("change your master password")
        .map_err(|m| CmdError::new("biometric_failed", &m))?;

    let mut st = guard(state.inner())?;
    {
        let vault = st.vault.as_mut().ok_or_else(CmdError::no_vault)?;
        vault.change_master_password(&new_password)?;
    }
    persist(&mut st)?;
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
    persist(&mut st)?;
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
            host: crate::bridge::host_of(&s.url),
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

/// Import logins from a CSV export at `path` (Chrome/Brave/Edge, Apple
/// Passwords, Firefox, or a generic header-mapped layout). The file is read in
/// Rust, so the exported plaintext passwords never pass through the webview.
#[tauri::command]
pub fn import_logins(state: St<'_>, path: String) -> Result<ImportSummary, CmdError> {
    do_import_logins(state.inner(), &path)
}

fn do_import_logins(state: &Mutex<AppState>, path: &str) -> Result<ImportSummary, CmdError> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| CmdError::new("io", "Could not read the selected file."))?;
    let (parsed, skipped) = parse_logins_csv(&text);

    let mut st = guard(state)?;
    st.touch();
    let now = now_millis();

    // Index existing active logins by (normalized host, lowercased username) so
    // re-importing an export updates/skips instead of duplicating. Entries
    // without a URL are never merged (a bare username is too weak an identity).
    let mut by_key: std::collections::HashMap<(String, String), Uuid> = st
        .vault()?
        .list_items(false)?
        .into_iter()
        .filter(|s| !crate::bridge::host_of(&s.url).is_empty())
        .map(|s| {
            let key = (crate::bridge::host_of(&s.url), s.subtitle.to_lowercase());
            (key, s.id)
        })
        .collect();

    let mut imported = 0usize;
    let mut updated = 0usize;
    let mut duplicates = 0usize;
    for p in parsed {
        // A bad/unsupported TOTP value shouldn't drop the whole login: keep the
        // credentials and just omit the code.
        let totp_secret = normalize_totp_secret(if p.totp.is_empty() {
            None
        } else {
            Some(p.totp)
        })
        .unwrap_or(None);

        let host = crate::bridge::host_of(&p.url);
        let key = (host.clone(), p.username.to_lowercase());
        let existing = if host.is_empty() {
            None
        } else {
            by_key.get(&key).copied()
        };

        if let Some(id) = existing {
            let current = st.vault()?.get_item(id)?;
            let (cur_title, cur_username, cur_url, cur_password, cur_totp, cur_notes) =
                match &current.data {
                    VaultItem::Login {
                        title,
                        username,
                        url,
                        password,
                        totp_secret,
                        notes,
                    } => (
                        title.clone(),
                        username.clone(),
                        url.clone(),
                        password.clone(),
                        totp_secret.clone(),
                        notes.clone(),
                    ),
                    // The merge key comes from a Login summary, so a non-Login
                    // hit is impossible; treat it as "not found" defensively.
                    _ => {
                        let item = Item::new(
                            VaultItem::Login {
                                title: p.title,
                                username: p.username,
                                password: p.password,
                                url: p.url,
                                totp_secret,
                                notes: p.notes,
                            },
                            now,
                        );
                        st.vault_mut()?.upsert_item(item)?;
                        imported += 1;
                        continue;
                    }
                };

            // Merge, never destroy: an empty CSV column keeps the existing
            // value (so a username-only row can't wipe a stored password, and a
            // browser export without TOTP/notes doesn't erase them). Title/URL/
            // username are the user's to own — imports refresh secrets, they
            // don't overwrite labels the user may have customized.
            let new_password = if p.password.is_empty() {
                cur_password.clone()
            } else {
                p.password
            };
            let new_totp = totp_secret.or_else(|| cur_totp.clone());
            let new_notes = if p.notes.is_empty() {
                cur_notes.clone()
            } else {
                p.notes
            };

            let changed =
                new_password != cur_password || new_totp != cur_totp || new_notes != cur_notes;
            if !changed {
                duplicates += 1;
                continue;
            }

            let item = Item {
                id: current.id,
                created_at: current.created_at,
                modified_at: now,
                deleted_at: None,
                data: VaultItem::Login {
                    title: cur_title,
                    username: cur_username,
                    url: cur_url,
                    password: new_password,
                    totp_secret: new_totp,
                    notes: new_notes,
                },
            };
            st.vault_mut()?.upsert_item(item)?;
            updated += 1;
            continue;
        }

        let item = Item::new(
            VaultItem::Login {
                title: p.title,
                username: p.username,
                password: p.password,
                url: p.url,
                totp_secret,
                notes: p.notes,
            },
            now,
        );
        // Register the new item so a second row for the same site + username
        // within this file dedupes against it instead of importing twice.
        if !host.is_empty() {
            by_key.insert(key, item.id);
        }
        st.vault_mut()?.upsert_item(item)?;
        imported += 1;
    }
    if imported > 0 || updated > 0 {
        persist(&mut st)?;
    }
    Ok(ImportSummary {
        imported,
        updated,
        duplicates,
        skipped,
    })
}

/// Open the system password manager app (macOS "Passwords"), as a convenience
/// next to the Safari/Apple import instructions. No-op elsewhere.
#[tauri::command]
pub fn open_passwords_app() -> Result<(), CmdError> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .args(["-a", "Passwords"])
            .spawn()
            .map_err(|_| CmdError::new("io", "Could not open the Passwords app."))?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CmdError::new(
            "unsupported",
            "Opening the system password manager is only wired up on macOS.",
        ))
    }
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

pub(crate) fn do_upsert_item(
    state: &Mutex<AppState>,
    input: LoginInput,
) -> Result<String, CmdError> {
    let mut st = guard(state)?;
    st.touch();
    let now = now_millis();
    let data = VaultItem::Login {
        title: input.title,
        username: input.username,
        password: input.password,
        url: input.url,
        totp_secret: normalize_totp_secret(input.totp_secret)?,
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
    persist(&mut st)?;
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
    persist(&mut st)?;
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
    persist(&mut st)?;
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
    persist(&mut st)?;
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
    // Persist (best-effort; settings are non-secret).
    let _ = crate::state::save_settings(st.store.path(), &st.settings);
    st.touch();
    Ok(())
}

/// Temporarily suppress blur-based auto-lock. The frontend sets this around its
/// own native dialogs (e.g. the import file picker), which blur the main window
/// without the user actually leaving the app.
#[tauri::command]
pub fn set_blur_lock_suppressed(state: St<'_>, suppressed: bool) -> Result<(), CmdError> {
    guard(state.inner())?.suppress_blur_lock = suppressed;
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
    fn list_items_reports_the_normalized_host_for_grouping() {
        let dir = TempDir::new().unwrap();
        let (state, _) = unlocked(&dir);

        // Messy-but-equivalent URLs normalize to the same host; no URL -> "".
        let mut a = sample_input();
        a.title = "GitHub (work)".into();
        a.url = "https://www.github.com/login?next=/".into();
        do_upsert_item(&state, a).unwrap();
        let mut b = sample_input();
        b.title = "GitHub (privat)".into();
        b.url = "github.com".into();
        do_upsert_item(&state, b).unwrap();
        let mut c = sample_input();
        c.title = "Uten nettsted".into();
        c.url = String::new();
        do_upsert_item(&state, c).unwrap();

        let list = do_list_items(&state, false).unwrap();
        let host_by_title = |t: &str| {
            list.iter()
                .find(|i| i.title == t)
                .map(|i| i.host.clone())
                .unwrap()
        };
        assert_eq!(host_by_title("GitHub (work)"), "github.com");
        assert_eq!(host_by_title("GitHub (privat)"), "github.com");
        assert_eq!(host_by_title("Uten nettsted"), "");
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
    fn upsert_accepts_otpauth_uri_and_stores_base32_secret() {
        let dir = TempDir::new().unwrap();
        let (state, _) = unlocked(&dir);

        let mut input = sample_input();
        input.totp_secret = Some(
            "otpauth://totp/GitHub:frank?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub"
                .into(),
        );
        let id = do_upsert_item(&state, input).unwrap();

        assert!(do_get_item(&state, &id).unwrap().has_totp);
        // The stored secret is the extracted Base32, not the raw URI.
        assert_eq!(
            do_reveal_field(&state, &id, "totp_secret").unwrap(),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }

    #[test]
    fn upsert_rejects_otpauth_with_unsupported_params() {
        let dir = TempDir::new().unwrap();
        let (state, _) = unlocked(&dir);
        let mut input = sample_input();
        input.totp_secret = Some("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=8".into());
        assert!(matches!(do_upsert_item(&state, input), Err(e) if e.code == "invalid_argument"));
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

    #[test]
    fn parse_chrome_csv() {
        let csv = "name,url,username,password,note\n\
                   GitHub,https://github.com,frank-lia,p4ss,my note\n\
                   ,https://x.com/login,user2,pw2,\n";
        let (logins, skipped) = parse_logins_csv(csv);
        assert_eq!(skipped, 0);
        assert_eq!(logins.len(), 2);
        assert_eq!(logins[0].title, "GitHub");
        assert_eq!(logins[0].username, "frank-lia");
        assert_eq!(logins[0].notes, "my note");
        // No title column value -> derived from the URL host.
        assert_eq!(logins[1].title, "x.com");
    }

    #[test]
    fn parse_apple_csv_keeps_otpauth_and_skips_blank_rows() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
                   Bank,https://bank.com,me,secret,\"a, b\",otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQ\n\
                   ,,,,,\n";
        let (logins, skipped) = parse_logins_csv(csv);
        assert_eq!(logins.len(), 1);
        assert_eq!(skipped, 1); // the empty row
        assert_eq!(logins[0].notes, "a, b"); // quoted comma preserved
        assert!(logins[0].totp.starts_with("otpauth://"));
    }

    #[test]
    fn do_import_logins_adds_items_and_normalizes_totp() {
        let dir = TempDir::new().unwrap();
        let (state, _) = unlocked(&dir);
        let csv_path = dir.path().join("export.csv");
        std::fs::write(
            &csv_path,
            "Title,URL,Username,Password,OTPAuth\n\
             Bank,https://bank.com,me,secret,otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQ\n\
             Mail,https://mail.com,you,hunter2,\n\
             ,,,,\n",
        )
        .unwrap();

        let summary = do_import_logins(&state, csv_path.to_str().unwrap()).unwrap();
        assert_eq!(summary.imported, 2);
        assert_eq!(summary.skipped, 1);

        let list = do_list_items(&state, false).unwrap();
        assert_eq!(list.len(), 2);
        let bank = list.iter().find(|i| i.title == "Bank").unwrap();
        assert!(bank.has_totp); // otpauth normalized to a stored secret
    }

    #[test]
    fn reimport_dedupes_and_updates_instead_of_duplicating() {
        let dir = TempDir::new().unwrap();
        let (state, _) = unlocked(&dir);
        let write = |name: &str, body: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, body).unwrap();
            p
        };

        let first = write(
            "a.csv",
            "name,url,username,password,otpauth,notes\n\
             Bank,https://www.bank.com/login,Me@Bank.com,old-secret,otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQ,viktig notat\n\
             NoUrl,,someone,pw1,,\n",
        );
        let s1 = do_import_logins(&state, first.to_str().unwrap()).unwrap();
        assert_eq!((s1.imported, s1.updated, s1.duplicates), (2, 0, 0));
        let bank_id = do_list_items(&state, false)
            .unwrap()
            .into_iter()
            .find(|i| i.title == "Bank")
            .unwrap()
            .id;

        // Re-import: same login (messier URL + different username case) with an
        // unchanged password is a duplicate; a changed password updates the
        // EXISTING item; a URL-less row never merges.
        let second = write(
            "b.csv",
            "name,url,username,password\n\
             Bank,bank.com,me@bank.com,old-secret\n\
             NoUrl,,someone,pw1\n",
        );
        let s2 = do_import_logins(&state, second.to_str().unwrap()).unwrap();
        assert_eq!((s2.imported, s2.updated, s2.duplicates), (1, 0, 1));

        let third = write(
            "c.csv",
            "name,url,username,password\n\
             Bank,https://bank.com,me@bank.com,NEW-secret\n",
        );
        let s3 = do_import_logins(&state, third.to_str().unwrap()).unwrap();
        assert_eq!((s3.imported, s3.updated, s3.duplicates), (0, 1, 0));

        // Still one Bank item, same id, with the new password — and the TOTP +
        // notes from the first import survive (the update CSV had neither).
        let list = do_list_items(&state, false).unwrap();
        assert_eq!(list.iter().filter(|i| i.title == "Bank").count(), 1);
        let bank = list.iter().find(|i| i.title == "Bank").unwrap();
        assert_eq!(bank.id, bank_id);
        assert_eq!(
            do_reveal_field(&state, &bank.id, "password").unwrap(),
            "NEW-secret"
        );
        assert!(bank.has_totp);
        assert_eq!(
            do_reveal_field(&state, &bank.id, "notes").unwrap(),
            "viktig notat"
        );

        // The user's title + full URL are preserved on update — not clobbered
        // by the export's synthesized/bare values.
        let detail = do_get_item(&state, &bank.id).unwrap();
        assert_eq!(detail.title, "Bank");
        assert_eq!(detail.url, "https://www.bank.com/login");

        // Two same-key rows within ONE file: first imports, second dedupes.
        let fourth = write(
            "d.csv",
            "name,url,username,password\n\
             Shop,https://shop.no,kunde,pw\n\
             Shop,https://www.shop.no,KUNDE,pw\n",
        );
        let s4 = do_import_logins(&state, fourth.to_str().unwrap()).unwrap();
        assert_eq!((s4.imported, s4.updated, s4.duplicates), (1, 0, 1));

        // A row with a BLANK password must never wipe the stored password: it's
        // a no-op (duplicate), not a destructive update.
        let blank = write(
            "e.csv",
            "name,url,username,password\n\
             Bank,https://bank.com,me@bank.com,\n",
        );
        let s5 = do_import_logins(&state, blank.to_str().unwrap()).unwrap();
        assert_eq!((s5.imported, s5.updated, s5.duplicates), (0, 0, 1));
        assert_eq!(
            do_reveal_field(&state, &bank.id, "password").unwrap(),
            "NEW-secret" // untouched
        );

        // Same password but a NEWLY populated TOTP column must MERGE into the
        // existing entry (Shop had none), not be dropped as a "duplicate".
        let shop_id = do_list_items(&state, false)
            .unwrap()
            .into_iter()
            .find(|i| i.title == "Shop")
            .unwrap()
            .id;
        assert!(
            !do_list_items(&state, false)
                .unwrap()
                .iter()
                .find(|i| i.id == shop_id)
                .unwrap()
                .has_totp
        );
        let shop_totp = write(
            "g.csv",
            "name,url,username,password,otpauth\n\
             Shop,https://shop.no,kunde,pw,otpauth://totp/Shop?secret=GEZDGNBVGY3TQOJQ\n",
        );
        let s6 = do_import_logins(&state, shop_totp.to_str().unwrap()).unwrap();
        assert_eq!((s6.imported, s6.updated, s6.duplicates), (0, 1, 0));
        assert!(
            do_list_items(&state, false)
                .unwrap()
                .iter()
                .find(|i| i.id == shop_id)
                .unwrap()
                .has_totp
        );
    }
}
