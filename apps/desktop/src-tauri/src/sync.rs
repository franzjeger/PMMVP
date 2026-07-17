//! Google Drive sync: the encrypted vault in Drive's hidden `appDataFolder`.
//!
//! Security model: Drive stores CIPHERTEXT ONLY (the vault file is sealed with
//! Argon2id + XChaCha20-Poly1305 before it leaves the machine). The Google
//! account is transport, never trust — Google can't read a single password.
//! Scope is `drive.appdata`: Arca sees its own hidden folder and nothing else
//! in the user's Drive.
//!
//! Auth: standard installed-app OAuth — PKCE + loopback redirect. The refresh
//! token lives in the OS secret store ([`vault_store::secrets`], no biometric
//! gate: the background loop must read it silently and it only reaches
//! ciphertext). Access tokens are held in memory with wall-clock expiry.
//!
//! Engine (reviewed adversarially; the shape below closes the findings):
//! pull → merge (vault-core item-level newest-wins + header-epoch adoption) →
//! preflight-checked push. One cycle at a time (in-flight guard); uploads only
//! when something actually changed (dirty flag / merged / bootstrap); the
//! remote md5 recorded ONLY from our own upload response; a mid-cycle peer
//! upload is detected by a cheap preflight and the cycle re-runs. Multiple
//! remote files (duplicate-create races) are all merged, the oldest is kept
//! and the extras deleted. A newer-format peer file is REFUSED (update the
//! app), never "repaired".

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::state::AppState;

/// OAuth client for the "Arca" desktop app. Installed-app client secrets are
/// not confidential (they ship in every binary) per Google's own docs.
const CLIENT_ID: &str = "269591410733-ger46m91l3ne5qmcrivhg1jo698gieck.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "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";
const SCOPE: &str = "https://www.googleapis.com/auth/drive.appdata";

/// Keychain slot for the refresh token.
const SECRET_SERVICE: &str = "no.sybr.vault";
const SECRET_ACCOUNT: &str = "gdrive-refresh-token";

/// Remote file name inside appDataFolder.
const REMOTE_NAME: &str = "arca.vault";

/// Background sync cadence.
const SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// Local changes waiting to be pushed. Set by every persist (app commands and
/// browser-bridge saves); cleared after a successful upload.
static DIRTY: AtomicBool = AtomicBool::new(true);

/// One sync cycle at a time, across the background loop and manual "Sync now".
static IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Mark that local vault state changed and should be pushed on the next cycle.
pub fn mark_dirty() {
    DIRTY.store(true, Ordering::Relaxed);
}

/// Sync status shared with the UI.
#[derive(Default)]
pub struct SyncState {
    pub account: Option<String>,
    pub last_sync_unix: Option<u64>,
    pub last_error: Option<String>,
    /// In-memory access token + wall-clock expiry.
    access_token: Option<(Zeroizing<String>, SystemTime)>,
    /// md5 of remote content we last integrated OR produced ourselves. Only
    /// ever set from our own upload response (never from a bare listing), so a
    /// peer's concurrent upload can't be marked "already integrated" unseen.
    last_remote_md5: Option<String>,
}

pub type SharedSync = Mutex<SyncState>;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusDto {
    pub connected: bool,
    pub account: Option<String>,
    pub last_sync_unix: Option<u64>,
    pub last_error: Option<String>,
}

/// Cycle-internal error classification (drives the retry policy).
enum CycleError {
    /// A peer uploaded mid-cycle; re-run pull-merge-push.
    Conflict,
    /// Token rejected; refresh once and re-run.
    Auth,
    Other(String),
}

impl From<String> for CycleError {
    fn from(s: String) -> Self {
        CycleError::Other(s)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("http client builds")
}

fn urlenc(s: &str) -> String {
    // Percent-encode everything outside the unreserved set (RFC 3986).
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// OAuth (PKCE + loopback)
// ---------------------------------------------------------------------------

/// Run the interactive sign-in: open the browser, catch the redirect on a
/// loopback port, exchange the code, store the refresh token. Blocking (call
/// from a command on a thread); returns the account label.
pub fn connect(app: &AppHandle) -> Result<String, String> {
    // PKCE verifier (43-128 chars) + S256 challenge. PKCE binds the code to
    // this process, so a local port-sniffer can't redeem an intercepted code.
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|_| "rng failure".to_string())?;
    let verifier = data_encoding::BASE64URL_NOPAD.encode(&raw);
    let challenge = data_encoding::BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()));

    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind failed: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect = format!("http://127.0.0.1:{port}");

    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&code_challenge={}&code_challenge_method=S256",
        urlenc(CLIENT_ID),
        urlenc(&redirect),
        urlenc(SCOPE),
        urlenc(&challenge),
    );
    {
        use tauri_plugin_opener::OpenerExt;
        app.opener()
            .open_url(&auth_url, None::<&str>)
            .map_err(|e| format!("could not open the browser: {e}"))?;
    }

    // Wait (max 3 min) for the redirect carrying ?code= (or ?error=).
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(180);
    let code = loop {
        if Instant::now() > deadline {
            return Err("sign-in timed out".into());
        }
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(150));
                continue;
            }
            Err(_) => continue,
        };
        // The accepted stream inherits nonblocking; make it a blocking read
        // with a short timeout so a stalled local connection can't hang us.
        stream.set_nonblocking(false).ok();
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).ok();
        // "GET /?code=...&scope=... HTTP/1.1" or "GET /?error=access_denied ..."
        let path = line.split_whitespace().nth(1).unwrap_or("");
        let denied = path.contains("error=");
        let code = path
            .split_once("code=")
            .map(|(_, r)| r.split('&').next().unwrap_or("").to_string());
        let mut stream = reader.into_inner();
        let body = if code.as_deref().is_some_and(|c| !c.is_empty()) {
            "<h2>Arca is connected.</h2>You can close this tab."
        } else {
            "<h2>Sign-in was cancelled.</h2>You can close this tab."
        };
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .as_bytes(),
        );
        if denied {
            return Err("sign-in was denied".into());
        }
        if let Some(c) = code {
            if !c.is_empty() {
                break c;
            }
        }
        // Favicon/noise request: keep waiting.
    };

    // Exchange the code for tokens.
    let resp: serde_json::Value = http()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("code", &code),
            ("code_verifier", &verifier),
            ("grant_type", "authorization_code"),
            ("redirect_uri", &redirect),
        ])
        .send()
        .map_err(|e| format!("token exchange failed: {e}"))?
        .json()
        .map_err(|e| format!("token response unreadable: {e}"))?;

    let refresh = resp["refresh_token"]
        .as_str()
        .ok_or("no refresh token in response")?;
    let access = resp["access_token"].as_str().ok_or("no access token")?;
    let expires = resp["expires_in"].as_u64().unwrap_or(3600);
    vault_store::secrets::set(SECRET_SERVICE, SECRET_ACCOUNT, refresh)
        .map_err(|_| "could not store the refresh token in the OS keychain")?;

    // Account label for the UI (about.get works with the appdata scope).
    let about: serde_json::Value = http()
        .get("https://www.googleapis.com/drive/v3/about?fields=user(emailAddress)")
        .bearer_auth(access)
        .send()
        .and_then(|r| r.json())
        .unwrap_or_default();
    let account = about["user"]["emailAddress"]
        .as_str()
        .unwrap_or("Google account")
        .to_string();

    if let Ok(mut s) = app.state::<SharedSync>().lock() {
        // Fresh connection: reset any previous account's bookkeeping.
        *s = SyncState::default();
        s.account = Some(account.clone());
        s.access_token = Some((
            Zeroizing::new(access.to_string()),
            SystemTime::now() + Duration::from_secs(expires.saturating_sub(60)),
        ));
    }
    mark_dirty(); // force a full first cycle
    Ok(account)
}

/// Forget the connection: delete the refresh token and clear state.
pub fn disconnect(app: &AppHandle) {
    let _ = vault_store::secrets::delete(SECRET_SERVICE, SECRET_ACCOUNT);
    if let Ok(mut s) = app.state::<SharedSync>().lock() {
        *s = SyncState::default();
    }
}

pub fn is_connected() -> bool {
    matches!(
        vault_store::secrets::get(SECRET_SERVICE, SECRET_ACCOUNT),
        Ok(Some(_))
    )
}

/// A valid access token, refreshing via the stored refresh token if needed.
fn access_token(app: &AppHandle) -> Result<Zeroizing<String>, CycleError> {
    {
        let st = app.state::<SharedSync>();
        let guard = st
            .lock()
            .map_err(|_| CycleError::Other("state poisoned".into()))?;
        if let Some((tok, until)) = &guard.access_token {
            if SystemTime::now() < *until {
                return Ok(tok.clone());
            }
        }
    }
    let refresh = vault_store::secrets::get(SECRET_SERVICE, SECRET_ACCOUNT)
        .map_err(|_| CycleError::Other("keychain read failed".into()))?
        .ok_or(CycleError::Other("not connected".into()))?;
    let resp: serde_json::Value = http()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("refresh_token", refresh.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .map_err(|e| CycleError::Other(format!("token refresh failed: {e}")))?
        .json()
        .map_err(|e| CycleError::Other(format!("refresh response unreadable: {e}")))?;
    let access = resp["access_token"].as_str().ok_or(CycleError::Other(
        "refresh rejected (reconnect Google in Settings)".into(),
    ))?;
    let expires = resp["expires_in"].as_u64().unwrap_or(3600);
    let tok = Zeroizing::new(access.to_string());
    if let Ok(mut s) = app.state::<SharedSync>().lock() {
        s.access_token = Some((
            tok.clone(),
            SystemTime::now() + Duration::from_secs(expires.saturating_sub(60)),
        ));
    }
    Ok(tok)
}

/// Drop the cached access token (after a 401) so the next call re-refreshes.
fn invalidate_token(app: &AppHandle) {
    if let Ok(mut s) = app.state::<SharedSync>().lock() {
        s.access_token = None;
    }
}

// ---------------------------------------------------------------------------
// Drive appDataFolder ops
// ---------------------------------------------------------------------------

/// Map a Drive HTTP status to the cycle error class.
fn classify(status: reqwest::StatusCode, what: &str) -> CycleError {
    if status.as_u16() == 401 {
        CycleError::Auth
    } else {
        CycleError::Other(format!("{what} HTTP {status}"))
    }
}

/// ALL remote vault files (normally 0 or 1; >1 after a create race), oldest
/// first. Errors are surfaced, never treated as "no file" (a silent failure
/// here caused duplicate creation).
fn find_remote(token: &str) -> Result<Vec<(String, String)>, CycleError> {
    let resp = http()
        .get(format!(
            "https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&q=name%3D%27{REMOTE_NAME}%27&orderBy=createdTime&fields=files(id,md5Checksum)"
        ))
        .bearer_auth(token)
        .send()
        .map_err(|e| CycleError::Other(format!("drive list failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "drive list"));
    }
    let v: serde_json::Value = resp
        .json()
        .map_err(|e| CycleError::Other(format!("drive list unreadable: {e}")))?;
    Ok(v["files"]
        .as_array()
        .map(|files| {
            files
                .iter()
                .map(|f| {
                    (
                        f["id"].as_str().unwrap_or_default().to_string(),
                        f["md5Checksum"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default())
}

fn download(token: &str, id: &str) -> Result<Vec<u8>, CycleError> {
    let resp = http()
        .get(format!(
            "https://www.googleapis.com/drive/v3/files/{id}?alt=media"
        ))
        .bearer_auth(token)
        .send()
        .map_err(|e| CycleError::Other(format!("download failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "download"));
    }
    resp.bytes()
        .map(|b| b.to_vec())
        .map_err(|e| CycleError::Other(format!("download body failed: {e}")))
}

/// Current md5 of a remote file (cheap preflight before the upload).
fn remote_md5(token: &str, id: &str) -> Result<String, CycleError> {
    let resp = http()
        .get(format!(
            "https://www.googleapis.com/drive/v3/files/{id}?fields=md5Checksum"
        ))
        .bearer_auth(token)
        .send()
        .map_err(|e| CycleError::Other(format!("preflight failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "preflight"));
    }
    let v: serde_json::Value = resp
        .json()
        .map_err(|e| CycleError::Other(format!("preflight unreadable: {e}")))?;
    Ok(v["md5Checksum"].as_str().unwrap_or_default().to_string())
}

fn delete_file(token: &str, id: &str) -> Result<(), CycleError> {
    let resp = http()
        .delete(format!("https://www.googleapis.com/drive/v3/files/{id}"))
        .bearer_auth(token)
        .send()
        .map_err(|e| CycleError::Other(format!("delete failed: {e}")))?;
    if !resp.status().is_success() && resp.status().as_u16() != 404 {
        return Err(classify(resp.status(), "delete"));
    }
    Ok(())
}

/// Create or update the remote file. Returns (id, md5) FROM THE UPLOAD
/// RESPONSE, so what we record as "integrated" is exactly what we wrote.
fn upload(
    token: &str,
    existing_id: Option<&str>,
    bytes: &[u8],
) -> Result<(String, String), CycleError> {
    let client = http();
    let resp = match existing_id {
        Some(id) => client
            .patch(format!(
                "https://www.googleapis.com/upload/drive/v3/files/{id}?uploadType=media&fields=id,md5Checksum"
            ))
            .bearer_auth(token)
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec())
            .send(),
        None => {
            let meta = format!(r#"{{"name":"{REMOTE_NAME}","parents":["appDataFolder"]}}"#);
            let boundary = "arca-vault-boundary";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{meta}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(bytes);
            body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
            client
                .post("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,md5Checksum")
                .bearer_auth(token)
                .header(
                    "Content-Type",
                    format!("multipart/related; boundary={boundary}"),
                )
                .body(body)
                .send()
        }
    }
    .map_err(|e| CycleError::Other(format!("upload failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "upload"));
    }
    let v: serde_json::Value = resp
        .json()
        .map_err(|e| CycleError::Other(format!("upload response unreadable: {e}")))?;
    Ok((
        v["id"].as_str().unwrap_or_default().to_string(),
        v["md5Checksum"].as_str().unwrap_or_default().to_string(),
    ))
}

// ---------------------------------------------------------------------------
// The sync cycle
// ---------------------------------------------------------------------------

/// One pull→merge→push attempt. See module docs for the invariants.
fn cycle(app: &AppHandle) -> Result<bool, CycleError> {
    let token = access_token(app)?;

    // Discover ALL remote copies (oldest first). Never silently "no file".
    let remotes = find_remote(&token)?;
    let primary = remotes.first().cloned();
    let duplicates: Vec<_> = remotes.iter().skip(1).cloned().collect();

    // Skip downloads we've provably already integrated (md5 recorded from our
    // own last upload); everything else gets pulled and merged.
    let known_md5 = {
        let st = app.state::<SharedSync>();
        let guard = st
            .lock()
            .map_err(|_| CycleError::Other("state poisoned".into()))?;
        guard.last_remote_md5.clone()
    };
    let mut to_merge: Vec<Vec<u8>> = Vec::new();
    let mut based_on_md5: Option<String> = None;
    if let Some((id, md5)) = &primary {
        if Some(md5) != known_md5.as_ref() {
            to_merge.push(download(&token, id)?);
        }
        based_on_md5 = Some(md5.clone());
    }
    for (id, _) in &duplicates {
        to_merge.push(download(&token, id)?);
    }

    let dirty = DIRTY.swap(false, Ordering::Relaxed);
    let merged_any = !to_merge.is_empty();
    // Nothing new remotely and nothing changed locally: genuine no-op.
    if !merged_any && !dirty && primary.is_some() {
        if let Ok(mut s) = app.state::<SharedSync>().lock() {
            s.last_sync_unix = Some(now_unix());
            s.last_error = None;
        }
        return Ok(false);
    }

    // Merge + serialize under the state lock (no network in here).
    let out_bytes;
    {
        let state = app.state::<Mutex<AppState>>();
        let mut st = state
            .lock()
            .map_err(|_| CycleError::Other("state poisoned".into()))?;
        let AppState { store, vault, .. } = &mut *st;
        let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
            // Locked: can't merge safely. Re-flag local changes and try later.
            if dirty {
                mark_dirty();
            }
            return Ok(false);
        };
        for bytes in &to_merge {
            match vault.merge_remote(bytes) {
                Ok(()) => {}
                // Truly unparseable remote (torn upload): replace it with ours.
                Err(vault_core::Error::Format) | Err(vault_core::Error::Serialization) => {}
                // A NEWER app version wrote it: refuse — updating is the fix.
                Err(vault_core::Error::UnsupportedVersion) => {
                    if dirty {
                        mark_dirty();
                    }
                    return Err(CycleError::Other(
                        "the synced vault was written by a newer Arca — update this app".into(),
                    ));
                }
                // Foreign vault (different key) or locked: never overwrite.
                Err(e) => {
                    if dirty {
                        mark_dirty();
                    }
                    return Err(CycleError::Other(format!("remote vault refused: {e}")));
                }
            }
        }
        store
            .save_synced(vault)
            .map_err(|e| CycleError::Other(e.to_string()))?;
        out_bytes = vault
            .to_bytes()
            .map_err(|e| CycleError::Other(e.to_string()))?;
    }

    // Preflight: if a peer uploaded since our download, re-run the whole cycle
    // instead of clobbering content we haven't merged.
    if let (Some((id, _)), Some(based)) = (&primary, &based_on_md5) {
        let now_md5 = remote_md5(&token, id)?;
        if &now_md5 != based {
            mark_dirty(); // our serialized state still needs pushing
            return Err(CycleError::Conflict);
        }
    }

    // Push, recording md5 from the upload response itself.
    let upload_result = upload(
        &token,
        primary.as_ref().map(|(id, _)| id.as_str()),
        &out_bytes,
    );
    let (_new_id, new_md5) = match upload_result {
        Ok(v) => v,
        Err(e) => {
            mark_dirty(); // not uploaded; keep the local-changes flag
            return Err(e);
        }
    };

    // Reconcile duplicates: their content is merged into what we just pushed.
    for (id, _) in &duplicates {
        delete_file(&token, id)?;
    }

    if let Ok(mut s) = app.state::<SharedSync>().lock() {
        s.last_remote_md5 = Some(new_md5);
        s.last_sync_unix = Some(now_unix());
        s.last_error = None;
    }
    Ok(merged_any)
}

/// Run sync now (used by the background loop and the manual command). At most
/// one cycle runs at a time; conflicts and expired tokens retry bounded.
pub fn sync_now(app: &AppHandle) -> Result<bool, String> {
    if !is_connected() {
        return Ok(false);
    }
    if IN_FLIGHT.swap(true, Ordering::Acquire) {
        return Ok(false); // another cycle is running; it will pick our changes up
    }
    let result = (|| {
        let mut auth_retried = false;
        for _attempt in 0..3 {
            match cycle(app) {
                Ok(merged) => return Ok(merged),
                Err(CycleError::Conflict) => continue, // peer raced us: re-pull
                Err(CycleError::Auth) if !auth_retried => {
                    auth_retried = true;
                    invalidate_token(app);
                    continue;
                }
                Err(CycleError::Auth) => {
                    return Err("Google sign-in expired — reconnect in Settings".into())
                }
                Err(CycleError::Other(m)) => return Err(m),
            }
        }
        Err("sync kept conflicting with another device — will retry".into())
    })();
    IN_FLIGHT.store(false, Ordering::Release);

    match &result {
        Ok(merged) => {
            if *merged {
                let _ = app.emit("sync-merged", ());
            }
            let _ = app.emit("sync-status", status(app));
        }
        Err(e) => {
            if let Ok(mut s) = app.state::<SharedSync>().lock() {
                s.last_error = Some(e.clone());
            }
            let _ = app.emit("sync-status", status(app));
        }
    }
    result
}

/// Status DTO for the UI.
pub fn status(app: &AppHandle) -> SyncStatusDto {
    let connected = is_connected();
    let s = app.state::<SharedSync>();
    let guard = s.lock().ok();
    SyncStatusDto {
        connected,
        account: guard.as_ref().and_then(|g| g.account.clone()),
        last_sync_unix: guard.as_ref().and_then(|g| g.last_sync_unix),
        last_error: guard.as_ref().and_then(|g| g.last_error.clone()),
    }
}

/// Background loop: a cycle every [`SYNC_INTERVAL`]. Errors land in the status
/// (shown in Settings), never fatal.
pub fn start_loop(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(SYNC_INTERVAL);
        let _ = sync_now(&app);
    });
}
