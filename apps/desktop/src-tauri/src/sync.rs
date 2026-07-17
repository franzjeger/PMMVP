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
//! ciphertext). Access tokens are held in memory.
//!
//! Engine: pull → merge (vault-core's item-level newest-wins) → push, run in a
//! background thread every [`SYNC_INTERVAL`] and on demand. Merging requires an
//! unlocked vault; while locked we skip silently. Network I/O happens OUTSIDE
//! the AppState lock; only merge + serialize hold it.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
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

/// Sync status shared with the UI.
#[derive(Default)]
pub struct SyncState {
    pub account: Option<String>,
    pub last_sync_unix: Option<u64>,
    pub last_error: Option<String>,
    /// In-memory access token + expiry.
    access_token: Option<(Zeroizing<String>, Instant)>,
    /// Drive file id of the remote vault, once discovered/created.
    remote_id: Option<String>,
    /// md5 of the remote content we last integrated, to skip no-op cycles.
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
    // PKCE verifier (43-128 chars) + S256 challenge.
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|_| "rng failure".to_string())?;
    let verifier = data_encoding::BASE64URL_NOPAD.encode(&raw);
    let challenge = data_encoding::BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()));

    // Loopback listener on an ephemeral port.
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
    // Open the system browser at the consent page.
    {
        use tauri_plugin_opener::OpenerExt;
        app.opener()
            .open_url(&auth_url, None::<&str>)
            .map_err(|e| format!("could not open the browser: {e}"))?;
    }

    // Wait (max 3 min) for exactly one redirect carrying ?code=...
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
        // The accepted stream inherits nonblocking; make it blocking to read.
        stream.set_nonblocking(false).ok();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).ok();
        // "GET /?code=...&scope=... HTTP/1.1"
        let path = line.split_whitespace().nth(1).unwrap_or("");
        let code = path
            .split_once("code=")
            .map(|(_, r)| r.split('&').next().unwrap_or("").to_string());
        let mut stream = reader.into_inner();
        let body = if code.is_some() {
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
        if let Some(c) = code {
            if !c.is_empty() {
                break c;
            }
            return Err("sign-in was denied".into());
        }
        // Ignore favicon/noise requests and keep waiting.
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

    let sync = app.state::<SharedSync>();
    if let Ok(mut s) = sync.lock() {
        s.account = Some(account.clone());
        s.access_token = Some((
            Zeroizing::new(access.to_string()),
            Instant::now() + Duration::from_secs(3000),
        ));
        s.last_error = None;
    }
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
fn access_token(app: &AppHandle) -> Result<Zeroizing<String>, String> {
    {
        let st = app.state::<SharedSync>();
        let guard = st.lock().map_err(|_| "state poisoned".to_string())?;
        if let Some((tok, until)) = &guard.access_token {
            if Instant::now() < *until {
                return Ok(tok.clone());
            }
        }
    }
    let refresh = vault_store::secrets::get(SECRET_SERVICE, SECRET_ACCOUNT)
        .map_err(|_| "keychain read failed".to_string())?
        .ok_or("not connected")?;
    let resp: serde_json::Value = http()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("refresh_token", refresh.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .map_err(|e| format!("token refresh failed: {e}"))?
        .json()
        .map_err(|e| format!("refresh response unreadable: {e}"))?;
    let access = resp["access_token"]
        .as_str()
        .ok_or("refresh rejected (reconnect Google in Settings)")?;
    let tok = Zeroizing::new(access.to_string());
    if let Ok(mut s) = app.state::<SharedSync>().lock() {
        s.access_token = Some((tok.clone(), Instant::now() + Duration::from_secs(3000)));
    }
    Ok(tok)
}

// ---------------------------------------------------------------------------
// Drive appDataFolder ops
// ---------------------------------------------------------------------------

/// (file_id, md5) of the remote vault, if it exists.
fn find_remote(token: &str) -> Result<Option<(String, String)>, String> {
    let resp: serde_json::Value = http()
        .get(format!(
            "https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&q=name%3D%27{REMOTE_NAME}%27&fields=files(id,md5Checksum)"
        ))
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("drive list failed: {e}"))?
        .json()
        .map_err(|e| format!("drive list unreadable: {e}"))?;
    Ok(resp["files"].as_array().and_then(|f| f.first()).map(|f| {
        (
            f["id"].as_str().unwrap_or_default().to_string(),
            f["md5Checksum"].as_str().unwrap_or_default().to_string(),
        )
    }))
}

fn download(token: &str, id: &str) -> Result<Vec<u8>, String> {
    let resp = http()
        .get(format!(
            "https://www.googleapis.com/drive/v3/files/{id}?alt=media"
        ))
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("download failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("download HTTP {}", resp.status()));
    }
    resp.bytes()
        .map(|b| b.to_vec())
        .map_err(|e| format!("download body failed: {e}"))
}

/// Create or update the remote file. Returns the file id.
fn upload(token: &str, existing_id: Option<&str>, bytes: &[u8]) -> Result<String, String> {
    let client = http();
    let resp = match existing_id {
        Some(id) => client
            .patch(format!(
                "https://www.googleapis.com/upload/drive/v3/files/{id}?uploadType=media&fields=id"
            ))
            .bearer_auth(token)
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec())
            .send(),
        None => {
            // Multipart create: metadata (name + appDataFolder parent) + content.
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
                .post("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id")
                .bearer_auth(token)
                .header(
                    "Content-Type",
                    format!("multipart/related; boundary={boundary}"),
                )
                .body(body)
                .send()
        }
    }
    .map_err(|e| format!("upload failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("upload HTTP {}", resp.status()));
    }
    let v: serde_json::Value = resp
        .json()
        .map_err(|e| format!("upload response unreadable: {e}"))?;
    Ok(v["id"].as_str().unwrap_or_default().to_string())
}

// ---------------------------------------------------------------------------
// The sync cycle
// ---------------------------------------------------------------------------

/// One pull→merge→push cycle. Skips silently when not connected or locked.
pub fn sync_now(app: &AppHandle) -> Result<bool, String> {
    if !is_connected() {
        return Ok(false);
    }
    let token = access_token(app)?;

    // Network: discover + download OUTSIDE the state lock.
    let remote = find_remote(&token)?;
    let (remote_id, remote_md5) = match &remote {
        Some((id, md5)) => (Some(id.clone()), Some(md5.clone())),
        None => (None, None),
    };
    let unchanged = {
        let s = app.state::<SharedSync>();
        let guard = s.lock().map_err(|_| "state poisoned".to_string())?;
        remote_md5.is_some() && remote_md5 == guard.last_remote_md5
    };
    let remote_bytes = match (&remote_id, unchanged) {
        (Some(id), false) => Some(download(&token, id)?),
        _ => None,
    };

    // Merge + serialize under the lock (no network in here).
    let out_bytes;
    {
        let state = app.state::<Mutex<AppState>>();
        let mut st = state.lock().map_err(|_| "state poisoned".to_string())?;
        let AppState { store, vault, .. } = &mut *st;
        let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
            return Ok(false); // locked: nothing to merge safely; try later
        };
        if let Some(bytes) = &remote_bytes {
            match vault.merge_remote(bytes) {
                Ok(()) => {}
                // Corrupt/partial remote: replace it with ours below.
                Err(vault_core::Error::Format) | Err(vault_core::Error::Serialization) => {}
                Err(e) => return Err(format!("remote vault refused: {e}")),
            }
        }
        store.save_synced(vault).map_err(|e| e.to_string())?;
        out_bytes = vault.to_bytes().map_err(|e| e.to_string())?;
    }

    // Push (outside the lock).
    let new_id = upload(&token, remote_id.as_deref(), &out_bytes)?;
    // Re-read md5 so the next cycle can no-op.
    let md5_now = find_remote(&token)?.map(|(_, m)| m);
    {
        let s = app.state::<SharedSync>();
        let mut guard = s.lock().map_err(|_| "state poisoned".to_string())?;
        guard.remote_id = Some(new_id);
        guard.last_remote_md5 = md5_now;
        guard.last_sync_unix = Some(now_unix());
        guard.last_error = None;
    }
    let merged = remote_bytes.is_some();
    if merged {
        let _ = app.emit("sync-merged", ());
    }
    let _ = app.emit("sync-status", status(app));
    Ok(merged)
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

/// Background loop: a cycle every [`SYNC_INTERVAL`]. Errors are recorded in the
/// status (shown in Settings), never fatal.
pub fn start_loop(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(SYNC_INTERVAL);
        if let Err(e) = sync_now(&app) {
            if let Ok(mut s) = app.state::<SharedSync>().lock() {
                s.last_error = Some(e);
            }
            let _ = app.emit("sync-status", status(&app));
        }
    });
}
