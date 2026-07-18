//! ssh-agent protocol server.
//!
//! Arca acts as an ssh-agent so `ssh`/`git` can use the Ed25519 keys stored in
//! the vault WITHOUT the private key ever leaving the app: the agent advertises
//! the public identities and, on a sign request, hands the bytes to
//! `vault_core::ssh::sign`, which signs in-process and returns only the
//! signature. The private seed is read from the (unlocked) vault and dropped
//! immediately.
//!
//! Transport: a Unix domain socket (`0600`, in the app data dir) on macOS/Linux;
//! point `SSH_AUTH_SOCK` at it. Windows (named pipe) is a follow-up — the agent
//! is a no-op there for now.
//!
//! Security:
//!   * Signing requires the vault to be UNLOCKED. When locked, the agent lists
//!     zero identities and refuses to sign (like an ssh-agent with no keys
//!     added). "Unlocked" is the equivalent of `ssh-add`.
//!   * The socket is user-only (`0600`); it is loopback-equivalent (AF_UNIX,
//!     not reachable off-device).
//!   * Only REQUEST_IDENTITIES and SIGN_REQUEST are honored; adding/removing/
//!     locking external keys over the protocol is refused (keys are managed in
//!     Arca, not injected by clients).

#[cfg(unix)]
pub use imp::{socket_path, start};

#[cfg(not(unix))]
pub fn start(_app: tauri::AppHandle) {}

#[cfg(not(unix))]
pub fn socket_path(_app: &tauri::AppHandle) -> std::path::PathBuf {
    // No Unix-socket agent on Windows yet (named pipe is a follow-up).
    std::path::PathBuf::new()
}

#[cfg(unix)]
mod imp {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::Mutex;

    use tauri::{AppHandle, Manager};
    use vault_core::{ssh, VaultItem};

    use crate::state::AppState;

    // Message numbers (draft-miller-ssh-agent).
    const SSH_AGENT_FAILURE: u8 = 5;
    const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

    /// Cap on an incoming message (a sign payload is small; guards against a
    /// malicious length prefix).
    const MAX_MSG: usize = 256 * 1024;

    /// The agent socket path: `<app-data>/ssh-agent.sock`.
    pub fn socket_path(app: &AppHandle) -> PathBuf {
        let dir = app
            .path()
            .app_data_dir()
            .unwrap_or_else(|_| std::env::temp_dir());
        dir.join("ssh-agent.sock")
    }

    /// Bind the socket and serve in the background. Best-effort: a bind failure
    /// just means the agent is unavailable this run.
    pub fn start(app: AppHandle) {
        let path = socket_path(&app);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Remove a stale socket left by a previous run (else bind fails).
        let _ = std::fs::remove_file(&path);
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("ssh-agent: could not bind {}: {e}", path.display());
                return;
            }
        };
        // Owner-only: nobody else on the box can talk to the agent.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut s) => {
                        let app = app.clone();
                        std::thread::spawn(move || {
                            let _ = serve(&app, &mut s);
                        });
                    }
                    Err(_) => break,
                }
            }
        });
    }

    fn serve(app: &AppHandle, s: &mut UnixStream) -> std::io::Result<()> {
        loop {
            let msg = match read_msg(s) {
                Ok(m) => m,
                Err(_) => return Ok(()), // client closed
            };
            if msg.is_empty() {
                return Ok(());
            }
            let resp = match msg[0] {
                SSH_AGENTC_REQUEST_IDENTITIES => identities(app),
                SSH_AGENTC_SIGN_REQUEST => sign(app, &msg[1..]),
                _ => vec![SSH_AGENT_FAILURE],
            };
            write_msg(s, &resp)?;
        }
    }

    // ---- framing -----------------------------------------------------------

    fn read_msg(s: &mut UnixStream) -> std::io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        s.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_MSG {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "oversized agent message",
            ));
        }
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn write_msg(s: &mut UnixStream, payload: &[u8]) -> std::io::Result<()> {
        s.write_all(&(payload.len() as u32).to_be_bytes())?;
        s.write_all(payload)?;
        s.flush()
    }

    /// Read an SSH `string` (u32 length + bytes) at `pos`, advancing it.
    fn read_string(buf: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
        let n = u32::from_be_bytes(buf.get(*pos..*pos + 4)?.try_into().ok()?) as usize;
        *pos += 4;
        let v = buf.get(*pos..*pos + n)?.to_vec();
        *pos += n;
        Some(v)
    }

    fn push_string(buf: &mut Vec<u8>, s: &[u8]) {
        buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
        buf.extend_from_slice(s);
    }

    // ---- operations --------------------------------------------------------

    /// (public_blob, comment) for every SSH key, when the vault is unlocked.
    fn collect_identities(st: &AppState) -> Vec<(Vec<u8>, String)> {
        let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let Ok(summaries) = vault.list_items(false) {
            for s in summaries {
                let Ok(item) = vault.get_item(s.id) else {
                    continue;
                };
                if let VaultItem::SshKey {
                    public_key,
                    comment,
                    ..
                } = &item.data
                {
                    if !public_key.is_empty() {
                        out.push((public_key.clone(), comment.clone()));
                    }
                }
            }
        }
        out
    }

    /// The Ed25519 seed for the key whose public blob matches, if unlocked.
    fn seed_for(st: &AppState, key_blob: &[u8]) -> Option<Vec<u8>> {
        let vault = st.vault.as_ref().filter(|v| v.is_unlocked())?;
        let summaries = vault.list_items(false).ok()?;
        for s in summaries {
            let Ok(item) = vault.get_item(s.id) else {
                continue;
            };
            if let VaultItem::SshKey {
                public_key,
                private_key,
                ..
            } = &item.data
            {
                if public_key == key_blob && !private_key.is_empty() {
                    return Some(private_key.clone());
                }
            }
        }
        None
    }

    fn identities(app: &AppHandle) -> Vec<u8> {
        let state = app.state::<Mutex<AppState>>();
        let keys = match state.lock() {
            Ok(st) => collect_identities(&st),
            Err(_) => Vec::new(),
        };
        let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
        out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
        for (blob, comment) in keys {
            push_string(&mut out, &blob);
            push_string(&mut out, comment.as_bytes());
        }
        out
    }

    fn sign(app: &AppHandle, body: &[u8]) -> Vec<u8> {
        let mut pos = 0;
        let (Some(key_blob), Some(data)) =
            (read_string(body, &mut pos), read_string(body, &mut pos))
        else {
            return vec![SSH_AGENT_FAILURE];
        };
        // A trailing u32 of flags follows; ignored for Ed25519 (no rsa-sha2).

        let state = app.state::<Mutex<AppState>>();
        let seed = match state.lock() {
            Ok(st) => seed_for(&st, &key_blob),
            Err(_) => None,
        };
        let Some(seed) = seed else {
            // Unknown key or vault locked.
            return vec![SSH_AGENT_FAILURE];
        };
        match ssh::sign(&seed, &data) {
            Ok(sig) => {
                let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
                push_string(&mut out, &sig);
                out
            }
            Err(_) => vec![SSH_AGENT_FAILURE],
        }
    }
}
