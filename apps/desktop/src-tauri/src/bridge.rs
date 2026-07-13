//! Local autofill bridge.
//!
//! A loopback-only (127.0.0.1) line-delimited-JSON server that the native
//! messaging host connects to, so the browser extension can autofill
//! credentials from the unlocked vault.
//!
//! Security model (see THREAT_MODEL.md):
//!   * **Loopback only** — bound to 127.0.0.1 on an ephemeral port, never
//!     reachable off-device.
//!   * **Token** — a random per-run token written to a `0600` connection-info
//!     file (only the user can read it); required on every connection.
//!   * **Unlock gate** — `match`/`fill` only succeed while the vault is
//!     unlocked.
//!   * **Origin binding** — `fill` returns a credential only when the requested
//!     page's host matches the stored login's host, so a page on one site can
//!     never pull another site's password.
//!   * **Least exposure** — `match` returns metadata only (id/title/username);
//!     the password crosses solely on an explicit `fill` for a matched id.
//!   * **Optional per-fill consent** — with the `confirm_autofill` setting on,
//!     a `fill` blocks on an in-app Allow/Deny prompt, making the desktop app
//!     the final approver (defence in depth if the extension is compromised).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;
use vault_core::VaultItem;

use crate::state::AppState;

/// How long a blocked `fill` waits for the user's Allow/Deny before defaulting
/// to deny.
const CONSENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Pending autofill-consent requests, keyed by a per-request id. When
/// `confirm_autofill` is on, the bridge thread parks on the receiver while the
/// frontend shows an Allow/Deny prompt; `resolve_autofill_consent` sends the
/// decision. Managed by Tauri so the command and the bridge share it.
#[derive(Default)]
pub struct PendingConsents(pub Mutex<HashMap<String, Sender<bool>>>);

/// What the user is being asked to approve for a single fill.
pub struct ConsentContext {
    pub site: String,
    pub account: String,
    pub title: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request {
    Hello { token: String },
    Match { url: String },
    Fill { id: String, url: String },
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Response {
    Ok,
    Logins { items: Vec<LoginMatch> },
    Credentials { username: String, password: String },
    Error { message: String },
}

#[derive(Debug, Serialize, PartialEq)]
struct LoginMatch {
    id: String,
    title: String,
    username: String,
}

/// Port + token, written for the native host to read.
#[derive(Serialize, Deserialize)]
struct BridgeInfo {
    port: u16,
    token: String,
}

fn info_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("native-bridge.json")
}

/// Bare host of a URL: scheme/path/port/userinfo stripped and a leading "www."
/// removed. Empty when there's no host.
fn host_of(url: &str) -> String {
    let after_scheme = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url.trim(),
    };
    let authority = after_scheme.split('/').next().unwrap_or("");
    let no_userinfo = authority.rsplit('@').next().unwrap_or(authority);
    let host = no_userinfo.split(':').next().unwrap_or(no_userinfo);
    host.trim().trim_start_matches("www.").to_ascii_lowercase()
}

/// Whether a stored login's URL should autofill on the requested page: exact
/// host, or a sub/parent-domain relationship (after stripping `www.`).
fn domain_matches(stored_url: &str, requested_url: &str) -> bool {
    let a = host_of(stored_url);
    let b = host_of(requested_url);
    if a.is_empty() || b.is_empty() {
        return false;
    }
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

/// Handle one parsed request. `authed` tracks whether this connection has
/// presented the token. Factored out (no sockets) so the security gates are
/// unit-testable.
fn handle_request(
    req: Request,
    state: &Mutex<AppState>,
    token: &str,
    authed: &mut bool,
    app: Option<&AppHandle>,
    consent: &mut dyn FnMut(&ConsentContext) -> bool,
) -> Response {
    match req {
        Request::Hello { token: presented } => {
            if presented == token {
                *authed = true;
                Response::Ok
            } else {
                Response::Error {
                    message: "unauthorized".into(),
                }
            }
        }
        _ if !*authed => Response::Error {
            message: "unauthorized".into(),
        },
        Request::Match { url } => {
            let st = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return Response::Error {
                        message: "internal".into(),
                    }
                }
            };
            let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                return Response::Error {
                    message: "locked".into(),
                };
            };
            let mut items = Vec::new();
            if let Ok(summaries) = vault.list_items(false) {
                for s in summaries {
                    if let Ok(item) = vault.get_item(s.id) {
                        if let VaultItem::Login {
                            url: u,
                            username,
                            title,
                            ..
                        } = &item.data
                        {
                            if domain_matches(u, &url) {
                                items.push(LoginMatch {
                                    id: item.id.to_string(),
                                    title: title.clone(),
                                    username: username.clone(),
                                });
                            }
                        }
                    }
                }
            }
            Response::Logins { items }
        }
        Request::Fill { id, url } => {
            // Resolve + validate under the lock, then extract just what we need
            // and release it before any (possibly slow) user consent prompt.
            let confirm;
            let username;
            let password;
            let title;
            {
                let st = match state.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        return Response::Error {
                            message: "internal".into(),
                        }
                    }
                };
                let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                let Ok(uuid) = Uuid::parse_str(&id) else {
                    return Response::Error {
                        message: "not_found".into(),
                    };
                };
                let Ok(item) = vault.get_item(uuid) else {
                    return Response::Error {
                        message: "not_found".into(),
                    };
                };
                let VaultItem::Login {
                    url: u,
                    username: un,
                    password: pw,
                    title: t,
                    ..
                } = &item.data
                else {
                    return Response::Error {
                        message: "not_found".into(),
                    };
                };
                // Origin binding: never hand a credential to a non-matching host.
                if !domain_matches(u, &url) {
                    return Response::Error {
                        message: "origin_mismatch".into(),
                    };
                }
                confirm = st.settings.confirm_autofill;
                username = un.clone();
                password = pw.clone();
                title = t.clone();
            }

            // Optional per-fill consent: the app is the final approver.
            if confirm {
                let ctx = ConsentContext {
                    site: host_of(&url),
                    account: username.clone(),
                    title: title.clone(),
                };
                if !consent(&ctx) {
                    return Response::Error {
                        message: "denied".into(),
                    };
                }
            }

            if let Some(app) = app {
                let _ = app.emit("autofilled", format!("{title} ({})", host_of(&url)));
            }
            Response::Credentials { username, password }
        }
    }
}

/// Production consent: emit the request to the frontend, bring the window
/// forward, and block this bridge thread until the user answers (or times out,
/// which denies). Returns `true` only on an explicit Allow.
fn request_consent(app: &AppHandle, ctx: &ConsentContext) -> bool {
    let consent_id = Uuid::new_v4().simple().to_string();
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    {
        let pending = app.state::<PendingConsents>();
        let Ok(mut map) = pending.0.lock() else {
            return false;
        };
        map.insert(consent_id.clone(), tx);
    }
    let _ = app.emit(
        "fill-consent-request",
        serde_json::json!({
            "id": consent_id,
            "site": ctx.site,
            "account": ctx.account,
            "title": ctx.title,
        }),
    );
    // Surface the prompt over the browser the user is filling into.
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
    let approved = rx.recv_timeout(CONSENT_TIMEOUT).unwrap_or(false);
    // Drop the sender if it's still registered (timeout path).
    if let Ok(mut map) = app.state::<PendingConsents>().0.lock() {
        map.remove(&consent_id);
    }
    approved
}

/// Deliver a user's Allow/Deny decision to the parked bridge thread.
pub fn resolve_consent(app: &AppHandle, id: &str, approved: bool) {
    if let Ok(mut map) = app.state::<PendingConsents>().0.lock() {
        if let Some(tx) = map.remove(id) {
            let _ = tx.send(approved);
        }
    }
}

fn write_info(path: &Path, info: &BridgeInfo) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    let json = serde_json::to_vec(info)?;
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(&json)?;
    Ok(())
}

/// Start the bridge server. Binds a loopback port, writes the connection-info
/// file, and serves connections on a background thread.
pub fn start(app: AppHandle, app_data_dir: &Path) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    write_info(
        &info_path(app_data_dir),
        &BridgeInfo {
            port,
            token: token.clone(),
        },
    )?;

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            // Defense in depth: only loopback peers.
            if stream
                .peer_addr()
                .map(|a| a.ip().is_loopback())
                .unwrap_or(false)
            {
                let app = app.clone();
                let token = token.clone();
                std::thread::spawn(move || {
                    let _ = serve(stream, &app, &token);
                });
            }
        }
    });
    Ok(())
}

fn serve(stream: TcpStream, app: &AppHandle, token: &str) -> std::io::Result<()> {
    let mut writer = stream.try_clone()?;
    let reader = BufReader::new(stream);
    let state = app.state::<Mutex<AppState>>();
    let mut authed = false;
    let mut consent = |ctx: &ConsentContext| request_consent(app, ctx);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle_request(
                req,
                state.inner(),
                token,
                &mut authed,
                Some(app),
                &mut consent,
            ),
            Err(_) => Response::Error {
                message: "bad_request".into(),
            },
        };
        let mut out =
            serde_json::to_string(&resp).unwrap_or_else(|_| String::from("{\"type\":\"error\"}"));
        out.push('\n');
        writer.write_all(out.as_bytes())?;
        writer.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::ClipboardManager;
    use crate::commands::{do_upsert_item, LoginInput};
    use tempfile::TempDir;
    use vault_core::{KdfAlgorithm, KdfParams, Vault};
    use vault_store::VaultStore;

    /// A consent closure that always approves (autofill confirmation off is the
    /// default, so this is only exercised when a test flips the setting on).
    fn allow() -> impl FnMut(&ConsentContext) -> bool {
        |_| true
    }

    fn cheap_params() -> KdfParams {
        KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![5u8; KdfParams::SALT_LEN],
        }
    }

    fn unlocked_state(dir: &TempDir) -> Mutex<AppState> {
        let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
        let vault = Vault::create("pw", cheap_params()).unwrap();
        let (clip, _) = ClipboardManager::memory();
        Mutex::new(AppState::new(store, Some(vault), clip))
    }

    fn add(state: &Mutex<AppState>, title: &str, user: &str, pw: &str, url: &str) -> String {
        do_upsert_item(
            state,
            LoginInput {
                id: None,
                title: title.into(),
                username: user.into(),
                password: pw.into(),
                url: url.into(),
                totp_secret: None,
                notes: String::new(),
            },
        )
        .unwrap()
    }

    #[test]
    fn host_normalization_and_domain_matching() {
        assert_eq!(host_of("https://www.github.com/login?x=1"), "github.com");
        assert_eq!(
            host_of("http://user@accounts.google.com:443/"),
            "accounts.google.com"
        );
        assert!(domain_matches(
            "https://github.com",
            "https://www.github.com/login"
        ));
        assert!(domain_matches(
            "https://github.com",
            "https://gist.github.com"
        ));
        assert!(domain_matches(
            "https://accounts.google.com",
            "https://google.com"
        ));
        // Look-alike must NOT match.
        assert!(!domain_matches(
            "https://evil-github.com",
            "https://github.com"
        ));
        assert!(!domain_matches("https://github.com", "https://github.org"));
    }

    #[test]
    fn requires_token_before_serving() {
        let dir = TempDir::new().unwrap();
        let state = unlocked_state(&dir);
        let mut authed = false;
        // Match without hello -> unauthorized.
        let r = handle_request(
            Request::Match {
                url: "https://x.com".into(),
            },
            &state,
            "secret",
            &mut authed,
            None,
            &mut allow(),
        );
        assert!(matches!(r, Response::Error { message } if message == "unauthorized"));
        // Wrong token -> unauthorized, stays unauthed.
        let r = handle_request(
            Request::Hello {
                token: "nope".into(),
            },
            &state,
            "secret",
            &mut authed,
            None,
            &mut allow(),
        );
        assert!(matches!(r, Response::Error { .. }));
        assert!(!authed);
        // Correct token -> ok.
        let r = handle_request(
            Request::Hello {
                token: "secret".into(),
            },
            &state,
            "secret",
            &mut authed,
            None,
            &mut allow(),
        );
        assert_eq!(r, Response::Ok);
        assert!(authed);
    }

    #[test]
    fn match_and_fill_respect_origin_and_unlock() {
        let dir = TempDir::new().unwrap();
        let state = unlocked_state(&dir);
        let gh = add(&state, "GitHub", "frank", "gh-pw", "https://github.com");
        add(&state, "Google", "frank@g", "g-pw", "https://google.com");

        let mut authed = true;

        // Match returns only the github.com login for a github.com page.
        let r = handle_request(
            Request::Match {
                url: "https://www.github.com/login".into(),
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        );
        match r {
            Response::Logins { items } => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].id, gh);
                assert_eq!(items[0].username, "frank");
            }
            other => panic!("expected logins, got {other:?}"),
        }

        // Fill on the matching origin returns the credential.
        let r = handle_request(
            Request::Fill {
                id: gh.clone(),
                url: "https://github.com/login".into(),
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        );
        assert_eq!(
            r,
            Response::Credentials {
                username: "frank".into(),
                password: "gh-pw".into()
            }
        );

        // Fill for the github id from a DIFFERENT origin is refused.
        let r = handle_request(
            Request::Fill {
                id: gh.clone(),
                url: "https://evil.com".into(),
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        );
        assert!(matches!(r, Response::Error { message } if message == "origin_mismatch"));

        // When locked, nothing is served.
        state.lock().unwrap().vault.as_mut().unwrap().lock();
        let r = handle_request(
            Request::Fill {
                id: gh,
                url: "https://github.com".into(),
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        );
        assert!(matches!(r, Response::Error { message } if message == "locked"));
    }

    #[test]
    fn fill_requires_consent_when_confirm_is_enabled() {
        let dir = TempDir::new().unwrap();
        let state = unlocked_state(&dir);
        let gh = add(&state, "GitHub", "frank", "gh-pw", "https://github.com");
        state.lock().unwrap().settings.confirm_autofill = true;
        let mut authed = true;

        // Denied consent -> no credential.
        let mut deny = |_: &ConsentContext| false;
        let r = handle_request(
            Request::Fill {
                id: gh.clone(),
                url: "https://github.com".into(),
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut deny,
        );
        assert!(matches!(r, Response::Error { message } if message == "denied"));

        // The consent prompt must carry the real site + account being approved.
        let mut seen: Option<(String, String)> = None;
        let mut capture = |ctx: &ConsentContext| {
            seen = Some((ctx.site.clone(), ctx.account.clone()));
            true
        };
        let r = handle_request(
            Request::Fill {
                id: gh,
                url: "https://github.com/login".into(),
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut capture,
        );
        assert_eq!(
            r,
            Response::Credentials {
                username: "frank".into(),
                password: "gh-pw".into()
            }
        );
        assert_eq!(seen, Some(("github.com".into(), "frank".into())));
    }
}
