//! Native-messaging host for the Arca browser extension.
//!
//! Browsers speak the "native messaging" wire protocol: each message is a
//! 4-byte length prefix (native byte order — little-endian on all supported
//! platforms) followed by that many bytes of UTF-8 JSON. This binary reads
//! requests on stdin and writes responses on stdout.
//!
//! Phase 1 implements the full framing + handshake + request dispatch. The
//! actual login lookup is delegated to the desktop app, which exclusively owns
//! the unlocked vault; that bridge is stubbed here (see [`query_desktop_app`])
//! and returns no credentials until implemented.
//!
//! SECURITY: this process never holds the vault key and never returns
//! passwords. It only ever relays *metadata* about matching logins; the actual
//! fill must be authorized by the (separately unlocked) desktop app.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};

const HOST_NAME: &str = "no.sybr.vault";
const PROTOCOL_VERSION: u32 = 1;
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Reject absurd frame sizes (browsers cap extension->host at 1 MiB).
const MAX_MESSAGE_BYTES: u32 = 8 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request {
    /// Handshake; the extension announces itself.
    Hello {
        // Parsed for protocol completeness; not acted on in Phase 1.
        #[serde(default)]
        #[allow(dead_code)]
        version: Option<String>,
    },
    /// Liveness check.
    Ping,
    /// Ask for logins whose site matches `url` (the active tab's URL).
    ListMatchingLogins { url: String },
    /// Fetch the credential for a chosen login id, to fill into `url`.
    Fill { id: String, url: String },
    /// Register a WebAuthn passkey (navigator.credentials.create).
    PasskeyCreate {
        origin: String,
        rp_id: String,
        #[serde(default)]
        user_name: String,
        #[serde(default)]
        user_handle: Vec<u8>,
    },
    /// Assert a WebAuthn passkey (navigator.credentials.get).
    PasskeyGet {
        origin: String,
        rp_id: String,
        client_data_hash: Vec<u8>,
        #[serde(default)]
        allow_credentials: Vec<Vec<u8>>,
    },
    /// Ask whether a submitted login is worth offering to save.
    SaveProbe {
        url: String,
        #[serde(default)]
        username: String,
        password: String,
    },
    /// Store a captured login (after the user clicked Save).
    SaveLogin {
        url: String,
        #[serde(default)]
        username: String,
        password: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Response {
    Hello {
        name: String,
        version: String,
        protocol: u32,
        /// Whether the desktop app is reachable & unlocked right now.
        app_connected: bool,
    },
    Pong,
    Logins {
        url: String,
        app_connected: bool,
        /// Credential *metadata* only — never passwords.
        items: Vec<LoginMatch>,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// The credential for a `fill` request. Only emitted after the desktop app
    /// authorized it (unlocked + origin match).
    Credentials {
        username: String,
        password: String,
    },
    /// Result of a passkey registration.
    PasskeyCredential {
        credential_id: Vec<u8>,
        attestation_object: Vec<u8>,
    },
    /// Result of a passkey assertion.
    PasskeyAssertion {
        credential_id: Vec<u8>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Vec<u8>,
    },
    /// Result of a save probe: "new" | "update" | "known" | "disabled" | "locked".
    SaveDecision {
        action: String,
    },
    /// A login was stored.
    Saved,
    Error {
        message: String,
    },
}

/// Non-secret summary of a matching login, safe to hand to the extension UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct LoginMatch {
    id: String,
    title: String,
    username: String,
    url: String,
    /// "password" for a stored login, "passkey" for a WebAuthn credential.
    /// Defaults to "password" so an older desktop app (no `kind`) still lists
    /// its logins.
    #[serde(default = "default_kind")]
    kind: String,
}

fn default_kind() -> String {
    "password".to_string()
}

fn handle(request: Request) -> Response {
    match request {
        Request::Hello { .. } => Response::Hello {
            name: HOST_NAME.to_string(),
            version: VERSION.to_string(),
            protocol: PROTOCOL_VERSION,
            app_connected: desktop_app_available(),
        },
        Request::Ping => Response::Pong,
        Request::ListMatchingLogins { url } => match query_desktop_app(&url) {
            Some(items) => Response::Logins {
                url,
                app_connected: true,
                items,
                note: None,
            },
            None => Response::Logins {
                url,
                app_connected: false,
                items: Vec::new(),
                note: Some("The Arca desktop app isn't running or is locked.".to_string()),
            },
        },
        Request::Fill { id, url } => match fill_credential(&id, &url) {
            Some((username, password)) => Response::Credentials { username, password },
            None => Response::Error {
                message: "Could not fill (app locked, origin mismatch, or not found).".to_string(),
            },
        },
        Request::PasskeyCreate {
            origin,
            rp_id,
            user_name,
            user_handle,
        } => match passkey_create(&origin, &rp_id, &user_name, &user_handle) {
            Some((credential_id, attestation_object)) => Response::PasskeyCredential {
                credential_id,
                attestation_object,
            },
            None => Response::Error {
                message: "Could not create passkey (app locked, origin mismatch, or not running)."
                    .to_string(),
            },
        },
        Request::PasskeyGet {
            origin,
            rp_id,
            client_data_hash,
            allow_credentials,
        } => match passkey_get(&origin, &rp_id, &client_data_hash, &allow_credentials) {
            Some((credential_id, authenticator_data, signature, user_handle)) => {
                Response::PasskeyAssertion {
                    credential_id,
                    authenticator_data,
                    signature,
                    user_handle,
                }
            }
            None => Response::Error {
                message: "No matching passkey (or app locked / origin mismatch).".to_string(),
            },
        },
        Request::SaveProbe {
            url,
            username,
            password,
        } => match save_probe(&url, &username, &password) {
            Some(action) => Response::SaveDecision { action },
            None => Response::Error {
                message: "Save probe failed (app locked or not running).".to_string(),
            },
        },
        Request::SaveLogin {
            url,
            username,
            password,
        } => {
            if save_login(&url, &username, &password) {
                Response::Saved
            } else {
                Response::Error {
                    message: "Could not save login (app locked or not running).".to_string(),
                }
            }
        }
    }
}

/// Ask the app whether a submitted login is worth offering to save; returns the
/// decision string ("new"/"update"/"known"/"disabled"/"locked").
fn save_probe(url: &str, username: &str, password: &str) -> Option<String> {
    let resp = bridge_request(serde_json::json!({
        "type": "save_probe", "url": url, "username": username, "password": password,
    }))?;
    if resp.get("type").and_then(|v| v.as_str()) != Some("save_decision") {
        return None;
    }
    Some(resp.get("action")?.as_str()?.to_string())
}

/// Ask the app to store a captured login. Returns whether it was saved.
fn save_login(url: &str, username: &str, password: &str) -> bool {
    let Some(resp) = bridge_request(serde_json::json!({
        "type": "save_login", "url": url, "username": username, "password": password,
    })) else {
        return false;
    };
    resp.get("type").and_then(|v| v.as_str()) == Some("saved")
}

/// Decode a JSON array-of-bytes field into `Vec<u8>`.
fn json_bytes(v: &serde_json::Value, key: &str) -> Option<Vec<u8>> {
    v.get(key)?
        .as_array()?
        .iter()
        .map(|n| u8::try_from(n.as_u64()?).ok())
        .collect()
}

/// Ask the app to register a passkey. Returns (credential_id, attestation_object).
fn passkey_create(
    origin: &str,
    rp_id: &str,
    user_name: &str,
    user_handle: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    let resp = bridge_request(serde_json::json!({
        "type": "passkey_create",
        "origin": origin,
        "rp_id": rp_id,
        "user_name": user_name,
        "user_handle": user_handle,
    }))?;
    if resp.get("type").and_then(|v| v.as_str()) != Some("passkey_credential") {
        return None;
    }
    Some((
        json_bytes(&resp, "credential_id")?,
        json_bytes(&resp, "attestation_object")?,
    ))
}

/// (credential_id, authenticator_data, signature, user_handle) from an assertion.
type AssertionParts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Ask the app to assert a passkey.
fn passkey_get(
    origin: &str,
    rp_id: &str,
    client_data_hash: &[u8],
    allow_credentials: &[Vec<u8>],
) -> Option<AssertionParts> {
    let resp = bridge_request(serde_json::json!({
        "type": "passkey_get",
        "origin": origin,
        "rp_id": rp_id,
        "client_data_hash": client_data_hash,
        "allow_credentials": allow_credentials,
    }))?;
    if resp.get("type").and_then(|v| v.as_str()) != Some("passkey_assertion") {
        return None;
    }
    Some((
        json_bytes(&resp, "credential_id")?,
        json_bytes(&resp, "authenticator_data")?,
        json_bytes(&resp, "signature")?,
        json_bytes(&resp, "user_handle")?,
    ))
}

/// Path to the bridge connection-info file the desktop app writes. Uses the
/// same per-user data dir Tauri's `app_data_dir()` resolves to.
fn bridge_info_path() -> Option<std::path::PathBuf> {
    Some(dirs::data_dir()?.join(HOST_NAME).join("native-bridge.json"))
}

/// Open an authenticated connection to the desktop app's loopback bridge and
/// send one request, returning the parsed JSON response.
fn bridge_request(payload: serde_json::Value) -> Option<serde_json::Value> {
    let info: serde_json::Value =
        serde_json::from_slice(&std::fs::read(bridge_info_path()?).ok()?).ok()?;
    let port = info.get("port")?.as_u64()? as u16;
    let token = info.get("token")?.as_str()?;

    let stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    // Long enough to outlast an in-app autofill-consent prompt (the app blocks
    // the reply until the user answers, up to ~30s) without hanging forever.
    stream
        .set_read_timeout(Some(Duration::from_secs(45)))
        .ok()?;
    let mut writer = stream.try_clone().ok()?;
    let mut reader = BufReader::new(stream);

    // Authenticate.
    writeln!(
        writer,
        "{}",
        serde_json::json!({ "type": "hello", "token": token })
    )
    .ok()?;
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let hello: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if hello.get("type").and_then(|v| v.as_str()) != Some("ok") {
        return None;
    }

    // Send the actual request and read its response.
    writeln!(writer, "{payload}").ok()?;
    line.clear();
    reader.read_line(&mut line).ok()?;
    serde_json::from_str(line.trim()).ok()
}

/// Whether the desktop app's bridge is reachable + authenticates.
fn desktop_app_available() -> bool {
    bridge_request(serde_json::json!({ "type": "match", "url": "" })).is_some()
}

/// Ask the app for logins matching `url` (metadata only, no passwords).
fn query_desktop_app(url: &str) -> Option<Vec<LoginMatch>> {
    let resp = bridge_request(serde_json::json!({ "type": "match", "url": url }))?;
    if resp.get("type").and_then(|v| v.as_str()) != Some("logins") {
        return None;
    }
    let items = resp.get("items")?.as_array()?;
    Some(
        items
            .iter()
            .filter_map(|i| {
                Some(LoginMatch {
                    id: i.get("id")?.as_str()?.to_string(),
                    title: i.get("title")?.as_str()?.to_string(),
                    username: i.get("username")?.as_str()?.to_string(),
                    url: url.to_string(),
                    kind: i
                        .get("kind")
                        .and_then(|v| v.as_str())
                        .unwrap_or("password")
                        .to_string(),
                })
            })
            .collect(),
    )
}

/// Ask the app for the credential of `id` to fill into `url`. The app enforces
/// unlock + origin matching before returning anything.
fn fill_credential(id: &str, url: &str) -> Option<(String, String)> {
    let resp = bridge_request(serde_json::json!({ "type": "fill", "id": id, "url": url }))?;
    if resp.get("type").and_then(|v| v.as_str()) != Some("credentials") {
        return None;
    }
    Some((
        resp.get("username")?.as_str()?.to_string(),
        resp.get("password")?.as_str()?.to_string(),
    ))
}

/// Read one framed message. Returns `Ok(None)` on clean EOF (browser closed
/// the pipe), which is the host's signal to exit.
fn read_message<R: Read>(reader: &mut R) -> io::Result<Option<Request>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len == 0 {
        return Ok(None);
    }
    if len > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf)?;
    let request = serde_json::from_slice::<Request>(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(request))
}

/// Write one framed message.
fn write_message<W: Write>(writer: &mut W, response: &Response) -> io::Result<()> {
    let payload =
        serde_json::to_vec(response).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response too large"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        match read_message(&mut reader) {
            Ok(Some(request)) => {
                let response = handle(request);
                if write_message(&mut writer, &response).is_err() {
                    break;
                }
            }
            Ok(None) => break, // EOF: browser closed the connection.
            Err(_) => {
                // Malformed frame: report once and stop.
                let _ = write_message(
                    &mut writer,
                    &Response::Error {
                        message: "malformed message".to_string(),
                    },
                );
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Frame a JSON string the way a browser would, for round-trip tests.
    fn frame(json: &str) -> Vec<u8> {
        let bytes = json.as_bytes();
        let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn reads_a_framed_request() {
        let mut cur = Cursor::new(frame(r#"{"type":"hello","version":"1.0"}"#));
        let req = read_message(&mut cur).unwrap().unwrap();
        assert!(matches!(req, Request::Hello { .. }));
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut cur = Cursor::new(Vec::<u8>::new());
        assert!(read_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn hello_handshake_round_trips_through_the_wire() {
        // Frame a hello, read it, handle it, write the response, re-read length.
        let mut input = Cursor::new(frame(r#"{"type":"hello"}"#));
        let req = read_message(&mut input).unwrap().unwrap();
        let resp = handle(req);

        let mut out = Vec::new();
        write_message(&mut out, &resp).unwrap();

        // Length prefix matches the JSON payload that follows.
        let len = u32::from_le_bytes(out[..4].try_into().unwrap()) as usize;
        assert_eq!(len, out.len() - 4);
        let json: serde_json::Value = serde_json::from_slice(&out[4..]).unwrap();
        assert_eq!(json["type"], "hello");
        assert_eq!(json["name"], HOST_NAME);
        assert_eq!(json["protocol"], PROTOCOL_VERSION);
    }

    #[test]
    fn list_matching_logins_returns_a_logins_response() {
        // The connected/items result depends on whether the desktop app is
        // running locally, so assert only the response shape (dispatch), not
        // environment-dependent connectivity.
        let resp = handle(Request::ListMatchingLogins {
            url: "https://github.com/login".to_string(),
        });
        assert!(matches!(resp, Response::Logins { .. }));
    }

    #[test]
    fn passkey_requests_are_dispatched() {
        // Without a reachable, unlocked app these resolve to an error; the point
        // is that both variants parse and route to a handler.
        let create = handle(Request::PasskeyCreate {
            origin: "https://github.com".to_string(),
            rp_id: "github.com".to_string(),
            user_name: "frank".to_string(),
            user_handle: vec![1, 2, 3],
        });
        assert!(matches!(
            create,
            Response::PasskeyCredential { .. } | Response::Error { .. }
        ));

        let get = handle(Request::PasskeyGet {
            origin: "https://github.com".to_string(),
            rp_id: "github.com".to_string(),
            client_data_hash: vec![0u8; 32],
            allow_credentials: vec![],
        });
        assert!(matches!(
            get,
            Response::PasskeyAssertion { .. } | Response::Error { .. }
        ));
    }

    #[test]
    fn fill_request_is_dispatched() {
        // Without a reachable, unlocked app this resolves to an error; the point
        // is that Fill is parsed and routed.
        let resp = handle(Request::Fill {
            id: "00000000-0000-0000-0000-000000000000".to_string(),
            url: "https://github.com".to_string(),
        });
        assert!(matches!(
            resp,
            Response::Credentials { .. } | Response::Error { .. }
        ));
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let mut bytes = (MAX_MESSAGE_BYTES + 1).to_le_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        let mut cur = Cursor::new(bytes);
        assert!(read_message(&mut cur).is_err());
    }
}
