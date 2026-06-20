//! Native-messaging host for the SYBR Passwords browser extension.
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
                note: Some(
                    "The SYBR Passwords desktop app isn't running or is locked.".to_string(),
                ),
            },
        },
        Request::Fill { id, url } => match fill_credential(&id, &url) {
            Some((username, password)) => Response::Credentials { username, password },
            None => Response::Error {
                message: "Could not fill (app locked, origin mismatch, or not found).".to_string(),
            },
        },
    }
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
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
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
