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

use std::io::{self, Read, Write};

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
                // TODO(phase-2): connect to the desktop app's local IPC endpoint.
                note: Some(
                    "Desktop app bridge not implemented yet (phase 1 scaffold).".to_string(),
                ),
            },
        },
    }
}

/// TODO(phase-2): probe the desktop app's local IPC endpoint (an OS-auth'd
/// loopback socket / named pipe with a per-install token). Returns false in
/// the Phase-1 scaffold.
fn desktop_app_available() -> bool {
    false
}

/// TODO(phase-2): ask the running, unlocked desktop app for logins matching
/// `url` via its local IPC endpoint. The app owns the vault key and decides
/// what (metadata) to return; it never sends passwords through this channel.
/// Returns `None` (app not connected) in the Phase-1 scaffold.
fn query_desktop_app(_url: &str) -> Option<Vec<LoginMatch>> {
    None
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
    fn list_matching_logins_is_empty_without_app_bridge() {
        let resp = handle(Request::ListMatchingLogins {
            url: "https://github.com/login".to_string(),
        });
        match resp {
            Response::Logins {
                items,
                app_connected,
                ..
            } => {
                assert!(items.is_empty());
                assert!(!app_connected);
            }
            _ => panic!("expected logins response"),
        }
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let mut bytes = (MAX_MESSAGE_BYTES + 1).to_le_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        let mut cur = Cursor::new(bytes);
        assert!(read_message(&mut cur).is_err());
    }
}
