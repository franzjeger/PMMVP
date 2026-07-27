//! Google Drive's hidden `appDataFolder` as a [`RemoteStore`].
//!
//! The scope is `drive.appdata`: Arca can see the private folder Drive keeps
//! for it and nothing else in the user's account. Combined with the vault
//! already being sealed before it gets here, Google holds one opaque blob it
//! cannot read and cannot browse past.
//!
//! Google is not special to this crate — it is one implementation of one
//! trait. A second backend (iCloud, WebDAV, a self-hosted bucket) is a file
//! next to this one, and the engine does not change.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;

use crate::oauth::{AppCredentials, OAuthClient};
use crate::{CycleError, RemoteFile, RemoteStore};

/// The OAuth client, per platform. Both live in the same Google Cloud project
/// and ask for the same scope, so every Arca client reaches the same
/// `appDataFolder` and syncs with the others.
///
/// Two clients rather than one because Google ties the redirect to the client
/// TYPE. The desktop client redirects to a loopback address, which iOS cannot
/// bind and cannot register a custom scheme against; an iOS client redirects to
/// its own reversed client id. Reusing the desktop client from the phone is
/// what produces `400 redirect_uri_mismatch`.
///
/// See [`AppCredentials`] on why an installed-app secret is not a secret.
#[cfg(not(target_os = "ios"))]
pub const CLIENT_ID: &str =
    "269591410733-ger46m91l3ne5qmcrivhg1jo698gieck.apps.googleusercontent.com";
#[cfg(not(target_os = "ios"))]
pub const CLIENT_SECRET: &str = "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";

/// iOS client (bundle id `no.sybr.vault.ios`). Public: Google issues NO secret
/// for this type, and sending an empty one is rejected — see `form_fields`.
#[cfg(target_os = "ios")]
pub const CLIENT_ID: &str =
    "269591410733-ltlkje5t7p8gajnp8vvk3gp9223nheu7.apps.googleusercontent.com";
#[cfg(target_os = "ios")]
pub const CLIENT_SECRET: &str = "";

/// The redirect this build's client is registered for. iOS uses the reversed
/// client id, which is the only form Google accepts for an iOS client; the
/// desktop catches a loopback address chosen at runtime, so it has none here.
#[cfg(target_os = "ios")]
pub const REDIRECT_URI: &str =
    "com.googleusercontent.apps.269591410733-ltlkje5t7p8gajnp8vvk3gp9223nheu7:/oauth2redirect";

/// Arca's own hidden folder, and nothing else in the user's Drive.
pub const SCOPE: &str = "https://www.googleapis.com/auth/drive.appdata";

/// The vault's name inside `appDataFolder`. Every client must agree on it —
/// two names is two vaults that never see each other.
pub const REMOTE_NAME: &str = "arca.vault";

pub fn arca_credentials() -> AppCredentials {
    AppCredentials {
        client_id: CLIENT_ID.into(),
        client_secret: CLIENT_SECRET.into(),
        scope: SCOPE.into(),
    }
}

/// Where the long-lived refresh token lives, which is entirely a platform
/// question: the OS secret store on desktop, the app's keychain on iOS.
///
/// Presence and content are separate operations on purpose. On macOS, reading
/// a keychain item's *data* runs its ACL and can put a prompt on screen (after
/// a code-signature change, for instance); a presence check does not. The
/// background loop asks [`exists`](RefreshTokenStore::exists) every tick, so
/// that call must never be able to interrupt the user.
pub trait RefreshTokenStore: Send + Sync {
    fn exists(&self) -> bool;
    fn read(&self) -> Result<Option<Zeroizing<String>>, String>;
}

pub struct DriveStore {
    oauth: OAuthClient,
    tokens: Arc<dyn RefreshTokenStore>,
    http: reqwest::blocking::Client,
    /// The short-lived access token and the wall clock at which we stop
    /// trusting it. In memory only — it is never written anywhere.
    access: Mutex<Option<(Zeroizing<String>, SystemTime)>>,
}

impl DriveStore {
    pub fn new(credentials: AppCredentials, tokens: Arc<dyn RefreshTokenStore>) -> Self {
        Self {
            oauth: OAuthClient::new(credentials),
            tokens,
            http: crate::http::client(),
            access: Mutex::new(None),
        }
    }

    /// Seed the cache with the access token a fresh sign-in just produced, so
    /// the first cycle after connecting does not immediately spend a refresh.
    pub fn cache_access_token(&self, token: Zeroizing<String>, expires_in: u64) {
        if let Ok(mut cached) = self.access.lock() {
            *cached = Some((token, expiry_from(expires_in)));
        }
    }

    /// The signed-in account's email, for the UI to show.
    pub fn account_email(&self) -> Option<String> {
        account_email(&self.access_token().ok()?)
    }

    /// A usable access token, refreshing through the stored refresh token when
    /// the cached one has expired.
    fn access_token(&self) -> Result<Zeroizing<String>, CycleError> {
        {
            let cached = self
                .access
                .lock()
                .map_err(|_| CycleError::Other("token cache poisoned".into()))?;
            if let Some((token, until)) = &*cached {
                if SystemTime::now() < *until {
                    return Ok(token.clone());
                }
            }
        }
        let refresh = self
            .tokens
            .read()
            .map_err(CycleError::Other)?
            .ok_or_else(|| CycleError::Other("not connected".into()))?;
        let (token, expires_in) = self.oauth.refresh(&refresh).map_err(CycleError::Other)?;
        self.cache_access_token(token.clone(), expires_in);
        Ok(token)
    }
}

/// The email address of the account an access token belongs to, for the UI to
/// show. `about.get` is one of the few endpoints the `appdata` scope reaches.
///
/// Free-standing rather than a method, because the caller who most needs it has
/// just finished a sign-in and holds an access token but has not yet built a
/// [`DriveStore`] — the refresh token is still on its way to the platform's
/// keychain. `None` on any failure: a missing label is a cosmetic problem and
/// must never be the reason a completed sign-in is reported as failed.
pub fn account_email(access_token: &str) -> Option<String> {
    let about: serde_json::Value = crate::http::client()
        .get("https://www.googleapis.com/drive/v3/about?fields=user(emailAddress)")
        .bearer_auth(access_token)
        .send()
        .and_then(|r| r.json())
        .ok()?;
    about["user"]["emailAddress"].as_str().map(str::to_string)
}

/// Stop trusting a token a minute before the server does, so a request cannot
/// be issued with a token that expires while it is in flight.
fn expiry_from(expires_in: u64) -> SystemTime {
    SystemTime::now() + Duration::from_secs(expires_in.saturating_sub(60))
}

/// Map a Drive HTTP status onto the retry policy. Only 401 is worth refreshing
/// a credential for; everything else is reported and retried on the next tick.
fn classify(status: reqwest::StatusCode, what: &str) -> CycleError {
    if status.as_u16() == 401 {
        CycleError::Auth
    } else {
        CycleError::Other(format!("{what} HTTP {status}"))
    }
}

fn field(value: &serde_json::Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_string()
}

impl RemoteStore for DriveStore {
    fn is_connected(&self) -> bool {
        self.tokens.exists()
    }

    fn list(&self) -> Result<Vec<RemoteFile>, CycleError> {
        let token = self.access_token()?;
        let resp = self
            .http
            .get(format!(
                "https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&q=name%3D%27{REMOTE_NAME}%27&orderBy=createdTime&fields=files(id,md5Checksum)"
            ))
            .bearer_auth(&*token)
            .send()
            .map_err(|e| CycleError::Other(format!("drive list failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(classify(resp.status(), "drive list"));
        }
        let body: serde_json::Value = resp
            .json()
            .map_err(|e| CycleError::Other(format!("drive list unreadable: {e}")))?;
        // `orderBy=createdTime` is what makes "oldest first" true, which is what
        // the engine relies on to pick which duplicate survives a create race.
        Ok(body["files"]
            .as_array()
            .map(|files| {
                files
                    .iter()
                    .map(|f| RemoteFile {
                        id: field(f, "id"),
                        checksum: field(f, "md5Checksum"),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn download(&self, id: &str) -> Result<Vec<u8>, CycleError> {
        let token = self.access_token()?;
        let resp = self
            .http
            .get(format!(
                "https://www.googleapis.com/drive/v3/files/{id}?alt=media"
            ))
            .bearer_auth(&*token)
            .send()
            .map_err(|e| CycleError::Other(format!("download failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(classify(resp.status(), "download"));
        }
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| CycleError::Other(format!("download body failed: {e}")))
    }

    fn checksum(&self, id: &str) -> Result<String, CycleError> {
        let token = self.access_token()?;
        let resp = self
            .http
            .get(format!(
                "https://www.googleapis.com/drive/v3/files/{id}?fields=md5Checksum"
            ))
            .bearer_auth(&*token)
            .send()
            .map_err(|e| CycleError::Other(format!("preflight failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(classify(resp.status(), "preflight"));
        }
        let body: serde_json::Value = resp
            .json()
            .map_err(|e| CycleError::Other(format!("preflight unreadable: {e}")))?;
        Ok(field(&body, "md5Checksum"))
    }

    fn delete(&self, id: &str) -> Result<(), CycleError> {
        let token = self.access_token()?;
        let resp = self
            .http
            .delete(format!("https://www.googleapis.com/drive/v3/files/{id}"))
            .bearer_auth(&*token)
            .send()
            .map_err(|e| CycleError::Other(format!("delete failed: {e}")))?;
        // Already gone is the outcome we wanted.
        if !resp.status().is_success() && resp.status().as_u16() != 404 {
            return Err(classify(resp.status(), "delete"));
        }
        Ok(())
    }

    fn upload(&self, existing: Option<&str>, bytes: &[u8]) -> Result<RemoteFile, CycleError> {
        let token = self.access_token()?;
        let resp = match existing {
            Some(id) => self
                .http
                .patch(format!(
                    "https://www.googleapis.com/upload/drive/v3/files/{id}?uploadType=media&fields=id,md5Checksum"
                ))
                .bearer_auth(&*token)
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
                self.http
                    .post("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,md5Checksum")
                    .bearer_auth(&*token)
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
        let body: serde_json::Value = resp
            .json()
            .map_err(|e| CycleError::Other(format!("upload response unreadable: {e}")))?;
        // `fields=id,md5Checksum` matters: the engine records this checksum as
        // integrated, so it has to describe what the server actually stored.
        Ok(RemoteFile {
            id: field(&body, "id"),
            checksum: field(&body, "md5Checksum"),
        })
    }

    fn invalidate_auth(&self) {
        if let Ok(mut cached) = self.access.lock() {
            *cached = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct FakeTokens {
        present: AtomicBool,
        reads: AtomicUsize,
    }

    impl RefreshTokenStore for FakeTokens {
        fn exists(&self) -> bool {
            self.present.load(Ordering::SeqCst)
        }
        fn read(&self) -> Result<Option<Zeroizing<String>>, String> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .present
                .load(Ordering::SeqCst)
                .then(|| Zeroizing::new("refresh-token".into())))
        }
    }

    fn store(tokens: Arc<FakeTokens>) -> DriveStore {
        DriveStore::new(arca_credentials(), tokens)
    }

    /// The tick-rate call must answer from presence alone. Reading the token
    /// data can raise a keychain prompt on macOS, and the background loop asks
    /// this every 30 seconds forever.
    #[test]
    fn the_connected_check_never_reads_the_token() {
        let tokens = Arc::new(FakeTokens::default());
        let drive = store(tokens.clone());

        assert!(!drive.is_connected());
        tokens.present.store(true, Ordering::SeqCst);
        assert!(drive.is_connected());

        assert_eq!(
            tokens.reads.load(Ordering::SeqCst),
            0,
            "is_connected must not touch the token's data"
        );
    }

    #[test]
    fn a_cached_token_is_reused_and_invalidation_drops_it() {
        let tokens = Arc::new(FakeTokens::default());
        let drive = store(tokens.clone());
        drive.cache_access_token(Zeroizing::new("access".into()), 3600);

        assert_eq!(&*drive.access_token().unwrap(), "access");
        assert_eq!(
            tokens.reads.load(Ordering::SeqCst),
            0,
            "a live token needs no refresh"
        );

        drive.invalidate_auth();
        // Nothing stored and no network in the test: the point is that it now
        // has to go looking rather than hand back the token we dropped.
        assert!(drive.access_token().is_err());
        assert_eq!(tokens.reads.load(Ordering::SeqCst), 1);
    }

    /// An expired token must not be handed out. Every request made with one
    /// costs a round trip and comes back 401.
    #[test]
    fn an_expired_token_is_not_reused() {
        let tokens = Arc::new(FakeTokens::default());
        let drive = store(tokens.clone());
        // Server lifetime under the 60s safety margin: already past expiry.
        drive.cache_access_token(Zeroizing::new("stale".into()), 0);

        assert!(drive.access_token().is_err());
        assert_eq!(tokens.reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn only_a_401_is_treated_as_an_auth_failure() {
        assert!(matches!(
            classify(reqwest::StatusCode::UNAUTHORIZED, "upload"),
            CycleError::Auth
        ));
        for status in [
            reqwest::StatusCode::FORBIDDEN,
            reqwest::StatusCode::NOT_FOUND,
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert!(
                matches!(classify(status, "upload"), CycleError::Other(_)),
                "{status} must not trigger a credential refresh"
            );
        }
    }

    /// Drive omits `md5Checksum` for some files. An absent checksum has to read
    /// as empty rather than panic, and the engine compares it as a value like
    /// any other.
    #[test]
    fn a_missing_field_reads_as_empty() {
        let body = serde_json::json!({ "id": "abc" });
        assert_eq!(field(&body, "id"), "abc");
        assert_eq!(field(&body, "md5Checksum"), "");
    }
}
