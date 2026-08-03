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
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;
use vault_core::{Item, VaultItem};

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

/// Pending passkey user-verification requests, keyed by request id. Kept in a
/// SEPARATE map from [`PendingConsents`] on purpose: an autofill consent is a
/// presence-only Allow/Deny (resolved by `resolve_autofill_consent` with no
/// password check), whereas a passkey verification may only be satisfied `true`
/// after `verify_passkey_approval` has checked the master password. Sharing one
/// map would let a presence-only resolver set the WebAuthn UV flag without any
/// verification. Only `resolve_verification` (from the password-checked command,
/// or a cancel that always sends `false`) drains this map.
#[derive(Default)]
pub struct PendingVerifications(pub Mutex<HashMap<String, Sender<bool>>>);

/// What the user is being asked to approve for a single fill.
pub struct ConsentContext {
    pub site: String,
    pub account: String,
    pub title: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request {
    Hello {
        token: String,
    },
    Match {
        url: String,
    },
    Fill {
        id: String,
        url: String,
    },
    /// Register a new WebAuthn passkey (navigator.credentials.create).
    PasskeyCreate {
        /// The page origin, e.g. "https://github.com". Validated against `rp_id`.
        origin: String,
        rp_id: String,
        #[serde(default)]
        user_name: String,
        #[serde(default)]
        user_handle: Vec<u8>,
        /// Credential ids the RP says it already has (WebAuthn
        /// excludeCredentials). If we hold one of them, registration must be
        /// refused with "excluded" (-> InvalidStateError in the page) WITHOUT
        /// prompting - this is what makes sites stop re-asking.
        #[serde(default)]
        exclude_credentials: Vec<Vec<u8>>,
    },
    /// Assert an existing passkey (navigator.credentials.get).
    PasskeyGet {
        origin: String,
        rp_id: String,
        /// SHA-256 of the clientDataJSON the extension constructed.
        client_data_hash: Vec<u8>,
        /// Credential ids the RP will accept; empty means "any for this rp".
        #[serde(default)]
        allow_credentials: Vec<Vec<u8>>,
    },
    /// Ask whether a just-submitted login is worth offering to save.
    SaveProbe {
        url: String,
        #[serde(default)]
        username: String,
        password: String,
    },
    /// Store a new / updated login captured from a submitted form (after the
    /// user clicked "Save" in the browser prompt).
    SaveLogin {
        url: String,
        #[serde(default)]
        username: String,
        password: String,
    },
    /// Bring Arca forward and ask for Touch ID, because the browser needs a
    /// password right now.
    ///
    /// The one moment an unlock prompt is the answer rather than an
    /// interruption: the user clicked a locked field's badge, so they have said
    /// what they want. Nothing is unlocked by this request itself — it puts the
    /// window in front and the user still authenticates.
    #[serde(rename = "request_unlock")]
    Unlock,
    /// A fresh random password for a sign-up form.
    ///
    /// Deliberately does NOT require an unlocked vault. Nothing here reads or
    /// writes one — the answer is bytes from the CSPRNG — and requiring unlock
    /// would put a master password between the user and the one moment they are
    /// most likely to give up and type "Sommer2026!" instead.
    ///
    /// Saving it does require unlock, but that is the existing save-on-submit
    /// path and it asks at a point where the user has already committed.
    GeneratePassword {
        #[serde(default)]
        length: Option<usize>,
        #[serde(default)]
        symbols: Option<bool>,
    },
}

impl Request {
    /// Whether this request is the user deciding to use the vault, as opposed
    /// to the extension talking to us on its own.
    ///
    /// Only the deliberate ones reset the idle timer. `Hello` and `Ping` are
    /// connection checks, `Match` fires when a password field takes focus, and
    /// `SaveProbe` fires on every submitted form — counting any of those would
    /// let one open tab hold the vault unlocked indefinitely. That is not a
    /// longer timeout, it is no timeout, arrived at by accident.
    fn is_deliberate_use(&self) -> bool {
        match self {
            // Picked a credential, approved a passkey, chose to save, asked for
            // a password. Each is a click.
            Request::Fill { .. }
            | Request::PasskeyCreate { .. }
            | Request::PasskeyGet { .. }
            | Request::SaveLogin { .. }
            | Request::GeneratePassword { .. } => true,
            // NOT activity: the vault is locked, so there is no idle timer to
            // reset, and counting it would let a page keep a future session
            // alive by asking to unlock.
            Request::Unlock
            | Request::Hello { .. }
            | Request::Match { .. }
            | Request::SaveProbe { .. } => false,
        }
    }
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Response {
    Ok,
    Logins {
        items: Vec<LoginMatch>,
    },
    Credentials {
        username: String,
        password: String,
    },
    /// Result of `PasskeyCreate`: the new credential id + CBOR attestation.
    PasskeyCredential {
        credential_id: Vec<u8>,
        attestation_object: Vec<u8>,
    },
    /// Result of `PasskeyGet`: the assertion the RP verifies.
    PasskeyAssertion {
        credential_id: Vec<u8>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Vec<u8>,
    },
    /// Result of `SaveProbe`. `action` is one of "new", "update", "known",
    /// "disabled" (setting off), or "locked".
    SaveDecision {
        action: String,
    },
    /// A login was stored/updated via `SaveLogin`.
    Saved,
    /// Result of `GeneratePassword`.
    GeneratedPassword {
        password: String,
    },
    /// Arca was brought forward and asked the user to unlock. Says nothing
    /// about whether they did — the extension retries and finds out.
    UnlockRequested,
    Error {
        message: String,
    },
}

#[derive(Debug, Serialize, PartialEq)]
struct LoginMatch {
    id: String,
    title: String,
    username: String,
    /// Credential type for the picker UI: "password" for a stored login,
    /// "passkey" for a WebAuthn credential. A passkey row is informational (it
    /// signs in via the site's own passkey ceremony, not by filling a field).
    kind: String,
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

/// The anti-phishing match key, from `vault-core` so the desktop bridge, the
/// AutoFill FFI and the duplicate finder cannot drift apart again. Also used for
/// item-list site grouping, so the UI groups by exactly the hosts autofill
/// matches on.
pub(crate) use vault_core::host_of;

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

/// WebAuthn RP-ID validation: `rp_id` must equal the page origin's host or be a
/// *registrable* parent-domain suffix of it. So a page on `sub.github.com` may
/// use rp_id `github.com`, but a page on `evil.com` may NOT — this is the core
/// anti-phishing binding for passkey create/get.
///
/// Crucially, `rp_id` must NOT be a public suffix / eTLD (`com`, `co.uk`,
/// `github.io`): the Public Suffix List guard stops a page scoping a passkey so
/// broadly that mutually-distrusting tenants (e.g. every `*.github.io`) could
/// share it — exactly what a browser's WebAuthn client enforces.
/// `rp_id_matches_origin`, plus the origins the relying party itself published
/// (WebAuthn L3 Related Origin Requests).
///
/// NEVER call this while holding the app-state lock: the first use per rpId
/// makes an HTTPS request. The direct rule is tried first, so the common case
/// costs nothing.
fn rp_id_allows_origin(rp_id: &str, origin: &str) -> bool {
    if rp_id_matches_origin(rp_id, origin) {
        return true;
    }
    let host = host_of(origin);
    if host.is_empty() {
        return false;
    }
    crate::related_origins::is_related(rp_id, &host)
}

fn rp_id_matches_origin(rp_id: &str, origin: &str) -> bool {
    let host = host_of(origin);
    let rp = rp_id.trim().to_lowercase();
    if rp.is_empty() || host.is_empty() {
        return false;
    }
    // rp_id must equal or be a parent suffix of the origin host.
    if host != rp && !host.ends_with(&format!(".{rp}")) {
        return false;
    }
    // ...and rp_id and the origin must share the SAME registrable domain, which
    // also rejects rp_id being a bare public suffix (no registrable domain).
    match (psl::domain_str(&rp), psl::domain_str(&host)) {
        (Some(rp_reg), Some(host_reg)) => rp_reg == host_reg,
        _ => false,
    }
}

/// Find an active login matching (normalized host, lowercased username).
/// Returns `(id, current_password)` for change detection.
fn find_login(vault: &vault_core::Vault, host: &str, username: &str) -> Option<(Uuid, String)> {
    let user = username.to_lowercase();
    for s in vault.list_items(false).ok()? {
        let Ok(item) = vault.get_item(s.id) else {
            continue;
        };
        if let VaultItem::Login {
            url,
            username: un,
            password,
            ..
        } = &item.data
        {
            if host_of(url) == host && un.to_lowercase() == user {
                return Some((item.id, password.clone()));
            }
        }
    }
    None
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
    // Using the passwords IS using Arca.
    //
    // The idle timer only ever saw the Arca window, so an hour spent filling
    // logins in the browser looked exactly like an hour away from the desk: the
    // vault locked underneath you, and the next fill wanted Touch ID. That is
    // the largest single source of "it keeps asking me to unlock", and the fix
    // is one line that was never there.
    if *authed && req.is_deliberate_use() {
        if let Ok(mut st) = state.lock() {
            st.touch();
        }
    }
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
            // Passkeys whose rp_id does not match this page directly. Resolved
            // after the lock is released.
            let mut deferred: Vec<(String, LoginMatch)> = Vec::new();
            if let Ok(summaries) = vault.list_items(false) {
                for s in summaries {
                    if let Ok(item) = vault.get_item(s.id) {
                        match &item.data {
                            VaultItem::Login {
                                url: u,
                                username,
                                title,
                                ..
                            } if domain_matches(u, &url) => {
                                items.push(LoginMatch {
                                    id: item.id.to_string(),
                                    title: title.clone(),
                                    username: username.clone(),
                                    kind: "password".into(),
                                });
                            }
                            // Passkeys for this site: surfaced so the picker can
                            // show the user a passkey exists. Matched by the same
                            // rule the ceremony uses. Those that do not match
                            // DIRECTLY are set aside — deciding them needs the
                            // relying party's related-origins file, and fetching
                            // it under this lock would stall every other command
                            // behind a network request.
                            VaultItem::Passkey {
                                rp_id,
                                user_name,
                                title,
                                ..
                            } => {
                                let entry = LoginMatch {
                                    id: item.id.to_string(),
                                    title: title.clone(),
                                    username: user_name.clone(),
                                    kind: "passkey".into(),
                                };
                                if rp_id_matches_origin(rp_id, &url) {
                                    items.push(entry);
                                } else {
                                    deferred.push((rp_id.clone(), entry));
                                }
                            }
                            // Non-matching logins/passkeys and other item kinds
                            // (SSH keys, secure notes) are not autofillable here.
                            _ => {}
                        }
                    }
                }
            }
            drop(st);

            // Now the network part, off the lock. Only for passkeys that did not
            // match outright, and only one request per relying party per twelve
            // hours — a vault with no such passkeys does no I/O at all.
            for (rp_id, entry) in deferred {
                if rp_id_allows_origin(&rp_id, &url) {
                    items.push(entry);
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
        Request::PasskeyCreate {
            origin,
            rp_id,
            user_name,
            user_handle,
            exclude_credentials,
        } => {
            // Kill switch: when passkey handling is off, ignore the ceremony so
            // the browser / platform authenticator takes over (the shim falls
            // back on this error). No prompt, ever.
            if !passkeys_enabled(state) {
                return Response::Error {
                    message: "passkeys_disabled".into(),
                };
            }
            // Anti-phishing: the RP id must belong to the page's origin.
            // Related Origin Requests apply to the ceremony too — a passkey
            // registered for login.microsoft.com must be usable on the page
            // Microsoft actually redirects you to. No lock is held here.
            if !rp_id_allows_origin(&rp_id, &origin) {
                return Response::Error {
                    message: "origin_mismatch".into(),
                };
            }
            // Must be unlocked before we prompt the user.
            let mut blocked_same_account = false;
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
                // Refuse a create WITHOUT prompting when we already hold a
                // passkey for this relying party — this is the loop killer.
                // Sites like GitHub re-fire `create` on nearly every sign-in;
                // if we serviced each one we'd pop a Touch ID prompt and pile up
                // a duplicate credential every single time (exactly the reported
                // bug). Refusing here makes the page see InvalidStateError, the
                // spec's "you already have a credential" signal, so it stops.
                //
                // Two conditions trigger the refusal, both BEFORE any prompt:
                //   1. The site listed a credential we hold in excludeCredentials
                //      (the polite, spec-driven path), OR
                //   2. we hold ANY passkey for this rp_id with the same
                //      user_handle — even when the site sent no exclude list.
                //      Byte-equal handle so a genuinely different account can
                //      still register once. (An RP that legitimately wants to
                //      re-register must first remove the old passkey in Arca.)
                //
                // Case 2 is a house rule, not the spec, and it has a nasty
                // failure mode: if the RP does NOT actually hold the credential
                // — a registration it rejected, or one deleted server-side —
                // then re-registering is the only way back, and this silently
                // refuses it. The page renders our InvalidStateError as "you
                // already have a passkey", which is a lie from the RP's point of
                // view, and nothing anywhere says the way out is to delete the
                // passkey in Arca first. So case 2 is reported to the user;
                // case 1 is the RP's own polite signal and needs no narration.
                if let Ok(summaries) = vault.list_items(false) {
                    for sum in summaries {
                        let Ok(item) = vault.get_item(sum.id) else {
                            continue;
                        };
                        if let VaultItem::Passkey {
                            rp_id: r,
                            credential_id: cid,
                            user_handle: uh,
                            ..
                        } = &item.data
                        {
                            if *r != rp_id {
                                continue;
                            }
                            if exclude_credentials.iter().any(|e| e == cid) {
                                return Response::Error {
                                    message: "excluded".into(),
                                };
                            }
                            if *uh == user_handle {
                                blocked_same_account = true;
                                break;
                            }
                        }
                    }
                }
            }
            if blocked_same_account {
                // Emitted outside the state lock: this reaches the webview, and
                // the webview answers by calling commands that take that lock.
                if let Some(app) = app {
                    let _ = app.emit("passkey-registration-blocked", rp_id.clone());
                }
                return Response::Error {
                    message: "excluded".into(),
                };
            }
            // Registration ALWAYS requires an explicit user approval; a silent
            // create must never register a credential. `true` = this is a NEW
            // passkey, so the prompt says "create" (not "sign in").
            let Some(user_verified) = approve_passkey(&rp_id, true, app, consent) else {
                return Response::Error {
                    message: "denied".into(),
                };
            };
            let Ok(new_pk) = vault_core::passkey::create(&rp_id, user_verified) else {
                return Response::Error {
                    message: "internal".into(),
                };
            };
            let credential_id = new_pk.credential_id.clone();
            let attestation_object = new_pk.attestation_object;
            {
                let mut st = match state.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        return Response::Error {
                            message: "internal".into(),
                        }
                    }
                };
                let AppState { store, vault, .. } = &mut *st;
                let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                // Dedup: if a passkey for the same relying party AND the same
                // user handle already exists, REPLACE it (reuse its id) instead
                // of piling up a duplicate. Only when the user handle is
                // non-empty — an empty handle can't distinguish accounts, so we
                // must not collapse them.
                //
                // This is a RACE GUARD, not the ordinary path: the check above
                // already refused that exact condition before prompting, so the
                // only way to arrive here holding a match is for one to have
                // been written while the approval dialog was open. Do not read
                // it as "re-registration replaces the old key" — re-registration
                // never gets this far.
                let existing_id = if user_handle.is_empty() {
                    None
                } else {
                    vault.list_items(false).ok().and_then(|sums| {
                        sums.into_iter().find_map(|s| {
                            let item = vault.get_item(s.id).ok()?;
                            match &item.data {
                                VaultItem::Passkey {
                                    rp_id: r,
                                    user_handle: uh,
                                    ..
                                } if *r == rp_id && *uh == user_handle => Some(s.id),
                                _ => None,
                            }
                        })
                    })
                };
                let mut item = Item::new(
                    VaultItem::Passkey {
                        title: rp_id.clone(),
                        rp_id: rp_id.clone(),
                        user_name,
                        user_handle,
                        credential_id: new_pk.credential_id,
                        private_key: new_pk.private_key.to_vec(),
                        sign_count: 0,
                    },
                    crate::state::now_millis(),
                );
                if let Some(id) = existing_id {
                    item.id = id;
                }
                if vault.upsert_item(item).is_err() || store.save_synced(vault).is_err() {
                    return Response::Error {
                        message: "internal".into(),
                    };
                }
                crate::sync::mark_dirty();
            }
            if let Some(app) = app {
                let _ = app.emit("passkey-created", rp_id);
            }
            Response::PasskeyCredential {
                credential_id,
                attestation_object,
            }
        }
        Request::PasskeyGet {
            origin,
            rp_id,
            client_data_hash,
            allow_credentials,
        } => {
            if !passkeys_enabled(state) {
                return Response::Error {
                    message: "passkeys_disabled".into(),
                };
            }
            // Related Origin Requests apply to the ceremony too — a passkey
            // registered for login.microsoft.com must be usable on the page
            // Microsoft actually redirects you to. No lock is held here.
            if !rp_id_allows_origin(&rp_id, &origin) {
                return Response::Error {
                    message: "origin_mismatch".into(),
                };
            }
            // Resolve the passkey under the lock; release it before the prompt.
            let credential_id;
            let user_handle;
            let private_key;
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
                let mut found = None;
                if let Ok(summaries) = vault.list_items(false) {
                    for s in summaries {
                        let Ok(item) = vault.get_item(s.id) else {
                            continue;
                        };
                        if let VaultItem::Passkey {
                            rp_id: r,
                            credential_id: cid,
                            private_key: pk,
                            user_handle: uh,
                            ..
                        } = &item.data
                        {
                            let allowed = allow_credentials.is_empty()
                                || allow_credentials.iter().any(|a| a == cid);
                            if *r == rp_id && allowed {
                                found = Some((cid.clone(), uh.clone(), pk.clone()));
                                break;
                            }
                        }
                    }
                }
                let Some((cid, uh, pk)) = found else {
                    return Response::Error {
                        message: "not_found".into(),
                    };
                };
                credential_id = cid;
                user_handle = uh;
                private_key = pk;
            }

            // An assertion ALWAYS requires an explicit user approval — otherwise
            // the authenticator would falsely claim user presence/verification,
            // which relying parties trust for step-up defenses. `false` = this
            // is a sign-in, so the prompt says "sign in" (not "create").
            let Some(user_verified) = approve_passkey(&rp_id, false, app, consent) else {
                return Response::Error {
                    message: "denied".into(),
                };
            };

            let Ok((authenticator_data, signature)) =
                vault_core::passkey::assert(&private_key, &rp_id, &client_data_hash, user_verified)
            else {
                return Response::Error {
                    message: "internal".into(),
                };
            };
            if let Some(app) = app {
                let _ = app.emit("passkey-used", rp_id);
            }
            Response::PasskeyAssertion {
                credential_id,
                authenticator_data,
                signature,
                user_handle,
            }
        }
        Request::SaveProbe {
            url,
            username,
            password,
        } => {
            if password.is_empty() {
                return Response::SaveDecision {
                    action: "known".into(), // nothing worth saving
                };
            }
            let st = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return Response::Error {
                        message: "internal".into(),
                    }
                }
            };
            if !st.settings.save_prompt {
                return Response::SaveDecision {
                    action: "disabled".into(),
                };
            }
            let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                return Response::SaveDecision {
                    action: "locked".into(),
                };
            };
            let host = host_of(&url);
            if host.is_empty() {
                return Response::SaveDecision {
                    action: "disabled".into(),
                };
            }
            let action = match find_login(vault, &host, &username) {
                None => "new",
                Some((_, cur)) if cur == password => "known",
                Some(_) => "update",
            };
            Response::SaveDecision {
                action: action.into(),
            }
        }
        Request::SaveLogin {
            url,
            username,
            password,
        } => {
            if password.is_empty() {
                return Response::Error {
                    message: "empty".into(),
                };
            }
            let mut st = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return Response::Error {
                        message: "internal".into(),
                    }
                }
            };
            if !st.settings.save_prompt {
                return Response::Error {
                    message: "disabled".into(),
                };
            }
            let host = host_of(&url);
            if host.is_empty() {
                return Response::Error {
                    message: "invalid".into(),
                };
            }
            {
                let AppState { store, vault, .. } = &mut *st;
                let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                match find_login(vault, &host, &username) {
                    // Already stored with this password: nothing to do.
                    Some((_, cur)) if cur == password => return Response::Saved,
                    // Same site + username, new password: update in place.
                    Some((id, _)) => {
                        let Ok(current) = vault.get_item(id) else {
                            return Response::Error {
                                message: "internal".into(),
                            };
                        };
                        if let VaultItem::Login {
                            title,
                            username: un,
                            url: u,
                            totp_secret,
                            notes,
                            ..
                        } = &current.data
                        {
                            let item = Item {
                                id: current.id,
                                created_at: current.created_at,
                                modified_at: crate::state::now_millis(),
                                deleted_at: None,
                                data: VaultItem::Login {
                                    title: title.clone(),
                                    username: un.clone(),
                                    url: u.clone(),
                                    password,
                                    totp_secret: totp_secret.clone(),
                                    notes: notes.clone(),
                                },
                            };
                            if vault.upsert_item(item).is_err() || store.save_synced(vault).is_err()
                            {
                                return Response::Error {
                                    message: "internal".into(),
                                };
                            }
                        }
                    }
                    // Brand-new login for this site.
                    None => {
                        let item = Item::new(
                            VaultItem::Login {
                                title: host.clone(),
                                username,
                                password,
                                url,
                                totp_secret: None,
                                notes: String::new(),
                            },
                            crate::state::now_millis(),
                        );
                        if vault.upsert_item(item).is_err() || store.save_synced(vault).is_err() {
                            return Response::Error {
                                message: "internal".into(),
                            };
                        }
                    }
                }
            }
            crate::sync::mark_dirty();
            if let Some(app) = app {
                let _ = app.emit("login-saved", host);
            }
            Response::Saved
        }
        Request::Unlock => {
            let already_open = state
                .lock()
                .ok()
                .and_then(|st| st.vault.as_ref().map(|v| v.is_unlocked()))
                .unwrap_or(false);
            if already_open {
                // Racing a fill that already succeeded, or a second field on the
                // same page. Do not steal focus from what the user is doing.
                return Response::UnlockRequested;
            }
            // The browser is about to be blurred, then focused again — that is
            // the flow, not the user leaving. Hold off blur-locking long enough
            // for them to authenticate here and click a credential there.
            if let Ok(mut st) = state.lock() {
                st.blur_grace_until =
                    Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
            }

            // Unlock RIGHT HERE, without bringing the window forward.
            //
            // Routing this through our lock screen meant the window jumped in
            // front of the page you were signing in to, and left you looking at
            // Arca instead of the field you started from. Apple's own Passwords
            // proves the prompt needs no app in the foreground.
            //
            // macOS: Touch ID is a free-floating system dialog.
            // Windows: Hello must be PARENTED to a window of ours, but parenting
            // is not focus — the dialog takes focus itself, the app stays put.
            // The prompt runs before the state lock, because it blocks on a
            // human.
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            {
                // Windows only: a hidden window is not a usable parent, so make
                // sure it exists on screen — without raising it.
                #[cfg(target_os = "windows")]
                if let Some(app) = app {
                    if let Some(w) = app.get_webview_window("main") {
                        if !w.is_visible().unwrap_or(false) {
                            let _ = w.show();
                        }
                    }
                }

                if crate::biometric::authenticate(app, "unlock your password vault").is_err() {
                    // Cancelled or failed. Nothing is unlocked, and the extension
                    // finds that out when it re-probes.
                    return Response::UnlockRequested;
                }
                let Ok(mut st) = state.lock() else {
                    return Response::Error {
                        message: "internal".into(),
                    };
                };
                if st.vault.is_none() && st.store.exists() {
                    st.vault = st.store.load().ok();
                }
                let AppState { store, vault, .. } = &mut *st;
                if let Some(vault) = vault.as_mut() {
                    let _ = store.quick_unlock(vault);
                }
                st.touch();
                drop(st);
                // The window may be on screen showing its lock screen; without
                // this it would sit there claiming to be locked while the vault
                // is open.
                if let Some(app) = app {
                    let _ = app.emit("vault-unlocked", ());
                }
            }

            // Everywhere else (Linux): there is no biometric to call, so the
            // master password has to be typed — and that needs a window. This is
            // a platform limit, not a shortcut.
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            if let Some(app) = app {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
                let _ = app.emit("unlock-requested", ());
            }
            Response::UnlockRequested
        }
        Request::GeneratePassword { length, symbols } => {
            // Clamped rather than refused. The caller is a browser extension,
            // and a site that caps passwords at 16 is a real thing; failing the
            // request would send the user to type one themselves, which is the
            // outcome this whole feature exists to avoid.
            let opts = vault_core::password::PasswordOptions {
                length: length.unwrap_or(20).clamp(8, 64),
                symbols: symbols.unwrap_or(true),
                ..Default::default()
            };
            match vault_core::password::generate_password(&opts) {
                Ok(pw) => Response::GeneratedPassword {
                    password: pw.to_string(),
                },
                Err(_) => Response::Error {
                    message: "internal".into(),
                },
            }
        }
    }
}

/// Mandatory user approval for a passkey create/get. Returns `Some(user_verified)`
/// on approval — `true` when a genuine user verification gated it — or `None`
/// on denial. A passkey operation must NEVER proceed without this.
/// Whether Arca should handle passkey ceremonies at all (the Settings kill
/// switch). Defaults to on if the state lock is unavailable.
fn passkeys_enabled(state: &Mutex<AppState>) -> bool {
    state
        .lock()
        .map(|st| st.settings.handle_passkeys)
        .unwrap_or(true)
}

/// How long a decline silences further passkey prompts for the same relying
/// party, by how many times in a row it has been declined.
///
/// A single fixed cooldown was the original design and it was wrong: a page
/// that keeps firing ceremonies just gets a fresh prompt every time the window
/// expires, forever. Ninety seconds is not a cooldown, it is a snooze button
/// nobody asked for, and from the user's chair it is indistinguishable from the
/// nag never stopping.
///
/// The escalation matters more than the exact numbers. The browser side tries
/// to tell a real "sign in with a passkey" click from a page auto-firing one,
/// but it only has `navigator.userActivation`, which means "the user did
/// *something* in the last few seconds" — click anywhere on a login page and a
/// background ceremony sails straight through. That heuristic will always be
/// approximate, so this side, which is the one that actually puts a Touch ID
/// prompt on screen, must be the one that can say no permanently.
const PASSKEY_DECLINE_BACKOFF: [Duration; 3] = [
    Duration::from_secs(90),
    Duration::from_secs(15 * 60),
    Duration::from_secs(60 * 60),
];

/// Consecutive declines after which a site is suppressed for the rest of the
/// session. Deliberately not forever-across-restarts: quitting the app is a
/// clear, discoverable way back, and persisting a refusal the user cannot see
/// would strand a genuine sign-in with no explanation.
const PASSKEY_DECLINE_LIMIT: u32 = 4;

/// A handful of declines and then stop, not an unbounded ladder. Checked here
/// rather than in a test because a test that loops to this value would hang
/// instead of failing if it ever grew.
const _: () = assert!(PASSKEY_DECLINE_LIMIT <= 10);

struct PasskeyDecline {
    at: Instant,
    /// Consecutive declines with no approval in between.
    count: u32,
}

/// Per-(site, action) decline state (see the backoff above).
static PASSKEY_DECLINED_AT: LazyLock<Mutex<HashMap<String, PasskeyDecline>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn passkey_decline_map() -> std::sync::MutexGuard<'static, HashMap<String, PasskeyDecline>> {
    match PASSKEY_DECLINED_AT.lock() {
        Ok(m) => m,
        Err(e) => e.into_inner(),
    }
}

/// Whether to stay silent instead of prompting again.
fn passkey_suppressed(key: &str) -> bool {
    let map = passkey_decline_map();
    let Some(decline) = map.get(key) else {
        return false;
    };
    if decline.count >= PASSKEY_DECLINE_LIMIT {
        return true;
    }
    let step = (decline.count as usize).saturating_sub(1);
    decline.at.elapsed() < PASSKEY_DECLINE_BACKOFF[step.min(PASSKEY_DECLINE_BACKOFF.len() - 1)]
}

/// Record a decline. Returns true when this one crossed into "suppressed for
/// the session", so the caller can say so rather than going quiet unexplained.
fn record_passkey_decline(key: &str) -> bool {
    let mut map = passkey_decline_map();
    let decline = map.entry(key.to_string()).or_insert(PasskeyDecline {
        at: Instant::now(),
        count: 0,
    });
    decline.at = Instant::now();
    decline.count += 1;
    decline.count == PASSKEY_DECLINE_LIMIT
}

/// Reset the backoff for a key (after a successful approval, so a later genuine
/// ceremony is not suppressed).
fn clear_passkey_decline(key: &str) {
    passkey_decline_map().remove(key);
}

/// Approve a passkey ceremony. `is_create` distinguishes registering a NEW
/// passkey from signing in with an existing one — the user sees a different
/// prompt for each, so accepting a background "create a passkey" can never be
/// mistaken for a login. The decline cooldown is keyed per (site, action) so a
/// declined create never suppresses a real sign-in.
fn approve_passkey(
    rp_id: &str,
    is_create: bool,
    app: Option<&AppHandle>,
    consent: &mut dyn FnMut(&ConsentContext) -> bool,
) -> Option<bool> {
    let cooldown_key = format!("{rp_id}/{}", if is_create { "create" } else { "get" });
    // If the user just declined this same action for this site, a background tab
    // is almost certainly re-firing it — suppress silently instead of nagging.
    // (Only active in production, where `app` drives a real prompt; unit tests
    // inject their own consent and must run every time.)
    if app.is_some() && passkey_suppressed(&cooldown_key) {
        return None;
    }
    let result = approve_passkey_inner(rp_id, is_create, app, consent);
    if let Some(app) = app {
        match result {
            None => {
                if record_passkey_decline(&cooldown_key) {
                    // Going quiet without saying so would look like a bug the
                    // next time the user genuinely wanted to sign in.
                    let _ = app.emit(
                        "passkey-suppressed",
                        PasskeySuppressedDto {
                            site: rp_id.to_string(),
                            is_create,
                        },
                    );
                }
            }
            Some(_) => clear_passkey_decline(&cooldown_key),
        }
    }
    result
}

/// Told to the UI when a site is muted for the session, so the user learns it
/// from Arca rather than from a sign-in that mysteriously stops working.
#[derive(Clone, serde::Serialize)]
struct PasskeySuppressedDto {
    site: String,
    is_create: bool,
}

fn approve_passkey_inner(
    rp_id: &str,
    is_create: bool,
    app: Option<&AppHandle>,
    consent: &mut dyn FnMut(&ConsentContext) -> bool,
) -> Option<bool> {
    // The reason string the user reads — clearly different for registering a new
    // passkey vs signing in, so a create can't be mistaken for a login.
    let reason = if is_create {
        format!("create a NEW passkey for {rp_id}")
    } else {
        format!("sign in to {rp_id}")
    };
    // macOS: Touch ID — a genuine platform user verification. It's a system
    // prompt, so it works even though the ceremony is triggered from the
    // background (the browser).
    #[cfg(target_os = "macos")]
    if app.is_some() {
        return match crate::biometric::authenticate(None, &reason) {
            Ok(()) => Some(true),
            Err(_) => None,
        };
    }
    // Windows/Linux: the OS platform-authenticator (Windows Hello) dialog can't
    // receive keyboard input when invoked from our background bridge thread, so
    // we do user verification in our OWN window instead — the user re-enters the
    // master password. A correct password is a genuine user-verification factor
    // (the very secret that unlocks the vault), so we may honestly set UV=1.
    #[cfg(not(target_os = "macos"))]
    if let Some(app) = app {
        return request_passkey_verification(app, rp_id, is_create);
    }
    // Tests / headless (no AppHandle): the injected consent closure provides
    // user presence only (user_verified = false).
    let _ = app;
    let ctx = ConsentContext {
        site: rp_id.to_string(),
        account: String::new(),
        title: reason,
    };
    consent(&ctx).then_some(false)
}

/// Windows/Linux user verification for a passkey ceremony: emit a request to the
/// frontend (which prompts for the master password in our own window), bring the
/// window forward, and block this bridge thread until the password is verified
/// (`Some(true)`) or the user cancels / it times out (`None`). Reuses the
/// `PendingConsents` channel; `verify_passkey_approval` only resolves it `true`
/// after the master password checks out.
#[cfg(not(target_os = "macos"))]
fn request_passkey_verification(app: &AppHandle, rp_id: &str, is_create: bool) -> Option<bool> {
    let verify_id = Uuid::new_v4().simple().to_string();
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    {
        // Dedicated verification map — never the shared consent map — so only a
        // password-checked resolve can satisfy this `true`.
        let pending = app.state::<PendingVerifications>();
        let Ok(mut map) = pending.0.lock() else {
            return None;
        };
        map.insert(verify_id.clone(), tx);
    }
    let _ = app.emit(
        "passkey-verify-request",
        serde_json::json!({ "id": verify_id, "site": rp_id, "isCreate": is_create }),
    );
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
    let verified = rx.recv_timeout(CONSENT_TIMEOUT).unwrap_or(false);
    if let Ok(mut map) = app.state::<PendingVerifications>().0.lock() {
        map.remove(&verify_id);
    }
    verified.then_some(true)
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

/// Resolve a pending passkey user-verification. Called only from the
/// password-checked `verify_passkey_approval` command (with `true`) and the
/// `cancel_passkey_verification` command (always `false`), so the presence-only
/// autofill-consent path can never set UV=1.
pub fn resolve_verification(app: &AppHandle, id: &str, approved: bool) {
    if let Ok(mut map) = app.state::<PendingVerifications>().0.lock() {
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

    /// The nag has to actually END. The original design suppressed for a fixed
    /// 90 seconds, which just meant a fresh Touch ID prompt every 90 seconds
    /// forever — and from the user's chair that is not a cooldown at all.
    #[test]
    fn declining_repeatedly_eventually_silences_a_site_for_good() {
        let key = "github.com/get-nag-test";
        clear_passkey_decline(key);

        // Bounded independently of the constant under test. A loop whose length
        // IS that constant hangs instead of failing when the value is wrong,
        // which is the least useful way for a test to react to a regression.
        // That the limit fits inside this bound is checked where it is declared,
        // at compile time.
        const TRIES: u32 = 10;

        let mut announcements = 0;
        for _ in 0..TRIES {
            if record_passkey_decline(key) {
                announcements += 1;
            }
            assert!(
                passkey_suppressed(key),
                "silent immediately after a decline"
            );
        }
        assert_eq!(
            announcements, 1,
            "the permanent stop is announced exactly once, not on every later attempt"
        );

        // Past the limit the elapsed time stops mattering: no window reopens,
        // which is the whole difference from the old behaviour.
        {
            let mut map = passkey_decline_map();
            let decline = map.get_mut(key).unwrap();
            decline.at = Instant::now() - Duration::from_secs(24 * 60 * 60);
        }
        assert!(
            passkey_suppressed(key),
            "a day later it must STILL be silent, or the nag simply resumes"
        );

        // An approval is the way back: a genuine sign-in later must not be
        // swallowed by a refusal the user has no way to see.
        clear_passkey_decline(key);
        assert!(!passkey_suppressed(key));
    }

    /// Before the limit, silence expires — declining once must not lock a site
    /// out of a real sign-in an hour later.
    #[test]
    fn an_early_decline_expires_instead_of_locking_the_site_out() {
        let key = "example.com/get-expiry-test";
        clear_passkey_decline(key);

        record_passkey_decline(key);
        assert!(passkey_suppressed(key));

        {
            let mut map = passkey_decline_map();
            map.get_mut(key).unwrap().at = Instant::now() - Duration::from_secs(120);
        }
        assert!(
            !passkey_suppressed(key),
            "one decline is a snooze, not a ban"
        );
        clear_passkey_decline(key);
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

    /// Regression: `host_of` used to end the authority at `/` only, so an `@`
    /// anywhere in a query or fragment read as userinfo and everything after it
    /// became the host. A stored `https://bank.example#@evil.com` therefore
    /// matched `evil.com`, and autofill offered the bank credential there.
    ///
    /// Browser-supplied URLs were never affected (`location.href` always carries
    /// the path `/`), but a stored URL need not come from a browser — CSV import
    /// is a documented path for a file the user may not control.
    ///
    /// The parsing now lives in `vault-core`; this pins the property that
    /// matters here, which is whether the credential is offered at all.
    #[test]
    fn an_at_sign_after_the_authority_never_moves_the_match() {
        for stored in [
            "https://bank.example#@evil.com",
            "https://bank.example?ref=@evil.com",
            "https://bank.example?email=me@gmail.com",
            r"https://bank.example\@evil.com",
        ] {
            assert!(
                !domain_matches(stored, "https://evil.com/"),
                "{stored} offered the credential on evil.com"
            );
            assert!(
                !domain_matches(stored, "https://gmail.com/"),
                "{stored} offered the credential on gmail.com"
            );
            assert!(
                domain_matches(stored, "https://bank.example/login"),
                "{stored} failed to match its own site"
            );
        }
        // Real userinfo is still userinfo: it sits before the authority ends.
        assert!(domain_matches(
            "https://me@bank.example/login",
            "https://bank.example/"
        ));
    }

    #[test]
    fn host_normalization_and_domain_matching() {
        assert_eq!(host_of("https://www.github.com/login?x=1"), "github.com");
        assert_eq!(
            host_of("http://user@accounts.google.com:443/"),
            "accounts.google.com"
        );
        // Case-insensitive: lowercase happens BEFORE the "www." strip.
        assert_eq!(host_of("https://WWW.GitHub.com/login"), "github.com");
        // IDN hosts need full Unicode lowercasing to compare equal.
        assert_eq!(host_of("https://MÜNCHEN.DE"), "münchen.de");
        // Bracketed IPv6 literals keep their identity (not cut at ':').
        assert_eq!(host_of("https://[fd00::a1]/admin"), "[fd00::a1]");
        assert_eq!(host_of("https://[::1]:8080/x"), "[::1]");
        // ...so two DIFFERENT IPv6 hosts must neither group nor autofill-match.
        assert!(!domain_matches("https://[fd00::a1]", "https://[fd00::b2]"));
        assert!(domain_matches(
            "https://[fd00::a1]",
            "https://[fd00::a1]:8443"
        ));
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

    /// Filling from the browser has to count as using Arca — and the automatic
    /// chatter must not.
    ///
    /// Both halves fail silently. Miss the first and the vault locks while you
    /// work, which is the complaint this came from. Miss the second and one open
    /// tab keeps it unlocked for ever, which looks like a generous timeout and
    /// is the absence of one.
    #[test]
    fn browser_use_resets_the_idle_timer_but_polling_does_not() {
        let deliberate = [
            Request::Fill {
                id: "x".into(),
                url: "https://github.com".into(),
            },
            Request::SaveLogin {
                url: "https://github.com".into(),
                username: "u".into(),
                password: "p".into(),
            },
            Request::GeneratePassword {
                length: None,
                symbols: None,
            },
        ];
        for req in deliberate {
            assert!(req.is_deliberate_use(), "{req:?} is the user acting");
        }

        let automatic = [
            Request::Hello { token: "t".into() },
            Request::Match {
                url: "https://github.com".into(),
            },
            // Sent on EVERY submitted form, including ones with nothing to do
            // with Arca. The clearest case for not counting it.
            Request::SaveProbe {
                url: "https://github.com".into(),
                username: "u".into(),
                password: "p".into(),
            },
        ];
        for req in automatic {
            assert!(!req.is_deliberate_use(), "{req:?} is the extension talking");
        }
    }

    /// Generation must work with the vault LOCKED.
    ///
    /// Every other bridge request reads or writes the vault and is right to
    /// refuse while locked, so "check unlocked first" is the reflex here — and
    /// applying it to this one would put a master password between the user and
    /// the exact moment they are deciding whether to invent a password instead.
    /// Nothing secret is read: the answer is bytes from the CSPRNG.
    #[test]
    fn generating_a_password_does_not_need_an_unlocked_vault() {
        let dir = TempDir::new().unwrap();
        let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
        let (clip, _) = ClipboardManager::memory();
        // No vault at all: stricter than locked, and it still has to answer.
        let state = Mutex::new(AppState::new(store, None, clip));
        let mut authed = true;

        let mut generate = |length: Option<usize>| {
            handle_request(
                Request::GeneratePassword {
                    length,
                    symbols: Some(true),
                },
                &state,
                "t",
                &mut authed,
                None,
                &mut allow(),
            )
        };

        let Response::GeneratedPassword { password } = generate(Some(24)) else {
            panic!("a locked vault must still generate");
        };
        assert_eq!(password.chars().count(), 24);

        // Clamped, not refused: a site that caps at 6 characters is a real
        // thing, and erroring would send the user off to type one by hand.
        let Response::GeneratedPassword { password } = generate(Some(1)) else {
            panic!("an absurd length must be clamped, not refused");
        };
        assert_eq!(password.chars().count(), 8);
        let Response::GeneratedPassword { password } = generate(Some(9999)) else {
            panic!("an absurd length must be clamped, not refused");
        };
        assert_eq!(password.chars().count(), 64);

        // Default when the caller says nothing.
        let Response::GeneratedPassword { password } = generate(None) else {
            panic!("a missing length must fall back to the default");
        };
        assert_eq!(password.chars().count(), 20);
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
    fn match_labels_passwords_and_passkeys_by_kind() {
        let dir = TempDir::new().unwrap();
        let state = unlocked_state(&dir);
        // A password login and a passkey, both for github.com.
        add(&state, "GitHub", "frank", "gh-pw", "https://github.com");
        let mut authed = true;
        let r = handle_request(
            Request::PasskeyCreate {
                origin: "https://github.com".into(),
                rp_id: "github.com".into(),
                user_name: "frank".into(),
                user_handle: vec![1, 2, 3],
                exclude_credentials: vec![],
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        );
        assert!(matches!(r, Response::PasskeyCredential { .. }));

        // Match on a github.com page returns both, each tagged by kind.
        let r = handle_request(
            Request::Match {
                url: "https://github.com/login".into(),
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        );
        match r {
            Response::Logins { items } => {
                assert_eq!(items.len(), 2);
                assert!(items
                    .iter()
                    .any(|i| i.kind == "password" && i.username == "frank"));
                assert!(items.iter().any(|i| i.kind == "passkey"));
            }
            other => panic!("expected logins, got {other:?}"),
        }
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

    #[test]
    fn passkey_create_then_get_binds_to_origin_and_signs() {
        use vault_core::passkey;

        let dir = TempDir::new().unwrap();
        let state = unlocked_state(&dir);
        let mut authed = true;
        let mut create = |origin: &str, rp: &str| {
            handle_request(
                Request::PasskeyCreate {
                    origin: origin.into(),
                    rp_id: rp.into(),
                    user_name: "frank".into(),
                    user_handle: vec![9, 9, 9],
                    exclude_credentials: vec![],
                },
                &state,
                "t",
                &mut authed,
                None,
                &mut allow(),
            )
        };

        // A page on evil.com may not create a github.com passkey.
        assert!(matches!(
            create("https://evil.com", "github.com"),
            Response::Error { message } if message == "origin_mismatch"
        ));

        // A page on the RP (incl. a subdomain) can.
        let cred_id = match create("https://sub.github.com/x", "github.com") {
            Response::PasskeyCredential {
                credential_id,
                attestation_object,
            } => {
                assert!(!attestation_object.is_empty());
                credential_id
            }
            other => panic!("expected credential, got {other:?}"),
        };

        // get() from a matching origin returns an assertion that verifies.
        let client_data_hash = vec![3u8; 32];
        let r = handle_request(
            Request::PasskeyGet {
                origin: "https://github.com/login".into(),
                rp_id: "github.com".into(),
                client_data_hash: client_data_hash.clone(),
                allow_credentials: vec![cred_id.clone()],
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        );
        let (auth_data, sig, ret_cred) = match r {
            Response::PasskeyAssertion {
                credential_id,
                authenticator_data,
                signature,
                user_handle,
            } => {
                assert_eq!(user_handle, vec![9, 9, 9]);
                (authenticator_data, signature, credential_id)
            }
            other => panic!("expected assertion, got {other:?}"),
        };
        assert_eq!(ret_cred, cred_id);

        // Independently verify the signature against a freshly asserted key is
        // not possible (private key is in the vault), but we can confirm the
        // assertion is well-formed: authData is 37 bytes with counter 0.
        assert_eq!(auth_data.len(), 37);
        assert_eq!(&auth_data[33..37], &0u32.to_be_bytes());
        assert!(!sig.is_empty());
        // Sanity: the same rp signs verifiably via the core (uses its own key).
        let fresh = passkey::create("github.com", true).unwrap();
        let (fa, fsig) =
            passkey::assert(&fresh.private_key, "github.com", &client_data_hash, true).unwrap();
        assert_eq!(fa.len(), 37);
        assert!(!fsig.is_empty());

        // get() from a non-RP origin is refused.
        assert!(matches!(
            handle_request(
                Request::PasskeyGet {
                    origin: "https://evil.com".into(),
                    rp_id: "github.com".into(),
                    client_data_hash: client_data_hash.clone(),
                    allow_credentials: vec![],
                },
                &state, "t", &mut authed, None, &mut allow(),
            ),
            Response::Error { message } if message == "origin_mismatch"
        ));

        // Unknown credential id -> not_found.
        assert!(matches!(
            handle_request(
                Request::PasskeyGet {
                    origin: "https://github.com".into(),
                    rp_id: "github.com".into(),
                    client_data_hash: client_data_hash.clone(),
                    allow_credentials: vec![vec![1, 2, 3, 4]],
                },
                &state, "t", &mut authed, None, &mut allow(),
            ),
            Response::Error { message } if message == "not_found"
        ));

        // A DENIED approval blocks the assertion (mandatory user approval).
        assert!(matches!(
            handle_request(
                Request::PasskeyGet {
                    origin: "https://github.com".into(),
                    rp_id: "github.com".into(),
                    client_data_hash,
                    allow_credentials: vec![cred_id],
                },
                &state, "t", &mut authed, None, &mut |_: &ConsentContext| false,
            ),
            Response::Error { message } if message == "denied"
        ));
    }

    #[test]
    fn rp_id_rejects_public_suffixes_and_cross_origin() {
        // A page may use its own registrable domain (incl. from a subdomain)...
        assert!(rp_id_matches_origin("github.com", "https://github.com"));
        assert!(rp_id_matches_origin(
            "github.com",
            "https://sub.github.com/x"
        ));
        assert!(rp_id_matches_origin(
            "evil.github.io",
            "https://evil.github.io"
        ));
        // ...but NOT a broader eTLD / public suffix...
        assert!(!rp_id_matches_origin("github.io", "https://evil.github.io"));
        assert!(!rp_id_matches_origin("com", "https://evil.com"));
        assert!(!rp_id_matches_origin("co.uk", "https://foo.co.uk"));
        // ...and never a different registrable domain (phishing).
        assert!(!rp_id_matches_origin("github.com", "https://evil.com"));
        assert!(!rp_id_matches_origin(
            "github.com",
            "https://github.com.evil.com"
        ));
    }

    #[test]
    fn save_probe_and_login_add_update_and_dedupe() {
        let dir = TempDir::new().unwrap();
        let state = unlocked_state(&dir);
        let mut authed = true;
        let probe = |url: &str, user: &str, pw: &str, authed: &mut bool| {
            handle_request(
                Request::SaveProbe {
                    url: url.into(),
                    username: user.into(),
                    password: pw.into(),
                },
                &state,
                "t",
                authed,
                None,
                &mut allow(),
            )
        };
        let save = |url: &str, user: &str, pw: &str, authed: &mut bool| {
            handle_request(
                Request::SaveLogin {
                    url: url.into(),
                    username: user.into(),
                    password: pw.into(),
                },
                &state,
                "t",
                authed,
                None,
                &mut allow(),
            )
        };
        let github_count = || {
            let st = state.lock().unwrap();
            st.vault
                .as_ref()
                .unwrap()
                .list_items(false)
                .unwrap()
                .iter()
                .filter(|s| host_of(&s.url) == "github.com")
                .count()
        };

        // Unknown login -> "new"; save it.
        assert!(matches!(
            probe("https://github.com/login", "frank", "pw1", &mut authed),
            Response::SaveDecision { action } if action == "new"
        ));
        assert_eq!(
            save("https://github.com/login", "frank", "pw1", &mut authed),
            Response::Saved
        );
        assert_eq!(github_count(), 1);

        // Same login (messier URL, different username case) + same pw -> "known".
        assert!(matches!(
            probe("https://www.github.com", "Frank", "pw1", &mut authed),
            Response::SaveDecision { action } if action == "known"
        ));
        // Saving a duplicate is a no-op, not a second entry.
        assert_eq!(
            save("https://github.com", "frank", "pw1", &mut authed),
            Response::Saved
        );
        assert_eq!(github_count(), 1);

        // Changed password -> "update"; commit updates in place (still one item).
        assert!(matches!(
            probe("https://github.com", "frank", "pw2", &mut authed),
            Response::SaveDecision { action } if action == "update"
        ));
        assert_eq!(
            save("https://github.com", "frank", "pw2", &mut authed),
            Response::Saved
        );
        assert_eq!(github_count(), 1);
        // Now pw2 is "known", pw1 would be an "update" back.
        assert!(matches!(
            probe("https://github.com", "frank", "pw2", &mut authed),
            Response::SaveDecision { action } if action == "known"
        ));

        // Setting off -> "disabled"; when locked -> "locked".
        state.lock().unwrap().settings.save_prompt = false;
        assert!(matches!(
            probe("https://x.com", "u", "p", &mut authed),
            Response::SaveDecision { action } if action == "disabled"
        ));
        state.lock().unwrap().settings.save_prompt = true;
        state.lock().unwrap().vault.as_mut().unwrap().lock();
        assert!(matches!(
            probe("https://x.com", "u", "p", &mut authed),
            Response::SaveDecision { action } if action == "locked"
        ));
        assert!(matches!(
            save("https://x.com", "u", "p", &mut authed),
            Response::Error { message } if message == "locked"
        ));
    }

    /// excludeCredentials: a create listing a credential we already hold must
    /// be refused with "excluded" WITHOUT consulting the user at all — that
    /// answer becomes InvalidStateError in the page and stops re-registration
    /// loops (the endless-Touch-ID bug).
    #[test]
    fn passkey_create_with_excluded_credential_is_refused_without_prompt() {
        let dir = TempDir::new().unwrap();
        let state = unlocked_state(&dir);
        let mut authed = true;

        // Register one passkey normally.
        let resp = handle_request(
            Request::PasskeyCreate {
                origin: "https://github.com".into(),
                rp_id: "github.com".into(),
                user_name: "frank".into(),
                user_handle: vec![1, 2, 3],
                exclude_credentials: vec![],
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        );
        let Response::PasskeyCredential { credential_id, .. } = resp else {
            panic!("expected a credential, got {resp:?}");
        };

        // Re-register with that credential excluded: refused, and the consent
        // closure must never run (no prompt).
        let mut never = |_: &ConsentContext| -> bool {
            panic!("consent must not be requested for an excluded create")
        };
        let resp = handle_request(
            Request::PasskeyCreate {
                origin: "https://github.com".into(),
                rp_id: "github.com".into(),
                user_name: "frank".into(),
                user_handle: vec![1, 2, 3],
                exclude_credentials: vec![credential_id],
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut never,
        );
        assert_eq!(
            resp,
            Response::Error {
                message: "excluded".into()
            }
        );
    }

    /// The other refusal branch: the site sent NO exclude list, but we already
    /// hold a passkey for this rp_id and account. Same answer, same silence
    /// towards the page — but this is the one the user gets told about, because
    /// re-registering is the only way back when the RP lost its copy.
    #[test]
    fn passkey_create_for_a_known_account_is_refused_without_an_exclude_list() {
        let dir = TempDir::new().unwrap();
        let state = unlocked_state(&dir);
        let mut authed = true;

        let create = |exclude: Vec<Vec<u8>>| Request::PasskeyCreate {
            origin: "https://login.microsoft.com".into(),
            rp_id: "login.microsoft.com".into(),
            user_name: "frank.lia@sybr.no".into(),
            user_handle: vec![9, 8, 7],
            exclude_credentials: exclude,
        };

        let resp = handle_request(create(vec![]), &state, "t", &mut authed, None, &mut allow());
        assert!(
            matches!(resp, Response::PasskeyCredential { .. }),
            "first registration should succeed, got {resp:?}"
        );

        // Same account, empty exclude list: refused, and without a prompt.
        let mut never = |_: &ConsentContext| -> bool {
            panic!("consent must not be requested for a known-account create")
        };
        let resp = handle_request(create(vec![]), &state, "t", &mut authed, None, &mut never);
        assert_eq!(
            resp,
            Response::Error {
                message: "excluded".into()
            }
        );

        // A different account on the same site still gets to register once.
        let resp = handle_request(
            Request::PasskeyCreate {
                origin: "https://login.microsoft.com".into(),
                rp_id: "login.microsoft.com".into(),
                user_name: "someone.else@sybr.no".into(),
                user_handle: vec![4, 5, 6],
                exclude_credentials: vec![],
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        );
        assert!(
            matches!(resp, Response::PasskeyCredential { .. }),
            "a distinct user handle must not be blocked, got {resp:?}"
        );
    }
}
