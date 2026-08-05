//! Arca's vault behind the CTAP2 authenticator (Linux).
//!
//! [`vault_ctap`] implements the protocol and [`vault_uhid`] gives it a device;
//! this is the part that knows what a passkey is. It answers five questions —
//! which credentials exist, does this one, make a new one, sign this, and does
//! the user agree — and every one of them goes through the same vault the rest
//! of the app uses.
//!
//! # How this differs from the browser-extension path
//!
//! `bridge.rs` answers the same ceremonies for the Chromium extension, and the
//! two share their consent machinery deliberately: the same prompt, the same
//! decline cooldown, the same log. Three things genuinely differ.
//!
//! **There is no origin.** The extension gets a page origin the page cannot
//! forge and binds `rp_id` to it. CTAP2 has no such field — the authenticator
//! is told an `rpId` and nothing about who is asking. Browsers do that check
//! correctly on our behalf; a native process does not have to. So on this path
//! the consent prompt *is* the anti-phishing control, which is why it names the
//! relying party and why that must never be softened into a bare "Approve?".
//!
//! **Duplicate registrations are handled by the spec, not by the house rule.**
//! `bridge.rs` refuses a `create` without prompting whenever it already holds a
//! passkey for the same relying party and user handle, because sites re-fire
//! `create` on every sign-in and each one popped a prompt. That rule is not
//! repeated here: on this path the *browser* shows its own authenticator picker
//! before a `makeCredential` ever reaches us, so a background tab cannot walk
//! us into the loop. The spec's `excludeList` is honoured by [`vault_ctap`]
//! before any prompt, and a same-account re-registration replaces the existing
//! item rather than piling up a duplicate.
//!
//! **Every stored passkey is discoverable.** A relying party can ask for a
//! non-discoverable credential, and we store it anyway — in the vault, where
//! the user can see it and where it is findable by relying party. Reporting it
//! as non-discoverable would mean holding a credential the user is looking at
//! and refusing to offer it.

use std::sync::Mutex;

use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;
use vault_core::{Item, Vault, VaultItem};
use vault_ctap::{
    Backend, BackendError, BackendResult, Consent, CreatedCredential, NewCredential, Operation,
    StoredCredential, User, UserAction,
};
use vault_uhid::{serve, Cancellation, DeviceOptions};
use zeroize::Zeroizing;

use crate::bridge;
use crate::state::AppState;

/// Stands in for the page origin in the passkey log. The extension path records
/// where a ceremony came from; here there is nothing to record, and saying so
/// is better than leaving the field blank as though it had been checked.
const CTAP_ORIGIN: &str = "(ctap-hid)";

/// One of the vault's passkeys, without its private key.
///
/// The secret is fetched only in [`VaultAuthenticator::sign`], so listing and
/// matching never copy key material out of the vault.
struct PasskeyRow {
    item_id: Uuid,
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
    user_name: String,
    modified_at: i64,
}

/// Arca's side of the CTAP2 authenticator.
pub struct VaultAuthenticator {
    app: AppHandle,
    cancellation: Cancellation,
}

impl VaultAuthenticator {
    /// Bind an authenticator to the running app.
    pub fn new(app: AppHandle, cancellation: Cancellation) -> Self {
        Self { app, cancellation }
    }

    /// Run `f` against the unlocked vault, or report why it could not.
    fn with_vault<T>(&self, f: impl FnOnce(&Vault) -> T) -> BackendResult<T> {
        let state = self.app.state::<Mutex<AppState>>();
        let guard = state.lock().map_err(|_| BackendError::Storage)?;
        let vault = guard
            .vault
            .as_ref()
            .filter(|v| v.is_unlocked())
            .ok_or(BackendError::Locked)?;
        Ok(f(vault))
    }

    /// Every passkey the vault holds for `rp_id`, newest first.
    fn rows_for(vault: &Vault, rp_id: &str) -> Vec<PasskeyRow> {
        let Ok(summaries) = vault.list_items(false) else {
            return Vec::new();
        };
        let mut rows: Vec<PasskeyRow> = summaries
            .into_iter()
            .filter_map(|summary| {
                let item = vault.get_item(summary.id).ok()?;
                match item.data {
                    VaultItem::Passkey {
                        rp_id: ref stored,
                        ref credential_id,
                        ref user_handle,
                        ref user_name,
                        ..
                    } if stored == rp_id => Some(PasskeyRow {
                        item_id: summary.id,
                        credential_id: credential_id.clone(),
                        user_handle: user_handle.clone(),
                        user_name: user_name.clone(),
                        modified_at: summary.modified_at,
                    }),
                    _ => None,
                }
            })
            .collect();
        // The one the user touched last is the one they most likely mean, and
        // it is the one a platform offers first when several come back.
        rows.sort_by_key(|row| std::cmp::Reverse(row.modified_at));
        rows
    }

    /// The private key for a credential id, pulled out on its own so no other
    /// path has to carry it.
    fn private_key(vault: &Vault, credential_id: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let summaries = vault.list_items(false).ok()?;
        summaries.into_iter().find_map(|summary| {
            let item = vault.get_item(summary.id).ok()?;
            match item.data {
                VaultItem::Passkey {
                    credential_id: ref stored,
                    ref private_key,
                    ..
                } if stored == credential_id => Some(Zeroizing::new(private_key.clone())),
                _ => None,
            }
        })
    }
}

fn stored(row: &PasskeyRow) -> StoredCredential {
    StoredCredential {
        credential_id: row.credential_id.clone(),
        user: User {
            id: row.user_handle.clone(),
            name: (!row.user_name.is_empty()).then(|| row.user_name.clone()),
            // The vault keeps one account name, not the separate display name
            // WebAuthn allows. Sending the same string twice would invent a
            // distinction the user never made.
            display_name: None,
        },
        discoverable: true,
    }
}

impl Backend for VaultAuthenticator {
    fn discover(&mut self, rp_id: &str) -> BackendResult<Vec<StoredCredential>> {
        self.with_vault(|vault| {
            Self::rows_for(vault, rp_id)
                .iter()
                .map(stored)
                .collect::<Vec<_>>()
        })
    }

    fn lookup(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
    ) -> BackendResult<Option<StoredCredential>> {
        // Scoped by rp_id, which is the whole point of this method: a
        // credential id is not a secret, so a caller that merely learned one
        // must not be able to reach the credential from another site.
        self.with_vault(|vault| {
            Self::rows_for(vault, rp_id)
                .iter()
                .find(|row| row.credential_id == credential_id)
                .map(stored)
        })
    }

    fn create(&mut self, credential: &NewCredential<'_>) -> BackendResult<CreatedCredential> {
        // The user has already approved by the time this runs — vault-ctap
        // calls `confirm` first — so a refused ceremony leaves no trace of the
        // site that asked.
        let rp_id = credential.rp.id.clone();
        let new_passkey = vault_core::passkey::create(&rp_id, credential.user_verified)
            .map_err(|_| BackendError::Storage)?;
        let credential_id = new_passkey.credential_id.clone();
        let cose_public_key = new_passkey.cose_public_key.clone();

        {
            let state = self.app.state::<Mutex<AppState>>();
            let mut guard = state.lock().map_err(|_| BackendError::Storage)?;
            let AppState { store, vault, .. } = &mut *guard;
            let vault = vault
                .as_mut()
                .filter(|v| v.is_unlocked())
                .ok_or(BackendError::Locked)?;

            // Re-registering the same account replaces its credential rather
            // than adding a second one the user would have to tell apart. Only
            // with a non-empty user handle: an empty one cannot distinguish
            // accounts, so collapsing on it would merge two real identities.
            let existing = (!credential.user.id.is_empty())
                .then(|| {
                    Self::rows_for(vault, &rp_id)
                        .into_iter()
                        .find(|row| row.user_handle == credential.user.id)
                        .map(|row| row.item_id)
                })
                .flatten();

            let mut item = Item::new(
                VaultItem::Passkey {
                    title: rp_id.clone(),
                    rp_id: rp_id.clone(),
                    user_name: credential.user.name.clone().unwrap_or_default(),
                    user_handle: credential.user.id.clone(),
                    credential_id: new_passkey.credential_id,
                    private_key: new_passkey.private_key.to_vec(),
                    sign_count: 0,
                },
                crate::state::now_millis(),
            );
            if let Some(id) = existing {
                item.id = id;
            }
            vault.upsert_item(item).map_err(|_| BackendError::Storage)?;
            store
                .save_synced(vault)
                .map_err(|_| BackendError::Storage)?;
            crate::sync::mark_dirty();
        }

        // Emitted outside the lock: this reaches the webview, and the webview
        // answers by calling commands that take the same lock.
        let _ = self.app.emit("passkey-created", rp_id);

        Ok(CreatedCredential {
            credential_id,
            cose_public_key,
        })
    }

    fn sign(&mut self, credential_id: &[u8], message: &[u8]) -> BackendResult<Vec<u8>> {
        let private_key = self
            .with_vault(|vault| Self::private_key(vault, credential_id))?
            .ok_or(BackendError::NotFound)?;
        vault_core::passkey::sign(&private_key, message).map_err(|_| BackendError::Signing)
    }

    fn confirm(&mut self, request: &Consent<'_>) -> UserAction {
        let state = self.app.state::<Mutex<AppState>>();

        // Kill switch. The device stays present when passkey handling is off —
        // it cannot be torn down from here, and a setting can change while a
        // browser is mid-ceremony — so the refusal happens at the prompt, which
        // is where every other refusal happens too.
        if !bridge::passkeys_enabled(&state) {
            return UserAction::Declined;
        }

        let is_create = match request.operation {
            Operation::Register => true,
            Operation::Authenticate => false,
            // `authenticatorSelection` asks "are you the authenticator the user
            // means?" with no ceremony attached and no relying party to name.
            // We advertise FIDO_2_0, where the command does not exist, so a
            // platform sending it is asking something we never claimed to
            // answer — and "not me" is the conservative reply. Approving would
            // claim a touch that never happened.
            Operation::Select => return UserAction::Declined,
        };

        // The host may already have given up while an earlier prompt was open.
        if self.cancellation.is_cancelled() {
            return UserAction::Declined;
        }

        bridge::log_passkey_request(&state, CTAP_ORIGIN, request.rp_id, is_create);

        // In the app, `approve_passkey` drives a real prompt and never reaches
        // this closure; it is the headless fallback, and refusing is the only
        // safe answer when there is nobody to ask.
        let mut no_one_to_ask = |_: &bridge::ConsentContext| false;

        match bridge::approve_passkey(
            request.rp_id,
            is_create,
            Some(&self.app),
            &mut no_one_to_ask,
        ) {
            Some(verified) => {
                bridge::log_passkey_outcome(
                    &state,
                    request.rp_id,
                    if verified {
                        "approved_verified"
                    } else {
                        "approved_presence_only"
                    },
                );
                UserAction::Approved { verified }
            }
            // `approve_passkey` folds a decline, a timeout and a suppressed
            // repeat into one `None`. Reporting all three as a refusal is the
            // quiet choice: a timeout invites the host to try again, and a
            // retry loop is exactly what the decline cooldown exists to stop.
            None => {
                bridge::log_passkey_outcome(&state, request.rp_id, "declined_or_no_verification");
                UserAction::Declined
            }
        }
    }
}

/// Bring up the virtual security key on a background thread.
///
/// Best-effort: creating the device needs write access to `/dev/uhid`, which is
/// root-only by default, and a machine without that rule installed should still
/// get an app — just not this path. The extension path is unaffected either way.
pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        let cancellation = Cancellation::new();
        let backend = VaultAuthenticator::new(app, cancellation.clone());
        if let Err(e) = serve(backend, &DeviceOptions::default(), &cancellation) {
            eprintln!(
                "arca: virtual security key unavailable ({e}). \
                 /dev/uhid is root-only by default; see 70-arca-uhid.rules."
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{KdfAlgorithm, KdfParams};

    /// One passkey to seed a test vault with.
    struct Seed<'a> {
        rp_id: &'a str,
        user_name: &'a str,
        user_handle: &'a [u8],
        credential_id: &'a [u8],
        modified_at: i64,
    }

    fn seed<'a>(
        rp_id: &'a str,
        user_name: &'a str,
        user_handle: &'a [u8],
        credential_id: &'a [u8],
        modified_at: i64,
    ) -> Seed<'a> {
        Seed {
            rp_id,
            user_name,
            user_handle,
            credential_id,
            modified_at,
        }
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

    fn vault_with(passkeys: &[Seed<'_>]) -> Vault {
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        for entry in passkeys {
            vault
                .upsert_item(Item::new(
                    VaultItem::Passkey {
                        title: entry.rp_id.into(),
                        rp_id: entry.rp_id.into(),
                        user_name: entry.user_name.into(),
                        user_handle: entry.user_handle.to_vec(),
                        credential_id: entry.credential_id.to_vec(),
                        // Real key material, so `private_key` is exercised
                        // against something that could actually sign.
                        private_key: vault_core::passkey::create(entry.rp_id, true)
                            .unwrap()
                            .private_key
                            .to_vec(),
                        sign_count: 0,
                    },
                    entry.modified_at,
                ))
                .unwrap();
        }
        vault
    }

    #[test]
    fn only_the_relying_partys_own_passkeys_come_back() {
        let vault = vault_with(&[
            seed("sybr.no", "frank", b"h1", b"c1", 1),
            seed("example.com", "someone", b"h2", b"c2", 2),
        ]);
        let rows = VaultAuthenticator::rows_for(&vault, "sybr.no");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].credential_id, b"c1");
    }

    #[test]
    fn a_credential_id_from_another_site_is_not_reachable() {
        // The property the whole path rests on: knowing a credential id — which
        // the relying party does — must not be enough to use it elsewhere.
        let vault = vault_with(&[seed("sybr.no", "frank", b"h1", b"c1", 1)]);
        let rows = VaultAuthenticator::rows_for(&vault, "evil.example");
        assert!(rows.is_empty());
        assert!(!rows.iter().any(|row| row.credential_id == b"c1"));
    }

    #[test]
    fn the_most_recently_used_passkey_is_offered_first() {
        let vault = vault_with(&[
            seed("sybr.no", "old", b"h1", b"c1", 100),
            seed("sybr.no", "newest", b"h2", b"c2", 300),
            seed("sybr.no", "middle", b"h3", b"c3", 200),
        ]);
        let names: Vec<String> = VaultAuthenticator::rows_for(&vault, "sybr.no")
            .into_iter()
            .map(|row| row.user_name)
            .collect();
        assert_eq!(names, ["newest", "middle", "old"]);
    }

    #[test]
    fn an_account_with_no_name_reports_none_rather_than_an_empty_string() {
        // WebAuthn treats an absent name and a blank one differently; a blank
        // one renders as an empty row in the browser's account picker.
        let vault = vault_with(&[seed("sybr.no", "", b"h1", b"c1", 1)]);
        let rows = VaultAuthenticator::rows_for(&vault, "sybr.no");
        let credential = stored(&rows[0]);
        assert_eq!(credential.user.name, None);
        assert_eq!(credential.user.display_name, None);
        assert_eq!(credential.user.id, b"h1");
        assert!(credential.discoverable);
    }

    #[test]
    fn the_account_name_crosses_when_there_is_one() {
        let vault = vault_with(&[seed("sybr.no", "frank@sybr.no", b"h1", b"c1", 1)]);
        let rows = VaultAuthenticator::rows_for(&vault, "sybr.no");
        assert_eq!(stored(&rows[0]).user.name.as_deref(), Some("frank@sybr.no"));
    }

    #[test]
    fn the_private_key_is_found_by_credential_id_and_can_sign() {
        let vault = vault_with(&[
            seed("sybr.no", "frank", b"h1", b"c1", 1),
            seed("example.com", "other", b"h2", b"c2", 2),
        ]);
        let key = VaultAuthenticator::private_key(&vault, b"c1").expect("credential exists");
        assert_eq!(key.len(), 32);
        assert!(vault_core::passkey::sign(&key, b"message").is_ok());

        // A different credential yields a different key, not the first match.
        let other = VaultAuthenticator::private_key(&vault, b"c2").unwrap();
        assert_ne!(key.to_vec(), other.to_vec());

        assert!(VaultAuthenticator::private_key(&vault, b"nope").is_none());
    }

    #[test]
    fn a_vault_with_no_passkeys_yields_nothing_rather_than_failing() {
        let vault = vault_with(&[]);
        assert!(VaultAuthenticator::rows_for(&vault, "sybr.no").is_empty());
        assert!(VaultAuthenticator::private_key(&vault, b"c1").is_none());
    }
}
