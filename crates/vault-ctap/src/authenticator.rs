//! The CTAP2 authenticator: command dispatch and the ceremony logic.
//!
//! One command in, one response out, no I/O. A transport (CTAPHID over uhid,
//! for the Linux virtual security key) hands us a command byte and a CBOR
//! payload and puts our answer back on the wire.
//!
//! # What this authenticator is
//!
//! ES256 only, discoverable credentials supported, **no CTAP PIN protocol**.
//! That last part is the one design decision everything else follows from:
//! Arca verifies the user itself, in its own window, against the master
//! password. So `authenticatorGetInfo` reports `uv: true` and omits
//! `clientPin` entirely, and platforms drive us with CTAP2's built-in
//! user-verification flow rather than negotiating a PIN token. It also means a
//! website can never see, set, or brute-force a PIN belonging to the vault.
//!
//! # Silent assertions
//!
//! A `getAssertion` with `up: false` and `uv: false` is answered **without
//! prompting the user**. This is not an oversight: browsers issue exactly this
//! request to discover which credentials a key holds before showing any UI
//! (Chromium's pre-flight, and conditional-UI autofill). Prompting for the
//! master password on every page load that mentions WebAuthn would make Arca
//! unusable.
//!
//! SECURITY: such an assertion carries a real signature with the UP and UV
//! flags **clear**, and WebAuthn §7.2 requires a relying party to reject an
//! assertion whose UP flag is unset. That check is what makes the flow safe,
//! and it is the same bargain every hardware security key makes.

use std::time::{Duration, Instant};

use ciborium::value::Value as Cbor;
use sha2::{Digest, Sha256};

use crate::backend::{approval, Backend, Consent, NewCredential, Operation, StoredCredential};
use crate::cbor::{self, int};
use crate::error::{CtapError, Result};
use crate::types::{GetAssertionRequest, MakeCredentialRequest, ALG_ES256, CREDENTIAL_TYPE};

/// `authenticatorMakeCredential`.
pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
/// `authenticatorGetAssertion`.
pub const CMD_GET_ASSERTION: u8 = 0x02;
/// `authenticatorGetInfo`.
pub const CMD_GET_INFO: u8 = 0x04;
/// `authenticatorClientPIN` — not implemented; see the module docs.
pub const CMD_CLIENT_PIN: u8 = 0x06;
/// `authenticatorReset` — deliberately refused; see [`Authenticator::handle`].
pub const CMD_RESET: u8 = 0x07;
/// `authenticatorGetNextAssertion`.
pub const CMD_GET_NEXT_ASSERTION: u8 = 0x08;
/// `authenticatorSelection`.
pub const CMD_SELECTION: u8 = 0x0B;

// authenticatorData flag bits (WebAuthn §6.1). These mirror the ones in
// `vault_core::passkey`, which builds the same structure for the browser
// extension path; the integration tests cross-check the two byte-for-byte so
// the pair cannot drift.
const FLAG_UP: u8 = 0x01; // user present
const FLAG_UV: u8 = 0x04; // user verified
const FLAG_BE: u8 = 0x08; // backup eligible
const FLAG_BS: u8 = 0x10; // backup state (currently backed up)
const FLAG_AT: u8 = 0x40; // attested credential data included

/// How long a `getAssertion` leaves the door open for `getNextAssertion`
/// (CTAP 2.1 §6.3).
const NEXT_ASSERTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Tunables reported in `authenticatorGetInfo` and enforced on requests.
#[derive(Debug, Clone)]
pub struct Config {
    /// Identifies the authenticator *model*. All-zero is the conventional
    /// value for a software authenticator that does not want to be individually
    /// identifiable, and matches what `vault_core::passkey` puts in the
    /// attestation. Relying parties that key on AAGUID will see "unknown",
    /// which is the honest answer for an attestation of `fmt: "none"`.
    pub aaguid: [u8; 16],
    /// Largest request payload we accept, in bytes.
    pub max_msg_size: u64,
    /// Longest `allowList`/`excludeList` we will process.
    pub max_credential_count_in_list: usize,
    /// Longest credential id we will look up.
    pub max_credential_id_length: usize,
    /// How long `getNextAssertion` stays available after a `getAssertion`.
    pub next_assertion_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            aaguid: [0u8; 16],
            max_msg_size: 4096,
            max_credential_count_in_list: 16,
            max_credential_id_length: 128,
            next_assertion_timeout: NEXT_ASSERTION_TIMEOUT,
        }
    }
}

/// State carried between a `getAssertion` that matched several credentials and
/// the `getNextAssertion` calls that walk the rest of them.
struct AssertionSession {
    rp_id: String,
    client_data_hash: Vec<u8>,
    user_present: bool,
    user_verified: bool,
    remaining: Vec<StoredCredential>,
    opened: Instant,
}

/// A CTAP2 authenticator backed by Arca's vault.
pub struct Authenticator<B: Backend> {
    backend: B,
    config: Config,
    session: Option<AssertionSession>,
}

impl<B: Backend> Authenticator<B> {
    /// Build an authenticator with the default [`Config`].
    pub fn new(backend: B) -> Self {
        Self::with_config(backend, Config::default())
    }

    /// Build an authenticator with an explicit configuration.
    pub fn with_config(backend: B, config: Config) -> Self {
        Self {
            backend,
            config,
            session: None,
        }
    }

    /// The backend, for a transport that needs to reach it directly.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Handle one CTAP2 message: a command byte followed by an optional CBOR
    /// payload. Returns the response as it goes on the wire — a status byte
    /// followed by an optional CBOR payload.
    ///
    /// This is the entry point a transport wants; [`Authenticator::handle`]
    /// exposes the same logic with a typed error for callers that would rather
    /// match on it.
    pub fn handle_message(&mut self, message: &[u8]) -> Vec<u8> {
        let Some((&command, payload)) = message.split_first() else {
            return vec![CtapError::InvalidLength.code()];
        };
        match self.handle(command, payload) {
            Ok(response) => {
                let mut out = Vec::with_capacity(response.len() + 1);
                out.push(0x00); // CTAP2_OK
                out.extend_from_slice(&response);
                out
            }
            Err(e) => vec![e.code()],
        }
    }

    /// Handle one command, returning the CBOR response payload (which is empty
    /// for commands that carry no data back).
    pub fn handle(&mut self, command: u8, payload: &[u8]) -> Result<Vec<u8>> {
        // Any command other than getNextAssertion ends an assertion session.
        // CTAP 2.1 §6.3 is explicit that an intervening command invalidates it,
        // and the alternative — leaving a half-walked credential list around —
        // would let a later caller collect assertions the user approved for an
        // earlier one.
        if command != CMD_GET_NEXT_ASSERTION {
            self.session = None;
        }

        if payload.len() as u64 > self.config.max_msg_size {
            return Err(CtapError::InvalidLength);
        }

        match command {
            CMD_MAKE_CREDENTIAL => self.make_credential(payload),
            CMD_GET_ASSERTION => self.get_assertion(payload),
            CMD_GET_INFO => Ok(self.get_info()),
            CMD_GET_NEXT_ASSERTION => self.get_next_assertion(),
            CMD_SELECTION => self.selection(),

            // Refused on purpose. A CTAP reset wipes every credential on the
            // authenticator; here those credentials are items in the user's
            // vault, sitting alongside their passwords, and a reset would be
            // reachable by anything that can open the HID device. Removing a
            // passkey is a thing you do in Arca, deliberately, with the vault
            // open — not something the protocol can ask for.
            CMD_RESET => Err(CtapError::OperationDenied),

            // We advertise no PIN support, so a platform should never send
            // this; if one does, "no such command" is the accurate answer.
            CMD_CLIENT_PIN => Err(CtapError::InvalidCommand),

            _ => Err(CtapError::InvalidCommand),
        }
    }

    // --- commands ---------------------------------------------------------

    fn get_info(&self) -> Vec<u8> {
        // Options are three-valued in CTAP: true, false, or absent — and
        // absent means "not supported", which is why `clientPin` and
        // `pinUvAuthToken` do not appear at all rather than appearing as
        // false. `plat` is false because we are reached over a removable
        // transport; claiming to be a platform authenticator would promise the
        // client a permanence a HID device does not have.
        let options = Cbor::Map(vec![
            (Cbor::Text("rk".into()), Cbor::Bool(true)),
            (Cbor::Text("up".into()), Cbor::Bool(true)),
            (Cbor::Text("uv".into()), Cbor::Bool(true)),
            (Cbor::Text("plat".into()), Cbor::Bool(false)),
        ]);

        let algorithms = Cbor::Array(vec![Cbor::Map(vec![
            (Cbor::Text("alg".into()), int(ALG_ES256)),
            (
                Cbor::Text("type".into()),
                Cbor::Text(CREDENTIAL_TYPE.into()),
            ),
        ])]);

        cbor::encode(Cbor::Map(vec![
            // We claim 2.0 only. Every passkey feature we implement —
            // discoverable credentials, built-in user verification — is CTAP
            // 2.0, and claiming 2.1 would advertise credential management and
            // pinUvAuthToken flows we do not have.
            (int(0x01), Cbor::Array(vec![Cbor::Text("FIDO_2_0".into())])),
            (int(0x03), Cbor::Bytes(self.config.aaguid.to_vec())),
            (int(0x04), options),
            (int(0x05), int(self.config.max_msg_size as i64)),
            (
                int(0x07),
                int(self.config.max_credential_count_in_list as i64),
            ),
            (int(0x08), int(self.config.max_credential_id_length as i64)),
            (int(0x09), Cbor::Array(vec![Cbor::Text("usb".into())])),
            (int(0x0A), algorithms),
        ]))
    }

    fn make_credential(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let req = MakeCredentialRequest::parse(payload)?;

        self.reject_pin_uv_auth(
            req.pin_uv_auth_param.as_deref(),
            req.pin_uv_auth_protocol,
            Operation::Register,
            &req.rp.id,
            req.rp.name.as_deref(),
        )?;

        if !req.algorithms.contains(&ALG_ES256) {
            return Err(CtapError::UnsupportedAlgorithm);
        }

        // Registration without user presence is meaningless — there would be
        // nobody to have consented to the new credential.
        if req.options.up == Some(false) {
            return Err(CtapError::InvalidOption);
        }
        let uv_requested = req.options.uv.unwrap_or(false);
        let discoverable = req.options.rk.unwrap_or(false);

        if req.exclude_list.len() > self.config.max_credential_count_in_list {
            return Err(CtapError::LimitExceeded);
        }

        // An excludeList hit means "you already have one of these". Ask for
        // presence *before* saying so: answering instantly would turn this
        // command into a free probe for whether the user holds a credential
        // for a given site, without them ever being told they were asked.
        let mut excluded = false;
        for descriptor in &req.exclude_list {
            if self.backend.lookup(&req.rp.id, &descriptor.id)?.is_some() {
                excluded = true;
                break;
            }
        }
        if excluded {
            let action = self.backend.confirm(&Consent {
                operation: Operation::Register,
                rp_id: &req.rp.id,
                rp_name: req.rp.name.as_deref(),
                user_name: req.user.name.as_deref(),
                require_verification: false,
            });
            approval(action, false)?;
            return Err(CtapError::CredentialExcluded);
        }

        let action = self.backend.confirm(&Consent {
            operation: Operation::Register,
            rp_id: &req.rp.id,
            rp_name: req.rp.name.as_deref(),
            user_name: req.user.name.as_deref(),
            require_verification: uv_requested,
        });
        let user_verified = approval(action, uv_requested)?;

        // Only now does anything reach the vault: a refused ceremony leaves no
        // trace of the site that asked.
        let created = self.backend.create(&NewCredential {
            rp: &req.rp,
            user: &req.user,
            discoverable,
            user_verified,
        })?;

        let auth_data = self.authenticator_data(
            &req.rp.id,
            true,
            user_verified,
            Some((&created.credential_id, &created.cose_public_key)),
        );

        // The attestation statement is empty: `fmt: "none"`. Arca has no
        // attestation key and inventing one would let relying parties
        // fingerprint installs.
        Ok(cbor::encode(Cbor::Map(vec![
            (int(0x01), Cbor::Text("none".into())),
            (int(0x02), Cbor::Bytes(auth_data)),
            (int(0x03), Cbor::Map(vec![])),
        ])))
    }

    fn get_assertion(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let req = GetAssertionRequest::parse(payload)?;

        self.reject_pin_uv_auth(
            req.pin_uv_auth_param.as_deref(),
            req.pin_uv_auth_protocol,
            Operation::Authenticate,
            &req.rp_id,
            None,
        )?;

        // `rk` asks for a credential to be *created* discoverable; it has no
        // meaning when signing in with one that already exists.
        if req.options.rk.is_some() {
            return Err(CtapError::UnsupportedOption);
        }
        let up_requested = req.options.up.unwrap_or(true);
        let uv_requested = req.options.uv.unwrap_or(false);

        if req.allow_list.len() > self.config.max_credential_count_in_list {
            return Err(CtapError::LimitExceeded);
        }

        let candidates = self.candidates(&req)?;
        if candidates.is_empty() {
            return Err(CtapError::NoCredentials);
        }

        // The silent path: no prompt, and the flags say so. See the module
        // docs — browsers depend on this to enumerate credentials before they
        // show any UI.
        let (user_present, user_verified) = if up_requested || uv_requested {
            let action = self.backend.confirm(&Consent {
                operation: Operation::Authenticate,
                rp_id: &req.rp_id,
                rp_name: None,
                user_name: candidates.first().and_then(|c| c.user.name.as_deref()),
                require_verification: uv_requested,
            });
            (up_requested, approval(action, uv_requested)?)
        } else {
            (false, false)
        };

        let total = candidates.len();
        let mut remaining = candidates;
        let credential = remaining.remove(0);

        let response = self.assertion_response(
            &req.rp_id,
            &req.client_data_hash,
            &credential,
            user_present,
            user_verified,
            // `numberOfCredentials` appears only on the first assertion of a
            // set, and only when there is in fact a choice to walk.
            (total > 1).then_some(total),
        )?;

        if !remaining.is_empty() {
            self.session = Some(AssertionSession {
                rp_id: req.rp_id,
                client_data_hash: req.client_data_hash,
                user_present,
                user_verified,
                remaining,
                opened: Instant::now(),
            });
        }

        Ok(response)
    }

    fn get_next_assertion(&mut self) -> Result<Vec<u8>> {
        let usable = match &self.session {
            Some(session) => {
                session.opened.elapsed() <= self.config.next_assertion_timeout
                    && !session.remaining.is_empty()
            }
            None => return Err(CtapError::NotAllowed),
        };
        if !usable {
            self.session = None;
            return Err(CtapError::NotAllowed);
        }
        let session = self.session.as_mut().expect("checked just above");

        // Copy what the response needs before releasing the borrow: the user
        // already approved this set, so no new prompt is issued here.
        let credential = session.remaining.remove(0);
        let rp_id = session.rp_id.clone();
        let client_data_hash = session.client_data_hash.clone();
        let user_present = session.user_present;
        let user_verified = session.user_verified;
        let exhausted = session.remaining.is_empty();

        let response = self.assertion_response(
            &rp_id,
            &client_data_hash,
            &credential,
            user_present,
            user_verified,
            None,
        )?;

        if exhausted {
            self.session = None;
        }
        Ok(response)
    }

    fn selection(&mut self) -> Result<Vec<u8>> {
        // The platform is asking "are you the authenticator the user means?".
        // Presence only — there is no ceremony yet to verify anything against.
        let action = self.backend.confirm(&Consent {
            operation: Operation::Select,
            rp_id: "",
            rp_name: None,
            user_name: None,
            require_verification: false,
        });
        approval(action, false)?;
        Ok(Vec::new())
    }

    // --- helpers ----------------------------------------------------------

    /// Resolve the credentials a `getAssertion` may answer with.
    ///
    /// An absent `allowList` invites discovery; a present one restricts us to
    /// what it names, in the order the relying party gave. Ids that are too
    /// long, name a credential we do not hold, or belong to another relying
    /// party simply drop out — the caller learns only that nothing matched.
    fn candidates(&mut self, req: &GetAssertionRequest) -> Result<Vec<StoredCredential>> {
        if !req.allow_list_present {
            return Ok(self.backend.discover(&req.rp_id)?);
        }

        let mut found: Vec<StoredCredential> = Vec::new();
        for descriptor in &req.allow_list {
            if descriptor.id.len() > self.config.max_credential_id_length {
                continue;
            }
            if let Some(credential) = self.backend.lookup(&req.rp_id, &descriptor.id)? {
                // A platform is free to repeat an id; we must not answer with
                // the same credential twice.
                if !found
                    .iter()
                    .any(|c| c.credential_id == credential.credential_id)
                {
                    found.push(credential);
                }
            }
        }
        Ok(found)
    }

    /// Build and sign one assertion response.
    #[allow(clippy::too_many_arguments)]
    fn assertion_response(
        &mut self,
        rp_id: &str,
        client_data_hash: &[u8],
        credential: &StoredCredential,
        user_present: bool,
        user_verified: bool,
        number_of_credentials: Option<usize>,
    ) -> Result<Vec<u8>> {
        let auth_data = self.authenticator_data(rp_id, user_present, user_verified, None);

        let mut message = auth_data.clone();
        message.extend_from_slice(client_data_hash);
        let signature = self.backend.sign(&credential.credential_id, &message)?;

        // SECURITY: name and displayName identify a human being, and an
        // unverified caller has not shown it is the human in question. CTAP
        // 2.1 §6.2.2 requires everything but the opaque user handle to be
        // withheld unless the authenticator verified the user — so a silent
        // pre-flight assertion learns that a credential exists, and nothing
        // about whose it is.
        let mut user = vec![(
            Cbor::Text("id".into()),
            Cbor::Bytes(credential.user.id.clone()),
        )];
        if user_verified {
            if let Some(name) = &credential.user.name {
                user.push((Cbor::Text("name".into()), Cbor::Text(name.clone())));
            }
            if let Some(display_name) = &credential.user.display_name {
                user.push((
                    Cbor::Text("displayName".into()),
                    Cbor::Text(display_name.clone()),
                ));
            }
        }

        let mut response = vec![
            (
                int(0x01),
                Cbor::Map(vec![
                    (
                        Cbor::Text("id".into()),
                        Cbor::Bytes(credential.credential_id.clone()),
                    ),
                    (
                        Cbor::Text("type".into()),
                        Cbor::Text(CREDENTIAL_TYPE.into()),
                    ),
                ]),
            ),
            (int(0x02), Cbor::Bytes(auth_data)),
            (int(0x03), Cbor::Bytes(signature)),
            (int(0x04), Cbor::Map(user)),
        ];
        if let Some(count) = number_of_credentials {
            response.push((int(0x05), int(count as i64)));
        }

        Ok(cbor::encode(Cbor::Map(response)))
    }

    /// Assemble authenticatorData (WebAuthn §6.1).
    ///
    /// BE and BS are always set: an Arca passkey lives in the vault, which
    /// syncs and is backed up, so it is backup-eligible and backed up by
    /// construction.
    ///
    /// signCount is always **0**, matching `vault_core::passkey`. WebAuthn L3
    /// §6.1.1 recommends a constant zero for credentials that cannot guarantee
    /// one monotonic counter across every device holding them; a counter that
    /// went backwards after a sync would look exactly like a cloned key to a
    /// relying party's clone detection.
    fn authenticator_data(
        &self,
        rp_id: &str,
        user_present: bool,
        user_verified: bool,
        attested: Option<(&[u8], &[u8])>, // (credential_id, cose_public_key)
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&sha256(rp_id.as_bytes()));

        let mut flags = FLAG_BE | FLAG_BS;
        if user_present {
            flags |= FLAG_UP;
        }
        if user_verified {
            flags |= FLAG_UV;
        }
        if attested.is_some() {
            flags |= FLAG_AT;
        }
        data.push(flags);
        data.extend_from_slice(&0u32.to_be_bytes()); // signCount

        if let Some((credential_id, cose_public_key)) = attested {
            data.extend_from_slice(&self.config.aaguid);
            // A credential id longer than u16::MAX cannot be expressed in
            // attested credential data; ours are 16 bytes, and the backend
            // cannot widen them past this without the length field lying.
            let length = u16::try_from(credential_id.len()).unwrap_or(u16::MAX);
            data.extend_from_slice(&length.to_be_bytes());
            data.extend_from_slice(&credential_id[..usize::from(length)]);
            data.extend_from_slice(cose_public_key);
        }
        data
    }

    /// Answer a platform that offered `pinUvAuthParam`.
    ///
    /// We implement no PIN protocol, so there is nothing here we could verify.
    /// The zero-length case is a defined probe — "do you have a PIN set?" — and
    /// the spec wants user presence before the answer, so that the question
    /// cannot be asked silently.
    fn reject_pin_uv_auth(
        &mut self,
        pin_uv_auth_param: Option<&[u8]>,
        _protocol: Option<i64>,
        operation: Operation,
        rp_id: &str,
        rp_name: Option<&str>,
    ) -> Result<()> {
        let Some(param) = pin_uv_auth_param else {
            return Ok(());
        };

        if param.is_empty() {
            let action = self.backend.confirm(&Consent {
                operation,
                rp_id,
                rp_name,
                user_name: None,
                require_verification: false,
            });
            approval(action, false)?;
            return Err(CtapError::PinNotSet);
        }

        // A non-empty parameter is a MAC we have no key for. Treating it as
        // invalid is both true and the safe direction: the alternative is
        // ignoring it and answering a ceremony the platform believes was
        // authorised by a PIN token.
        Err(CtapError::PinAuthInvalid)
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
