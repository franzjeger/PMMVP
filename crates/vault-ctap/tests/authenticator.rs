//! End-to-end tests for the CTAP2 authenticator, driven the way a platform
//! drives it: raw command bytes in, raw response bytes out.
//!
//! The fake vault behind [`FakeVault`] uses the real key generation and the
//! real signing primitive, so an assertion that verifies here would verify at a
//! relying party. Nothing is stubbed except storage and the user's answer.

use std::time::Duration;

use ciborium::value::{Integer, Value as Cbor};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use vault_ctap::{
    Authenticator, Backend, BackendError, BackendResult, Config, Consent, CreatedCredential,
    CtapError, NewCredential, Operation, StoredCredential, User, UserAction, ALG_ES256,
    CMD_CLIENT_PIN, CMD_GET_ASSERTION, CMD_GET_INFO, CMD_GET_NEXT_ASSERTION, CMD_MAKE_CREDENTIAL,
    CMD_RESET, CMD_SELECTION, CREDENTIAL_TYPE, CTAP2_OK,
};

// --- the fake vault -------------------------------------------------------

struct Record {
    rp_id: String,
    credential_id: Vec<u8>,
    private_key: Vec<u8>,
    user: User,
    discoverable: bool,
}

/// What the authenticator asked the user, so a test can assert on whether a
/// prompt happened at all — the difference between a silent pre-flight and a
/// ceremony is exactly that.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Prompt {
    operation: Operation,
    rp_id: String,
    user_name: Option<String>,
    require_verification: bool,
}

struct FakeVault {
    records: Vec<Record>,
    answer: UserAction,
    prompts: Vec<Prompt>,
    fail_storage: bool,
}

impl FakeVault {
    fn new() -> Self {
        Self {
            records: Vec::new(),
            answer: UserAction::Approved { verified: true },
            prompts: Vec::new(),
            fail_storage: false,
        }
    }

    fn answering(answer: UserAction) -> Self {
        Self {
            answer,
            ..Self::new()
        }
    }

    fn public_key(&self, credential_id: &[u8]) -> Vec<u8> {
        let record = self
            .records
            .iter()
            .find(|r| r.credential_id == credential_id)
            .expect("credential exists");
        vault_core::passkey::public_key_sec1(&record.private_key).unwrap()
    }
}

impl Backend for FakeVault {
    fn discover(&mut self, rp_id: &str) -> BackendResult<Vec<StoredCredential>> {
        if self.fail_storage {
            return Err(BackendError::Storage);
        }
        Ok(self
            .records
            .iter()
            .filter(|r| r.rp_id == rp_id && r.discoverable)
            .map(|r| StoredCredential {
                credential_id: r.credential_id.clone(),
                user: r.user.clone(),
                discoverable: r.discoverable,
            })
            .collect())
    }

    fn lookup(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
    ) -> BackendResult<Option<StoredCredential>> {
        if self.fail_storage {
            return Err(BackendError::Storage);
        }
        Ok(self
            .records
            .iter()
            .find(|r| r.rp_id == rp_id && r.credential_id == credential_id)
            .map(|r| StoredCredential {
                credential_id: r.credential_id.clone(),
                user: r.user.clone(),
                discoverable: r.discoverable,
            }))
    }

    fn create(&mut self, credential: &NewCredential<'_>) -> BackendResult<CreatedCredential> {
        let created = vault_core::passkey::create(&credential.rp.id, credential.user_verified)
            .map_err(|_| BackendError::Storage)?;
        self.records.push(Record {
            rp_id: credential.rp.id.clone(),
            credential_id: created.credential_id.clone(),
            private_key: created.private_key.to_vec(),
            user: credential.user.clone(),
            discoverable: credential.discoverable,
        });
        Ok(CreatedCredential {
            credential_id: created.credential_id,
            cose_public_key: created.cose_public_key,
        })
    }

    fn sign(&mut self, credential_id: &[u8], message: &[u8]) -> BackendResult<Vec<u8>> {
        let record = self
            .records
            .iter()
            .find(|r| r.credential_id == credential_id)
            .ok_or(BackendError::NotFound)?;
        let key = SigningKey::from_slice(&record.private_key).map_err(|_| BackendError::Signing)?;
        let signature: Signature = key.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn confirm(&mut self, request: &Consent<'_>) -> UserAction {
        self.prompts.push(Prompt {
            operation: request.operation,
            rp_id: request.rp_id.to_string(),
            user_name: request.user_name.map(str::to_string),
            require_verification: request.require_verification,
        });
        self.answer
    }
}

// --- CBOR helpers for building requests and reading responses -------------

fn int(n: i64) -> Cbor {
    Cbor::Integer(Integer::from(n))
}

fn text(s: &str) -> Cbor {
    Cbor::Text(s.into())
}

fn encode(value: Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).unwrap();
    out
}

fn message(command: u8, payload: Cbor) -> Vec<u8> {
    let mut out = vec![command];
    out.extend_from_slice(&encode(payload));
    out
}

/// Assert the response succeeded and hand back its decoded payload map.
fn ok_map(response: &[u8]) -> Vec<(Cbor, Cbor)> {
    assert_eq!(
        response[0], CTAP2_OK,
        "expected success, got {response:02x?}"
    );
    match ciborium::from_reader::<Cbor, _>(&response[1..]).unwrap() {
        Cbor::Map(entries) => entries,
        other => panic!("response is not a map: {other:?}"),
    }
}

fn status(response: &[u8]) -> u8 {
    response[0]
}

fn get(entries: &[(Cbor, Cbor)], key: i64) -> Option<&Cbor> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, Cbor::Integer(i) if i128::from(*i) == i128::from(key)))
        .map(|(_, v)| v)
}

fn get_text<'a>(entries: &'a [(Cbor, Cbor)], key: &str) -> Option<&'a Cbor> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, Cbor::Text(t) if t == key))
        .map(|(_, v)| v)
}

fn bytes(value: &Cbor) -> &[u8] {
    match value {
        Cbor::Bytes(b) => b,
        other => panic!("not bytes: {other:?}"),
    }
}

fn map(value: &Cbor) -> &[(Cbor, Cbor)] {
    match value {
        Cbor::Map(entries) => entries,
        other => panic!("not a map: {other:?}"),
    }
}

fn descriptor(id: &[u8]) -> Cbor {
    Cbor::Map(vec![
        (text("type"), text(CREDENTIAL_TYPE)),
        (text("id"), Cbor::Bytes(id.to_vec())),
    ])
}

/// A makeCredential request for `rp_id`, with `extra` merged into the map.
fn make_credential(rp_id: &str, extra: Vec<(Cbor, Cbor)>) -> Cbor {
    let mut entries = vec![
        (int(0x01), Cbor::Bytes(vec![0xAB; 32])),
        (int(0x02), Cbor::Map(vec![(text("id"), text(rp_id))])),
        (
            int(0x03),
            Cbor::Map(vec![
                (text("id"), Cbor::Bytes(vec![1, 2, 3, 4])),
                (text("name"), text("frank@sybr.no")),
                (text("displayName"), text("Frank")),
            ]),
        ),
        (
            int(0x04),
            Cbor::Array(vec![Cbor::Map(vec![
                (text("alg"), int(ALG_ES256)),
                (text("type"), text(CREDENTIAL_TYPE)),
            ])]),
        ),
    ];
    entries.extend(extra);
    Cbor::Map(entries)
}

/// A discoverable, user-verified registration — what a browser sends for a
/// passkey.
fn register(rp_id: &str) -> Cbor {
    make_credential(
        rp_id,
        vec![(
            int(0x07),
            Cbor::Map(vec![
                (text("rk"), Cbor::Bool(true)),
                (text("uv"), Cbor::Bool(true)),
            ]),
        )],
    )
}

fn get_assertion(rp_id: &str, extra: Vec<(Cbor, Cbor)>) -> Cbor {
    let mut entries = vec![
        (int(0x01), text(rp_id)),
        (int(0x02), Cbor::Bytes(vec![0xCD; 32])),
    ];
    entries.extend(extra);
    Cbor::Map(entries)
}

fn options(pairs: &[(&str, bool)]) -> Cbor {
    Cbor::Map(
        pairs
            .iter()
            .map(|(k, v)| (text(k), Cbor::Bool(*v)))
            .collect(),
    )
}

/// Register a passkey and return its credential id.
fn enrol(authenticator: &mut Authenticator<FakeVault>, rp_id: &str) -> Vec<u8> {
    let response = authenticator.handle_message(&message(CMD_MAKE_CREDENTIAL, register(rp_id)));
    let entries = ok_map(&response);
    let auth_data = bytes(get(&entries, 0x02).unwrap());
    // attestedCredentialData: 32 rpIdHash + 1 flags + 4 count + 16 aaguid,
    // then a big-endian u16 length and the id itself.
    let length = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    auth_data[55..55 + length].to_vec()
}

// --- authenticatorGetInfo -------------------------------------------------

#[test]
fn get_info_reports_only_what_is_implemented() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let entries = ok_map(&authenticator.handle_message(&[CMD_GET_INFO]));

    let versions = match get(&entries, 0x01).unwrap() {
        Cbor::Array(items) => items.clone(),
        other => panic!("versions: {other:?}"),
    };
    assert_eq!(versions, vec![text("FIDO_2_0")]);

    assert_eq!(bytes(get(&entries, 0x03).unwrap()).len(), 16);

    let opts = map(get(&entries, 0x04).unwrap());
    assert_eq!(get_text(opts, "rk"), Some(&Cbor::Bool(true)));
    assert_eq!(get_text(opts, "up"), Some(&Cbor::Bool(true)));
    assert_eq!(get_text(opts, "uv"), Some(&Cbor::Bool(true)));
    assert_eq!(get_text(opts, "plat"), Some(&Cbor::Bool(false)));

    // Absent, not false: a `clientPin` key of either value would tell the
    // platform we implement the PIN protocol.
    assert_eq!(get_text(opts, "clientPin"), None);
    assert_eq!(get_text(opts, "pinUvAuthToken"), None);
    // And no pinUvAuthProtocols list.
    assert_eq!(get(&entries, 0x06), None);

    let algorithms = match get(&entries, 0x0A).unwrap() {
        Cbor::Array(items) => items.clone(),
        other => panic!("algorithms: {other:?}"),
    };
    assert_eq!(algorithms.len(), 1);
    assert_eq!(get_text(map(&algorithms[0]), "alg"), Some(&int(ALG_ES256)));
}

#[test]
fn get_info_is_canonical_cbor() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let response = authenticator.handle_message(&[CMD_GET_INFO]);
    let entries = ok_map(&response);

    // Integer keys ascending.
    let keys: Vec<i128> = entries
        .iter()
        .map(|(k, _)| match k {
            Cbor::Integer(i) => i128::from(*i),
            other => panic!("non-integer key: {other:?}"),
        })
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted);

    // Text keys by length, then bytewise: rk, up, uv, plat.
    let option_keys: Vec<String> = map(get(&entries, 0x04).unwrap())
        .iter()
        .map(|(k, _)| match k {
            Cbor::Text(t) => t.clone(),
            other => panic!("non-text key: {other:?}"),
        })
        .collect();
    assert_eq!(option_keys, ["rk", "up", "uv", "plat"]);
}

// --- registration ---------------------------------------------------------

#[test]
fn a_registration_produces_attested_credential_data() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let entries =
        ok_map(&authenticator.handle_message(&message(CMD_MAKE_CREDENTIAL, register("sybr.no"))));

    assert_eq!(get(&entries, 0x01).unwrap(), &text("none"));
    assert_eq!(get(&entries, 0x03).unwrap(), &Cbor::Map(vec![]));

    let auth_data = bytes(get(&entries, 0x02).unwrap());
    // UP | UV | BE | BS | AT
    assert_eq!(auth_data[32], 0x01 | 0x04 | 0x08 | 0x10 | 0x40);
    assert_eq!(&auth_data[33..37], &0u32.to_be_bytes());
    assert_eq!(&auth_data[37..53], &[0u8; 16]); // AAGUID
    let length = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    assert_eq!(length, 16);
    assert!(auth_data.len() > 55 + length, "COSE key follows the id");
}

#[test]
fn registration_needs_an_algorithm_we_can_sign_with() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    // The relying party will accept Ed25519 (-8) only, which we cannot sign.
    let request = Cbor::Map(vec![
        (int(0x01), Cbor::Bytes(vec![0xAB; 32])),
        (int(0x02), Cbor::Map(vec![(text("id"), text("sybr.no"))])),
        (
            int(0x03),
            Cbor::Map(vec![(text("id"), Cbor::Bytes(vec![1]))]),
        ),
        (
            int(0x04),
            Cbor::Array(vec![Cbor::Map(vec![
                (text("alg"), int(-8)),
                (text("type"), text(CREDENTIAL_TYPE)),
            ])]),
        ),
    ]);
    let response = authenticator.handle_message(&message(CMD_MAKE_CREDENTIAL, request));
    assert_eq!(status(&response), CtapError::UnsupportedAlgorithm.code());
}

#[test]
fn registration_without_user_presence_is_refused() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let response = authenticator.handle_message(&message(
        CMD_MAKE_CREDENTIAL,
        make_credential("sybr.no", vec![(int(0x07), options(&[("up", false)]))]),
    ));
    assert_eq!(status(&response), CtapError::InvalidOption.code());
}

#[test]
fn a_refused_registration_writes_nothing_to_the_vault() {
    let mut authenticator = Authenticator::new(FakeVault::answering(UserAction::Declined));
    let response = authenticator.handle_message(&message(CMD_MAKE_CREDENTIAL, register("sybr.no")));
    assert_eq!(status(&response), CtapError::OperationDenied.code());
    // Not even the fact that sybr.no asked survives.
    assert!(authenticator.backend_mut().records.is_empty());
}

#[test]
fn a_timeout_is_reported_apart_from_a_refusal() {
    let mut authenticator = Authenticator::new(FakeVault::answering(UserAction::TimedOut));
    let response = authenticator.handle_message(&message(CMD_MAKE_CREDENTIAL, register("sybr.no")));
    assert_eq!(status(&response), CtapError::UserActionTimeout.code());
}

#[test]
fn asking_for_verification_and_getting_only_a_click_is_denied() {
    // The vault approves but reports no verification happened. Setting UV
    // anyway would be a false claim to the relying party.
    let mut authenticator = Authenticator::new(FakeVault::answering(UserAction::Approved {
        verified: false,
    }));
    let response = authenticator.handle_message(&message(CMD_MAKE_CREDENTIAL, register("sybr.no")));
    assert_eq!(status(&response), CtapError::OperationDenied.code());
    assert!(authenticator.backend_mut().records.is_empty());
}

#[test]
fn presence_only_registration_succeeds_with_uv_clear() {
    let mut authenticator = Authenticator::new(FakeVault::answering(UserAction::Approved {
        verified: false,
    }));
    let entries = ok_map(&authenticator.handle_message(&message(
        CMD_MAKE_CREDENTIAL,
        make_credential("sybr.no", vec![(int(0x07), options(&[("rk", true)]))]),
    )));
    let auth_data = bytes(get(&entries, 0x02).unwrap());
    assert_eq!(auth_data[32] & 0x01, 0x01, "UP set");
    assert_eq!(auth_data[32] & 0x04, 0x00, "UV clear");
}

#[test]
fn an_excluded_credential_prompts_before_it_reports_the_exclusion() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let credential_id = enrol(&mut authenticator, "sybr.no");
    authenticator.backend_mut().prompts.clear();

    let response = authenticator.handle_message(&message(
        CMD_MAKE_CREDENTIAL,
        make_credential(
            "sybr.no",
            vec![
                (int(0x05), Cbor::Array(vec![descriptor(&credential_id)])),
                (int(0x07), options(&[("rk", true), ("uv", true)])),
            ],
        ),
    ));

    assert_eq!(status(&response), CtapError::CredentialExcluded.code());
    // The user was asked. Answering instantly would make this a silent probe
    // for "does Frank have a passkey for this site?".
    assert_eq!(authenticator.backend_mut().prompts.len(), 1);
    // And nothing was written.
    assert_eq!(authenticator.backend_mut().records.len(), 1);
}

#[test]
fn an_exclude_list_naming_another_sites_credential_does_not_block() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let elsewhere = enrol(&mut authenticator, "example.com");

    let response = authenticator.handle_message(&message(
        CMD_MAKE_CREDENTIAL,
        make_credential(
            "sybr.no",
            vec![
                (int(0x05), Cbor::Array(vec![descriptor(&elsewhere)])),
                (int(0x07), options(&[("rk", true), ("uv", true)])),
            ],
        ),
    ));
    assert_eq!(status(&response), CTAP2_OK);
}

// --- assertion ------------------------------------------------------------

#[test]
fn an_assertion_signature_verifies_against_the_registered_key() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let credential_id = enrol(&mut authenticator, "sybr.no");
    let client_data_hash = vec![0xCD; 32];

    let entries = ok_map(&authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![(int(0x05), options(&[("uv", true)]))]),
    )));

    assert_eq!(
        bytes(get_text(map(get(&entries, 0x01).unwrap()), "id").unwrap()),
        credential_id.as_slice()
    );

    let auth_data = bytes(get(&entries, 0x02).unwrap()).to_vec();
    let signature = bytes(get(&entries, 0x03).unwrap()).to_vec();

    // This is exactly what a relying party reconstructs and checks.
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&client_data_hash);
    let public_key = authenticator.backend_mut().public_key(&credential_id);
    let verifying = VerifyingKey::from_sec1_bytes(&public_key).unwrap();
    assert!(verifying
        .verify(&signed, &Signature::from_der(&signature).unwrap())
        .is_ok());

    // No attested credential data on an assertion, and UP|UV set.
    assert_eq!(auth_data.len(), 37);
    assert_eq!(auth_data[32] & 0x40, 0);
    assert_eq!(auth_data[32] & 0x05, 0x05);
}

#[test]
fn a_verified_assertion_returns_the_account_name() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    enrol(&mut authenticator, "sybr.no");
    let entries = ok_map(&authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![(int(0x05), options(&[("uv", true)]))]),
    )));

    let user = map(get(&entries, 0x04).unwrap());
    assert_eq!(bytes(get_text(user, "id").unwrap()), &[1, 2, 3, 4]);
    assert_eq!(get_text(user, "name"), Some(&text("frank@sybr.no")));
    assert_eq!(get_text(user, "displayName"), Some(&text("Frank")));
}

#[test]
fn a_silent_assertion_neither_prompts_nor_names_the_user() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    enrol(&mut authenticator, "sybr.no");
    authenticator.backend_mut().prompts.clear();

    // This is the browser's pre-flight: up=false, uv=false.
    let entries = ok_map(&authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion(
            "sybr.no",
            vec![(int(0x05), options(&[("up", false), ("uv", false)]))],
        ),
    )));

    // Nobody was disturbed.
    assert!(authenticator.backend_mut().prompts.is_empty());

    // The flags say plainly that no human was involved; a relying party is
    // required to reject this.
    let auth_data = bytes(get(&entries, 0x02).unwrap());
    assert_eq!(auth_data[32] & 0x01, 0, "UP clear");
    assert_eq!(auth_data[32] & 0x04, 0, "UV clear");

    // And it leaks only the opaque handle, never the account name.
    let user = map(get(&entries, 0x04).unwrap());
    assert!(get_text(user, "id").is_some());
    assert_eq!(get_text(user, "name"), None);
    assert_eq!(get_text(user, "displayName"), None);
}

#[test]
fn an_assertion_prompts_by_default_when_no_options_are_given() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    enrol(&mut authenticator, "sybr.no");
    authenticator.backend_mut().prompts.clear();

    let response = authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![]),
    ));
    assert_eq!(status(&response), CTAP2_OK);
    // up defaults to true, so the user is asked.
    assert_eq!(authenticator.backend_mut().prompts.len(), 1);
    assert_eq!(
        authenticator.backend_mut().prompts[0].operation,
        Operation::Authenticate
    );
}

#[test]
fn the_prompt_names_the_site_and_the_account() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    enrol(&mut authenticator, "sybr.no");
    authenticator.backend_mut().prompts.clear();

    authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![(int(0x05), options(&[("uv", true)]))]),
    ));
    let prompt = authenticator.backend_mut().prompts[0].clone();
    assert_eq!(prompt.rp_id, "sybr.no");
    assert_eq!(prompt.user_name.as_deref(), Some("frank@sybr.no"));
    assert!(prompt.require_verification);
}

#[test]
fn no_credential_for_the_site_is_reported_as_no_credentials() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    enrol(&mut authenticator, "sybr.no");
    let response = authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("example.com", vec![]),
    ));
    assert_eq!(status(&response), CtapError::NoCredentials.code());
    // The user is not asked about a site we hold nothing for.
    assert_eq!(authenticator.backend_mut().prompts.len(), 1); // only the enrolment
}

#[test]
fn a_credential_id_cannot_be_replayed_against_another_relying_party() {
    // The security property that matters most here: a credential id is not a
    // secret, so knowing one must not be enough to assert with it elsewhere.
    let mut authenticator = Authenticator::new(FakeVault::new());
    let sybr = enrol(&mut authenticator, "sybr.no");

    let response = authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion(
            "evil.example",
            vec![(int(0x03), Cbor::Array(vec![descriptor(&sybr)]))],
        ),
    ));
    assert_eq!(status(&response), CtapError::NoCredentials.code());
}

#[test]
fn a_non_discoverable_credential_is_reachable_only_by_id() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    // rk absent, so not discoverable.
    let entries = ok_map(&authenticator.handle_message(&message(
        CMD_MAKE_CREDENTIAL,
        make_credential("sybr.no", vec![(int(0x07), options(&[("uv", true)]))]),
    )));
    let auth_data = bytes(get(&entries, 0x02).unwrap());
    let length = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let credential_id = auth_data[55..55 + length].to_vec();

    // Discovery finds nothing…
    let response = authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![]),
    ));
    assert_eq!(status(&response), CtapError::NoCredentials.code());

    // …but the relying party naming it does.
    let response = authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion(
            "sybr.no",
            vec![(int(0x03), Cbor::Array(vec![descriptor(&credential_id)]))],
        ),
    ));
    assert_eq!(status(&response), CTAP2_OK);
}

#[test]
fn rk_is_not_a_valid_option_for_an_assertion() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    enrol(&mut authenticator, "sybr.no");
    let response = authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![(int(0x05), options(&[("rk", true)]))]),
    ));
    assert_eq!(status(&response), CtapError::UnsupportedOption.code());
}

#[test]
fn an_over_long_allow_list_is_refused_rather_than_walked() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let list: Vec<Cbor> = (0..17u8).map(|i| descriptor(&[i; 16])).collect();
    let response = authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![(int(0x03), Cbor::Array(list))]),
    ));
    assert_eq!(status(&response), CtapError::LimitExceeded.code());
}

#[test]
fn a_repeated_credential_id_is_answered_once() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let credential_id = enrol(&mut authenticator, "sybr.no");
    let entries = ok_map(&authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion(
            "sybr.no",
            vec![
                (
                    int(0x03),
                    Cbor::Array(vec![descriptor(&credential_id), descriptor(&credential_id)]),
                ),
                (int(0x05), options(&[("uv", true)])),
            ],
        ),
    )));
    // One match, so no numberOfCredentials and no session to walk.
    assert_eq!(get(&entries, 0x05), None);
    assert_eq!(
        status(&authenticator.handle_message(&[CMD_GET_NEXT_ASSERTION])),
        CtapError::NotAllowed.code()
    );
}

// --- getNextAssertion -----------------------------------------------------

#[test]
fn several_credentials_are_walked_with_get_next_assertion() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    enrol(&mut authenticator, "sybr.no");
    enrol(&mut authenticator, "sybr.no");
    enrol(&mut authenticator, "sybr.no");

    let first = ok_map(&authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![(int(0x05), options(&[("uv", true)]))]),
    )));
    assert_eq!(get(&first, 0x05), Some(&int(3)));
    authenticator.backend_mut().prompts.clear();

    let second = ok_map(&authenticator.handle_message(&[CMD_GET_NEXT_ASSERTION]));
    // numberOfCredentials rides only on the first response.
    assert_eq!(get(&second, 0x05), None);
    let third = ok_map(&authenticator.handle_message(&[CMD_GET_NEXT_ASSERTION]));

    // Three distinct credentials, and the user was asked exactly once for the
    // whole set.
    let ids: Vec<Vec<u8>> = [&first, &second, &third]
        .iter()
        .map(|e| bytes(get_text(map(get(e, 0x01).unwrap()), "id").unwrap()).to_vec())
        .collect();
    assert_eq!(ids.len(), 3);
    assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
    assert!(authenticator.backend_mut().prompts.is_empty());

    // The set is exhausted.
    assert_eq!(
        status(&authenticator.handle_message(&[CMD_GET_NEXT_ASSERTION])),
        CtapError::NotAllowed.code()
    );
}

#[test]
fn the_assertion_window_closes_on_time() {
    // A session that outlived its window must not keep handing out
    // assertions on an approval the user gave long ago.
    let mut authenticator = Authenticator::with_config(
        FakeVault::new(),
        Config {
            next_assertion_timeout: Duration::ZERO,
            ..Config::default()
        },
    );
    enrol(&mut authenticator, "sybr.no");
    enrol(&mut authenticator, "sybr.no");

    let first = ok_map(&authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![(int(0x05), options(&[("uv", true)]))]),
    )));
    assert_eq!(get(&first, 0x05), Some(&int(2)));

    assert_eq!(
        status(&authenticator.handle_message(&[CMD_GET_NEXT_ASSERTION])),
        CtapError::NotAllowed.code()
    );
}

#[test]
fn get_next_assertion_without_a_session_is_not_allowed() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    assert_eq!(
        status(&authenticator.handle_message(&[CMD_GET_NEXT_ASSERTION])),
        CtapError::NotAllowed.code()
    );
}

#[test]
fn an_intervening_command_closes_the_assertion_session() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    enrol(&mut authenticator, "sybr.no");
    enrol(&mut authenticator, "sybr.no");

    authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![(int(0x05), options(&[("uv", true)]))]),
    ));
    // Anything else in between ends it — otherwise a half-walked list from one
    // caller's approval stays available to the next.
    authenticator.handle_message(&[CMD_GET_INFO]);

    assert_eq!(
        status(&authenticator.handle_message(&[CMD_GET_NEXT_ASSERTION])),
        CtapError::NotAllowed.code()
    );
}

// --- PIN, reset, and unknown commands -------------------------------------

#[test]
fn a_pin_probe_reports_that_no_pin_is_set() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let response = authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![(int(0x06), Cbor::Bytes(vec![]))]),
    ));
    assert_eq!(status(&response), CtapError::PinNotSet.code());
    // The probe is not silent.
    assert_eq!(authenticator.backend_mut().prompts.len(), 1);
}

#[test]
fn a_pin_token_we_cannot_check_is_invalid_not_ignored() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    enrol(&mut authenticator, "sybr.no");
    let response = authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![(int(0x06), Cbor::Bytes(vec![9; 16]))]),
    ));
    assert_eq!(status(&response), CtapError::PinAuthInvalid.code());
}

#[test]
fn reset_is_refused_so_a_website_cannot_empty_the_vault() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    enrol(&mut authenticator, "sybr.no");
    let response = authenticator.handle_message(&[CMD_RESET]);
    assert_eq!(status(&response), CtapError::OperationDenied.code());
    assert_eq!(authenticator.backend_mut().records.len(), 1);
}

#[test]
fn selection_asks_for_presence_and_nothing_more() {
    // The platform is asking which authenticator the user means. There is no
    // ceremony yet, so there is nothing to verify against.
    let mut authenticator = Authenticator::new(FakeVault::new());
    let response = authenticator.handle_message(&[CMD_SELECTION]);
    assert_eq!(status(&response), CTAP2_OK);
    assert_eq!(response.len(), 1, "no payload");

    let prompt = authenticator.backend_mut().prompts[0].clone();
    assert_eq!(prompt.operation, Operation::Select);
    assert!(!prompt.require_verification);
}

#[test]
fn selection_reports_a_refusal() {
    let mut authenticator = Authenticator::new(FakeVault::answering(UserAction::Declined));
    assert_eq!(
        status(&authenticator.handle_message(&[CMD_SELECTION])),
        CtapError::OperationDenied.code()
    );
}

#[test]
fn client_pin_and_unknown_commands_are_invalid_commands() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    assert_eq!(
        status(&authenticator.handle_message(&[CMD_CLIENT_PIN])),
        CtapError::InvalidCommand.code()
    );
    assert_eq!(
        status(&authenticator.handle_message(&[0xEE])),
        CtapError::InvalidCommand.code()
    );
}

#[test]
fn an_empty_message_is_a_length_error_not_a_panic() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    assert_eq!(
        status(&authenticator.handle_message(&[])),
        CtapError::InvalidLength.code()
    );
}

#[test]
fn a_malformed_payload_is_reported_as_bad_cbor() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let response = authenticator.handle_message(&[CMD_GET_ASSERTION, 0xA1, 0x01]);
    assert_eq!(status(&response), CtapError::InvalidCbor.code());
}

#[test]
fn a_storage_failure_does_not_leak_which_failure_it_was() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    authenticator.backend_mut().fail_storage = true;
    let response = authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![]),
    ));
    assert_eq!(status(&response), CtapError::Other.code());
}

// --- agreement with the WebAuthn path ------------------------------------

#[test]
fn authenticator_data_agrees_with_vault_core_byte_for_byte() {
    // `vault_core::passkey` builds the same structure for the browser
    // extension and the macOS AutoFill extension. If the two ever disagree,
    // one of Arca's two doors is signing something different from the other.
    let mut authenticator = Authenticator::new(FakeVault::new());
    let credential_id = enrol(&mut authenticator, "sybr.no");

    let entries = ok_map(&authenticator.handle_message(&message(
        CMD_GET_ASSERTION,
        get_assertion("sybr.no", vec![(int(0x05), options(&[("uv", true)]))]),
    )));
    let ours = bytes(get(&entries, 0x02).unwrap()).to_vec();

    let private_key = authenticator
        .backend_mut()
        .records
        .iter()
        .find(|r| r.credential_id == credential_id)
        .unwrap()
        .private_key
        .clone();
    let (theirs, _) =
        vault_core::passkey::assert(&private_key, "sybr.no", &[0xCD; 32], true).unwrap();

    assert_eq!(ours, theirs);
}

#[test]
fn registration_flags_and_aaguid_agree_with_vault_core() {
    let mut authenticator = Authenticator::new(FakeVault::new());
    let entries =
        ok_map(&authenticator.handle_message(&message(CMD_MAKE_CREDENTIAL, register("sybr.no"))));
    let ours = bytes(get(&entries, 0x02).unwrap()).to_vec();

    let theirs = vault_core::passkey::create("sybr.no", true).unwrap();
    let attestation: Cbor = ciborium::from_reader(&theirs.attestation_object[..]).unwrap();
    let their_auth_data = match get_text(map(&attestation), "authData").unwrap() {
        Cbor::Bytes(b) => b.clone(),
        other => panic!("authData: {other:?}"),
    };

    // rpIdHash, flags, signCount and AAGUID are identical; only the random
    // credential id and public key differ.
    assert_eq!(ours[..53], their_auth_data[..53]);
}
