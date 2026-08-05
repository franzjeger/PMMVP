//! Request types and their CBOR parsing.
//!
//! The map keys are fixed by CTAP 2.1 (§6.1 `authenticatorMakeCredential`, §6.2
//! `authenticatorGetAssertion`). Parsing here is strict about types and lengths
//! but ignores map entries it does not recognise, so a newer platform can send
//! parameters this build predates without the ceremony failing.
//!
//! One deliberate exception to that leniency: an unrecognised key in the
//! `options` map is [`CtapError::UnsupportedOption`], as the spec requires.
//! Options change behaviour, so silently ignoring one would mean answering a
//! question the platform did not ask — the opposite of ignoring an extra
//! descriptive field.

use ciborium::value::Value as Cbor;

use crate::cbor;
use crate::error::{CtapError, Result};

/// ES256 (ECDSA with P-256 and SHA-256), the one algorithm we sign with.
pub const ALG_ES256: i64 = -7;

/// The only credential type WebAuthn defines.
pub const CREDENTIAL_TYPE: &str = "public-key";

/// A clientDataHash is always a SHA-256 digest.
const CLIENT_DATA_HASH_LEN: usize = 32;

/// WebAuthn caps a user handle at 64 bytes.
const MAX_USER_ID_LEN: usize = 64;

/// The relying party a credential belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    /// The rpId — the effective domain the credential is scoped to.
    pub id: String,
    /// Human-readable name, for display in the consent prompt.
    pub name: Option<String>,
}

/// The account a credential signs in to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct User {
    /// The user handle. Opaque to us; returned verbatim in an assertion.
    pub id: Vec<u8>,
    /// Account name, e.g. an email address.
    pub name: Option<String>,
    /// Friendly name, e.g. "Frank".
    pub display_name: Option<String>,
}

/// A reference to a credential, as used in `allowList` and `excludeList`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDescriptor {
    /// The credential id we issued at registration.
    pub id: Vec<u8>,
}

/// The `options` map of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Options {
    /// Discoverable credential ("resident key") requested.
    pub rk: Option<bool>,
    /// User presence requested. Absent means the command's default.
    pub up: Option<bool>,
    /// User verification requested.
    pub uv: Option<bool>,
}

impl Options {
    fn parse(value: &Cbor) -> Result<Self> {
        let entries = cbor::as_map(value)?;
        let mut options = Options::default();
        for (key, value) in entries {
            match cbor::as_text(key)? {
                "rk" => options.rk = Some(cbor::as_bool(value)?),
                "up" => options.up = Some(cbor::as_bool(value)?),
                "uv" => options.uv = Some(cbor::as_bool(value)?),
                _ => return Err(CtapError::UnsupportedOption),
            }
        }
        Ok(options)
    }
}

/// `authenticatorMakeCredential` (0x01).
#[derive(Debug, Clone)]
pub struct MakeCredentialRequest {
    /// SHA-256 of the client data the platform assembled. Always 32 bytes.
    pub client_data_hash: Vec<u8>,
    /// The site registering the credential.
    pub rp: RelyingParty,
    /// The account it will sign in to.
    pub user: User,
    /// Algorithms the relying party will accept, in its order of preference.
    pub algorithms: Vec<i64>,
    /// Credentials that already exist for this account; registering a second
    /// one would be a duplicate.
    pub exclude_list: Vec<CredentialDescriptor>,
    /// The `options` map, with each entry absent unless the platform sent it.
    pub options: Options,
    /// Present iff the platform supplied `pinUvAuthParam`. We implement no PIN
    /// protocol, so this exists only so the authenticator can answer the
    /// platform's probe correctly rather than ignoring it.
    pub pin_uv_auth_param: Option<Vec<u8>>,
    /// The PIN protocol version the platform used, if any.
    pub pin_uv_auth_protocol: Option<i64>,
}

impl MakeCredentialRequest {
    /// Parse a `authenticatorMakeCredential` payload.
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let value = cbor::decode(payload)?;
        let entries = cbor::as_map(&value)?;

        let client_data_hash =
            client_data_hash(cbor::get(entries, 0x01).ok_or(CtapError::MissingParameter)?)?;

        let rp = {
            let map = cbor::as_map(cbor::get(entries, 0x02).ok_or(CtapError::MissingParameter)?)?;
            let id = cbor::get_text_key(map, "id").ok_or(CtapError::MissingParameter)?;
            RelyingParty {
                id: cbor::as_text(id)?.to_string(),
                name: optional_text(map, "name")?,
            }
        };
        if rp.id.is_empty() {
            return Err(CtapError::InvalidParameter);
        }

        let user = {
            let map = cbor::as_map(cbor::get(entries, 0x03).ok_or(CtapError::MissingParameter)?)?;
            let id =
                cbor::as_bytes(cbor::get_text_key(map, "id").ok_or(CtapError::MissingParameter)?)?;
            if id.len() > MAX_USER_ID_LEN {
                return Err(CtapError::InvalidLength);
            }
            User {
                id: id.to_vec(),
                name: optional_text(map, "name")?,
                display_name: optional_text(map, "displayName")?,
            }
        };

        // pubKeyCredParams is an ordered list of {alg, type}. Entries of an
        // unknown credential type are skipped rather than rejected, so a
        // future type alongside "public-key" does not break the ceremony.
        let algorithms = {
            let items =
                cbor::as_array(cbor::get(entries, 0x04).ok_or(CtapError::MissingParameter)?)?;
            let mut algorithms = Vec::with_capacity(items.len());
            for item in items {
                let map = cbor::as_map(item)?;
                let kind = cbor::get_text_key(map, "type").ok_or(CtapError::MissingParameter)?;
                if cbor::as_text(kind)? != CREDENTIAL_TYPE {
                    continue;
                }
                let alg = cbor::get_text_key(map, "alg").ok_or(CtapError::MissingParameter)?;
                algorithms.push(cbor::as_i64(alg)?);
            }
            algorithms
        };

        let exclude_list = match cbor::get(entries, 0x05) {
            Some(value) => descriptors(value)?,
            None => Vec::new(),
        };

        let options = match cbor::get(entries, 0x07) {
            Some(value) => Options::parse(value)?,
            None => Options::default(),
        };

        Ok(Self {
            client_data_hash,
            rp,
            user,
            algorithms,
            exclude_list,
            options,
            pin_uv_auth_param: optional_bytes(entries, 0x08)?,
            pin_uv_auth_protocol: optional_i64(entries, 0x09)?,
        })
    }
}

/// `authenticatorGetAssertion` (0x02).
#[derive(Debug, Clone)]
pub struct GetAssertionRequest {
    /// The site asking for an assertion.
    pub rp_id: String,
    /// SHA-256 of the client data the platform assembled. Always 32 bytes.
    pub client_data_hash: Vec<u8>,
    /// Empty means the platform did not constrain the choice, so any
    /// discoverable credential for this relying party is a candidate.
    pub allow_list: Vec<CredentialDescriptor>,
    /// True when `allowList` was present in the request, even if it parsed to
    /// nothing usable. An absent list and an empty one mean different things:
    /// absent invites discovery, present-but-empty matches nothing.
    pub allow_list_present: bool,
    /// The `options` map, with each entry absent unless the platform sent it.
    pub options: Options,
    /// A MAC over the request, if the platform believes it holds a PIN token.
    pub pin_uv_auth_param: Option<Vec<u8>>,
    /// The PIN protocol version the platform used, if any.
    pub pin_uv_auth_protocol: Option<i64>,
}

impl GetAssertionRequest {
    /// Parse an `authenticatorGetAssertion` payload.
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let value = cbor::decode(payload)?;
        let entries = cbor::as_map(&value)?;

        let rp_id = cbor::as_text(cbor::get(entries, 0x01).ok_or(CtapError::MissingParameter)?)?
            .to_string();
        if rp_id.is_empty() {
            return Err(CtapError::InvalidParameter);
        }

        let client_data_hash =
            client_data_hash(cbor::get(entries, 0x02).ok_or(CtapError::MissingParameter)?)?;

        let allow_list_value = cbor::get(entries, 0x03);
        let allow_list = match allow_list_value {
            Some(value) => descriptors(value)?,
            None => Vec::new(),
        };

        let options = match cbor::get(entries, 0x05) {
            Some(value) => Options::parse(value)?,
            None => Options::default(),
        };

        Ok(Self {
            rp_id,
            client_data_hash,
            allow_list,
            allow_list_present: allow_list_value.is_some(),
            options,
            pin_uv_auth_param: optional_bytes(entries, 0x06)?,
            pin_uv_auth_protocol: optional_i64(entries, 0x07)?,
        })
    }
}

fn client_data_hash(value: &Cbor) -> Result<Vec<u8>> {
    let hash = cbor::as_bytes(value)?;
    if hash.len() != CLIENT_DATA_HASH_LEN {
        return Err(CtapError::InvalidLength);
    }
    Ok(hash.to_vec())
}

/// Parse an array of PublicKeyCredentialDescriptor. Entries whose `type` is not
/// "public-key" are skipped per spec; a descriptor without an `id` is an error.
fn descriptors(value: &Cbor) -> Result<Vec<CredentialDescriptor>> {
    let items = cbor::as_array(value)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let map = cbor::as_map(item)?;
        let kind = cbor::get_text_key(map, "type").ok_or(CtapError::MissingParameter)?;
        if cbor::as_text(kind)? != CREDENTIAL_TYPE {
            continue;
        }
        let id = cbor::get_text_key(map, "id").ok_or(CtapError::MissingParameter)?;
        out.push(CredentialDescriptor {
            id: cbor::as_bytes(id)?.to_vec(),
        });
    }
    Ok(out)
}

fn optional_text(entries: &[(Cbor, Cbor)], key: &str) -> Result<Option<String>> {
    match cbor::get_text_key(entries, key) {
        Some(value) => Ok(Some(cbor::as_text(value)?.to_string())),
        None => Ok(None),
    }
}

fn optional_bytes(entries: &[(Cbor, Cbor)], key: i64) -> Result<Option<Vec<u8>>> {
    match cbor::get(entries, key) {
        Some(value) => Ok(Some(cbor::as_bytes(value)?.to_vec())),
        None => Ok(None),
    }
}

fn optional_i64(entries: &[(Cbor, Cbor)], key: i64) -> Result<Option<i64>> {
    match cbor::get(entries, key) {
        Some(value) => Ok(Some(cbor::as_i64(value)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::int;

    fn text(s: &str) -> Cbor {
        Cbor::Text(s.into())
    }

    fn descriptor(id: &[u8]) -> Cbor {
        Cbor::Map(vec![
            (text("type"), text(CREDENTIAL_TYPE)),
            (text("id"), Cbor::Bytes(id.to_vec())),
        ])
    }

    /// A minimal but complete makeCredential request, as a browser sends it.
    fn make_credential_payload(extra: Vec<(Cbor, Cbor)>) -> Vec<u8> {
        let mut entries = vec![
            (int(0x01), Cbor::Bytes(vec![7u8; 32])),
            (
                int(0x02),
                Cbor::Map(vec![
                    (text("id"), text("example.com")),
                    (text("name"), text("Example")),
                ]),
            ),
            (
                int(0x03),
                Cbor::Map(vec![
                    (text("id"), Cbor::Bytes(vec![1, 2, 3])),
                    (text("name"), text("frank@example.com")),
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
        cbor::encode(Cbor::Map(entries))
    }

    fn get_assertion_payload(extra: Vec<(Cbor, Cbor)>) -> Vec<u8> {
        let mut entries = vec![
            (int(0x01), text("example.com")),
            (int(0x02), Cbor::Bytes(vec![9u8; 32])),
        ];
        entries.extend(extra);
        cbor::encode(Cbor::Map(entries))
    }

    #[test]
    fn parses_a_full_make_credential_request() {
        let req = MakeCredentialRequest::parse(&make_credential_payload(vec![(
            int(0x07),
            Cbor::Map(vec![(text("rk"), Cbor::Bool(true))]),
        )]))
        .unwrap();

        assert_eq!(req.rp.id, "example.com");
        assert_eq!(req.rp.name.as_deref(), Some("Example"));
        assert_eq!(req.user.id, vec![1, 2, 3]);
        assert_eq!(req.user.display_name.as_deref(), Some("Frank"));
        assert_eq!(req.algorithms, vec![ALG_ES256]);
        assert_eq!(req.options.rk, Some(true));
        assert_eq!(req.options.uv, None);
        assert!(req.exclude_list.is_empty());
    }

    #[test]
    fn skips_credential_params_of_an_unknown_type_but_keeps_the_rest() {
        let req = MakeCredentialRequest::parse(&cbor::encode(Cbor::Map(vec![
            (int(0x01), Cbor::Bytes(vec![7u8; 32])),
            (
                int(0x02),
                Cbor::Map(vec![(text("id"), text("example.com"))]),
            ),
            (
                int(0x03),
                Cbor::Map(vec![(text("id"), Cbor::Bytes(vec![1]))]),
            ),
            (
                int(0x04),
                Cbor::Array(vec![
                    Cbor::Map(vec![
                        (text("alg"), int(-8)),
                        (text("type"), text("future-key")),
                    ]),
                    Cbor::Map(vec![
                        (text("alg"), int(ALG_ES256)),
                        (text("type"), text(CREDENTIAL_TYPE)),
                    ]),
                ]),
            ),
        ])))
        .unwrap();
        assert_eq!(req.algorithms, vec![ALG_ES256]);
    }

    #[test]
    fn an_unknown_top_level_key_is_ignored() {
        // Forward compatibility: a platform sending a parameter we predate
        // must not break the ceremony.
        let req = MakeCredentialRequest::parse(&make_credential_payload(vec![(
            int(0x63),
            text("something new"),
        )]))
        .unwrap();
        assert_eq!(req.rp.id, "example.com");
    }

    #[test]
    fn an_unknown_option_is_refused() {
        let err = MakeCredentialRequest::parse(&make_credential_payload(vec![(
            int(0x07),
            Cbor::Map(vec![(text("fictional"), Cbor::Bool(true))]),
        )]))
        .unwrap_err();
        assert_eq!(err, CtapError::UnsupportedOption);
    }

    #[test]
    fn a_short_client_data_hash_is_rejected() {
        let payload = cbor::encode(Cbor::Map(vec![
            (int(0x01), Cbor::Bytes(vec![7u8; 31])),
            (
                int(0x02),
                Cbor::Map(vec![(text("id"), text("example.com"))]),
            ),
            (
                int(0x03),
                Cbor::Map(vec![(text("id"), Cbor::Bytes(vec![1]))]),
            ),
            (int(0x04), Cbor::Array(vec![])),
        ]));
        assert_eq!(
            MakeCredentialRequest::parse(&payload).unwrap_err(),
            CtapError::InvalidLength
        );
    }

    #[test]
    fn an_oversized_user_handle_is_rejected() {
        let payload = cbor::encode(Cbor::Map(vec![
            (int(0x01), Cbor::Bytes(vec![7u8; 32])),
            (
                int(0x02),
                Cbor::Map(vec![(text("id"), text("example.com"))]),
            ),
            (
                int(0x03),
                Cbor::Map(vec![(text("id"), Cbor::Bytes(vec![0u8; 65]))]),
            ),
            (int(0x04), Cbor::Array(vec![])),
        ]));
        assert_eq!(
            MakeCredentialRequest::parse(&payload).unwrap_err(),
            CtapError::InvalidLength
        );
    }

    #[test]
    fn missing_required_parameters_are_reported_as_missing() {
        // No rp at all.
        let payload = cbor::encode(Cbor::Map(vec![(int(0x01), Cbor::Bytes(vec![7u8; 32]))]));
        assert_eq!(
            MakeCredentialRequest::parse(&payload).unwrap_err(),
            CtapError::MissingParameter
        );
    }

    #[test]
    fn an_empty_rp_id_is_invalid() {
        let payload = cbor::encode(Cbor::Map(vec![
            (int(0x01), Cbor::Bytes(vec![7u8; 32])),
            (int(0x02), Cbor::Map(vec![(text("id"), text(""))])),
            (
                int(0x03),
                Cbor::Map(vec![(text("id"), Cbor::Bytes(vec![1]))]),
            ),
            (int(0x04), Cbor::Array(vec![])),
        ]));
        assert_eq!(
            MakeCredentialRequest::parse(&payload).unwrap_err(),
            CtapError::InvalidParameter
        );
    }

    #[test]
    fn parses_exclude_and_allow_lists() {
        let req = MakeCredentialRequest::parse(&make_credential_payload(vec![(
            int(0x05),
            Cbor::Array(vec![descriptor(&[1, 1]), descriptor(&[2, 2])]),
        )]))
        .unwrap();
        assert_eq!(req.exclude_list.len(), 2);
        assert_eq!(req.exclude_list[0].id, vec![1, 1]);

        let req = GetAssertionRequest::parse(&get_assertion_payload(vec![(
            int(0x03),
            Cbor::Array(vec![descriptor(&[3, 3])]),
        )]))
        .unwrap();
        assert!(req.allow_list_present);
        assert_eq!(req.allow_list[0].id, vec![3, 3]);
    }

    #[test]
    fn an_absent_allow_list_is_distinguishable_from_an_empty_one() {
        let absent = GetAssertionRequest::parse(&get_assertion_payload(vec![])).unwrap();
        assert!(!absent.allow_list_present);

        let empty = GetAssertionRequest::parse(&get_assertion_payload(vec![(
            int(0x03),
            Cbor::Array(vec![]),
        )]))
        .unwrap();
        assert!(empty.allow_list_present);
        assert!(empty.allow_list.is_empty());
    }

    #[test]
    fn pin_uv_auth_parameters_are_carried_through() {
        let req = GetAssertionRequest::parse(&get_assertion_payload(vec![
            (int(0x06), Cbor::Bytes(vec![])),
            (int(0x07), int(2)),
        ]))
        .unwrap();
        assert_eq!(req.pin_uv_auth_param, Some(vec![]));
        assert_eq!(req.pin_uv_auth_protocol, Some(2));
    }

    #[test]
    fn a_wrongly_typed_field_is_a_type_error_not_a_default() {
        // rp.id as bytes instead of text.
        let payload = cbor::encode(Cbor::Map(vec![
            (int(0x01), Cbor::Bytes(vec![7u8; 32])),
            (
                int(0x02),
                Cbor::Map(vec![(text("id"), Cbor::Bytes(vec![1, 2]))]),
            ),
            (
                int(0x03),
                Cbor::Map(vec![(text("id"), Cbor::Bytes(vec![1]))]),
            ),
            (int(0x04), Cbor::Array(vec![])),
        ]));
        assert_eq!(
            MakeCredentialRequest::parse(&payload).unwrap_err(),
            CtapError::CborUnexpectedType
        );
    }
}
