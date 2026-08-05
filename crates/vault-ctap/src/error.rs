//! CTAP2 status codes.
//!
//! Every CTAP2 response is a single status byte followed by an optional CBOR
//! payload. `0x00` is success; anything else is one of the codes below and the
//! payload is empty. The numeric values are fixed by the CTAP 2.1 spec
//! (§ "Error Responses") — they are wire format, not an internal convention, so
//! they must never be renumbered.
//!
//! SECURITY: a status code is the *only* thing an error tells the platform, and
//! that is deliberate. The variants carry no data, so nothing about the vault's
//! contents — which relying parties have credentials, why a lookup failed — can
//! leak through an error path. Two different internal failures that a caller
//! must not be able to tell apart map to the same code on purpose.

use thiserror::Error;

/// A CTAP2 error status. Convert to the wire byte with [`CtapError::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
#[repr(u8)]
pub enum CtapError {
    /// The command byte is not one this authenticator implements.
    #[error("invalid command")]
    InvalidCommand = 0x01,

    /// A parameter had a valid type but an unusable value.
    #[error("invalid parameter")]
    InvalidParameter = 0x02,

    /// A fixed-width field was the wrong size (e.g. a clientDataHash that is
    /// not 32 bytes).
    #[error("invalid length")]
    InvalidLength = 0x03,

    /// A CBOR item parsed, but was the wrong major type for its position.
    #[error("cbor unexpected type")]
    CborUnexpectedType = 0x11,

    /// The request payload is not well-formed CBOR.
    #[error("invalid cbor")]
    InvalidCbor = 0x12,

    /// A required parameter was absent.
    #[error("missing parameter")]
    MissingParameter = 0x14,

    /// The request exceeded a limit this authenticator advertises in
    /// `authenticatorGetInfo` (e.g. `maxCredentialCountInList`).
    #[error("limit exceeded")]
    LimitExceeded = 0x15,

    /// A credential in `excludeList` is already registered for this relying
    /// party, so registering another would be a duplicate.
    #[error("credential excluded")]
    CredentialExcluded = 0x19,

    /// The requested algorithm is not one we can sign with (we do ES256 only).
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm = 0x21,

    /// The user declined, or a required user verification did not succeed.
    #[error("operation denied")]
    OperationDenied = 0x22,

    /// An option key was present that this authenticator does not implement.
    #[error("unsupported option")]
    UnsupportedOption = 0x26,

    /// An option was supported but not valid for this command, or its value is
    /// one we cannot honour (e.g. `up: false` on makeCredential).
    #[error("invalid option")]
    InvalidOption = 0x27,

    /// The host withdrew the request while the user was still being asked
    /// (`CTAPHID_CANCEL`).
    #[error("keepalive cancel")]
    KeepaliveCancel = 0x2B,

    /// No credential matched the request.
    #[error("no credentials")]
    NoCredentials = 0x2E,

    /// The user did not answer the prompt in time.
    #[error("user action timeout")]
    UserActionTimeout = 0x2F,

    /// The command is not allowed in the current state — in practice, a
    /// `getNextAssertion` with no assertion session open.
    #[error("not allowed")]
    NotAllowed = 0x30,

    /// `pinUvAuthParam` was supplied but we cannot verify it: this
    /// authenticator implements no PIN protocol.
    #[error("pin auth invalid")]
    PinAuthInvalid = 0x33,

    /// The platform probed for a PIN and there is none. Arca verifies the user
    /// internally (master password), so a CTAP PIN is never set.
    #[error("pin not set")]
    PinNotSet = 0x35,

    /// Catch-all for an internal failure. Deliberately indistinct.
    #[error("other error")]
    Other = 0x7F,
}

impl CtapError {
    /// The status byte to put on the wire.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// What a [`Backend`](crate::Backend) reports when it cannot service a request.
///
/// Kept separate from [`CtapError`] so a backend never has to reason about wire
/// status codes; [`From`] maps each case to the code the platform should see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BackendError {
    /// The vault is locked and the user did not unlock it.
    #[error("vault is locked")]
    Locked,

    /// The credential does not exist, or does not belong to this relying party.
    #[error("credential not found")]
    NotFound,

    /// Reading or writing the vault failed.
    #[error("storage failure")]
    Storage,

    /// The stored key material could not be used to sign.
    #[error("signing failure")]
    Signing,
}

impl From<BackendError> for CtapError {
    fn from(e: BackendError) -> Self {
        match e {
            // A locked vault means the user was asked to unlock and did not.
            // From the platform's side that is indistinguishable from — and
            // should look identical to — an outright refusal.
            BackendError::Locked => CtapError::OperationDenied,
            BackendError::NotFound => CtapError::NoCredentials,
            BackendError::Storage | BackendError::Signing => CtapError::Other,
        }
    }
}

/// Result alias for the authenticator's command handlers.
pub type Result<T> = core::result::Result<T, CtapError>;

/// Result alias for [`Backend`](crate::Backend) implementations.
pub type BackendResult<T> = core::result::Result<T, BackendError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// These bytes are wire format. If one of them changes, every platform
    /// talking to us misreads the failure — so pin them.
    #[test]
    fn status_codes_match_the_ctap_spec() {
        assert_eq!(CtapError::InvalidCommand.code(), 0x01);
        assert_eq!(CtapError::InvalidParameter.code(), 0x02);
        assert_eq!(CtapError::InvalidLength.code(), 0x03);
        assert_eq!(CtapError::CborUnexpectedType.code(), 0x11);
        assert_eq!(CtapError::InvalidCbor.code(), 0x12);
        assert_eq!(CtapError::MissingParameter.code(), 0x14);
        assert_eq!(CtapError::LimitExceeded.code(), 0x15);
        assert_eq!(CtapError::CredentialExcluded.code(), 0x19);
        assert_eq!(CtapError::UnsupportedAlgorithm.code(), 0x21);
        assert_eq!(CtapError::OperationDenied.code(), 0x22);
        assert_eq!(CtapError::UnsupportedOption.code(), 0x26);
        assert_eq!(CtapError::InvalidOption.code(), 0x27);
        assert_eq!(CtapError::KeepaliveCancel.code(), 0x2B);
        assert_eq!(CtapError::NoCredentials.code(), 0x2E);
        assert_eq!(CtapError::UserActionTimeout.code(), 0x2F);
        assert_eq!(CtapError::NotAllowed.code(), 0x30);
        assert_eq!(CtapError::PinAuthInvalid.code(), 0x33);
        assert_eq!(CtapError::PinNotSet.code(), 0x35);
        assert_eq!(CtapError::Other.code(), 0x7F);
    }

    #[test]
    fn a_locked_vault_is_indistinguishable_from_a_refusal() {
        // A caller must not be able to probe whether the vault holds anything
        // by telling "locked" apart from "you said no".
        assert_eq!(
            CtapError::from(BackendError::Locked),
            CtapError::OperationDenied
        );
    }

    #[test]
    fn storage_and_signing_failures_collapse_to_one_code() {
        assert_eq!(CtapError::from(BackendError::Storage), CtapError::Other);
        assert_eq!(CtapError::from(BackendError::Signing), CtapError::Other);
    }
}
