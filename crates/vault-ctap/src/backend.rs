//! The seam between the CTAP2 protocol and Arca's vault.
//!
//! Everything stateful lives behind [`Backend`]: credential storage, signing,
//! and asking the user. The authenticator itself is a pure function of the
//! request plus whatever the backend answers, which is what makes the whole
//! protocol layer testable against a fake and keeps `vault-ctap` free of any
//! dependency on `vault-store`, Tauri, or a filesystem.
//!
//! SECURITY: private keys never cross this boundary. [`Backend::sign`] takes a
//! credential id and a message and returns a signature; the scalar stays in the
//! vault. That does make `sign` a signing oracle for whoever holds the
//! `Backend` — but the message is always `authenticatorData || clientDataHash`,
//! and `authenticatorData` opens with the SHA-256 of an rpId the authenticator
//! has already authorised, so a signature this crate requests can only ever be
//! valid for the relying party the user just approved.

use crate::error::{BackendResult, CtapError};
use crate::types::{RelyingParty, User};

/// A credential the vault holds, as the protocol layer needs to see it.
///
/// Note what is absent: the private key. Everything here is either public or
/// already known to the relying party that is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredential {
    /// The id issued at registration; the relying party's handle on this key.
    pub credential_id: Vec<u8>,
    /// The account this credential signs in to.
    pub user: User,
    /// Whether this credential can be found without the relying party naming
    /// it — a passkey, in other words. Non-discoverable credentials are still
    /// stored, but only [`Backend::lookup`] can reach them.
    pub discoverable: bool,
}

/// A credential to create and persist.
#[derive(Debug, Clone)]
pub struct NewCredential<'a> {
    /// The site the credential is scoped to.
    pub rp: &'a RelyingParty,
    /// The account it will sign in to.
    pub user: &'a User,
    /// The relying party asked for a discoverable credential.
    pub discoverable: bool,
    /// True when a real user verification gated this registration. Recorded so
    /// the vault can tell an approved registration from a silent one.
    pub user_verified: bool,
}

/// What the backend produced for a [`NewCredential`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedCredential {
    /// The freshly issued credential id.
    pub credential_id: Vec<u8>,
    /// The COSE_Key encoding of the public key (RFC 9052), which goes into the
    /// attested credential data verbatim.
    pub cose_public_key: Vec<u8>,
}

/// What the authenticator is asking the user to approve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Registering a new credential.
    Register,
    /// Signing in with an existing one.
    Authenticate,
    /// The platform is asking which authenticator the user meant, with no
    /// ceremony attached yet (`authenticatorSelection`).
    Select,
}

/// A request for the user's approval, with enough context for a prompt that
/// says what is actually happening.
#[derive(Debug, Clone)]
pub struct Consent<'a> {
    /// What the user is being asked to approve.
    pub operation: Operation,
    /// The relying party the credential is scoped to.
    pub rp_id: &'a str,
    /// The relying party's display name, if it supplied one.
    pub rp_name: Option<&'a str>,
    /// The account involved, when one is known.
    pub user_name: Option<&'a str>,
    /// True when the platform asked for user verification. The backend must
    /// then perform a real check (Arca's master password) and only report
    /// `verified: true` if it succeeded.
    pub require_verification: bool,
}

/// The user's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAction {
    /// The user approved. `verified` records whether a genuine verification —
    /// not merely a click — took place; it becomes the WebAuthn UV flag.
    ///
    /// SECURITY: reporting `verified: true` without an actual check would tell
    /// every relying party that the user was just authenticated, which is
    /// exactly the claim step-up defences rely on. Report what happened.
    Approved {
        /// Whether a genuine user verification took place, not merely a click.
        verified: bool,
    },
    /// The user refused.
    Declined,
    /// Nobody answered in time.
    TimedOut,
}

/// Arca's side of the authenticator.
///
/// Calls are serialised: a CTAP transport handles one command at a time, so
/// `&mut self` is honest here and implementations need no interior mutability.
pub trait Backend {
    /// Discoverable credentials for `rp_id`, most recently used first — the
    /// order the user will see them offered in.
    fn discover(&mut self, rp_id: &str) -> BackendResult<Vec<StoredCredential>>;

    /// The credential with this id, if it exists **and** belongs to `rp_id`.
    ///
    /// SECURITY: the rpId check belongs here, not in the caller. A credential
    /// id is not a secret — the relying party knows it — so returning one
    /// scoped to a different site would let any page assert with a credential
    /// it merely learned the id of.
    fn lookup(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
    ) -> BackendResult<Option<StoredCredential>>;

    /// Generate a P-256 keypair, store it against `rp`/`user`, and return the
    /// public half. The private scalar stays in the vault.
    fn create(&mut self, credential: &NewCredential<'_>) -> BackendResult<CreatedCredential>;

    /// Sign `message` with the named credential's private key, returning a
    /// DER-encoded ECDSA signature.
    fn sign(&mut self, credential_id: &[u8], message: &[u8]) -> BackendResult<Vec<u8>>;

    /// Ask the user. Blocks until they answer or the implementation's own
    /// timeout elapses, whichever comes first.
    fn confirm(&mut self, request: &Consent<'_>) -> UserAction;
}

/// Turn a [`UserAction`] into the flags an approved ceremony carries, or the
/// status code a refused one reports.
pub(crate) fn approval(action: UserAction, verification_required: bool) -> Result<bool, CtapError> {
    match action {
        // The platform asked for verification and the backend did not do one.
        // Proceeding would mean either lying in the UV flag or quietly
        // answering a weaker ceremony than was requested; refuse instead.
        UserAction::Approved { verified: false } if verification_required => {
            Err(CtapError::OperationDenied)
        }
        UserAction::Approved { verified } => Ok(verified),
        UserAction::Declined => Err(CtapError::OperationDenied),
        UserAction::TimedOut => Err(CtapError::UserActionTimeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unverified_approval_cannot_satisfy_a_verified_request() {
        assert_eq!(
            approval(UserAction::Approved { verified: false }, true).unwrap_err(),
            CtapError::OperationDenied
        );
    }

    #[test]
    fn a_verified_approval_carries_the_uv_flag() {
        assert!(approval(UserAction::Approved { verified: true }, true).unwrap());
        assert!(approval(UserAction::Approved { verified: true }, false).unwrap());
    }

    #[test]
    fn presence_only_approval_is_allowed_when_verification_was_not_asked_for() {
        assert!(!approval(UserAction::Approved { verified: false }, false).unwrap());
    }

    #[test]
    fn refusal_and_timeout_are_distinct_on_the_wire() {
        assert_eq!(
            approval(UserAction::Declined, false).unwrap_err(),
            CtapError::OperationDenied
        );
        assert_eq!(
            approval(UserAction::TimedOut, false).unwrap_err(),
            CtapError::UserActionTimeout
        );
    }
}
