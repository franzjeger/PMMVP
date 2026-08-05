//! CTAP2 authenticator protocol for Arca.
//!
//! Arca can already answer WebAuthn ceremonies in a browser we ship an
//! extension for. This crate is how it answers them *everywhere else* on
//! Linux: implement CTAP2 — the protocol a security key speaks — and any
//! WebAuthn client on the machine can use the vault without knowing Arca
//! exists. Chromium, Firefox, Electron apps, and `ssh-keygen -t ecdsa-sk` all
//! already speak it.
//!
//! # Layering
//!
//! ```text
//!   relying party  ──WebAuthn──▶  browser / OS
//!                                      │  CTAP2 over some transport
//!                                      ▼
//!                            ┌──────────────────────┐
//!                            │  transport (CTAPHID  │   [not in this crate]
//!                            │  over /dev/uhid, …)  │
//!                            └──────────┬───────────┘
//!                                       │ command byte + CBOR
//!                                       ▼
//!                            ┌──────────────────────┐
//!                            │  vault-ctap          │   ← you are here
//!                            │  Authenticator       │
//!                            └──────────┬───────────┘
//!                                       │ Backend trait
//!                                       ▼
//!                            ┌──────────────────────┐
//!                            │  the vault: storage, │
//!                            │  signing, consent UI │
//!                            └──────────────────────┘
//! ```
//!
//! The crate is deliberately inert: no threads, no sockets, no files, no
//! clocks beyond the one timer CTAP requires, and no key material. It is a
//! function from a request and a [`Backend`] to a response, which is why the
//! whole protocol can be tested against a fake vault.
//!
//! # Relationship to `vault_core::passkey`
//!
//! `vault_core::passkey` is the same authenticator seen through WebAuthn: it
//! builds an attestation object and an assertion for callers that already have
//! a `clientDataHash` in hand — the macOS AutoFill extension and the browser
//! extension's native path. CTAP2 needs finer control (the flags vary per
//! request, and registration and assertion arrive as separate commands), so
//! this crate assembles `authenticatorData` itself. The integration tests
//! check the two implementations byte-for-byte against each other so they
//! cannot drift.
//!
//! # Usage
//!
//! ```no_run
//! use vault_ctap::{Authenticator, Backend};
//! # fn example<B: Backend>(vault: B, message: &[u8]) -> Vec<u8> {
//! let mut authenticator = Authenticator::new(vault);
//! // `message` is a command byte followed by a CBOR payload, straight off the
//! // transport; the answer is a status byte followed by a CBOR payload.
//! authenticator.handle_message(message)
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod authenticator;
mod backend;
mod cbor;
mod error;
mod types;

pub mod hid;

pub use authenticator::{
    Authenticator, Config, CMD_CLIENT_PIN, CMD_GET_ASSERTION, CMD_GET_INFO, CMD_GET_NEXT_ASSERTION,
    CMD_MAKE_CREDENTIAL, CMD_RESET, CMD_SELECTION,
};
pub use backend::{
    Backend, Consent, CreatedCredential, NewCredential, Operation, StoredCredential, UserAction,
};
pub use error::{BackendError, BackendResult, CtapError, Result};
pub use types::{
    CredentialDescriptor, GetAssertionRequest, MakeCredentialRequest, Options, RelyingParty, User,
    ALG_ES256, CREDENTIAL_TYPE,
};

/// CTAP2 success status byte.
pub const CTAP2_OK: u8 = 0x00;
