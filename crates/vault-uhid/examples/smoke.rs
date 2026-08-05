//! Bring up the virtual authenticator against a throwaway in-memory vault, so
//! the whole stack can be exercised with real FIDO tooling.
//!
//! ```sh
//! cargo build -p vault-uhid --example smoke
//! sudo ./target/debug/examples/smoke        # /dev/uhid is root-only
//!
//! # in another shell
//! fido2-token -L                            # is it listed as a FIDO device?
//! fido2-token -I /dev/hidrawN               # INIT + authenticatorGetInfo
//! ```
//!
//! This approves every ceremony without asking anyone, and keeps credentials in
//! a `Vec` that dies with the process. It is a wire-protocol test rig, not a
//! preview of the real integration.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("vault-uhid is Linux-only");
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use vault_uhid::{serve, Cancellation, DeviceOptions};

    let options = DeviceOptions::default();
    println!("creating \"{}\" on /dev/uhid…", options.name);
    println!("try:  fido2-token -L");

    serve(MemoryVault::default(), &options, &Cancellation::new())
}

#[cfg(target_os = "linux")]
use memory_vault::MemoryVault;

#[cfg(target_os = "linux")]
mod memory_vault {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use vault_ctap::{
        Backend, BackendError, BackendResult, Consent, CreatedCredential, NewCredential,
        StoredCredential, User, UserAction,
    };

    struct Record {
        rp_id: String,
        credential_id: Vec<u8>,
        private_key: Vec<u8>,
        user: User,
        discoverable: bool,
    }

    #[derive(Default)]
    pub struct MemoryVault {
        records: Vec<Record>,
    }

    impl Backend for MemoryVault {
        fn discover(&mut self, rp_id: &str) -> BackendResult<Vec<StoredCredential>> {
            Ok(self
                .records
                .iter()
                .filter(|r| r.rp_id == rp_id && r.discoverable)
                .map(stored)
                .collect())
        }

        fn lookup(
            &mut self,
            rp_id: &str,
            credential_id: &[u8],
        ) -> BackendResult<Option<StoredCredential>> {
            Ok(self
                .records
                .iter()
                .find(|r| r.rp_id == rp_id && r.credential_id == credential_id)
                .map(stored))
        }

        fn create(&mut self, credential: &NewCredential<'_>) -> BackendResult<CreatedCredential> {
            let created = vault_core::passkey::create(&credential.rp.id, credential.user_verified)
                .map_err(|_| BackendError::Storage)?;
            println!(
                "register  rp={} user={:?}  discoverable={}",
                credential.rp.id, credential.user.name, credential.discoverable
            );
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
            let key =
                SigningKey::from_slice(&record.private_key).map_err(|_| BackendError::Signing)?;
            let signature: Signature = key.sign(message);
            Ok(signature.to_der().as_bytes().to_vec())
        }

        fn confirm(&mut self, request: &Consent<'_>) -> UserAction {
            println!(
                "consent   {:?} rp={} user={:?} verification={}  → approved",
                request.operation, request.rp_id, request.user_name, request.require_verification
            );
            UserAction::Approved { verified: true }
        }
    }

    fn stored(record: &Record) -> StoredCredential {
        StoredCredential {
            credential_id: record.credential_id.clone(),
            user: record.user.clone(),
            discoverable: record.discoverable,
        }
    }
}
