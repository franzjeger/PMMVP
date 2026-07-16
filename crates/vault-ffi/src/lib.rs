//! C ABI over `vault-core` for native platform integrations.
//!
//! Consumed by the macOS AutoFill Credential Provider extension (Swift), which
//! drives the WebAuthn ceremony and calls these functions to do the ES256
//! authenticator work. Kept intentionally small and stateless: every function
//! takes explicit inputs and returns freshly-allocated output buffers that the
//! caller frees with [`vault_ffi_free`]. Vault open/unlock is handled on the
//! Swift side (App Group container + OS-keychain device key) and is out of
//! scope for this pure-crypto surface — see `docs/PASSKEYS.md`.
//!
//! SECURITY: buffers returned here may contain a credential private key
//! (`vault_ffi_passkey_create`). The caller must store it in the encrypted
//! vault and free it promptly; this crate zeroes returned buffers on
//! [`vault_ffi_free`].

use std::os::raw::c_char;
use std::slice;

/// ABI version. Bump on any breaking change to a signature below.
pub const ABI_VERSION: i32 = 1;

// Return codes.
const OK: i32 = 0;
const ERR_NULL_ARG: i32 = -1;
const ERR_UTF8: i32 = -2;
const ERR_OP_FAILED: i32 = -3;

#[no_mangle]
pub extern "C" fn vault_ffi_abi_version() -> i32 {
    ABI_VERSION
}

/// Move a `Vec<u8>` into a caller-owned buffer via the out-pointers. The caller
/// must release it with [`vault_ffi_free`].
///
/// # Safety
/// `out_ptr` and `out_len` must be valid, writable pointers.
unsafe fn emit(buf: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) {
    let mut boxed = buf.into_boxed_slice();
    *out_len = boxed.len();
    *out_ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
}

/// Free a buffer returned by this library, zeroing it first.
///
/// # Safety
/// `ptr`/`len` must be a pair previously produced by this library (or `ptr`
/// null). Passing any other pointer is undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let mut boxed = Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len));
    for b in boxed.iter_mut() {
        *b = 0;
    }
    drop(boxed);
}

/// Read a NUL-terminated UTF-8 C string into a `&str`.
///
/// # Safety
/// `s` must be a valid NUL-terminated C string or null.
unsafe fn cstr<'a>(s: *const c_char) -> Option<&'a str> {
    if s.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(s).to_str().ok()
}

/// Create a new passkey for `rp_id`. On `OK`, the three out-pairs are heap
/// buffers to free with [`vault_ffi_free`]: the credential id, the P-256 private
/// key (SEC1, 32 bytes — store it encrypted!), and the CBOR attestation object.
///
/// # Safety
/// All pointers must be valid; `rp_id` a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_passkey_create(
    rp_id: *const c_char,
    user_verified: bool,
    out_credential_id: *mut *mut u8,
    out_credential_id_len: *mut usize,
    out_private_key: *mut *mut u8,
    out_private_key_len: *mut usize,
    out_attestation_object: *mut *mut u8,
    out_attestation_object_len: *mut usize,
) -> i32 {
    if out_credential_id.is_null()
        || out_credential_id_len.is_null()
        || out_private_key.is_null()
        || out_private_key_len.is_null()
        || out_attestation_object.is_null()
        || out_attestation_object_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    let Some(rp_id) = cstr(rp_id) else {
        return ERR_UTF8;
    };
    match vault_core::passkey::create(rp_id, user_verified) {
        Ok(pk) => {
            emit(pk.credential_id, out_credential_id, out_credential_id_len);
            emit(
                pk.private_key.to_vec(),
                out_private_key,
                out_private_key_len,
            );
            emit(
                pk.attestation_object,
                out_attestation_object,
                out_attestation_object_len,
            );
            OK
        }
        Err(_) => ERR_OP_FAILED,
    }
}

/// Produce an assertion. On `OK`, the two out-pairs are heap buffers to free:
/// `authenticatorData` and the DER ES256 signature. The signature counter is
/// always 0 (synced credential), so there is nothing to persist.
///
/// # Safety
/// All pointers must be valid; slices described by (ptr, len) must be readable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn vault_ffi_passkey_assert(
    private_key: *const u8,
    private_key_len: usize,
    rp_id: *const c_char,
    user_verified: bool,
    client_data_hash: *const u8,
    client_data_hash_len: usize,
    out_authenticator_data: *mut *mut u8,
    out_authenticator_data_len: *mut usize,
    out_signature: *mut *mut u8,
    out_signature_len: *mut usize,
) -> i32 {
    if private_key.is_null()
        || client_data_hash.is_null()
        || out_authenticator_data.is_null()
        || out_authenticator_data_len.is_null()
        || out_signature.is_null()
        || out_signature_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    let Some(rp_id) = cstr(rp_id) else {
        return ERR_UTF8;
    };
    let key = slice::from_raw_parts(private_key, private_key_len);
    let hash = slice::from_raw_parts(client_data_hash, client_data_hash_len);
    match vault_core::passkey::assert(key, rp_id, hash, user_verified) {
        Ok((auth_data, sig)) => {
            emit(
                auth_data,
                out_authenticator_data,
                out_authenticator_data_len,
            );
            emit(sig, out_signature, out_signature_len);
            OK
        }
        Err(_) => ERR_OP_FAILED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    /// Drive create → assert entirely through the C ABI and verify the
    /// signature with vault-core, exercising the exact bytes Swift will get.
    #[test]
    fn ffi_create_then_assert_round_trips() {
        assert_eq!(vault_ffi_abi_version(), ABI_VERSION);
        let rp = CString::new("github.com").unwrap();

        let (mut cid, mut cid_len) = (ptr::null_mut(), 0usize);
        let (mut pk, mut pk_len) = (ptr::null_mut(), 0usize);
        let (mut att, mut att_len) = (ptr::null_mut(), 0usize);
        let rc = unsafe {
            vault_ffi_passkey_create(
                rp.as_ptr(),
                true,
                &mut cid,
                &mut cid_len,
                &mut pk,
                &mut pk_len,
                &mut att,
                &mut att_len,
            )
        };
        assert_eq!(rc, OK);
        assert_eq!(pk_len, 32);
        assert!(cid_len == 16 && att_len > 0);

        let private_key = unsafe { slice::from_raw_parts(pk, pk_len).to_vec() };
        let hash = [7u8; 32];
        let (mut ad, mut ad_len) = (ptr::null_mut(), 0usize);
        let (mut sig, mut sig_len) = (ptr::null_mut(), 0usize);
        let rc = unsafe {
            vault_ffi_passkey_assert(
                private_key.as_ptr(),
                private_key.len(),
                rp.as_ptr(),
                true,
                hash.as_ptr(),
                hash.len(),
                &mut ad,
                &mut ad_len,
                &mut sig,
                &mut sig_len,
            )
        };
        assert_eq!(rc, OK);

        // The signature the FFI produced verifies against the credential.
        let auth_data = unsafe { slice::from_raw_parts(ad, ad_len).to_vec() };
        let signature = unsafe { slice::from_raw_parts(sig, sig_len).to_vec() };
        let mut signed = auth_data;
        signed.extend_from_slice(&hash);
        use p256_check::verify;
        assert!(verify(&private_key, &signed, &signature));

        unsafe {
            vault_ffi_free(cid, cid_len);
            vault_ffi_free(pk, pk_len);
            vault_ffi_free(att, att_len);
            vault_ffi_free(ad, ad_len);
            vault_ffi_free(sig, sig_len);
        }
    }

    #[test]
    fn null_and_bad_utf8_are_errors_not_crashes() {
        let mut a = ptr::null_mut();
        let mut al = 0usize;
        // Null rp_id -> UTF8/null error, no panic.
        let rc = unsafe {
            vault_ffi_passkey_create(
                ptr::null(),
                true,
                &mut a,
                &mut al,
                &mut a,
                &mut al,
                &mut a,
                &mut al,
            )
        };
        assert!(rc < 0);
        // Freeing null is a no-op.
        unsafe { vault_ffi_free(ptr::null_mut(), 0) };
    }

    /// Tiny verifier so the test asserts real cryptographic validity of the
    /// FFI output, using vault-core's public-key derivation.
    mod p256_check {
        pub fn verify(private_key: &[u8], msg: &[u8], der_sig: &[u8]) -> bool {
            let Ok(pub_sec1) = vault_core::passkey::public_key_sec1(private_key) else {
                return false;
            };
            // Re-verify via vault-core by re-deriving; a mismatch means invalid.
            // vault-core has no public verify fn, so re-sign a fresh assertion
            // is not equal; instead we trust the sec1 derivation + p256 here.
            use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let Ok(vk) = VerifyingKey::from_sec1_bytes(&pub_sec1) else {
                return false;
            };
            let Ok(sig) = Signature::from_der(der_sig) else {
                return false;
            };
            vk.verify(msg, &sig).is_ok()
        }
    }
}
