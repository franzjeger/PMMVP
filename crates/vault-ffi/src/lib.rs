//! C ABI over `vault-core` for native platform integrations.
//!
//! Consumed by the macOS AutoFill Credential Provider extension (Swift). Two
//! surfaces, both returning freshly-allocated buffers the caller frees with
//! [`vault_ffi_free`]:
//!
//! * **Passkeys (v1)** — stateless ES256 authenticator ops
//!   (`vault_ffi_passkey_create` / `_assert`). The caller already holds the
//!   private key; see `docs/PASSKEYS.md`.
//! * **Passwords (v2)** — a stateful vault surface (`vault_ffi_vault_open` +
//!   `_identities` / `_password_for_id` / `_vault_free`). Swift can't run
//!   Argon2id/XChaCha20, so it hands over the encrypted file bytes (from the
//!   shared App Group container) and the device key (from the shared keychain);
//!   the unlocked vault lives behind an opaque [`VaultHandle`] here.
//!
//! Every entry point is wrapped so a panic becomes an error code instead of
//! unwinding across the C boundary.
//!
//! SECURITY: returned buffers may contain secrets (a passkey private key, or a
//! password). The caller must copy them into the platform credential / encrypted
//! vault and free them promptly; [`vault_ffi_free`] zeroes them. Error codes
//! never leak key material or plaintext.

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use serde::Serialize;
use vault_core::{Error, ItemKind, SymmetricKey, Vault, VaultItem, KEY_LEN};

/// ABI version. Bump on any breaking change to a signature below.
///
/// v2 adds the stateful passwords surface (`vault_ffi_vault_open`,
/// `vault_ffi_identities`, `vault_ffi_password_for_id`, `vault_ffi_vault_free`)
/// used by the macOS AutoFill credential provider.
pub const ABI_VERSION: i32 = 2;

// Return codes.
const OK: i32 = 0;
const ERR_NULL_ARG: i32 = -1;
const ERR_UTF8: i32 = -2;
const ERR_OP_FAILED: i32 = -3;
const ERR_LOCKED: i32 = -4;
const ERR_NOT_FOUND: i32 = -5;
const ERR_PANIC: i32 = -6;
const ERR_DECRYPT: i32 = -7;
const ERR_BAD_KEY_LEN: i32 = -8;

/// Map a core error to a stable return code (never leaks detail).
fn err_code(e: &Error) -> i32 {
    match e {
        Error::Locked => ERR_LOCKED,
        Error::NotFound => ERR_NOT_FOUND,
        Error::Decryption => ERR_DECRYPT,
        _ => ERR_OP_FAILED,
    }
}

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
    // An empty result would otherwise hand back a non-null dangling pointer
    // (Box::as_mut_ptr of a zero-length slice), which a caller keying off
    // `ptr != null` could dereference. Return an unambiguous (null, 0) instead.
    if buf.is_empty() {
        *out_ptr = std::ptr::null_mut();
        *out_len = 0;
        return;
    }
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
    match catch_unwind(|| vault_core::passkey::create(rp_id, user_verified)) {
        Ok(Ok(pk)) => {
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
        Ok(Err(_)) => ERR_OP_FAILED,
        Err(_) => ERR_PANIC,
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
    match catch_unwind(|| vault_core::passkey::assert(key, rp_id, hash, user_verified)) {
        Ok(Ok((auth_data, sig))) => {
            emit(
                auth_data,
                out_authenticator_data,
                out_authenticator_data_len,
            );
            emit(sig, out_signature, out_signature_len);
            OK
        }
        Ok(Err(_)) => ERR_OP_FAILED,
        Err(_) => ERR_PANIC,
    }
}

// ===========================================================================
// Passwords surface (ABI v2) — for the macOS AutoFill credential provider.
//
// Vault open/unlock happens here (Swift can't do Argon2id/XChaCha20). Swift
// reads the encrypted vault file from the shared App Group container and a
// device key from the shared keychain, passes both in, and gets back login
// identities (metadata) and, on selection, a single password.
// ===========================================================================

/// Opaque handle to an unlocked vault. Created by [`vault_ffi_vault_open`],
/// released (locked + zeroized) by [`vault_ffi_vault_free`].
pub struct VaultHandle {
    vault: Vault,
}

/// One login identity as handed to Swift: metadata only, never a secret.
#[derive(Serialize)]
struct Identity {
    id: String,
    user: String,
    domain: String,
    label: String,
}

/// Bare host of a URL for domain matching: scheme, path, query, userinfo and
/// port stripped, a leading "www." and a trailing "." removed, lowercased. IPv6
/// literals in brackets keep their inner colons.
///
/// This domain is the anti-phishing match key, so it MUST agree with how a
/// browser resolves the host. Browsers strip ASCII tab/newline from a URL and
/// treat backslashes as forward slashes before parsing; we do the same first,
/// otherwise a crafted stored URL like `https://good.com\@evil.com` (which a
/// browser navigates to good.com) would be read here as host `evil.com`.
fn host_of(url: &str) -> String {
    let normalized: String = url
        .chars()
        .filter(|&c| c != '\t' && c != '\n' && c != '\r')
        .map(|c| if c == '\\' { '/' } else { c })
        .collect();
    let s = normalized.trim();
    let after_scheme = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map(|(inner, _)| inner).unwrap_or(rest)
    } else {
        host.split_once(':').map(|(h, _)| h).unwrap_or(host)
    };
    let host = host.trim_end_matches('.');
    host.strip_prefix("www.")
        .unwrap_or(host)
        .to_ascii_lowercase()
}

/// Build the JSON identity array from the unlocked vault's active logins.
fn identities_json(vault: &Vault) -> vault_core::Result<String> {
    let ids: Vec<Identity> = vault
        .list_items(false)?
        .into_iter()
        .filter(|s| s.kind == ItemKind::Login)
        .map(|s| Identity {
            id: s.id.to_string(),
            user: s.subtitle,
            domain: host_of(&s.url),
            label: s.title,
        })
        .collect();
    serde_json::to_string(&ids).map_err(|_| Error::Serialization)
}

/// Fetch the password bytes for a login item by its id string.
fn password_for(vault: &Vault, id_str: &str) -> vault_core::Result<Vec<u8>> {
    let id = uuid::Uuid::parse_str(id_str).map_err(|_| Error::NotFound)?;
    match &vault.get_item(id)?.data {
        VaultItem::Login { password, .. } => Ok(password.as_bytes().to_vec()),
        _ => Err(Error::NotFound),
    }
}

/// Open + unlock a vault from its raw file bytes using a device key (the 32-byte
/// quick-unlock key from the shared keychain). On `OK`, `*out_handle` is a handle
/// to free with [`vault_ffi_vault_free`]. Errors: `ERR_BAD_KEY_LEN` (wrong key
/// size), `ERR_DECRYPT` (wrong key / not a device-unlock vault / tampered),
/// `ERR_OP_FAILED` (unrecognized format).
///
/// # Safety
/// `vault_bytes`/`device_key` must point to readable buffers of the given
/// lengths; `out_handle` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_vault_open(
    vault_bytes: *const u8,
    vault_len: usize,
    device_key: *const u8,
    device_key_len: usize,
    out_handle: *mut *mut VaultHandle,
) -> i32 {
    if vault_bytes.is_null() || device_key.is_null() || out_handle.is_null() {
        return ERR_NULL_ARG;
    }
    // Pre-null the out-handle so a caller that inspects it without checking the
    // return code never sees a stale/uninitialized pointer on an error path.
    *out_handle = std::ptr::null_mut();
    if device_key_len != KEY_LEN {
        return ERR_BAD_KEY_LEN;
    }
    let bytes = slice::from_raw_parts(vault_bytes, vault_len);
    let mut key_arr = zeroize::Zeroizing::new([0u8; KEY_LEN]);
    key_arr.copy_from_slice(slice::from_raw_parts(device_key, device_key_len));
    let device = SymmetricKey::from_bytes(*key_arr);

    let opened = guard_result(|| {
        let mut vault = Vault::from_bytes(bytes)?;
        vault.unlock_with_device_key(&device)?;
        Ok(vault)
    });
    match opened {
        Ok(vault) => {
            *out_handle = Box::into_raw(Box::new(VaultHandle { vault }));
            OK
        }
        Err(code) => code,
    }
}

/// Lock + free a handle (zeroizes the vault key and all decrypted items).
/// Passing null is a no-op.
///
/// # Safety
/// `handle` must be a handle from [`vault_ffi_vault_open`] (or null), freed once.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_vault_free(handle: *mut VaultHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let mut boxed = Box::from_raw(handle);
        boxed.vault.lock(); // re-seal + zeroize before drop
        drop(boxed);
    }));
}

/// All login identities as a UTF-8 JSON array (metadata only, never a secret):
/// `[{"id","user","domain","label"}, ...]`. On `OK`, `*out_json` is a buffer to
/// free with [`vault_ffi_free`].
///
/// # Safety
/// `handle` must be valid; `out_json`/`out_json_len` writable pointers.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_identities(
    handle: *mut VaultHandle,
    out_json: *mut *mut u8,
    out_json_len: *mut usize,
) -> i32 {
    if handle.is_null() || out_json.is_null() || out_json_len.is_null() {
        return ERR_NULL_ARG;
    }
    let vault = &(*handle).vault;
    match guard_result(|| identities_json(vault)) {
        Ok(json) => {
            emit(json.into_bytes(), out_json, out_json_len);
            OK
        }
        Err(code) => code,
    }
}

/// The password for one identity id (the `id` from [`vault_ffi_identities`]).
/// SECRET: the returned buffer is zeroized by [`vault_ffi_free`]; the caller must
/// copy it into the platform credential and not retain it. `ERR_NOT_FOUND` if the
/// id is unknown or not a login.
///
/// # Safety
/// `handle` valid; `id_utf8` a NUL-terminated C string; out pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_password_for_id(
    handle: *mut VaultHandle,
    id_utf8: *const c_char,
    out_password: *mut *mut u8,
    out_password_len: *mut usize,
) -> i32 {
    if handle.is_null() || out_password.is_null() || out_password_len.is_null() {
        return ERR_NULL_ARG;
    }
    let Some(id) = cstr(id_utf8) else {
        return ERR_UTF8;
    };
    let vault = &(*handle).vault;
    match guard_result(|| password_for(vault, id)) {
        Ok(pw) => {
            emit(pw, out_password, out_password_len);
            OK
        }
        Err(code) => code,
    }
}

/// Run a fallible closure inside a panic guard, flattening the core error to a
/// return code. `Ok(value)` on success, `Err(code)` on error or panic.
fn guard_result<T>(f: impl FnOnce() -> vault_core::Result<T>) -> Result<T, i32> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(err_code(&e)),
        Err(_) => Err(ERR_PANIC),
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

    // ---- passwords surface (ABI v2) -------------------------------------

    /// A serialized device-unlock vault holding one login, plus the raw device
    /// key and the login's id string.
    fn sample_vault() -> (Vec<u8>, [u8; KEY_LEN], String) {
        use vault_core::{Item, KdfAlgorithm, KdfParams};
        let params = KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![7u8; KdfParams::SALT_LEN],
        };
        let mut v = Vault::create("pw", params).unwrap();
        let device = SymmetricKey::generate().unwrap();
        v.enable_device_unlock(&device).unwrap();
        let item = Item::new(
            VaultItem::Login {
                title: "GitHub".into(),
                username: "frank@sybr.no".into(),
                password: "s3cr3t-pw".into(),
                url: "https://github.com/login".into(),
                totp_secret: None,
                notes: String::new(),
            },
            0,
        );
        let id = item.id.to_string();
        v.upsert_item(item).unwrap();
        (v.to_bytes().unwrap(), *device.as_bytes(), id)
    }

    #[test]
    fn abi_version_is_2() {
        assert_eq!(vault_ffi_abi_version(), 2);
    }

    #[test]
    fn host_of_extracts_the_matchable_domain() {
        assert_eq!(host_of("https://www.github.com/login"), "github.com");
        assert_eq!(host_of("http://example.com:8080/x"), "example.com");
        assert_eq!(
            host_of("https://user:pass@sub.example.com/y"),
            "sub.example.com"
        );
        assert_eq!(host_of("https://[fd00::1]:8443/z"), "fd00::1");
        assert_eq!(host_of("bareword"), "bareword");
    }

    #[test]
    fn host_of_matches_browser_normalization() {
        // Backslash is treated as a path separator by browsers, so the host is
        // good.com, NOT evil.com — otherwise a good.com credential could be
        // offered on evil.com.
        assert_eq!(host_of(r"https://good.com\@evil.com"), "good.com");
        assert_eq!(host_of("https://good.com\t/login"), "good.com");
        assert_eq!(host_of("https://good.com\n"), "good.com");
        // Trailing-dot FQDN and case normalize so matching doesn't fail-closed.
        assert_eq!(host_of("https://Good.COM./x"), "good.com");
    }

    #[test]
    fn open_list_fetch_free_round_trip() {
        let (bytes, key, id) = sample_vault();

        let mut handle: *mut VaultHandle = ptr::null_mut();
        let rc = unsafe {
            vault_ffi_vault_open(
                bytes.as_ptr(),
                bytes.len(),
                key.as_ptr(),
                key.len(),
                &mut handle,
            )
        };
        assert_eq!(rc, OK);
        assert!(!handle.is_null());

        // identities: metadata only, no password.
        let (mut json, mut json_len) = (ptr::null_mut(), 0usize);
        assert_eq!(
            unsafe { vault_ffi_identities(handle, &mut json, &mut json_len) },
            OK
        );
        let json_str =
            unsafe { std::str::from_utf8(slice::from_raw_parts(json, json_len)).unwrap() };
        assert!(json_str.contains("\"user\":\"frank@sybr.no\""));
        assert!(json_str.contains("\"domain\":\"github.com\""));
        assert!(json_str.contains(&format!("\"id\":\"{id}\"")));
        assert!(!json_str.contains("s3cr3t-pw"));
        unsafe { vault_ffi_free(json, json_len) };

        // password for that id.
        let cid = CString::new(id).unwrap();
        let (mut pw, mut pw_len) = (ptr::null_mut(), 0usize);
        assert_eq!(
            unsafe { vault_ffi_password_for_id(handle, cid.as_ptr(), &mut pw, &mut pw_len) },
            OK
        );
        assert_eq!(unsafe { slice::from_raw_parts(pw, pw_len) }, b"s3cr3t-pw");
        unsafe { vault_ffi_free(pw, pw_len) };

        unsafe { vault_ffi_vault_free(handle) };
    }

    #[test]
    fn wrong_device_key_refuses_without_leaking() {
        let (bytes, _key, _id) = sample_vault();
        let bad = [9u8; KEY_LEN];
        let mut handle: *mut VaultHandle = ptr::null_mut();
        let rc = unsafe {
            vault_ffi_vault_open(
                bytes.as_ptr(),
                bytes.len(),
                bad.as_ptr(),
                bad.len(),
                &mut handle,
            )
        };
        assert_eq!(rc, ERR_DECRYPT);
        assert!(handle.is_null());
    }

    #[test]
    fn bad_key_length_is_rejected() {
        let (bytes, _key, _id) = sample_vault();
        let short = [0u8; 16];
        let mut handle: *mut VaultHandle = ptr::null_mut();
        let rc = unsafe {
            vault_ffi_vault_open(
                bytes.as_ptr(),
                bytes.len(),
                short.as_ptr(),
                short.len(),
                &mut handle,
            )
        };
        assert_eq!(rc, ERR_BAD_KEY_LEN);
        assert!(handle.is_null());
    }

    #[test]
    fn unknown_id_is_not_found() {
        let (bytes, key, _id) = sample_vault();
        let mut handle: *mut VaultHandle = ptr::null_mut();
        unsafe {
            vault_ffi_vault_open(
                bytes.as_ptr(),
                bytes.len(),
                key.as_ptr(),
                key.len(),
                &mut handle,
            );
        }
        let other = CString::new(uuid::Uuid::from_bytes([1; 16]).to_string()).unwrap();
        let (mut pw, mut pw_len) = (ptr::null_mut(), 0usize);
        let rc = unsafe { vault_ffi_password_for_id(handle, other.as_ptr(), &mut pw, &mut pw_len) };
        assert_eq!(rc, ERR_NOT_FOUND);
        unsafe { vault_ffi_vault_free(handle) };
    }

    #[test]
    fn null_handle_and_free_are_safe() {
        let (mut j, mut jl) = (ptr::null_mut(), 0usize);
        assert_eq!(
            unsafe { vault_ffi_identities(ptr::null_mut(), &mut j, &mut jl) },
            ERR_NULL_ARG
        );
        unsafe { vault_ffi_vault_free(ptr::null_mut()) }; // no-op, no crash
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
