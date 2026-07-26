//! C ABI over `vault-core` for native platform integrations.
//!
//! Consumed by the AutoFill Credential Provider extensions (Swift) on macOS and
//! iOS. Three surfaces, all returning freshly-allocated buffers the caller frees
//! with [`vault_ffi_free`]:
//!
//! * **Passkeys (v1)** — stateless ES256 authenticator ops
//!   (`vault_ffi_passkey_create` / `_assert`). The caller already holds the
//!   private key; see `docs/PASSKEYS.md`.
//! * **Passwords (v2, v3)** — a stateful vault surface (`vault_ffi_vault_open`,
//!   `_vault_open_password` + `_identities` / `_password_for_id` /
//!   `_vault_free`). Swift can't run Argon2id/XChaCha20, so it hands over the
//!   encrypted file bytes (from the shared App Group container) and either the
//!   device key (from the shared keychain) or the master password; the unlocked
//!   vault lives behind an opaque [`VaultHandle`] here.
//! * **Device unlock (v4)** — `vault_ffi_enable_device_unlock` /
//!   `_disable_device_unlock` / `_has_device_unlock`, so a client that opened
//!   with the password can mint its own quick-unlock key. The only surface that
//!   produces a **new vault file**; it still performs no I/O, the bytes come
//!   back for the caller to persist.
//! * **Sync (v5)** — [`mod@sync`]: the pull→merge→push cycle from
//!   [`vault_sync`], so a client can reach the user's encrypted vault in their
//!   own Drive instead of being handed a file. This is the one surface that
//!   **does** perform I/O, and only network I/O: it talks to Google, never to
//!   the filesystem. Merged vault bytes still come back for the caller to
//!   persist.
//!
//! No file or clock access here — [`vault_core`] is I/O-free and this is a thin
//! wrapper over it. Network access is confined to the sync surface.
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
use std::sync::{Arc, Mutex, MutexGuard};

use serde::Serialize;
use vault_core::{host_of, Error, ItemKind, SymmetricKey, Vault, VaultItem, KEY_LEN};

pub mod sync;

/// ABI version. Bump on any breaking change to a signature below.
///
/// v2 adds the stateful passwords surface (`vault_ffi_vault_open`,
/// `vault_ffi_identities`, `vault_ffi_password_for_id`, `vault_ffi_vault_free`)
/// used by the macOS AutoFill credential provider.
///
/// v3 adds `vault_ffi_vault_open_password`, so a client with no device key
/// (a phone on first launch) can open the vault at all. Purely additive.
///
/// v4 adds the device-unlock surface (`vault_ffi_enable_device_unlock`,
/// `vault_ffi_disable_device_unlock`, `vault_ffi_has_device_unlock`), so a
/// client that opened with the master password can mint its own quick-unlock
/// key instead of waiting for some other process to do it. This is the first
/// operation that produces a **new vault file**, though it still writes
/// nothing: the bytes come back for the caller to persist. Purely additive.
///
/// v5 adds the sync surface (see [`mod@sync`]). Purely additive to the C
/// signatures, but it changes two things a client may have relied on, which is
/// why it is a version bump rather than a silent extension:
///
/// * the vault behind a [`VaultHandle`] is now internally synchronized, so
///   calls on one handle from several threads no longer need external locking
///   (the restriction on `vault_ffi_vault_free` is unchanged);
/// * a handle's contents can now change underneath the caller, because a sync
///   merges a peer's items into the very vault the handle exposes.
pub const ABI_VERSION: i32 = 5;

// Return codes.
pub(crate) const OK: i32 = 0;
pub(crate) const ERR_NULL_ARG: i32 = -1;
pub(crate) const ERR_UTF8: i32 = -2;
pub(crate) const ERR_OP_FAILED: i32 = -3;
const ERR_LOCKED: i32 = -4;
const ERR_NOT_FOUND: i32 = -5;
pub(crate) const ERR_PANIC: i32 = -6;
const ERR_DECRYPT: i32 = -7;
const ERR_BAD_KEY_LEN: i32 = -8;
// -9 (ERR_SYNC_FAILED) is defined by the sync surface.

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
pub(crate) unsafe fn emit(buf: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) {
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
pub(crate) unsafe fn cstr<'a>(s: *const c_char) -> Option<&'a str> {
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
///
/// The vault is behind an `Arc<Mutex<_>>` so the sync surface (v5) can hold the
/// *same* vault this handle exposes. Sharing it is the point: a cycle merges a
/// peer's changes into this vault, and the next `vault_ffi_identities` on this
/// handle sees them. The `Arc` also makes [`vault_ffi_sync_new`] outlive its
/// vault handle safely — freeing the handle mid-sync drops one reference, not
/// the vault.
pub struct VaultHandle {
    vault: Arc<Mutex<Vault>>,
}

impl VaultHandle {
    /// A second owner of this handle's vault, for the sync surface. Safe in
    /// itself — the unsafety is in getting a `&VaultHandle` from the caller's
    /// raw pointer, which happens at the entry point.
    fn share_vault(&self) -> Arc<Mutex<Vault>> {
        self.vault.clone()
    }
}

/// Borrow the vault, treating a poisoned lock as a failure rather than
/// recovering from it.
///
/// Poisoning means an earlier call panicked while holding the lock, and
/// `Vault::merge_remote` takes the item list out before putting the merged one
/// back — so a panic mid-merge can leave the vault holding *no items*. The
/// panic guard already turned that into an error code for whoever hit it;
/// silently handing the emptied vault to the next caller is how it would become
/// an empty vault serialized over the user's file, or pushed to their Drive.
fn lock_vault(vault: &Mutex<Vault>) -> Result<MutexGuard<'_, Vault>, i32> {
    vault.lock().map_err(|_| ERR_OP_FAILED)
}

/// One login identity as handed to Swift: metadata only, never a secret.
#[derive(Serialize)]
struct Identity {
    id: String,
    user: String,
    domain: String,
    label: String,
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
            *out_handle = Box::into_raw(Box::new(VaultHandle {
                vault: Arc::new(Mutex::new(vault)),
            }));
            OK
        }
        Err(code) => code,
    }
}

/// Open + unlock a vault from its raw file bytes using the **master password**.
///
/// [`vault_ffi_vault_open`] needs a device key that some *other* process must
/// already have minted into the keychain. A fresh client — a phone on first
/// launch, a recovery tool — has no such key and could otherwise never open the
/// vault at all. This is the entry point that makes the FFI usable on its own.
///
/// `password` is a NUL-terminated UTF-8 C string. Deriving the key runs Argon2id
/// with the parameters stored in the vault header, so this deliberately takes
/// hundreds of milliseconds; call it off the UI thread. Errors: `ERR_DECRYPT`
/// (wrong password or tampered file), `ERR_OP_FAILED` (unrecognized format or
/// non-UTF-8 password).
///
/// # Safety
/// `vault_bytes` must point to a readable buffer of `vault_len`; `password` must
/// be a valid NUL-terminated string; `out_handle` must be a valid writable
/// pointer.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_vault_open_password(
    vault_bytes: *const u8,
    vault_len: usize,
    password: *const c_char,
    out_handle: *mut *mut VaultHandle,
) -> i32 {
    if vault_bytes.is_null() || password.is_null() || out_handle.is_null() {
        return ERR_NULL_ARG;
    }
    *out_handle = std::ptr::null_mut();
    let bytes = slice::from_raw_parts(vault_bytes, vault_len);
    let Some(password) = cstr(password) else {
        return ERR_OP_FAILED;
    };

    let opened = guard_result(|| {
        let mut vault = Vault::from_bytes(bytes)?;
        vault.unlock(password)?;
        Ok(vault)
    });
    match opened {
        Ok(vault) => {
            *out_handle = Box::into_raw(Box::new(VaultHandle {
                vault: Arc::new(Mutex::new(vault)),
            }));
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
        let boxed = Box::from_raw(handle);
        // Poison recovery is right *here* and nowhere else: the vault is being
        // destroyed, so re-sealing an inconsistent one still zeroizes the key
        // and the plaintext items, which is the whole job. Refusing would leave
        // secrets resident until the process exits.
        if let Ok(mut vault) = boxed.vault.lock().or_else(|e| Ok::<_, ()>(e.into_inner())) {
            vault.lock(); // Vault::lock — re-seal + zeroize
        }
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
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match guard_result(|| identities_json(&vault)) {
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
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match guard_result(|| password_for(&vault, id)) {
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

// ===========================================================================
// Device-unlock surface (ABI v4)
//
// Until now the FFI could only *use* a device key some other process had
// minted. On a phone there is no other process, so quick unlock was impossible
// and every AutoFill cost the user their master password and an Argon2id
// derivation. These let a client that opened with the password mint its own.
//
// Still no I/O: `vault-core` is I/O-free and this stays a thin wrapper, so the
// new file bytes come back for the caller to persist. The caller owns the
// atomic write, the backup, and the ordering.
// ===========================================================================

/// Re-serialize the handle's vault, verifying it can be reopened with
/// `check_key` before handing the bytes back.
///
/// Cheap insurance on the only path that produces a replacement vault file: the
/// caller is about to overwrite the user's only copy, so bytes that do not open
/// must never leave this function. `None` skips the device-key check (nothing to
/// check against once device unlock has been removed).
fn reserialize_verified(
    vault: &Vault,
    check_key: Option<&SymmetricKey>,
) -> vault_core::Result<Vec<u8>> {
    let bytes = vault.to_bytes()?;
    let mut probe = Vault::from_bytes(&bytes)?;
    // With no key to check against, parsing IS the check: `disable` only clears
    // a header field, and the master-password wrapped key is untouched either
    // way.
    if let Some(key) = check_key {
        probe.unlock_with_device_key(key)?;
    }
    Ok(bytes)
}

/// Turn on quick unlock. Mints a fresh 32-byte device key, wraps the vault key
/// with it, and returns **both** the key and the new vault file bytes.
///
/// The master password keeps working: this only adds a second wrapping of the
/// same vault key, it does not replace the first.
///
/// SECRET: `*out_device_key` is the quick-unlock key. Put it straight into the
/// platform keychain behind a biometric access control and free it with
/// [`vault_ffi_free`], which zeroes it. Anyone holding it can open the vault
/// without the master password — that is the entire point of it.
///
/// The handle is updated in place, so it now reports `has_device_unlock`. If the
/// caller then fails to persist the bytes, memory and file disagree until the
/// next open; nothing is lost, because the file is simply the older one.
///
/// # Safety
/// `handle` must be valid; all four out-pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_enable_device_unlock(
    handle: *mut VaultHandle,
    out_device_key: *mut *mut u8,
    out_device_key_len: *mut usize,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
) -> i32 {
    if handle.is_null()
        || out_device_key.is_null()
        || out_device_key_len.is_null()
        || out_vault_bytes.is_null()
        || out_vault_bytes_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    // Pre-null both out-pairs so an error path never leaves a caller holding a
    // stale pointer it might free or read.
    *out_device_key = std::ptr::null_mut();
    *out_device_key_len = 0;
    *out_vault_bytes = std::ptr::null_mut();
    *out_vault_bytes_len = 0;

    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if !vault.is_unlocked() {
        return ERR_LOCKED;
    }
    let was_enabled = vault.has_device_unlock();

    let result = guard_result(|| {
        let device = SymmetricKey::generate()?;
        vault.enable_device_unlock(&device)?;
        let bytes = reserialize_verified(&vault, Some(&device))?;
        Ok((device, bytes))
    });
    match result {
        Ok((device, bytes)) => {
            emit(
                device.as_bytes().to_vec(),
                out_device_key,
                out_device_key_len,
            );
            emit(bytes, out_vault_bytes, out_vault_bytes_len);
            OK
        }
        Err(code) => {
            // The header may already carry the new wrapping. If there was
            // nothing there before, putting it back is exact. If quick unlock
            // was already on we cannot restore the OLD blob — `vault-core`
            // exposes no setter for it — so the handle keeps a key that was
            // never persisted. Harmless but stale: free the handle and reopen.
            if !was_enabled {
                vault.disable_device_unlock();
            }
            code
        }
    }
}

/// Turn quick unlock off: drop the device-wrapped key from the header and
/// return the new vault file bytes. The master password is unaffected.
///
/// Deleting the key from the keychain is not enough on its own — the wrapping
/// would stay in the file and travel to every device the vault syncs to.
///
/// # Safety
/// `handle` must be valid; both out-pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_disable_device_unlock(
    handle: *mut VaultHandle,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
) -> i32 {
    if handle.is_null() || out_vault_bytes.is_null() || out_vault_bytes_len.is_null() {
        return ERR_NULL_ARG;
    }
    *out_vault_bytes = std::ptr::null_mut();
    *out_vault_bytes_len = 0;

    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if !vault.is_unlocked() {
        return ERR_LOCKED;
    }

    match guard_result(|| {
        vault.disable_device_unlock();
        reserialize_verified(&vault, None)
    }) {
        Ok(bytes) => {
            emit(bytes, out_vault_bytes, out_vault_bytes_len);
            OK
        }
        Err(code) => code,
    }
}

/// `1` if the vault carries a device-wrapped key, `0` if not, negative on error.
///
/// The keychain can hold a key for a vault that no longer accepts it (restored
/// from a backup, say), so a client that trusts the keychain alone will prompt
/// for a biometric and then fail. Ask the vault.
///
/// # Safety
/// `handle` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_has_device_unlock(handle: *mut VaultHandle) -> i32 {
    if handle.is_null() {
        return ERR_NULL_ARG;
    }
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match catch_unwind(AssertUnwindSafe(|| vault.has_device_unlock())) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => ERR_PANIC,
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

    // Pinned deliberately: clients gate features on this number, so a bump has
    // to be a conscious edit here, not a side effect.
    #[test]
    fn abi_version_is_5() {
        assert_eq!(vault_ffi_abi_version(), 5);
    }

    // ---- device-unlock surface (ABI v4) ---------------------------------

    /// A serialized vault with NO device unlock — what a phone actually starts
    /// from. `sample_vault` already has it enabled, which would only exercise
    /// the re-enrolment path.
    fn password_only_vault() -> Vec<u8> {
        use vault_core::{Item, KdfAlgorithm, KdfParams};
        let params = KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![3u8; KdfParams::SALT_LEN],
        };
        let mut v = Vault::create("pw", params).unwrap();
        v.upsert_item(Item::new(
            VaultItem::Login {
                title: "GitHub".into(),
                username: "frank@sybr.no".into(),
                password: "s3cr3t-pw".into(),
                url: "https://github.com/login".into(),
                totp_secret: None,
                notes: String::new(),
            },
            0,
        ))
        .unwrap();
        v.to_bytes().unwrap()
    }

    fn open_with_password(bytes: &[u8], password: &str) -> *mut VaultHandle {
        let mut handle: *mut VaultHandle = ptr::null_mut();
        let pw = CString::new(password).unwrap();
        let rc = unsafe {
            vault_ffi_vault_open_password(bytes.as_ptr(), bytes.len(), pw.as_ptr(), &mut handle)
        };
        assert_eq!(rc, OK);
        handle
    }

    /// The whole point of v4: a client that only knows the master password can
    /// mint a quick-unlock key, and what comes back actually works.
    #[test]
    fn enabling_device_unlock_yields_a_key_and_a_vault_that_opens_with_it() {
        let original = password_only_vault();
        let handle = open_with_password(&original, "pw");
        assert_eq!(unsafe { vault_ffi_has_device_unlock(handle) }, 0);

        let (mut key, mut key_len) = (ptr::null_mut(), 0usize);
        let (mut bytes, mut bytes_len) = (ptr::null_mut(), 0usize);
        let rc = unsafe {
            vault_ffi_enable_device_unlock(
                handle,
                &mut key,
                &mut key_len,
                &mut bytes,
                &mut bytes_len,
            )
        };
        assert_eq!(rc, OK);
        assert_eq!(key_len, KEY_LEN);
        assert!(bytes_len > 0);
        assert_eq!(unsafe { vault_ffi_has_device_unlock(handle) }, 1);

        let key_bytes = unsafe { slice::from_raw_parts(key, key_len).to_vec() };
        let new_vault = unsafe { slice::from_raw_parts(bytes, bytes_len).to_vec() };
        unsafe {
            vault_ffi_free(key, key_len);
            vault_ffi_free(bytes, bytes_len);
            vault_ffi_vault_free(handle);
        }

        // The returned key opens the returned bytes...
        let mut device_handle: *mut VaultHandle = ptr::null_mut();
        assert_eq!(
            unsafe {
                vault_ffi_vault_open(
                    new_vault.as_ptr(),
                    new_vault.len(),
                    key_bytes.as_ptr(),
                    key_bytes.len(),
                    &mut device_handle,
                )
            },
            OK
        );
        // ...and the vault behind it is whole, not a husk that merely parsed.
        let (mut json, mut json_len) = (ptr::null_mut(), 0usize);
        assert_eq!(
            unsafe { vault_ffi_identities(device_handle, &mut json, &mut json_len) },
            OK
        );
        let listed = unsafe { std::str::from_utf8(slice::from_raw_parts(json, json_len)).unwrap() }
            .to_string();
        assert!(listed.contains("github.com"));
        unsafe {
            vault_ffi_free(json, json_len);
            vault_ffi_vault_free(device_handle);
        }

        // THE property that matters: enabling quick unlock must not cost the
        // user their master password. Locking someone out of their own vault is
        // unrecoverable — there is no reset.
        let still_mine = open_with_password(&new_vault, "pw");
        assert!(!still_mine.is_null());
        unsafe { vault_ffi_vault_free(still_mine) };

        // And a wrong device key is still refused by the new file.
        let mut bad: *mut VaultHandle = ptr::null_mut();
        assert_eq!(
            unsafe {
                vault_ffi_vault_open(
                    new_vault.as_ptr(),
                    new_vault.len(),
                    [9u8; KEY_LEN].as_ptr(),
                    KEY_LEN,
                    &mut bad,
                )
            },
            ERR_DECRYPT
        );
        assert!(bad.is_null());
    }

    /// Turning it off has to strip the wrapping from the FILE. Deleting the
    /// keychain item alone would leave the wrapped key in the vault, where it
    /// travels to every device the vault syncs to.
    #[test]
    fn disabling_device_unlock_revokes_the_key_in_the_file() {
        let (original, device_key, _id) = sample_vault();
        let handle = open_with_password(&original, "pw");
        assert_eq!(unsafe { vault_ffi_has_device_unlock(handle) }, 1);

        let (mut bytes, mut bytes_len) = (ptr::null_mut(), 0usize);
        let rc = unsafe { vault_ffi_disable_device_unlock(handle, &mut bytes, &mut bytes_len) };
        assert_eq!(rc, OK);
        assert_eq!(unsafe { vault_ffi_has_device_unlock(handle) }, 0);
        let new_vault = unsafe { slice::from_raw_parts(bytes, bytes_len).to_vec() };
        unsafe {
            vault_ffi_free(bytes, bytes_len);
            vault_ffi_vault_free(handle);
        }

        // The key that used to work no longer does.
        let mut revoked: *mut VaultHandle = ptr::null_mut();
        assert_eq!(
            unsafe {
                vault_ffi_vault_open(
                    new_vault.as_ptr(),
                    new_vault.len(),
                    device_key.as_ptr(),
                    device_key.len(),
                    &mut revoked,
                )
            },
            ERR_DECRYPT
        );
        assert!(revoked.is_null());

        // The master password still does.
        let still_mine = open_with_password(&new_vault, "pw");
        assert!(!still_mine.is_null());
        unsafe { vault_ffi_vault_free(still_mine) };
    }

    /// Re-enrolling replaces the key rather than adding a second one, so a
    /// device key that leaked can be rotated away.
    #[test]
    fn re_enrolling_invalidates_the_previous_device_key() {
        let (original, old_key, _id) = sample_vault();
        let handle = open_with_password(&original, "pw");

        let (mut key, mut key_len) = (ptr::null_mut(), 0usize);
        let (mut bytes, mut bytes_len) = (ptr::null_mut(), 0usize);
        assert_eq!(
            unsafe {
                vault_ffi_enable_device_unlock(
                    handle,
                    &mut key,
                    &mut key_len,
                    &mut bytes,
                    &mut bytes_len,
                )
            },
            OK
        );
        let new_key = unsafe { slice::from_raw_parts(key, key_len).to_vec() };
        let new_vault = unsafe { slice::from_raw_parts(bytes, bytes_len).to_vec() };
        assert_ne!(new_key.as_slice(), old_key.as_slice());
        unsafe {
            vault_ffi_free(key, key_len);
            vault_ffi_free(bytes, bytes_len);
            vault_ffi_vault_free(handle);
        }

        let mut stale: *mut VaultHandle = ptr::null_mut();
        assert_eq!(
            unsafe {
                vault_ffi_vault_open(
                    new_vault.as_ptr(),
                    new_vault.len(),
                    old_key.as_ptr(),
                    old_key.len(),
                    &mut stale,
                )
            },
            ERR_DECRYPT
        );
        assert!(stale.is_null());
    }

    #[test]
    fn device_unlock_rejects_null_arguments_without_dereferencing_them() {
        let (mut a, mut al) = (ptr::null_mut(), 0usize);
        assert_eq!(
            unsafe {
                vault_ffi_enable_device_unlock(ptr::null_mut(), &mut a, &mut al, &mut a, &mut al)
            },
            ERR_NULL_ARG
        );
        assert_eq!(
            unsafe { vault_ffi_disable_device_unlock(ptr::null_mut(), &mut a, &mut al) },
            ERR_NULL_ARG
        );
        assert_eq!(
            unsafe { vault_ffi_has_device_unlock(ptr::null_mut()) },
            ERR_NULL_ARG
        );

        // A valid handle with null out-pointers must also be refused, not
        // written through.
        let bytes = password_only_vault();
        let handle = open_with_password(&bytes, "pw");
        assert_eq!(
            unsafe {
                vault_ffi_enable_device_unlock(
                    handle,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            },
            ERR_NULL_ARG
        );
        // Refused cleanly: the vault is untouched, so a retry still works.
        assert_eq!(unsafe { vault_ffi_has_device_unlock(handle) }, 0);
        unsafe { vault_ffi_vault_free(handle) };
    }

    /// include/vault_ffi.h is the contract Swift compiles against, and it is
    /// maintained by hand — it sat claiming "ABI version 2" for a v3 library,
    /// which is exactly the drift a client checking the version would trust.
    #[test]
    fn the_header_names_the_abi_it_documents() {
        let header = include_str!("../include/vault_ffi.h");
        let expected = format!("ABI version {ABI_VERSION}");
        assert!(
            header.contains(&expected),
            "vault_ffi.h does not say {expected:?} — bump it with ABI_VERSION"
        );
    }

    /// The other half of the same promise: an export with no declaration is
    /// invisible to Swift until someone notices, and adding one is precisely
    /// when this file is easy to forget.
    #[test]
    fn every_export_is_declared_in_the_header() {
        let header = include_str!("../include/vault_ffi.h");
        let mut checked = 0;
        // Both files: the sync surface lives in sync.rs, and a scan that only
        // read lib.rs would quietly stop covering the newest exports — which is
        // the exact moment this check earns its keep.
        let sources = [include_str!("lib.rs"), include_str!("sync.rs")];
        for line in sources.iter().flat_map(|src| src.lines()) {
            let line = line.trim();
            let Some(rest) = line
                .strip_prefix("pub extern \"C\" fn ")
                .or_else(|| line.strip_prefix("pub unsafe extern \"C\" fn "))
            else {
                continue;
            };
            let name = rest.split('(').next().unwrap_or_default();
            // Look for an actual declaration line, not the name anywhere: a
            // bare `contains(name)` matches a prose mention in the header's
            // comments, and matches `<name>X` too, so a renamed export would
            // sail past.
            let declared = header.lines().any(|l| {
                let l = l.trim_start();
                (l.starts_with("int32_t ") || l.starts_with("void "))
                    && l.contains(&format!(" {name}("))
            });
            assert!(
                declared,
                "{name} is exported but not declared in include/vault_ffi.h"
            );
            checked += 1;
        }
        // Guard against the scan silently matching nothing (a formatting change
        // that splits the signature across lines would do it).
        assert!(checked >= 17, "only found {checked} exports to check");
    }

    // A client with no device key (a phone on first launch) must still be able
    // to open the vault. Without this the FFI is unusable on its own: every
    // caller would depend on some other process having minted a device key
    // into the keychain first.
    #[test]
    fn opens_with_the_master_password_and_rejects_a_wrong_one() {
        let (bytes, _device, id) = sample_vault();

        let mut handle: *mut VaultHandle = std::ptr::null_mut();
        let pw = std::ffi::CString::new("pw").unwrap();
        let rc = unsafe {
            vault_ffi_vault_open_password(bytes.as_ptr(), bytes.len(), pw.as_ptr(), &mut handle)
        };
        assert_eq!(rc, OK);
        assert!(!handle.is_null());

        // The handle is fully usable, not a half-open shell.
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut len = 0usize;
        let cid = std::ffi::CString::new(id).unwrap();
        assert_eq!(
            unsafe { vault_ffi_password_for_id(handle, cid.as_ptr(), &mut out, &mut len) },
            OK
        );
        unsafe { vault_ffi_free(out, len) };
        unsafe { vault_ffi_vault_free(handle) };

        // A wrong password must fail closed, and leave no handle behind.
        let mut bad_handle: *mut VaultHandle = std::ptr::null_mut();
        let bad = std::ffi::CString::new("not-the-password").unwrap();
        let rc = unsafe {
            vault_ffi_vault_open_password(
                bytes.as_ptr(),
                bytes.len(),
                bad.as_ptr(),
                &mut bad_handle,
            )
        };
        assert_eq!(rc, ERR_DECRYPT);
        assert!(bad_handle.is_null(), "no handle on the error path");

        // Null arguments are rejected, not dereferenced.
        let mut h: *mut VaultHandle = std::ptr::null_mut();
        assert_eq!(
            unsafe { vault_ffi_vault_open_password(std::ptr::null(), 0, pw.as_ptr(), &mut h) },
            ERR_NULL_ARG
        );
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
