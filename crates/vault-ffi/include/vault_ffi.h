/* vault-ffi — C ABI over vault-core for native platform integrations.
 *
 * Hand-maintained to match crates/vault-ffi/src/lib.rs (ABI version 2). All
 * out-buffers are heap-allocated by the library and must be released with
 * vault_ffi_free(ptr, len), which also zeroes them.
 *
 * Return codes:
 *    0  OK
 *   -1  null argument
 *   -2  invalid UTF-8 in a C string argument
 *   -3  operation failed (unrecognized format / generic)
 *   -4  vault is locked
 *   -5  item not found
 *   -6  a panic was caught at the boundary
 *   -7  decryption failed (wrong key / not a device-unlock vault / tampered)
 *   -8  device key was not 32 bytes
 */
#ifndef VAULT_FFI_H
#define VAULT_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t vault_ffi_abi_version(void);

void vault_ffi_free(uint8_t *ptr, size_t len);

/* ---- Passwords surface (ABI v2) ----------------------------------------
 *
 * Opaque handle to an unlocked vault. Vault open/unlock is done here because
 * Swift can't run Argon2id/XChaCha20; Swift supplies the encrypted file bytes
 * (read from the shared App Group container) and the 32-byte device key (from
 * the shared keychain).
 *
 * OWNERSHIP / THREADING: a VaultHandle is NOT internally synchronized. Multiple
 * read calls (vault_ffi_identities / vault_ffi_password_for_id) on one handle
 * from different threads are fine, but vault_ffi_vault_free must NOT overlap any
 * other call on the same handle, and must be called exactly once. While the
 * handle is open the decrypted vault (passwords included) is resident in memory,
 * so open, fetch the one password you need, and free the handle promptly. */
typedef struct VaultHandle VaultHandle;

/* Open + unlock a vault from its raw file bytes with a 32-byte device key.
 * On OK, *out_handle is a handle to release with vault_ffi_vault_free. */
int32_t vault_ffi_vault_open(const uint8_t *vault_bytes, size_t vault_len,
                             const uint8_t *device_key, size_t device_key_len,
                             VaultHandle **out_handle);

/* Lock + free a handle (zeroizes the vault key and all decrypted items).
 * Null-safe. */
void vault_ffi_vault_free(VaultHandle *handle);

/* All login identities as UTF-8 JSON, METADATA ONLY (never a secret):
 *   [ {"id":"<uuid>","user":"<username>","domain":"<host>","label":"<title>"} ]
 * Out-buffer freed by the caller with vault_ffi_free. */
int32_t vault_ffi_identities(VaultHandle *handle, uint8_t **out_json,
                             size_t *out_json_len);

/* The password for one identity id (the "id" from vault_ffi_identities).
 * SECRET: the buffer is zeroed by vault_ffi_free; copy it into the platform
 * credential and do not retain it. -5 (not found) for an unknown id. */
int32_t vault_ffi_password_for_id(VaultHandle *handle, const char *id_utf8,
                                  uint8_t **out_password,
                                  size_t *out_password_len);

/* Create a passkey for rp_id. Out-pairs (freed by the caller):
 *   credential_id, private_key (SEC1 P-256, 32 bytes — store encrypted!),
 *   attestation_object (CBOR, fmt "none"). */
int32_t vault_ffi_passkey_create(const char *rp_id, bool user_verified,
                                 uint8_t **out_credential_id,
                                 size_t *out_credential_id_len,
                                 uint8_t **out_private_key,
                                 size_t *out_private_key_len,
                                 uint8_t **out_attestation_object,
                                 size_t *out_attestation_object_len);

/* Produce an assertion. Signature is DER ES256 over
 * (authenticatorData || client_data_hash). The signature counter is always 0
 * (synced credential), so there is nothing to persist. */
int32_t vault_ffi_passkey_assert(const uint8_t *private_key,
                                 size_t private_key_len, const char *rp_id,
                                 bool user_verified,
                                 const uint8_t *client_data_hash,
                                 size_t client_data_hash_len,
                                 uint8_t **out_authenticator_data,
                                 size_t *out_authenticator_data_len,
                                 uint8_t **out_signature,
                                 size_t *out_signature_len);

#ifdef __cplusplus
}
#endif

#endif /* VAULT_FFI_H */
