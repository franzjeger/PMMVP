/* vault-ffi — C ABI over vault-core for native platform integrations.
 *
 * Hand-maintained to match crates/vault-ffi/src/lib.rs (ABI version 1). All
 * out-buffers are heap-allocated by the library and must be released with
 * vault_ffi_free(ptr, len), which also zeroes them.
 *
 * Return codes: 0 = OK, negative = error.
 */
#ifndef VAULT_FFI_H
#define VAULT_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t vault_ffi_abi_version(void);

void vault_ffi_free(uint8_t *ptr, size_t len);

/* Create a passkey for rp_id. Out-pairs (freed by the caller):
 *   credential_id, private_key (SEC1 P-256, 32 bytes — store encrypted!),
 *   attestation_object (CBOR, fmt "none"). */
int32_t vault_ffi_passkey_create(const char *rp_id,
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
