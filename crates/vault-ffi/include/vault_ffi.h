/* vault-ffi — C ABI over vault-core for native platform integrations.
 *
 * Hand-maintained to match crates/vault-ffi/src/lib.rs (ABI version 5). All
 * out-buffers are heap-allocated by the library and must be released with
 * vault_ffi_free(ptr, len), which also zeroes them.
 *
 * ABI_VERSION in lib.rs is the authority, and vault_ffi_abi_version() reports
 * it at runtime; clients should refuse to run against a number they were not
 * written for. Tests in lib.rs check that this file names the same version and
 * declares every exported symbol, because "hand-maintained" is otherwise a
 * promise nothing enforces — this comment claimed v2 for a v3 library.
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
 *   -9  a sync cycle failed; the reason is in the status JSON's lastError
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
 * OWNERSHIP / THREADING (relaxed in ABI v5): the vault behind a VaultHandle is
 * internally synchronized, so calls on one handle from different threads no
 * longer need external locking — which is what makes it safe to sync on a
 * background thread while the UI reads. vault_ffi_vault_free must still NOT
 * overlap any other call on the same handle, and must be called exactly once.
 *
 * Note that from v5 a handle's CONTENTS can change underneath you: a sync
 * merges a peer's items into the very vault the handle exposes, so a list taken
 * before a sync may be stale afterwards. A read that lands during the merge
 * BLOCKS until it finishes (milliseconds, and no network happens inside that
 * window) — one more reason not to call this from a UI thread.
 *
 * While the handle is open the decrypted vault (passwords included) is resident
 * in memory, so open, fetch the one password you need, and free the handle
 * promptly. */
typedef struct VaultHandle VaultHandle;

/* Open + unlock a vault from its raw file bytes with a 32-byte device key.
 * On OK, *out_handle is a handle to release with vault_ffi_vault_free. */
int32_t vault_ffi_vault_open(const uint8_t *vault_bytes, size_t vault_len,
                             const uint8_t *device_key, size_t device_key_len,
                             VaultHandle **out_handle);

/* ADDED IN ABI v3, purely additive.
 * Open + unlock from the MASTER PASSWORD (NUL-terminated UTF-8). Needed by any
 * client that has no device key yet - a phone on first launch, a recovery tool.
 * Runs Argon2id with the header's parameters, so it takes hundreds of ms: call
 * it off the UI thread. On OK, *out_handle is a handle to release with
 * vault_ffi_vault_free. */
int32_t vault_ffi_vault_open_password(const uint8_t *vault_bytes, size_t vault_len,
                                      const char *password,
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

/* ---- Device-unlock surface (ABI v4) -------------------------------------
 *
 * Lets a client that opened with the MASTER PASSWORD mint its own quick-unlock
 * key, instead of waiting for some other process to put one in the keychain.
 * On a phone there is no other process, so without this every AutoFill costs
 * the user their master password and an Argon2id derivation.
 *
 * Still no I/O here: the new vault file bytes come back for the CALLER to
 * persist. The caller owns the atomic write and the ordering. Write the vault
 * file BEFORE storing the key: a vault carrying a wrapping whose key was never
 * saved is harmless (the master password still opens it), whereas a stored key
 * for a vault that was never written opens nothing. */

/* Turn on quick unlock. Mints a fresh 32-byte device key, wraps the vault key
 * with it, and returns BOTH the key and the new vault file bytes. Both are
 * freed with vault_ffi_free.
 *
 * The master password keeps working — this adds a second wrapping of the same
 * vault key, it does not replace the first.
 *
 * SECRET: *out_device_key opens the vault without the master password. Put it
 * straight into the platform keychain behind a biometric access control.
 *
 * The returned bytes are verified to reopen with the returned key before they
 * are handed back, so a caller can never be given a vault it cannot unlock. */
int32_t vault_ffi_enable_device_unlock(VaultHandle *handle,
                                       uint8_t **out_device_key,
                                       size_t *out_device_key_len,
                                       uint8_t **out_vault_bytes,
                                       size_t *out_vault_bytes_len);

/* Turn quick unlock off: drop the device-wrapped key from the header and return
 * the new vault file bytes. Deleting the keychain item alone is NOT enough —
 * the wrapping would stay in the file and travel to every device the vault
 * syncs to. The master password is unaffected. */
int32_t vault_ffi_disable_device_unlock(VaultHandle *handle,
                                        uint8_t **out_vault_bytes,
                                        size_t *out_vault_bytes_len);

/* 1 if the vault carries a device-wrapped key, 0 if not, negative on error.
 * Ask this rather than trusting the keychain: a key can outlive the vault that
 * accepted it (restored from a backup), and a client that trusts the keychain
 * alone prompts for a biometric and then fails. */
int32_t vault_ffi_has_device_unlock(VaultHandle *handle);

/* ---- Sync surface (ABI v5) -----------------------------------------------
 *
 * The pull -> merge -> push cycle against the user's own Google Drive. This is
 * the only surface that performs I/O, and only NETWORK I/O: it talks to Google,
 * never to the filesystem. Drive holds CIPHERTEXT ONLY — the vault is sealed
 * before it leaves the device, and the scope is drive.appdata, so Arca sees its
 * own hidden folder and nothing else in the account.
 *
 * Everything network-shaped stays below this line: the REST calls, the TLS, the
 * token refresh, the retry policy. Two things do not, because they have no
 * portable form:
 *
 *   - the interactive sign-in. vault_ffi_sync_auth_begin hands back a URL and
 *     keeps the PKCE verifier; open it however the platform does
 *     (ASWebAuthenticationSession on iOS, a loopback listener on desktop) and
 *     return the code to vault_ffi_sync_auth_finish. The verifier never crosses
 *     this boundary.
 *   - storage. The refresh token comes back for your keychain, merged vault
 *     bytes come back for your file.
 *
 * THREADING: vault_ffi_sync_now and vault_ffi_sync_auth_finish block on the
 * network. Call them off the UI thread — on iOS an AutoFill extension that
 * blocks its main thread is killed by the watchdog, not merely slow. */

/* Opaque sync engine bound to one open vault. */
typedef struct SyncHandle SyncHandle;

/* An interactive sign-in in progress (holds the PKCE verifier). */
typedef struct SyncAuth SyncAuth;

/* Create a sync engine over an already-open vault. Starts DISCONNECTED: call
 * vault_ffi_sync_set_credential before vault_ffi_sync_now will do anything.
 *
 * The engine shares the handle's vault rather than copying it, so a merge is
 * visible to vault_ffi_identities on that handle with no reload — and the vault
 * handle may be freed while this one lives. */
int32_t vault_ffi_sync_new(VaultHandle *vault, SyncHandle **out_handle);

/* Free a sync handle. Null-safe, call exactly once, and never while
 * vault_ffi_sync_now is running on another thread. */
void vault_ffi_sync_free(SyncHandle *handle);

/* Set (or clear) the credential. refresh_token NULL DISCONNECTS: the cached
 * access token is dropped and the account forgotten. account is a display label
 * and may be NULL. Connecting resets the engine's bookkeeping — a remote
 * checksum recorded against one Google account means nothing under another. */
int32_t vault_ffi_sync_set_credential(SyncHandle *handle,
                                      const char *refresh_token,
                                      const char *account);

/* Local vault state changed and should be pushed on the next cycle. */
void vault_ffi_sync_mark_dirty(SyncHandle *handle);

/* Status as UTF-8 JSON, no network:
 *   {"connected":bool,"account":string|null,"lastSyncUnix":number|null,
 *    "lastError":string|null,"merged":false}
 * merged is always false here; only vault_ffi_sync_now can merge. */
int32_t vault_ffi_sync_status(SyncHandle *handle, uint8_t **out_json,
                              size_t *out_json_len);

/* Run one pull -> merge -> push cycle. BLOCKING, network I/O.
 *
 * *out_status_json is always produced, so a failed cycle still reports why.
 *
 * *out_vault_bytes is non-NULL ONLY when remote changes were merged, and is
 * then the new vault file to persist. Write it: the merge is already live in
 * the shared vault, so skipping the write leaves memory ahead of disk. Bytes
 * come back on failure too when a merge happened before the failure did.
 *
 * Returns 0, or -9 with the reason in the status JSON. */
int32_t vault_ffi_sync_now(SyncHandle *handle, uint8_t **out_vault_bytes,
                           size_t *out_vault_bytes_len,
                           uint8_t **out_status_json,
                           size_t *out_status_json_len);

/* Begin a sign-in: returns the authorization URL to open, and a handle holding
 * the PKCE verifier. redirect_uri is whatever the platform can catch (a custom
 * URL scheme on iOS, http://127.0.0.1:<port> on desktop); it is remembered, so
 * finish cannot disagree with begin about it. */
int32_t vault_ffi_sync_auth_begin(const char *redirect_uri, uint8_t **out_url,
                                  size_t *out_url_len, SyncAuth **out_auth);

/* Finish a sign-in: redeem code, return the refresh token and the account's
 * email. BLOCKING, network I/O.
 *
 * SECRET: *out_refresh_token grants access to the synced ciphertext until the
 * user revokes it. Put it straight into the platform keychain and free it with
 * vault_ffi_free, which zeroes it. It is the value to hand to
 * vault_ffi_sync_set_credential.
 *
 * *out_account is a display label and may come back NULL — the lookup is a
 * second request, and losing it must not fail a sign-in that succeeded.
 *
 * The verifier is single-use; a second call is rejected by the server. */
int32_t vault_ffi_sync_auth_finish(SyncAuth *auth, const char *code,
                                   uint8_t **out_refresh_token,
                                   size_t *out_refresh_token_len,
                                   uint8_t **out_account,
                                   size_t *out_account_len);

/* Free a sign-in handle, zeroizing the PKCE verifier. Null-safe. */
void vault_ffi_sync_auth_free(SyncAuth *auth);

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
