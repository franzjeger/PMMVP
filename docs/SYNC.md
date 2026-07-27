# Sync — architecture & status

**Goal:** multi-device sync with zero server. The *encrypted* vault file lives in
the user's own cloud folder (iCloud Drive / Dropbox / OneDrive); only ciphertext
ever leaves the device, so it's end-to-end encrypted by construction. Concurrent
edits are reconciled at the item level so a device never clobbers another's
changes.

## Built (foundation)

- **`vault-core::sync::merge(local, remote)`** — unions two decrypted item sets;
  per id, the version with the newer change-time (`max(modified_at, deleted_at)`)
  wins, ties keep local, soft-delete tombstones propagate. Pure, tested.
- **`Vault::merge_remote(&mut self, bytes)`** — decrypts a peer file's items with
  *this* vault's key (valid because a synced vault shares one stable vault key)
  and merges. A different vault's key can't decrypt → refused (`Decryption`), so
  a foreign file is never merged as garbage. Tested.
- **`VaultStore::save_synced(&mut Vault)`** — if the on-disk file changed since we
  last read/wrote it (fingerprint), merge it in before the atomic write, so a
  peer's edits survive. A **corrupt/partial** file (e.g. a cloud daemon
  mid-write) is treated as garbage and replaced (doesn't wedge saving); a
  **valid foreign** vault is refused (not clobbered). Tested.
- Wired into `persist` and the bridge writes: every save is now sync-aware.
- **`sync::Purge`** — a hard `purge_item` used to leave nothing behind, so the
  next merge with a peer that still held the item put it straight back: a
  credential deleted on purpose, resurrected. A purge now leaves an id and a
  timestamp that travel with the vault, and `apply_purges` drops the item
  wherever it reappears. An edit *after* the purge still wins, exactly as it
  does against a soft-delete tombstone. The records are never expired, because
  expiry would resurrect items on any device offline longer than the window.
  This is why the container is `SYBRVLT3`; V2 and V1 still open, and simply have
  no purges, which is the truth about them.
- **A vault from a newer Arca is refused, not replaced.** `merge_remotes` treats
  an unparseable remote as a torn upload and overwrites it, which is right for
  half a file and catastrophic for a vault written by a version that knows more
  than we do. `from_bytes` now answers `UnsupportedVersion` for any unknown
  `SYBRVLT*` container instead of `Format`. Tested.

## Google credentials, and why they are not in this repository

Drive sync needs an OAuth client. There are two, both in the same Google Cloud
project so every Arca reaches the same `appDataFolder`: a **desktop** client for
macOS/Windows/Linux, and an **iOS** client, because Google ties the redirect to
the client *type* and iOS cannot bind the loopback address a desktop client
redirects to.

The client **ids** are in `crates/vault-sync/src/drive.rs`, which is correct —
an id is public by design, it appears on the consent screen and, on iOS, inside
the app's own URL scheme.

The desktop client **secret** is not. Google's documentation is clear that an
installed-app secret is not confidential (it ships inside every binary, and PKCE
is what binds an authorization code to the process that asked for it), but this
repository is public, and a credential in public git history cannot be
withdrawn — only rotated, which costs a release. One was published that way, and
has since been rotated. So `crates/vault-sync/build.rs` supplies it at build
time from, in order:

1. `ARCA_GOOGLE_CLIENT_SECRET` in the environment.
2. `~/.arca/google-client-secret` — one line, `chmod 600`, next to the updater
   key, and backed up with it.

An iOS client is a **public** client: Google issues no secret for it at all and
rejects a request that sends an empty one, so the token calls omit the field
entirely when there is none. That is pinned by a test.

**A build without the secret is a supported build.** `drive::sync_configured()`
returns false, and the desktop sign-in refuses before opening a browser rather
than walking the user to a consent page that dies at the token exchange. That is
what CI builds and what a clone of this repository builds; everything except
Drive sync works. `release-macos.sh` refuses to build without it, because a
release that silently cannot sync is a bad thing to discover after shipping.

## Not yet built (required before enabling user-facing sync)

These are prospective — they only bite once the vault actually lives in a shared
folder, which needs the path-config UI below. Flagged by an adversarial review.

1. **Vault-path configuration + onboarding UX.** Let the user point Arca at a
   vault in a cloud folder, and — critically — choose *"use the existing vault
   here"* vs *"create new"*. Two independent `create`s in the same folder mint
   different vault keys and can never reconcile (each refuses the other). The
   onboarding flow must prevent that.
2. **Same-item conflict handling.** Merge is last-writer-wins per item on the
   wall clock, so two devices editing the same item concurrently silently drop
   the older edit — and clock skew can pick the wrong winner. Add a conflict
   copy (keep both) rather than discarding, at least for same-item collisions.
3. **Cross-process lost update.** `save_synced`'s read→merge→write isn't atomic
   across writers; a peer/cloud write landing mid-save is lost (never a *torn*
   file — the atomic rename guarantees a complete old-or-new vault, just a lost
   update). Consider a file lock or a re-check-after-write.
4. **Header changes over sync.** `merge_remote` keeps the local header. If master
   password rotation (`change_master_password`, currently unwired) ships, a
   stale-header device would revert the rotation on its next save. Add a header
   version/epoch and take the newer header before wiring password change.
5. **Status/refresh UX.** Show sync state; refresh the item list when a
   background merge brings in a peer's changes.
