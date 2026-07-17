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
5. **Purge vs sync.** A hard `purge_item` leaves no tombstone, so a peer
   re-introduces the item on the next merge — a "permanently deleted" credential
   can reappear. Gate purge while sync is active, or give it a tombstone.
6. **Status/refresh UX.** Show sync state; refresh the item list when a
   background merge brings in a peer's changes.
