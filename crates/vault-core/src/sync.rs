//! Vault sync merge.
//!
//! The planned sync model keeps the *encrypted vault file* in the user's own
//! cloud folder (iCloud Drive / Dropbox / OneDrive): zero server, end-to-end by
//! construction since only ciphertext leaves the device. The one hard problem
//! is concurrent edits — if two devices each write the whole blob, a plain
//! last-writer-wins clobbers the other device's changes.
//!
//! [`merge`] solves that at the *item* granularity: it unions two decrypted
//! item sets and, for any id present on both sides, keeps the one changed most
//! recently. Soft-deletes ([`Item::deleted_at`]) are tombstones, so a deletion
//! on one device propagates — unless the other device edited the same item
//! *later*, in which case the edit wins. This is last-writer-wins per item,
//! which is correct and predictable for a personal vault (true same-item
//! conflicts are rare, and the loser is still recoverable from the other
//! device's file history).
//!
//! A **hard purge** removes the item entirely, so there is nothing left in the
//! item set to outvote a peer that still holds it. [`Purge`] is the record that
//! closes that: a purge travels with the vault, and [`apply_purges`] drops the
//! item wherever it turns up again. Without it, emptying the Trash on one device
//! is undone by the next merge — which matters most for exactly the credential
//! someone destroys on purpose.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::item::Item;

/// A hard delete, kept so it can outvote a peer that still holds the item.
///
/// An id and a timestamp, nothing else: no title, no payload, nothing derived
/// from the secret. The id costs no privacy — it sat in cleartext next to the
/// item's ciphertext for as long as the item existed (see `EncryptedItem`), so
/// every revision the remote already holds contains it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Purge {
    pub id: Uuid,
    /// When the purge happened, unix milliseconds.
    pub at: i64,
}

/// The item's last-change time: the newer of its edit and its (soft-)delete
/// timestamp. Used to pick the winning version during [`merge`].
fn change_time(item: &Item) -> i64 {
    item.modified_at.max(item.deleted_at.unwrap_or(i64::MIN))
}

/// Merge two decrypted item sets into one. For each id, the version with the
/// newer [`change_time`] wins; ties keep the `local` version. Tombstones
/// (soft-deleted items) are retained so deletions propagate.
pub fn merge(local: Vec<Item>, remote: Vec<Item>) -> Vec<Item> {
    let mut by_id: HashMap<uuid::Uuid, Item> = HashMap::with_capacity(local.len());
    // Insert local first so a tie resolves in its favour.
    for item in local {
        by_id.insert(item.id, item);
    }
    for item in remote {
        match by_id.get(&item.id) {
            Some(existing) if change_time(existing) >= change_time(&item) => {}
            _ => {
                by_id.insert(item.id, item);
            }
        }
    }
    by_id.into_values().collect()
}

/// Union two purge lists, keeping the LATEST purge per id.
///
/// Latest rather than earliest so a purge cannot be weakened by an older copy
/// of itself: the record's whole job is to out-date the item, and taking the
/// earlier timestamp would let an edit between the two revive it.
pub fn merge_purges(local: Vec<Purge>, remote: Vec<Purge>) -> Vec<Purge> {
    let mut by_id: HashMap<Uuid, Purge> = HashMap::with_capacity(local.len());
    for purge in local.into_iter().chain(remote) {
        match by_id.get(&purge.id) {
            Some(existing) if existing.at >= purge.at => {}
            _ => {
                by_id.insert(purge.id, purge);
            }
        }
    }
    by_id.into_values().collect()
}

/// Drop every item a purge outvotes.
///
/// Same rule as a soft-delete tombstone, deliberately: the purge wins unless
/// the item changed *after* it. An edit that late is a peer doing something to
/// an item this device had already thrown away, and silently discarding the
/// newer of two versions is the failure mode merge exists to avoid.
///
/// Purge records are never dropped. They are 24 bytes each, and expiring them
/// would resurrect items on any device that was offline longer than the expiry.
pub fn apply_purges(items: Vec<Item>, purges: &[Purge]) -> Vec<Item> {
    if purges.is_empty() {
        return items;
    }
    let by_id: HashMap<Uuid, i64> = purges.iter().map(|p| (p.id, p.at)).collect();
    items
        .into_iter()
        .filter(|item| match by_id.get(&item.id) {
            Some(at) => change_time(item) > *at,
            None => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::VaultItem;

    fn login(title: &str) -> VaultItem {
        VaultItem::Login {
            title: title.into(),
            username: "u".into(),
            password: "p".into(),
            url: "https://x.com".into(),
            totp_secret: None,
            notes: String::new(),
        }
    }

    /// Build an item with explicit id + timestamps for deterministic tests.
    fn item(id_byte: u8, modified_at: i64, deleted_at: Option<i64>, title: &str) -> Item {
        Item {
            id: uuid::Uuid::from_bytes([id_byte; 16]),
            created_at: 0,
            modified_at,
            deleted_at,
            data: login(title),
        }
    }

    fn find(items: &[Item], id_byte: u8) -> Option<&Item> {
        let id = uuid::Uuid::from_bytes([id_byte; 16]);
        items.iter().find(|i| i.id == id)
    }

    #[test]
    fn unions_disjoint_items() {
        let merged = merge(vec![item(1, 5, None, "a")], vec![item(2, 5, None, "b")]);
        assert_eq!(merged.len(), 2);
        assert!(find(&merged, 1).is_some());
        assert!(find(&merged, 2).is_some());
    }

    #[test]
    fn newer_edit_wins_regardless_of_side() {
        // Remote edited later -> remote version.
        let merged = merge(
            vec![item(1, 5, None, "local")],
            vec![item(1, 9, None, "remote")],
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].data.title(), "remote");

        // Local edited later -> local version.
        let merged = merge(
            vec![item(1, 9, None, "local")],
            vec![item(1, 5, None, "remote")],
        );
        assert_eq!(merged[0].data.title(), "local");
    }

    #[test]
    fn tie_keeps_local() {
        let merged = merge(
            vec![item(1, 7, None, "local")],
            vec![item(1, 7, None, "remote")],
        );
        assert_eq!(merged[0].data.title(), "local");
    }

    #[test]
    fn deletion_propagates_but_a_later_edit_beats_it() {
        // Remote deleted at t=8 beats local edit at t=5 -> tombstone kept.
        let merged = merge(
            vec![item(1, 5, None, "edited")],
            vec![item(1, 5, Some(8), "deleted")],
        );
        assert!(merged[0].deleted_at.is_some());

        // But a local edit at t=10 beats a remote delete at t=8 -> item lives.
        let merged = merge(
            vec![item(1, 10, None, "edited")],
            vec![item(1, 5, Some(8), "deleted")],
        );
        assert!(merged[0].deleted_at.is_none());
        assert_eq!(merged[0].data.title(), "edited");
    }

    fn purge(id_byte: u8, at: i64) -> Purge {
        Purge {
            id: uuid::Uuid::from_bytes([id_byte; 16]),
            at,
        }
    }

    /// The bug this whole mechanism exists for: without a purge record, a peer
    /// that still holds the item hands it straight back on the next merge, and
    /// the credential a user destroyed on purpose is alive again.
    #[test]
    fn a_purged_item_is_not_resurrected_by_a_peer_that_still_has_it() {
        // This device purged item 1 at t=20. The peer never heard about it.
        let merged = merge(vec![], vec![item(1, 5, None, "still on the peer")]);
        assert_eq!(merged.len(), 1, "merge alone cannot know it was purged");

        let survivors = apply_purges(merged, &[purge(1, 20)]);
        assert!(
            survivors.is_empty(),
            "the purge must outvote the peer's copy"
        );
    }

    /// Same rule as a soft-delete tombstone. Someone editing an item after this
    /// device threw it away is making a newer decision, and merge exists
    /// precisely so the newer of two versions is not silently discarded.
    #[test]
    fn an_edit_after_the_purge_still_wins() {
        let survivors = apply_purges(vec![item(1, 30, None, "edited later")], &[purge(1, 20)]);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].data.title(), "edited later");

        // Edited at exactly the purge instant: the purge wins, matching how a
        // tie resolves everywhere else here rather than inventing a third rule.
        assert!(apply_purges(vec![item(1, 20, None, "same instant")], &[purge(1, 20)]).is_empty());
    }

    /// A soft-delete tombstone is not a licence to forget: it carries a
    /// change_time too, so it must lose to the purge exactly like a live item.
    #[test]
    fn a_purge_also_removes_a_peers_tombstone() {
        let survivors = apply_purges(vec![item(1, 5, Some(9), "trashed")], &[purge(1, 20)]);
        assert!(survivors.is_empty());
    }

    #[test]
    fn purges_union_and_the_later_one_wins() {
        let merged = merge_purges(vec![purge(1, 10), purge(2, 5)], vec![purge(1, 30)]);
        assert_eq!(merged.len(), 2);
        let first = merged.iter().find(|p| p.id == purge(1, 0).id).unwrap();
        assert_eq!(first.at, 30, "an older copy must not weaken a purge");

        // Order must not matter: same answer with the sides swapped.
        let swapped = merge_purges(vec![purge(1, 30)], vec![purge(1, 10)]);
        assert_eq!(swapped[0].at, 30);
    }

    #[test]
    fn purges_leave_unrelated_items_alone() {
        let items = vec![item(1, 5, None, "a"), item(2, 5, None, "b")];
        let survivors = apply_purges(items, &[purge(3, 99)]);
        assert_eq!(survivors.len(), 2);
    }
}
