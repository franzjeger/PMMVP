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
//! Limitation: a **hard purge** (item removed entirely) can be resurrected by a
//! peer that still has the item, because there's no tombstone to outvote it.
//! Sync therefore relies on soft-delete; purging should be a local-only,
//! post-sync operation.

use std::collections::HashMap;

use crate::item::Item;

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
}
