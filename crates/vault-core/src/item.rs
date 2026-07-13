//! Vault data model.
//!
//! [`VaultItem`] carries the secret payload and is zeroized on drop. [`Item`]
//! wraps it with non-secret metadata (id, timestamps, soft-delete marker).
//! Timestamps are supplied by the caller (unix milliseconds) so this crate
//! stays free of clock I/O and fully deterministic under test.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The kind of a [`VaultItem`], for filtering/summaries without decrypting the
/// whole payload conceptually (used by the sidebar categories).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemKind {
    Login,
    Passkey,
    SecureNote,
}

/// The secret-bearing payload of a vault entry.
///
/// All variants and their string fields are zeroized when dropped. Only
/// `Login` is implemented in Phase 1; the others are deliberate stubs.
///
/// `#[serde(tag = "type")]` makes the on-disk representation tagged by the
/// variant *name* (e.g. `{"type":"Login", ...}`) rather than by a positional
/// index. Combined with the self-describing CBOR encoding used for the at-rest
/// item payload (see [`crate::vault`]), the format stays stable when variants
/// are reordered or new ones are appended — a guarantee a positional codec
/// such as bincode does NOT provide.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "type")]
pub enum VaultItem {
    Login {
        title: String,
        username: String,
        password: String,
        url: String,
        /// Base32 TOTP secret, if the login has 2FA. `None` means no code.
        totp_secret: Option<String>,
        notes: String,
    },

    /// TODO(phase-2): WebAuthn/passkey credential. A real implementation will
    /// store rp_id, credential_id, the (non-extractable where possible)
    /// private key handle, sign counter, and user handle. Stubbed for now.
    Passkey { title: String },

    /// TODO(phase-2): free-form secure note (title + encrypted body). Stubbed.
    SecureNote { title: String },
}

impl VaultItem {
    pub fn kind(&self) -> ItemKind {
        match self {
            VaultItem::Login { .. } => ItemKind::Login,
            VaultItem::Passkey { .. } => ItemKind::Passkey,
            VaultItem::SecureNote { .. } => ItemKind::SecureNote,
        }
    }

    /// Display title for list/detail panes.
    pub fn title(&self) -> &str {
        match self {
            VaultItem::Login { title, .. }
            | VaultItem::Passkey { title }
            | VaultItem::SecureNote { title } => title,
        }
    }

    /// Secondary line in the entry list (e.g. the username/email).
    pub fn subtitle(&self) -> &str {
        match self {
            VaultItem::Login { username, .. } => username,
            VaultItem::Passkey { .. } | VaultItem::SecureNote { .. } => "",
        }
    }

    /// Whether a non-empty TOTP secret is present.
    pub fn has_totp(&self) -> bool {
        matches!(self, VaultItem::Login { totp_secret: Some(s), .. } if !s.is_empty())
    }

    /// The website URL, for kinds that have one (empty otherwise). Non-secret
    /// metadata, used e.g. to group entries for the same site in the list.
    pub fn url(&self) -> &str {
        match self {
            VaultItem::Login { url, .. } => url,
            VaultItem::Passkey { .. } | VaultItem::SecureNote { .. } => "",
        }
    }
}

/// A stored vault entry: secret payload plus non-secret metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    /// Creation time, unix milliseconds.
    pub created_at: i64,
    /// Last-modified time, unix milliseconds.
    pub modified_at: i64,
    /// Soft-delete marker. `Some(ts)` means the item is in the Trash and shows
    /// under the "Deleted" sidebar category; `None` means active.
    pub deleted_at: Option<i64>,
    pub data: VaultItem,
}

impl Item {
    /// Create a new active item with a fresh random UUID.
    pub fn new(data: VaultItem, now_unix_millis: i64) -> Self {
        Self {
            id: Uuid::new_v4(),
            created_at: now_unix_millis,
            modified_at: now_unix_millis,
            deleted_at: None,
            data,
        }
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Build a lightweight, decrypted summary for list rendering.
    pub fn summary(&self) -> ItemSummary {
        ItemSummary {
            id: self.id,
            kind: self.data.kind(),
            title: self.data.title().to_owned(),
            subtitle: self.data.subtitle().to_owned(),
            url: self.data.url().to_owned(),
            has_totp: self.data.has_totp(),
            is_deleted: self.is_deleted(),
            modified_at: self.modified_at,
        }
    }
}

/// Lightweight, already-decrypted view of an item for list rendering.
///
/// NOTE: this contains plaintext title/subtitle (shown in the UI list anyway)
/// but never the password, TOTP secret, or notes. It is not zeroized: it is a
/// short-lived view object handed to the presentation layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ItemSummary {
    pub id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    pub subtitle: String,
    /// Website URL (empty for kinds without one). Non-secret metadata.
    pub url: String,
    pub has_totp: bool,
    pub is_deleted: bool,
    pub modified_at: i64,
}
