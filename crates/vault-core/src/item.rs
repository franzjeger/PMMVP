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
    SshKey,
    Wifi,
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
///
/// `Debug` is implemented by hand (below) so secret fields (passwords, TOTP
/// secrets, notes, private keys) are redacted rather than printed — a derived
/// `Debug` would dump them into any log line or `{:?}` of a containing struct.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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

    /// A WebAuthn passkey credential. The private key is a P-256 scalar held as
    /// bytes and zeroized with the rest of the payload; see [`crate::passkey`]
    /// for the authenticator operations. New fields are `#[serde(default)]` so
    /// the tagged-CBOR payload stays backward-compatible.
    Passkey {
        title: String,
        /// Relying-party id, e.g. "github.com".
        #[serde(default)]
        rp_id: String,
        /// Human-facing account name shown by the RP (e.g. "franzjeger").
        #[serde(default)]
        user_name: String,
        /// Opaque user handle chosen by the RP at registration.
        #[serde(default)]
        user_handle: Vec<u8>,
        /// Credential id presented on assertions.
        #[serde(default)]
        credential_id: Vec<u8>,
        /// SEC1 P-256 private scalar (32 bytes). Secret.
        #[serde(default)]
        private_key: Vec<u8>,
        /// Reserved. Assertions always report counter 0 (synced/backup-eligible
        /// credential; see [`crate::passkey::assert`]); kept for schema stability.
        #[serde(default)]
        sign_count: u32,
    },

    /// An SSH key served over the ssh-agent protocol. The private key is a
    /// 32-byte Ed25519 seed, zeroized with the rest of the payload; see
    /// [`crate::ssh`] for generation and signing. Signing happens inside the
    /// vault and the seed never leaves it. New fields are `#[serde(default)]`
    /// so the tagged-CBOR payload stays backward-compatible.
    SshKey {
        title: String,
        /// OpenSSH comment (conventionally `user@host`); shown by the agent.
        #[serde(default)]
        comment: String,
        /// Key algorithm on the wire, e.g. "ssh-ed25519". Stored so future
        /// algorithms can coexist; only Ed25519 is generated today.
        #[serde(default)]
        key_type: String,
        /// OpenSSH public-key blob (the agent identity + `authorized_keys` body).
        #[serde(default)]
        public_key: Vec<u8>,
        /// Ed25519 seed (32 bytes). Secret.
        #[serde(default)]
        private_key: Vec<u8>,
        /// SHA-256 fingerprint (`SHA256:…`), cached for display.
        #[serde(default)]
        fingerprint: String,
    },

    /// A saved Wi-Fi network. The passphrase is secret (zeroized with the rest
    /// of the payload). New fields are `#[serde(default)]` so the tagged-CBOR
    /// payload stays backward-compatible.
    Wifi {
        title: String,
        /// Network name.
        #[serde(default)]
        ssid: String,
        /// Passphrase. Secret. Empty for an open network.
        #[serde(default)]
        password: String,
        /// Auth token used in the join QR: "WPA" (covers WPA/WPA2/WPA3), "WEP",
        /// or "nopass" (open). Empty is treated as "WPA".
        #[serde(default)]
        security: String,
        /// Whether the SSID is hidden (not broadcast).
        #[serde(default)]
        hidden: bool,
        #[serde(default)]
        notes: String,
    },

    /// A free-form secure note: a title plus an encrypted body. The body is
    /// secret (zeroized with the payload, redacted in Debug). `body` is
    /// `#[serde(default)]` so notes written before it existed still load.
    SecureNote {
        title: String,
        #[serde(default)]
        body: String,
    },
}

/// Build the standard Wi-Fi join string that network QR codes encode
/// (`WIFI:T:<auth>;S:<ssid>;P:<pass>;H:<hidden>;;`). Special characters in the
/// SSID/password are backslash-escaped per the de-facto spec. Kept in the I/O-
/// free core so the actual QR rendering can happen wherever, from the secret.
pub fn wifi_qr_payload(ssid: &str, password: &str, security: &str, hidden: bool) -> String {
    fn esc(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if matches!(c, '\\' | ';' | ',' | ':' | '"') {
                out.push('\\');
            }
            out.push(c);
        }
        out
    }
    let auth = if security.eq_ignore_ascii_case("nopass") {
        "nopass"
    } else if security.eq_ignore_ascii_case("wep") {
        "WEP"
    } else {
        "WPA"
    };
    let mut out = format!("WIFI:T:{auth};S:{};", esc(ssid));
    if auth != "nopass" {
        out.push_str(&format!("P:{};", esc(password)));
    }
    if hidden {
        out.push_str("H:true;");
    }
    out.push(';');
    out
}

impl VaultItem {
    pub fn kind(&self) -> ItemKind {
        match self {
            VaultItem::Login { .. } => ItemKind::Login,
            VaultItem::Passkey { .. } => ItemKind::Passkey,
            VaultItem::SshKey { .. } => ItemKind::SshKey,
            VaultItem::Wifi { .. } => ItemKind::Wifi,
            VaultItem::SecureNote { .. } => ItemKind::SecureNote,
        }
    }

    /// Display title for list/detail panes.
    pub fn title(&self) -> &str {
        match self {
            VaultItem::Login { title, .. }
            | VaultItem::Passkey { title, .. }
            | VaultItem::SshKey { title, .. }
            | VaultItem::Wifi { title, .. }
            | VaultItem::SecureNote { title, .. } => title,
        }
    }

    /// Secondary line in the entry list (e.g. the username/email).
    pub fn subtitle(&self) -> &str {
        match self {
            VaultItem::Login { username, .. } => username,
            VaultItem::Passkey { user_name, .. } => user_name,
            // The comment (conventionally user@host) is the recognizable label.
            VaultItem::SshKey { comment, .. } => comment,
            // The network name is the recognizable label.
            VaultItem::Wifi { ssid, .. } => ssid,
            VaultItem::SecureNote { .. } => "",
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
            // The rp_id ("github.com") acts as the passkey's site, so it groups
            // next to the matching login in the list.
            VaultItem::Passkey { rp_id, .. } => rp_id,
            // SSH keys are not tied to a web site; they group under their kind.
            VaultItem::SshKey { .. } => "",
            VaultItem::Wifi { .. } => "",
            VaultItem::SecureNote { .. } => "",
        }
    }
}

/// Hand-written `Debug` that redacts every secret field. Non-secret metadata
/// (titles, usernames, URLs, rp ids, fingerprints) is shown to keep logs useful;
/// passwords, TOTP secrets, notes, and private keys are replaced with a marker.
impl std::fmt::Debug for VaultItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const REDACTED: &str = "<redacted>";
        match self {
            VaultItem::Login {
                title,
                username,
                url,
                ..
            } => f
                .debug_struct("Login")
                .field("title", title)
                .field("username", username)
                .field("url", url)
                .field("password", &REDACTED)
                .field("totp_secret", &REDACTED)
                .field("notes", &REDACTED)
                .finish(),
            VaultItem::Passkey {
                title,
                rp_id,
                user_name,
                credential_id,
                ..
            } => f
                .debug_struct("Passkey")
                .field("title", title)
                .field("rp_id", rp_id)
                .field("user_name", user_name)
                .field("credential_id", credential_id)
                .field("private_key", &REDACTED)
                .finish_non_exhaustive(),
            VaultItem::SshKey {
                title,
                comment,
                key_type,
                fingerprint,
                ..
            } => f
                .debug_struct("SshKey")
                .field("title", title)
                .field("comment", comment)
                .field("key_type", key_type)
                .field("fingerprint", fingerprint)
                .field("private_key", &REDACTED)
                .finish_non_exhaustive(),
            VaultItem::Wifi {
                title,
                ssid,
                security,
                hidden,
                ..
            } => f
                .debug_struct("Wifi")
                .field("title", title)
                .field("ssid", ssid)
                .field("security", security)
                .field("hidden", hidden)
                .field("password", &REDACTED)
                .field("notes", &REDACTED)
                .finish(),
            VaultItem::SecureNote { title, .. } => f
                .debug_struct("SecureNote")
                .field("title", title)
                .field("body", &REDACTED)
                .finish(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secrets_for_every_variant() {
        let login = VaultItem::Login {
            title: "GitHub".into(),
            username: "frank".into(),
            password: "hunter2-SECRET".into(),
            url: "https://github.com".into(),
            totp_secret: Some("JBSWY3DP-SECRET".into()),
            notes: "note-SECRET".into(),
        };
        let passkey = VaultItem::Passkey {
            title: "pk".into(),
            rp_id: "github.com".into(),
            user_name: "frank".into(),
            user_handle: vec![1, 2, 3],
            credential_id: vec![4, 5, 6],
            private_key: b"PASSKEY-SEED-SECRET".to_vec(),
            sign_count: 0,
        };
        let ssh = VaultItem::SshKey {
            title: "laptop".into(),
            comment: "frank@host".into(),
            key_type: "ssh-ed25519".into(),
            public_key: vec![7, 8, 9],
            private_key: b"SSH-SEED-SECRET".to_vec(),
            fingerprint: "SHA256:abc".into(),
        };
        for item in [&login, &passkey, &ssh] {
            let dbg = format!("{item:?}");
            assert!(dbg.contains("<redacted>"), "no redaction marker in {dbg}");
            assert!(
                !dbg.contains("SECRET"),
                "a secret leaked into Debug output: {dbg}"
            );
        }
        // Non-secret metadata is still visible (keeps logs useful).
        assert!(format!("{login:?}").contains("frank"));
        assert!(format!("{ssh:?}").contains("SHA256:abc"));
    }
}

#[cfg(test)]
mod wifi_tests {
    use super::*;

    #[test]
    fn wifi_qr_payload_encodes_and_escapes() {
        let p = wifi_qr_payload("Home;Net", "p@ss:word", "WPA2", false);
        // Auth normalizes to WPA; ';' and ':' are backslash-escaped.
        assert_eq!(p, r"WIFI:T:WPA;S:Home\;Net;P:p@ss\:word;;");

        // Open network: no password segment.
        let open = wifi_qr_payload("Cafe", "ignored", "nopass", false);
        assert_eq!(open, "WIFI:T:nopass;S:Cafe;;");

        // Hidden network adds H:true.
        let hidden = wifi_qr_payload("Secret", "pw", "WPA", true);
        assert_eq!(hidden, "WIFI:T:WPA;S:Secret;P:pw;H:true;;");
    }
}
