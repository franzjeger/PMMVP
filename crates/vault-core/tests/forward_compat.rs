//! Can a client that predates a new item kind still read the vault?
//!
//! The on-disk item payload is CBOR tagged by variant NAME, which makes adding
//! a kind safe for a NEW client reading OLD data. It says nothing about the
//! other direction, and the other direction is the one that ships: a phone
//! updates through review, a desktop updates from a script, and for days the
//! two are not the same build.
use serde::{Deserialize, Serialize};

/// The enum as an OLDER build knows it: every variant except Bookmark.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
enum OldVaultItem {
    Login {
        title: String,
        username: String,
        password: String,
        url: String,
        totp_secret: Option<String>,
        notes: String,
    },
    Passkey {
        title: String,
    },
    SshKey {
        title: String,
    },
    Wifi {
        title: String,
    },
    SecureNote {
        title: String,
        body: String,
    },
}

#[test]
fn an_older_client_reading_a_bookmark() {
    let new = vault_core::VaultItem::Bookmark {
        title: "Sybr".into(),
        url: "https://sybr.no".into(),
        folder: "Arbeid".into(),
        notes: String::new(),
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&new, &mut buf).unwrap();
    let got: Result<OldVaultItem, _> = ciborium::from_reader(&buf[..]);
    println!("OLD CLIENT / ONE BOOKMARK: {:?}", got.as_ref().err());
    assert!(got.is_err(), "if this passes, older clients are fine");
}

#[test]
fn and_a_whole_list_containing_one() {
    // The real shape: the vault decodes ALL items at once, so one unknown kind
    // decides the fate of every other entry in the file.
    let items = vec![
        vault_core::VaultItem::SecureNote {
            title: "Note".into(),
            body: "b".into(),
        },
        vault_core::VaultItem::Bookmark {
            title: "B".into(),
            url: "https://x.test".into(),
            folder: String::new(),
            notes: String::new(),
        },
    ];
    let mut buf = Vec::new();
    ciborium::into_writer(&items, &mut buf).unwrap();
    let got: Result<Vec<OldVaultItem>, _> = ciborium::from_reader(&buf[..]);
    println!("OLD CLIENT / LIST WITH ONE: {:?}", got.as_ref().err());
    assert!(
        got.is_err(),
        "one unknown kind takes the whole list with it"
    );
}
