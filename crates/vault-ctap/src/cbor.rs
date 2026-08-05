//! CBOR helpers for CTAP2: canonical encoding on the way out, forgiving typed
//! accessors on the way in.
//!
//! CTAP2 does not merely use CBOR, it requires the **CTAP2 canonical form**
//! (CTAP 2.1 §6, "Message Encoding"): definite lengths, shortest-form integers,
//! and map keys sorted. `ciborium` gives us the first two but preserves
//! insertion order for maps, so [`canonical`] re-sorts every map in the tree
//! before we hand bytes to the transport.
//!
//! The sort is not RFC 8949's. CTAP2 orders keys by, in this order: major type,
//! then encoded length, then bytewise. That is why [`key_order`] encodes each
//! key and sorts on the result rather than comparing `Value`s directly.
//!
//! Parsing goes the other way and is deliberately liberal about *shape* while
//! strict about *type*: an unknown map key is ignored (so a newer platform can
//! send fields we predate without breaking), but a field of the wrong CBOR
//! major type is [`CtapError::CborUnexpectedType`], never a silent default.

use ciborium::value::{Integer, Value as Cbor};

use crate::error::{CtapError, Result};

/// Build `Cbor::Integer` from a plain `i64`, which is all CTAP keys and
/// algorithm identifiers need.
pub(crate) fn int(n: i64) -> Cbor {
    Cbor::Integer(Integer::from(n))
}

/// Encode a value with no canonicalisation. Only used to derive sort keys; all
/// output goes through [`encode`].
fn encode_raw(value: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    // A `Value` built in this crate is always encodable; ciborium only fails
    // here on writer I/O, and a Vec never fails to accept bytes.
    ciborium::into_writer(value, &mut out).expect("in-memory CBOR encoding cannot fail");
    out
}

/// The CTAP2 canonical sort key for a map key: (major type, encoded length,
/// encoded bytes).
fn key_order(key: &Cbor) -> (u8, usize, Vec<u8>) {
    let bytes = encode_raw(key);
    let major = bytes[0] >> 5;
    (major, bytes.len(), bytes)
}

/// Recursively put every map in `value` into CTAP2 canonical key order.
pub(crate) fn canonical(value: Cbor) -> Cbor {
    match value {
        Cbor::Map(entries) => {
            let mut entries: Vec<(Cbor, Cbor)> = entries
                .into_iter()
                .map(|(k, v)| (k, canonical(v)))
                .collect();
            // Cached, because deriving a sort key means encoding the key and
            // allocating; a plain comparator would redo that on every compare.
            entries.sort_by_cached_key(|(key, _)| key_order(key));
            Cbor::Map(entries)
        }
        Cbor::Array(items) => Cbor::Array(items.into_iter().map(canonical).collect()),
        other => other,
    }
}

/// Encode a response value in CTAP2 canonical form.
pub(crate) fn encode(value: Cbor) -> Vec<u8> {
    encode_raw(&canonical(value))
}

/// Parse a request payload into a CBOR value.
pub(crate) fn decode(bytes: &[u8]) -> Result<Cbor> {
    ciborium::from_reader(bytes).map_err(|_| CtapError::InvalidCbor)
}

/// The entries of a CBOR map, or [`CtapError::CborUnexpectedType`].
pub(crate) fn as_map(value: &Cbor) -> Result<&[(Cbor, Cbor)]> {
    match value {
        Cbor::Map(entries) => Ok(entries),
        _ => Err(CtapError::CborUnexpectedType),
    }
}

/// Look up an integer-keyed entry. CTAP request maps are keyed 0x01, 0x02, …
pub(crate) fn get(entries: &[(Cbor, Cbor)], key: i64) -> Option<&Cbor> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, Cbor::Integer(i) if i128::from(*i) == i128::from(key)))
        .map(|(_, v)| v)
}

/// Look up a text-keyed entry, used inside the nested `rp`, `user` and
/// `options` maps.
pub(crate) fn get_text_key<'a>(entries: &'a [(Cbor, Cbor)], key: &str) -> Option<&'a Cbor> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, Cbor::Text(t) if t == key))
        .map(|(_, v)| v)
}

pub(crate) fn as_bytes(value: &Cbor) -> Result<&[u8]> {
    match value {
        Cbor::Bytes(b) => Ok(b),
        _ => Err(CtapError::CborUnexpectedType),
    }
}

pub(crate) fn as_text(value: &Cbor) -> Result<&str> {
    match value {
        Cbor::Text(t) => Ok(t),
        _ => Err(CtapError::CborUnexpectedType),
    }
}

pub(crate) fn as_bool(value: &Cbor) -> Result<bool> {
    match value {
        Cbor::Bool(b) => Ok(*b),
        _ => Err(CtapError::CborUnexpectedType),
    }
}

pub(crate) fn as_array(value: &Cbor) -> Result<&[Cbor]> {
    match value {
        Cbor::Array(items) => Ok(items),
        _ => Err(CtapError::CborUnexpectedType),
    }
}

pub(crate) fn as_i64(value: &Cbor) -> Result<i64> {
    match value {
        Cbor::Integer(i) => i64::try_from(i128::from(*i)).map_err(|_| CtapError::InvalidParameter),
        _ => Err(CtapError::CborUnexpectedType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Cbor {
        Cbor::Text(s.into())
    }

    #[test]
    fn integer_keys_are_emitted_in_ascending_order() {
        let map = Cbor::Map(vec![
            (int(3), text("third")),
            (int(1), text("first")),
            (int(2), text("second")),
        ]);
        let bytes = encode(map);
        // a3 = map(3), then key 01, 02, 03 in order.
        assert_eq!(bytes[0], 0xa3);
        assert_eq!(bytes[1], 0x01);
        let second = bytes.iter().position(|&b| b == 0x02).unwrap();
        let third = bytes.iter().position(|&b| b == 0x03).unwrap();
        assert!(second < third);
    }

    #[test]
    fn text_keys_sort_by_length_then_bytes_not_plain_lexicographically() {
        // "plat" is lexicographically before "rk", but CTAP2 sorts shorter
        // keys first — so the options map must come out rk, up, uv, plat.
        let map = Cbor::Map(vec![
            (text("plat"), Cbor::Bool(false)),
            (text("uv"), Cbor::Bool(true)),
            (text("rk"), Cbor::Bool(true)),
            (text("up"), Cbor::Bool(true)),
        ]);
        let decoded: Cbor = ciborium::from_reader(&encode(map)[..]).unwrap();
        let keys: Vec<String> = as_map(&decoded)
            .unwrap()
            .iter()
            .map(|(k, _)| as_text(k).unwrap().to_string())
            .collect();
        assert_eq!(keys, ["rk", "up", "uv", "plat"]);
    }

    #[test]
    fn nested_maps_are_sorted_too() {
        let map = Cbor::Map(vec![(
            int(1),
            Cbor::Map(vec![(text("b"), int(2)), (text("a"), int(1))]),
        )]);
        let decoded: Cbor = ciborium::from_reader(&encode(map)[..]).unwrap();
        let inner = get(as_map(&decoded).unwrap(), 1).unwrap();
        let keys: Vec<String> = as_map(inner)
            .unwrap()
            .iter()
            .map(|(k, _)| as_text(k).unwrap().to_string())
            .collect();
        assert_eq!(keys, ["a", "b"]);
    }

    #[test]
    fn maps_inside_arrays_are_sorted() {
        let map = Cbor::Array(vec![Cbor::Map(vec![
            (text("bb"), int(2)),
            (text("a"), int(1)),
        ])]);
        let decoded: Cbor = ciborium::from_reader(&encode(map)[..]).unwrap();
        let first = &as_array(&decoded).unwrap()[0];
        let keys: Vec<String> = as_map(first)
            .unwrap()
            .iter()
            .map(|(k, _)| as_text(k).unwrap().to_string())
            .collect();
        assert_eq!(keys, ["a", "bb"]);
    }

    #[test]
    fn integer_keys_sort_before_text_keys() {
        // Major type 0 (unsigned) precedes major type 3 (text).
        let map = Cbor::Map(vec![(text("a"), int(1)), (int(9), int(2))]);
        let bytes = encode(map);
        assert_eq!(bytes[1], 0x09);
    }

    #[test]
    fn typed_accessors_reject_the_wrong_major_type() {
        assert_eq!(
            as_bytes(&text("no")).unwrap_err(),
            CtapError::CborUnexpectedType
        );
        assert_eq!(
            as_text(&Cbor::Bytes(vec![1])).unwrap_err(),
            CtapError::CborUnexpectedType
        );
        assert_eq!(as_bool(&int(1)).unwrap_err(), CtapError::CborUnexpectedType);
        assert_eq!(
            as_array(&int(1)).unwrap_err(),
            CtapError::CborUnexpectedType
        );
        assert_eq!(
            as_i64(&Cbor::Bool(true)).unwrap_err(),
            CtapError::CborUnexpectedType
        );
    }

    #[test]
    fn negative_algorithm_identifiers_round_trip() {
        // ES256 is -7; a naive unsigned reader would mangle it.
        assert_eq!(as_i64(&int(-7)).unwrap(), -7);
    }

    #[test]
    fn malformed_cbor_is_an_error_not_a_panic() {
        assert_eq!(decode(&[0xa1, 0x01]).unwrap_err(), CtapError::InvalidCbor);
        assert_eq!(decode(&[]).unwrap_err(), CtapError::InvalidCbor);
    }
}
