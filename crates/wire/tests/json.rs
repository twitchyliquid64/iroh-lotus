//! The JSON representation of wire types, for pushing values over APIs.
//!
//! JSON never reaches the ledger — digests and signatures are taken over
//! the canonical CBOR, which the in-crate wire tests pin. The serde impls
//! dispatch on `is_human_readable()`: enums that carry short tags on the
//! wire become adjacently tagged objects (`{"type": "int", "value": 7}`),
//! `#[cbor(key = ...)]` fields fall back to their Rust names, and byte
//! fields — keys, signatures, digests — become lowercase hex strings,
//! type-prefixed (`ed:`) for the digests that could be mistaken for one
//! another.

use std::collections::BTreeMap;
use std::fmt::Debug;

use serde::{Serialize, de::DeserializeOwned};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    keys::{Ed25519PublicKey, Ed25519Signature, Key, KeyId, PublicKey, Signature},
    msg::{
        AmendNamespaceKey, AmendOp, FullCheckpoint, IncrementDecrement, InitMsg, NamespaceKey,
        Value,
    },
    subkey::{Subkey, SubkeyPath},
};

/// Asserts the exact JSON of a value, in both directions. The expected
/// string is hand-written, not captured, so an encoding change fails the
/// test rather than silently redefining the representation.
#[track_caller]
fn assert_json<T>(value: &T, expected: &str)
where
    T: Serialize + DeserializeOwned + Debug + PartialEq,
{
    assert_eq!(
        serde_json::to_string(value).unwrap(),
        expected,
        "encoding of {value:?}"
    );

    let decoded: T = serde_json::from_str(expected).unwrap();
    assert_eq!(&decoded, value, "decoding of {expected}");
}

fn val(v: &str) -> Value {
    Value::String(v.to_string())
}

fn public_key() -> PublicKey {
    PublicKey::Ed25519(Ed25519PublicKey::from_bytes([0xab; 32]))
}

/// Each variant is an adjacently tagged object under its full name — not
/// the single-letter tags the wire encoding keys by.
#[test]
fn value_variants() {
    assert_json(&val("hi"), r#"{"type":"string","value":"hi"}"#);
    assert_json(&val(""), r#"{"type":"string","value":""}"#);
    assert_json(&Value::Int(7), r#"{"type":"int","value":7}"#);
    assert_json(&Value::Int(-1), r#"{"type":"int","value":-1}"#);
    assert_json(
        &Value::Int(i64::MAX),
        r#"{"type":"int","value":9223372036854775807}"#,
    );
    assert_json(
        &Value::Int(i64::MIN),
        r#"{"type":"int","value":-9223372036854775808}"#,
    );
    assert_json(&Value::Bool(true), r#"{"type":"bool","value":true}"#);
    assert_json(&Value::Bool(false), r#"{"type":"bool","value":false}"#);
    assert_json(&Value::Array(vec![]), r#"{"type":"array","value":[]}"#);
    assert_json(&Value::Map(BTreeMap::new()), r#"{"type":"map","value":{}}"#);
}

/// The wire tags don't leak into JSON: neither the single-letter
/// externally tagged shape nor an unknown type name decodes.
#[test]
fn value_rejects_the_wire_shape_and_unknown_types() {
    for bad in [
        r#"{"s":"hi"}"#,
        r#"{"i":7}"#,
        r#"{"type":"integer","value":7}"#,
    ] {
        assert!(
            serde_json::from_str::<Value>(bad).is_err(),
            "expected {bad} to be rejected",
        );
    }
}

#[test]
fn value_arrays_and_maps_nest() {
    assert_json(
        &Value::Array(vec![Value::Bool(true), Value::Array(vec![val("x")])]),
        r#"{"type":"array","value":[{"type":"bool","value":true},{"type":"array","value":[{"type":"string","value":"x"}]}]}"#,
    );
    assert_json(
        &Value::Map(BTreeMap::from([
            ("z".to_string(), val("1")),
            ("aa".to_string(), val("2")),
        ])),
        r#"{"type":"map","value":{"aa":{"type":"string","value":"2"},"z":{"type":"string","value":"1"}}}"#,
    );
}

/// The `#[cbor(key = ...)]` integer keys are a CBOR affair: JSON sees the
/// Rust field names, and the public key as hex under its scheme.
#[test]
fn value_holds_a_key() {
    let key = Key::new(public_key(), 7).with_metadata(BTreeMap::from([(
        "operator".to_string(),
        "alice".to_string(),
    )]));

    assert_json(
        &Value::Key(key),
        &format!(
            r#"{{"type":"key","value":{{"public_key":{{"type":"ed25519","value":"{}"}},"weight":7,"metadata":{{"operator":"alice"}}}}}}"#,
            "ab".repeat(32)
        ),
    );
}

/// A whole message: the `Msg` and `AmendOp` tags spell out their variant
/// names, subkey paths are arrays of tagged segments, unset bounds are
/// null.
#[test]
fn msg_round_trips() {
    let msg = Msg::AmendNamespaceKey(AmendNamespaceKey {
        prev: EnvelopeDigest::from_bytes([0xab; 32]),
        key: NamespaceKey::try_new("a").unwrap(),
        path: Some(
            SubkeyPath::try_new(vec![Subkey::Key("servers".to_string()), Subkey::Index(0)])
                .unwrap(),
        ),
        op: AmendOp::IncrementDecrement(IncrementDecrement::new(5).with_min(0)),
    });

    assert_json(
        &msg,
        &format!(
            r#"{{"type":"amend_namespace_key","value":{{"prev":"ed:{}","key":"a","path":[{{"type":"key","value":"servers"}},{{"type":"index","value":0}}],"op":{{"type":"increment_decrement","value":{{"delta":5,"min":0,"max":null}}}}}}}}"#,
            "ab".repeat(32)
        ),
    );
}

/// Key ids serialize as hex strings, so a signature map keyed by them is
/// representable in JSON at all — JSON object keys must be strings.
#[test]
fn envelope_round_trips() {
    let envelope = Envelope::new(Msg::Init(InitMsg {
        state: FullCheckpoint::default(),
    }))
    .with_signature(
        KeyId::from_bytes([0xef; 32]),
        Signature::Ed25519(Ed25519Signature::from_bytes([0xcd; 64])),
    );

    assert_json(
        &envelope,
        &format!(
            r#"{{"payload":{{"type":"init","value":{{"state":{{"namespaces":{{}}}}}}}},"signatures":{{"{}":{{"type":"ed25519","value":"{}"}}}},"timestamps":[]}}"#,
            "ef".repeat(32),
            "cd".repeat(64)
        ),
    );
}

/// The digest carries an `ed:` type prefix, so a digest of one kind
/// pasted where another belongs fails to parse instead of resolving to
/// the wrong thing.
#[test]
fn digests_encode_as_prefixed_lowercase_hex() {
    assert_json(
        &EnvelopeDigest::from_bytes([0xab; 32]),
        &format!("\"ed:{}\"", "ab".repeat(32)),
    );
}

/// Hex decodes in either case — only encoding is pinned to lowercase.
/// The prefix itself is verbatim.
#[test]
fn json_hex_decodes_either_case() {
    let upper = format!("\"ed:{}\"", "AB".repeat(32));
    let decoded: EnvelopeDigest = serde_json::from_str(&upper).unwrap();
    assert_eq!(decoded, EnvelopeDigest::from_bytes([0xab; 32]));
}

#[test]
fn json_hex_rejects_wrong_shape_length_or_prefix() {
    let bad = [
        format!("\"ed:{}\"", "ab".repeat(31)),         // too short
        format!("\"ed:{}\"", "ab".repeat(33)),         // too long
        format!("\"ed:{}zz\"", "ab".repeat(31)),       // right length, not hex
        format!("\"ed:+{}b\"", "ab".repeat(31)), // right length, but a sign is not a hex digit
        format!("\"{}\"", "ab".repeat(32)),      // bare hex, no prefix
        format!("\"sd:{}\"", "ab".repeat(32)),   // another digest's prefix
        format!("\"ED:{}\"", "ab".repeat(32)),   // the prefix is verbatim, not case-folded
        serde_json::to_string(&[0xabu8; 32]).unwrap(), // array of integers
        "\"\"".to_string(),
    ];
    for bad in bad {
        assert!(
            serde_json::from_str::<EnvelopeDigest>(&bad).is_err(),
            "expected {bad} to be rejected",
        );
    }
}
