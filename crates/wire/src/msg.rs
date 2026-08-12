//! Specific message types.
//!
//! [`Msg`] is re-exported at the crate root; the payload types it wraps
//! are reached through this module, which keeps names as general as
//! [`Value`] and [`Namespace`] qualified at the use site.

use std::collections::BTreeMap;

use cbor2::Cbor;

use crate::EnvelopeDigest;

/// A specific message in the ledger.
///
/// Variants are renamed to single letters to shorten their wire encoding.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub enum Msg {
    /// The first message, establishes the initial data of the ledger and
    /// shared parameters.
    #[serde(rename = "i")]
    Init(InitMsg),
    /// Sets the value of a namespace entirely.
    #[serde(rename = "s")]
    SetNamespace(SetNamespace),
    /// Deletes an entire namespace.
    #[serde(rename = "dn")]
    DeleteNamespace(DeleteNamespace),
}

impl Msg {
    /// The digest of the previous envelope in the ledger.
    pub fn prev_digest(&self) -> Option<&EnvelopeDigest> {
        match self {
            Msg::Init(_) => None,
            Msg::SetNamespace(s) => Some(&s.prev),
            Msg::DeleteNamespace(d) => Some(&d.prev),
        }
    }

    /// The digest of the previous envelope in the ledger.
    ///
    /// # Panics
    ///
    /// Will panic if the message is of variant `Init`.
    pub fn must_prev_digest(&self) -> &EnvelopeDigest {
        match self {
            Msg::Init(_) => panic!("must_prev_digest called on Msg::Init"),
            Msg::SetNamespace(s) => &s.prev,
            Msg::DeleteNamespace(d) => &d.prev,
        }
    }
}

/// The first message in the ledger.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct InitMsg {
    #[cbor(key = 1)]
    state: FullCheckpoint,
}

/// A complete encoding of the data contained in the ledger.
#[derive(Debug, Default, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct FullCheckpoint {
    #[cbor(key = 1)]
    namespaces: BTreeMap<String, Namespace>,
    #[cbor(key = 2)]
    config: LedgerConfig,
}

/// The configuration of the ledger.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct LedgerConfig {
    /// The minimum number of minutes a message must be kept by all
    /// nodes before it is eligible for compaction.
    ///
    /// The determination that enough time has passed MUST be relative
    /// to a local time source, and/or using a signed timestamp.
    #[cbor(key = 1)]
    min_keep_minutes: usize,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            min_keep_minutes: 5 * 24 * 60,
        }
    }
}

/// Sets / overwrites a namespace.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct SetNamespace {
    #[cbor(key = 1)]
    prev: EnvelopeDigest,
    #[cbor(key = 2)]
    key: String,
    #[cbor(key = 3)]
    namespace: Namespace,
}

/// Deletes a namespace.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct DeleteNamespace {
    #[cbor(key = 1)]
    prev: EnvelopeDigest,
    #[cbor(key = 2)]
    key: String,
}

/// A complete representation of the data & configuration of a namespace.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct Namespace {
    #[cbor(key = 1)]
    value: Value,
}

/// A data value.
///
/// Variants are renamed to single letters to shorten their wire encoding.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub enum Value {
    #[serde(rename = "s")]
    String(String),
    #[serde(rename = "i")]
    Int(i64),
    #[serde(rename = "b")]
    Bool(bool),
    #[serde(rename = "a")]
    Array(Vec<Value>),
    #[serde(rename = "m")]
    Map(BTreeMap<String, Value>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::assert_wire;

    fn val(v: &str) -> Value {
        Value::String(v.to_string())
    }

    fn ns(v: &str) -> Namespace {
        Namespace { value: val(v) }
    }

    /// Each variant is a one-entry map keyed by the renamed variant tag:
    /// `a1` (map, 1 pair), `61 xx` (1-char text key), then the payload.
    #[test]
    fn value_variants() {
        assert_wire(&Value::String("hi".into()), "a16173626869");
        assert_wire(&Value::String(String::new()), "a1617360");
        assert_wire(&Value::Int(7), "a1616907");
        assert_wire(&Value::Int(-1), "a1616920");
        assert_wire(&Value::Int(i64::MAX), "a161691b7fffffffffffffff");
        assert_wire(&Value::Bool(true), "a16162f5");
        assert_wire(&Value::Bool(false), "a16162f4");
        assert_wire(&Value::Array(vec![]), "a1616180");
    }

    #[test]
    fn value_arrays_nest() {
        assert_wire(
            &Value::Array(vec![Value::Bool(true), Value::Int(1)]),
            "a1616182a16162f5a1616901",
        );
        assert_wire(
            &Value::Array(vec![Value::Array(vec![Value::String("x".into())])]),
            "a1616181a1616181a161736178",
        );
    }

    /// `#[cbor(key = 1)]` on a struct field emits the integer key `01`,
    /// not the field name.
    #[test]
    fn namespace_uses_integer_field_key() {
        assert_wire(&ns("hi"), "a101a16173626869");
    }

    /// `min_keep_minutes` is a bare unsigned integer under key `01`, so its
    /// width tracks the value: `00` at zero, `19 xxxx` once past 255.
    #[test]
    fn config_encodes_min_keep_minutes() {
        assert_wire(
            &LedgerConfig {
                min_keep_minutes: 0,
            },
            "a10100",
        );
        assert_wire(
            &LedgerConfig {
                min_keep_minutes: 23,
            },
            "a10117",
        );
        assert_wire(
            &LedgerConfig {
                min_keep_minutes: 24,
            },
            "a1011818",
        );
        assert_wire(&LedgerConfig::default(), "a101191c20");
    }

    #[test]
    fn checkpoint_roundtrips() {
        // a2          map(2)
        //   01 a0     namespaces = {}
        //   02 …      config = LedgerConfig::default()
        assert_wire(&FullCheckpoint::default(), "a201a002a101191c20");
        assert_wire(
            &FullCheckpoint {
                namespaces: BTreeMap::from([("a".to_string(), ns("1"))]),
                ..Default::default()
            },
            "a201a16161a101a16173613102a101191c20",
        );
    }

    /// Map keys must be sorted the way RFC 8949 §4.2.1 requires — bytewise
    /// over the *encoded* key, which is length-first for text strings. That
    /// disagrees with `BTreeMap`'s plain lexicographic ordering: the map
    /// iterates `"aa"` before `"z"`, the wire format must put `"z"` first.
    #[test]
    fn checkpoint_sorts_keys_canonically() {
        assert_wire(
            &FullCheckpoint {
                namespaces: BTreeMap::from([
                    ("z".to_string(), ns("1")),
                    ("aa".to_string(), ns("2")),
                ]),
                ..Default::default()
            },
            "a201a2617aa101a161736131626161a101a16173613202a101191c20",
        );
    }

    /// Insertion order must not reach the wire.
    #[test]
    fn checkpoint_encoding_depends_only_on_content() {
        let forwards = FullCheckpoint {
            namespaces: BTreeMap::from([("z".to_string(), ns("1")), ("aa".to_string(), ns("2"))]),
            ..Default::default()
        };
        let backwards = FullCheckpoint {
            namespaces: BTreeMap::from([("aa".to_string(), ns("2")), ("z".to_string(), ns("1"))]),
            ..Default::default()
        };

        assert_eq!(
            crate::encode(&forwards).unwrap(),
            crate::encode(&backwards).unwrap(),
        );
    }

    #[test]
    fn msg_wraps_checkpoint() {
        let msg = Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: BTreeMap::new(),
                ..Default::default()
            },
        });
        assert_wire(&msg, "a16169a101a201a002a101191c20");
    }

    /// `Value::Map` sorts its keys the same canonical way a checkpoint does.
    #[test]
    fn value_maps_nest() {
        assert_wire(&Value::Map(BTreeMap::new()), "a1616da0");
        assert_wire(
            &Value::Map(BTreeMap::from([("a".to_string(), val("1"))])),
            "a1616da16161a161736131",
        );
        assert_wire(
            &Value::Map(BTreeMap::from([
                ("z".to_string(), val("1")),
                ("aa".to_string(), val("2")),
            ])),
            "a1616da2617aa161736131626161a161736132",
        );
    }

    /// `a3` (map, 3 pairs): the digest as a byte string under `01`, the
    /// namespace name under `02`, the namespace itself under `03`.
    #[test]
    fn set_namespace_carries_prev_digest() {
        let msg = Msg::SetNamespace(SetNamespace {
            prev: EnvelopeDigest::from_bytes([0xab; 32]),
            key: "a".to_string(),
            namespace: ns("1"),
        });
        assert_wire(
            &msg,
            &format!(
                "a16173a3015820{}026161{}",
                "ab".repeat(32),
                "03a101a161736131"
            ),
        );
    }

    /// Only `SetNamespace` chains; `Init` starts the ledger and has nothing
    /// to point back at.
    #[test]
    fn prev_digest_is_absent_only_for_init() {
        let init = Msg::Init(InitMsg {
            state: FullCheckpoint::default(),
        });
        assert_eq!(init.prev_digest(), None);

        let digest = EnvelopeDigest::from_bytes([0xab; 32]);
        let set = Msg::SetNamespace(SetNamespace {
            prev: digest,
            key: "a".to_string(),
            namespace: ns("1"),
        });
        assert_eq!(set.prev_digest(), Some(&digest));
        assert_eq!(set.must_prev_digest(), &digest);
    }

    #[test]
    #[should_panic(expected = "must_prev_digest called on Msg::Init")]
    fn must_prev_digest_panics_on_init() {
        let init = Msg::Init(InitMsg {
            state: FullCheckpoint::default(),
        });
        init.must_prev_digest();
    }
}
