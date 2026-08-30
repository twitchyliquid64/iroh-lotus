//! Specific message types.
//!
//! [`Msg`] is re-exported at the crate root; the payload types it wraps
//! are reached through this module, which keeps names as general as
//! [`Value`] and [`Namespace`] qualified at the use site.

use core::fmt;
use std::collections::BTreeMap;

use cbor2::Cbor;
use nutype::nutype;

use crate::{
    EnvelopeDigest,
    codec::dual_repr,
    keys::Key,
    subkey::{Subkey, SubkeyPath},
};

/// The name a namespace is stored under in the ledger.
#[nutype(
    validate(not_empty),
    derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        AsRef,
        Display,
        Borrow,
        Serialize,
        Deserialize
    )
)]
pub struct NamespaceKey(String);

/// A specific message in the ledger.
///
/// `dual_repr!` below defines the serde representations: integer wire
/// tags, adjacently tagged full names in JSON.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Msg {
    /// The first message, establishes the initial data of the ledger and
    /// shared parameters.
    Init(InitMsg),
    /// Sets the value of a namespace entirely.
    SetNamespace(SetNamespace),
    /// Sets or clears a single value nested inside a namespace.
    SetNamespaceKey(SetNamespaceKey),
    /// Amends a single value nested inside a namespace in place.
    AmendNamespaceKey(AmendNamespaceKey),
    /// Deletes an entire namespace.
    DeleteNamespace(DeleteNamespace),
}

dual_repr! {
    Msg {
        Init(InitMsg) = 1 | "init",
        SetNamespace(SetNamespace) = 2 | "set_namespace",
        SetNamespaceKey(SetNamespaceKey) = 3 | "set_namespace_key",
        AmendNamespaceKey(AmendNamespaceKey) = 4 | "amend_namespace_key",
        DeleteNamespace(DeleteNamespace) = 5 | "delete_namespace",
    }
}

impl Msg {
    /// The digest of the previous envelope in the ledger.
    pub fn prev_digest(&self) -> Option<&EnvelopeDigest> {
        match self {
            Msg::Init(_) => None,
            Msg::SetNamespace(s) => Some(&s.prev),
            Msg::SetNamespaceKey(s) => Some(&s.prev),
            Msg::AmendNamespaceKey(a) => Some(&a.prev),
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
            Msg::SetNamespaceKey(s) => &s.prev,
            Msg::AmendNamespaceKey(a) => &a.prev,
            Msg::DeleteNamespace(d) => &d.prev,
        }
    }
}

/// The first message in the ledger.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct InitMsg {
    #[cbor(key = 1)]
    pub state: FullCheckpoint,
}

/// A complete encoding of the data contained in the ledger.
#[derive(Debug, Default, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct FullCheckpoint {
    #[cbor(key = 1)]
    pub namespaces: BTreeMap<NamespaceKey, Namespace>,
}

/// Sets / overwrites a namespace.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct SetNamespace {
    #[cbor(key = 1)]
    pub prev: EnvelopeDigest,
    #[cbor(key = 2)]
    pub key: NamespaceKey,
    #[cbor(key = 3)]
    pub namespace: Namespace,
}

/// Sets or clears a single value nested inside a namespace.
///
/// Lets a large namespace be amended without republishing the whole of it.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct SetNamespaceKey {
    #[cbor(key = 1)]
    pub prev: EnvelopeDigest,
    #[cbor(key = 2)]
    pub key: NamespaceKey,
    /// The path to walk from the namespace's value to the value being set.
    #[cbor(key = 3)]
    pub path: SubkeyPath,
    /// The value to write, or `None` to clear what the path addresses.
    #[cbor(key = 4)]
    pub value: Option<Value>,
}

/// Amends a single value nested inside a namespace in place.
///
/// Where [`SetNamespaceKey`] replaces what a path addresses, this derives
/// the new value from the old one — the message carries only the change,
/// however large the value it amends.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct AmendNamespaceKey {
    #[cbor(key = 1)]
    pub prev: EnvelopeDigest,
    #[cbor(key = 2)]
    pub key: NamespaceKey,
    /// The path to walk from the namespace's value to the value being
    /// amended, or `None` to amend the namespace's value as a whole —
    /// a namespace that is one array or one integer.
    #[cbor(key = 3)]
    pub path: Option<SubkeyPath>,
    #[cbor(key = 4)]
    pub op: AmendOp,
}

/// How an [`AmendNamespaceKey`] transforms the value its path addresses.
///
/// `dual_repr!` below defines the serde representations: integer wire
/// tags, adjacently tagged full names in JSON.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum AmendOp {
    /// Appends the entry to the array at the path. A path addressing
    /// nothing creates a one-entry array — as a fresh key under an
    /// existing map only.
    AppendEntry(Value),
    /// Adds a delta to the integer at the path, which must exist,
    /// clamping the sum to the bounds that are set.
    IncrementDecrement(IncrementDecrement),
    /// Removes every entry of the map or array at the path — which must
    /// exist — that the predicate matches. Later array indices shift
    /// down. Idempotent: matching nothing removes nothing.
    DeleteMatching(Predicate),
}

dual_repr! {
    AmendOp {
        AppendEntry(Value) = 1 | "append_entry",
        IncrementDecrement(IncrementDecrement) = 2 | "increment_decrement",
        DeleteMatching(Predicate) = 3 | "delete_matching",
    }
}

/// The conditions an entry must meet, every one of them, for
/// [`AmendOp::DeleteMatching`] to remove it.
///
/// Never empty: with no condition every entry would match, and emptying
/// a container is [`SetNamespaceKey`]'s job, said outright.
#[nutype(
    validate(predicate = |matches| !matches.is_empty()),
    derive(Debug, Clone, PartialEq, Eq, Hash, AsRef, Serialize, Deserialize)
)]
pub struct Predicate(Vec<Match>);

impl Predicate {
    /// Whether `entry` meets every condition.
    pub fn matches(&self, entry: &Value) -> bool {
        self.as_ref().iter().all(|m| m.matches(entry))
    }
}

/// One condition of a [`Predicate`]: the value at `path` inside an entry
/// equals `value`. An entry the path does not reach — a leaf where a map
/// is expected, a key it lacks, an index past its end — does not match.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct Match {
    /// Where to look inside the entry, or `None` for the entry itself.
    #[cbor(key = 1)]
    pub path: Option<SubkeyPath>,
    #[cbor(key = 2)]
    pub value: Value,
}

impl Match {
    /// Matches the entry itself against `value`.
    pub fn entry(value: Value) -> Self {
        Self { path: None, value }
    }

    /// Matches what `path` addresses inside the entry against `value`.
    pub fn at(path: SubkeyPath, value: Value) -> Self {
        Self {
            path: Some(path),
            value,
        }
    }

    /// Whether `entry` meets this condition.
    pub fn matches(&self, entry: &Value) -> bool {
        self.path
            .as_ref()
            .map_or(&[][..], |path| path.as_ref())
            .iter()
            .try_fold(entry, |value, segment| match (value, segment) {
                (Value::Map(map), Subkey::Key(key)) => map.get(key),
                (Value::Array(array), Subkey::Index(index)) => array.get(*index as usize),
                _ => None,
            })
            .is_some_and(|found| found == &self.value)
    }
}

/// Adds a delta — possibly negative — to an integer, then clamps the sum
/// to whichever of `min` and `max` are set.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct IncrementDecrement {
    #[cbor(key = 1)]
    pub delta: i64,
    /// The floor the sum is clamped up to, when set.
    #[cbor(key = 2)]
    pub min: Option<i64>,
    /// The ceiling the sum is clamped down to, when set.
    #[cbor(key = 3)]
    pub max: Option<i64>,
}

impl IncrementDecrement {
    /// An unclamped increment of `delta`.
    pub fn new(delta: i64) -> Self {
        Self {
            delta,
            min: None,
            max: None,
        }
    }

    /// Clamps the sum up to `min`.
    pub fn with_min(mut self, min: i64) -> Self {
        self.min = Some(min);
        self
    }

    /// Clamps the sum down to `max`.
    pub fn with_max(mut self, max: i64) -> Self {
        self.max = Some(max);
        self
    }

    /// The integer `n` becomes: the delta added, then clamped to the
    /// bounds that are set. `None` when the sum leaves `i64` with no
    /// bound on that side to pull it back.
    ///
    /// Callers must have refused a `min` above `max`; on such bounds the
    /// max wins, deterministically, rather than panicking.
    pub fn apply(&self, n: i64) -> Option<i64> {
        match n.checked_add(self.delta) {
            Some(sum) => {
                let floored = self.min.map_or(sum, |min| sum.max(min));
                Some(self.max.map_or(floored, |max| floored.min(max)))
            }
            // The true sum is beyond i64 on the delta's side; only a
            // bound on that side can represent the clamped result.
            None if self.delta > 0 => self.max,
            None => self.min,
        }
    }
}

/// Deletes a namespace.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct DeleteNamespace {
    #[cbor(key = 1)]
    pub prev: EnvelopeDigest,
    #[cbor(key = 2)]
    pub key: NamespaceKey,
}

/// A complete representation of the data & configuration of a namespace.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct Namespace {
    #[cbor(key = 1)]
    pub value: Value,
}

/// A data value.
///
/// `dual_repr!` below defines the serde representations: integer wire
/// tags (`{2: 7}`), adjacently tagged full names in JSON
/// (`{"type": "int", "value": 7}`) — the latter pinned by `tests/json.rs`.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Value {
    String(String),
    Int(i64),
    Bool(bool),
    Array(Vec<Value>),
    Map(BTreeMap<String, Value>),
    /// A key in the ledger's trusted key set. A leaf: subkey paths do not
    /// reach inside one, so a key is replaced whole rather than amended
    /// field by field.
    Key(Key),
}

dual_repr! {
    Value {
        String(String) = 1 | "string",
        Int(i64) = 2 | "int",
        Bool(bool) = 3 | "bool",
        Array(Vec<Value>) = 4 | "array",
        Map(BTreeMap<String, Value>) = 5 | "map",
        Key(Key) = 6 | "key",
    }
}

/// Field names an [`iroh::EndpointAddr`] takes in a [`Value::Map`], and
/// the `type` tags its transport addresses are written under. Named once
/// so both directions of the conversion stay in step.
const ENDPOINT_ID: &str = "endpoint_id";
/// The field holding the transport addresses, as an array. Public so a
/// writer can amend that array entry by entry rather than rewriting the
/// whole address around it.
pub const ADDRS: &str = "addrs";
const ADDR_TYPE: &str = "type";
const ADDR: &str = "addr";
const RELAY: &str = "relay";
const IP: &str = "ip";
const CUSTOM: &str = "custom";

/// Why a [`Value`] could not be read as an iroh address, or an iroh
/// address could not be written as a [`Value`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddrError {
    /// A value that must be a map was not one. Holds what was expected.
    NotAMap(&'static str),
    /// A required string field was absent or held something other than a
    /// string. Holds the field name.
    MissingField(&'static str),
    /// `addrs` held something other than an array.
    AddrsNotAnArray,
    /// `endpoint_id` was not a z-base-32 public key. Holds the text.
    BadEndpointId(String),
    /// An `addrs` entry named a known type but its `addr` did not parse as
    /// one. Holds the type and the text.
    BadAddr {
        /// The `type` the entry named.
        kind: String,
        /// The `addr` that did not parse.
        text: String,
    },
    /// An `addrs` entry named a type this build has no transport for. Holds
    /// the type. Reading a whole endpoint address skips such entries.
    UnknownAddrType(String),
    /// An iroh transport address of a kind this crate has no encoding for.
    /// Holds its display form.
    UnsupportedAddr(String),
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrError::NotAMap(what) => write!(f, "a {what} is a map"),
            AddrError::MissingField(field) => write!(f, "no `{field}` string"),
            AddrError::AddrsNotAnArray => write!(f, "`{ADDRS}` is an array"),
            AddrError::BadEndpointId(text) => write!(f, "{text} is not an endpoint id"),
            AddrError::BadAddr { kind, text } => write!(f, "{text} is not a {kind} address"),
            AddrError::UnknownAddrType(kind) => write!(f, "no transport is called {kind}"),
            AddrError::UnsupportedAddr(addr) => write!(f, "{addr} has no ledger encoding"),
        }
    }
}

impl core::error::Error for AddrError {}

impl TryFrom<&Value> for iroh::EndpointAddr {
    type Error = AddrError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let Value::Map(fields) = value else {
            return Err(AddrError::NotAMap("endpoint address"));
        };

        let id = match fields.get(ENDPOINT_ID) {
            Some(Value::String(id)) => id,
            _ => return Err(AddrError::MissingField(ENDPOINT_ID)),
        };
        let id =
            iroh::EndpointId::from_z32(id).map_err(|_| AddrError::BadEndpointId(id.to_string()))?;

        let addrs = match fields.get(ADDRS) {
            Some(Value::Array(addrs)) => addrs,
            Some(_) => return Err(AddrError::AddrsNotAnArray),
            None => return Err(AddrError::MissingField(ADDRS)),
        };

        Ok(iroh::EndpointAddr::from_parts(
            id,
            addrs
                .iter()
                .map(iroh::TransportAddr::try_from)
                // A newer node lists transports this build has no variant
                // for; dial by the ones it does understand rather than
                // refusing the whole address over them.
                .filter(|addr| !matches!(addr, Err(AddrError::UnknownAddrType(_))))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

impl TryFrom<&iroh::EndpointAddr> for Value {
    type Error = AddrError;

    fn try_from(addr: &iroh::EndpointAddr) -> Result<Self, Self::Error> {
        Ok(Value::Map(BTreeMap::from([
            (ENDPOINT_ID.to_string(), Value::String(addr.id.to_z32())),
            (
                ADDRS.to_string(),
                Value::Array(
                    addr.addrs
                        .iter()
                        .map(Value::try_from)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
        ])))
    }
}

impl TryFrom<&Value> for iroh::TransportAddr {
    type Error = AddrError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let Value::Map(fields) = value else {
            return Err(AddrError::NotAMap("transport address"));
        };

        let kind = match fields.get(ADDR_TYPE) {
            Some(Value::String(kind)) => kind,
            _ => return Err(AddrError::MissingField(ADDR_TYPE)),
        };
        let addr = match fields.get(ADDR) {
            Some(Value::String(addr)) => addr,
            _ => return Err(AddrError::MissingField(ADDR)),
        };
        let bad = || AddrError::BadAddr {
            kind: kind.to_string(),
            text: addr.to_string(),
        };

        match kind.as_str() {
            RELAY => addr
                .parse()
                .map(iroh::TransportAddr::Relay)
                .map_err(|_| bad()),
            IP => addr.parse().map(iroh::TransportAddr::Ip).map_err(|_| bad()),
            CUSTOM => addr
                .parse()
                .map(iroh::TransportAddr::Custom)
                .map_err(|_| bad()),
            _ => Err(AddrError::UnknownAddrType(kind.to_string())),
        }
    }
}

impl TryFrom<&iroh::TransportAddr> for Value {
    type Error = AddrError;

    fn try_from(addr: &iroh::TransportAddr) -> Result<Self, Self::Error> {
        let (kind, text) = match addr {
            iroh::TransportAddr::Relay(url) => (RELAY, url.to_string()),
            iroh::TransportAddr::Ip(socket) => (IP, socket.to_string()),
            iroh::TransportAddr::Custom(custom) => (CUSTOM, custom.to_string()),
            // `TransportAddr` is `#[non_exhaustive]`: a variant added
            // upstream has no encoding here until one is chosen for it.
            other => return Err(AddrError::UnsupportedAddr(other.to_string())),
        };

        Ok(Value::Map(BTreeMap::from([
            (ADDR_TYPE.to_string(), Value::String(kind.to_string())),
            (ADDR.to_string(), Value::String(text)),
        ])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keys::{Ed25519PublicKey, PublicKey},
        subkey::Subkey,
        testutil::{assert_wire, unhex},
    };

    fn val(v: &str) -> Value {
        Value::String(v.to_string())
    }

    fn ns(v: &str) -> Namespace {
        Namespace { value: val(v) }
    }

    fn key(k: &str) -> NamespaceKey {
        NamespaceKey::try_new(k).unwrap()
    }

    /// Each variant is a one-pair map keyed by the variant's integer tag —
    /// the same shape integer-keyed struct fields use: `a1` (map, 1 pair),
    /// the tag (`01`…), then the payload.
    #[test]
    fn value_variants() {
        assert_wire(&Value::String("hi".into()), "a101626869");
        assert_wire(&Value::String(String::new()), "a10160");
        assert_wire(&Value::Int(7), "a10207");
        assert_wire(&Value::Int(-1), "a10220");
        assert_wire(&Value::Int(i64::MAX), "a1021b7fffffffffffffff");
        assert_wire(&Value::Bool(true), "a103f5");
        assert_wire(&Value::Bool(false), "a103f4");
        assert_wire(&Value::Array(vec![]), "a10480");
    }

    /// `a1 06` wraps the key, which carries its own three-pair map:
    /// the public key under `01`, the weight under `02`, metadata under
    /// `03`. A key is a value like any other, so the trusted key set is
    /// ordinary namespace data.
    #[test]
    fn value_holds_a_key() {
        assert_wire(
            &Value::Key(Key::new(
                PublicKey::Ed25519(Ed25519PublicKey::from_bytes([0xab; 32])),
                7,
            )),
            &format!("a106a301a1015820{}020703a0", "ab".repeat(32)),
        );
    }

    #[test]
    fn value_arrays_nest() {
        assert_wire(
            &Value::Array(vec![Value::Bool(true), Value::Int(1)]),
            "a10482a103f5a10201",
        );
        assert_wire(
            &Value::Array(vec![Value::Array(vec![Value::String("x".into())])]),
            "a10481a10481a1016178",
        );
    }

    /// `#[cbor(key = 1)]` on a struct field emits the integer key `01`,
    /// not the field name.
    #[test]
    fn namespace_uses_integer_field_key() {
        assert_wire(&ns("hi"), "a101a101626869");
    }

    #[test]
    fn checkpoint_roundtrips() {
        // a1          map(1)
        //   01 a0     namespaces = {}
        assert_wire(&FullCheckpoint::default(), "a101a0");
        assert_wire(
            &FullCheckpoint {
                namespaces: BTreeMap::from([(key("a"), ns("1"))]),
            },
            "a101a16161a101a1016131",
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
                namespaces: BTreeMap::from([(key("z"), ns("1")), (key("aa"), ns("2"))]),
            },
            "a101a2617aa101a1016131626161a101a1016132",
        );
    }

    /// Insertion order must not reach the wire.
    #[test]
    fn checkpoint_encoding_depends_only_on_content() {
        let forwards = FullCheckpoint {
            namespaces: BTreeMap::from([(key("z"), ns("1")), (key("aa"), ns("2"))]),
        };
        let backwards = FullCheckpoint {
            namespaces: BTreeMap::from([(key("aa"), ns("2")), (key("z"), ns("1"))]),
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
            },
        });
        assert_wire(&msg, "a101a101a101a0");
    }

    /// `Value::Map` sorts its keys the same canonical way a checkpoint does.
    #[test]
    fn value_maps_nest() {
        assert_wire(&Value::Map(BTreeMap::new()), "a105a0");
        assert_wire(
            &Value::Map(BTreeMap::from([("a".to_string(), val("1"))])),
            "a105a16161a1016131",
        );
        assert_wire(
            &Value::Map(BTreeMap::from([
                ("z".to_string(), val("1")),
                ("aa".to_string(), val("2")),
            ])),
            "a105a2617aa1016131626161a1016132",
        );
    }

    fn endpoint_id(seed: u8) -> iroh::EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// `iroh` does not export `CustomAddr`, so the one way to name a custom
    /// transport is to read one back.
    fn custom_addr(text: &str) -> iroh::TransportAddr {
        iroh::TransportAddr::try_from(&addr_entry("custom", text)).unwrap()
    }

    fn addr_entry(kind: &str, addr: &str) -> Value {
        Value::Map(BTreeMap::from([
            ("type".to_string(), val(kind)),
            ("addr".to_string(), val(addr)),
        ]))
    }

    /// The shape endpoint addresses take in the ledger, pinned: a map of
    /// the z-base-32 id and an array of `type`/`addr` entries.
    #[test]
    fn endpoint_addr_writes_a_tagged_map() {
        let id = endpoint_id(7);
        let addr = iroh::EndpointAddr::from_parts(
            id,
            [
                iroh::TransportAddr::Ip("192.0.2.1:4433".parse().unwrap()),
                iroh::TransportAddr::Relay("https://relay.example./".parse().unwrap()),
                custom_addr("1f_dead"),
            ],
        );

        assert_eq!(
            Value::try_from(&addr).unwrap(),
            Value::Map(BTreeMap::from([
                ("endpoint_id".to_string(), val(&id.to_z32())),
                (
                    "addrs".to_string(),
                    // Sorted the way `BTreeSet<TransportAddr>` holds them:
                    // by variant, relay first.
                    Value::Array(vec![
                        addr_entry("relay", "https://relay.example./"),
                        addr_entry("ip", "192.0.2.1:4433"),
                        addr_entry("custom", "1f_dead"),
                    ]),
                ),
            ])),
        );
    }

    #[test]
    fn endpoint_addr_roundtrips() {
        let addr = iroh::EndpointAddr::from_parts(
            endpoint_id(1),
            [
                iroh::TransportAddr::Ip("192.0.2.1:4433".parse().unwrap()),
                iroh::TransportAddr::Ip("[2001:db8::1]:4433".parse().unwrap()),
                iroh::TransportAddr::Relay("https://relay.example./".parse().unwrap()),
                custom_addr("1f_dead"),
            ],
        );

        let value = Value::try_from(&addr).unwrap();
        assert_eq!(iroh::EndpointAddr::try_from(&value).unwrap(), addr);
    }

    /// An id alone is a usable address — address lookup can supply the rest.
    #[test]
    fn endpoint_addr_roundtrips_without_addrs() {
        let addr = iroh::EndpointAddr::new(endpoint_id(2));

        let value = Value::try_from(&addr).unwrap();
        assert_eq!(iroh::EndpointAddr::try_from(&value).unwrap(), addr);
        assert!(iroh::EndpointAddr::try_from(&value).unwrap().is_empty());
    }

    /// A ledger written by a newer node can name transports this build has
    /// no variant for; the entries it does understand still come through.
    #[test]
    fn endpoint_addr_skips_unknown_transports() {
        let id = endpoint_id(3);
        let value = Value::Map(BTreeMap::from([
            ("endpoint_id".to_string(), val(&id.to_z32())),
            (
                "addrs".to_string(),
                Value::Array(vec![
                    addr_entry("carrier-pigeon", "loft-3"),
                    addr_entry("ip", "192.0.2.1:4433"),
                ]),
            ),
        ]));

        assert_eq!(
            iroh::EndpointAddr::try_from(&value).unwrap(),
            iroh::EndpointAddr::from_parts(
                id,
                [iroh::TransportAddr::Ip("192.0.2.1:4433".parse().unwrap())],
            ),
        );
    }

    /// Skipping is the endpoint address's leniency, not the entry's: read on
    /// its own, an unknown type is an error rather than a silent nothing.
    #[test]
    fn transport_addr_rejects_an_unknown_type() {
        assert_eq!(
            iroh::TransportAddr::try_from(&addr_entry("carrier-pigeon", "loft-3")),
            Err(AddrError::UnknownAddrType("carrier-pigeon".to_string())),
        );
    }

    /// A malformed entry of a *known* type is a real error: the writer meant
    /// an address this build understands and got it wrong.
    #[test]
    fn endpoint_addr_rejects_a_malformed_transport() {
        let value = Value::Map(BTreeMap::from([
            ("endpoint_id".to_string(), val(&endpoint_id(4).to_z32())),
            (
                "addrs".to_string(),
                Value::Array(vec![addr_entry("ip", "192.0.2.1")]),
            ),
        ]));

        assert_eq!(
            iroh::EndpointAddr::try_from(&value),
            Err(AddrError::BadAddr {
                kind: "ip".to_string(),
                text: "192.0.2.1".to_string(),
            }),
        );
    }

    #[test]
    fn transport_addr_reports_what_is_wrong() {
        assert_eq!(
            iroh::TransportAddr::try_from(&val("ip:192.0.2.1:4433")),
            Err(AddrError::NotAMap("transport address")),
        );
        assert_eq!(
            iroh::TransportAddr::try_from(&Value::Map(BTreeMap::from([(
                "addr".to_string(),
                val("192.0.2.1:4433"),
            )]))),
            Err(AddrError::MissingField("type")),
        );
        assert_eq!(
            iroh::TransportAddr::try_from(&Value::Map(BTreeMap::from([
                ("type".to_string(), val("ip")),
                ("addr".to_string(), Value::Int(4433)),
            ]))),
            Err(AddrError::MissingField("addr")),
        );
        assert_eq!(
            iroh::TransportAddr::try_from(&addr_entry("relay", "not a url")),
            Err(AddrError::BadAddr {
                kind: "relay".to_string(),
                text: "not a url".to_string(),
            }),
        );
    }

    #[test]
    fn endpoint_addr_reports_what_is_wrong() {
        assert_eq!(
            iroh::EndpointAddr::try_from(&Value::Array(vec![])),
            Err(AddrError::NotAMap("endpoint address")),
        );
        assert_eq!(
            iroh::EndpointAddr::try_from(&Value::Map(BTreeMap::from([(
                "addrs".to_string(),
                Value::Array(vec![]),
            )]))),
            Err(AddrError::MissingField("endpoint_id")),
        );
        assert_eq!(
            iroh::EndpointAddr::try_from(&Value::Map(BTreeMap::from([
                ("endpoint_id".to_string(), val("not-an-id")),
                ("addrs".to_string(), Value::Array(vec![])),
            ]))),
            Err(AddrError::BadEndpointId("not-an-id".to_string())),
        );
        assert_eq!(
            iroh::EndpointAddr::try_from(&Value::Map(BTreeMap::from([(
                "endpoint_id".to_string(),
                val(&endpoint_id(5).to_z32()),
            )]))),
            Err(AddrError::MissingField("addrs")),
        );
        assert_eq!(
            iroh::EndpointAddr::try_from(&Value::Map(BTreeMap::from([
                ("endpoint_id".to_string(), val(&endpoint_id(5).to_z32())),
                ("addrs".to_string(), val("192.0.2.1:4433")),
            ]))),
            Err(AddrError::AddrsNotAnArray),
        );
    }

    /// `a3` (map, 3 pairs): the digest as a byte string under `01`, the
    /// namespace name under `02`, the namespace itself under `03`.
    #[test]
    fn set_namespace_carries_prev_digest() {
        let msg = Msg::SetNamespace(SetNamespace {
            prev: EnvelopeDigest::from_bytes([0xab; 32]),
            key: key("a"),
            namespace: ns("1"),
        });
        assert_wire(
            &msg,
            &format!("a102a3015820{}026161{}", "ab".repeat(32), "03a101a1016131"),
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
            key: key("a"),
            namespace: ns("1"),
        });
        assert_eq!(set.prev_digest(), Some(&digest));
        assert_eq!(set.must_prev_digest(), &digest);

        let amend = Msg::AmendNamespaceKey(AmendNamespaceKey {
            prev: digest,
            key: key("a"),
            path: Some(path([Subkey::Key("b".into())])),
            op: AmendOp::IncrementDecrement(IncrementDecrement::new(1)),
        });
        assert_eq!(amend.prev_digest(), Some(&digest));
        assert_eq!(amend.must_prev_digest(), &digest);
    }

    fn path(segments: impl IntoIterator<Item = Subkey>) -> SubkeyPath {
        SubkeyPath::try_new(segments.into_iter().collect()).unwrap()
    }

    /// `a4` (map, 4 pairs): prev, namespace key, path, then the value —
    /// `f6` (null) when the message clears rather than sets.
    #[test]
    fn set_namespace_key_carries_a_path_and_optional_value() {
        let set = |value| {
            Msg::SetNamespaceKey(SetNamespaceKey {
                prev: EnvelopeDigest::from_bytes([0xab; 32]),
                key: key("a"),
                path: path([Subkey::Key("b".into())]),
                value,
            })
        };

        assert_wire(
            &set(Some(val("1"))),
            &format!(
                "a103a4015820{}0261610381a101616204a1016131",
                "ab".repeat(32)
            ),
        );
        assert_wire(
            &set(None),
            &format!("a103a4015820{}0261610381a101616204f6", "ab".repeat(32)),
        );
    }

    /// Same one-pair integer-tag shape as `Value`. An increment's payload
    /// is an `a3` (map, 3 pairs) of delta, min, max — the unset bounds
    /// encode as `f6` (null), not omitted.
    #[test]
    fn amend_op_variants() {
        assert_wire(&AmendOp::AppendEntry(Value::Int(7)), "a101a10207");
        assert_wire(&AmendOp::AppendEntry(val("1")), "a101a1016131");
        assert_wire(
            &AmendOp::IncrementDecrement(IncrementDecrement::new(0)),
            "a102a3010002f603f6",
        );
        assert_wire(
            &AmendOp::IncrementDecrement(IncrementDecrement::new(-1)),
            "a102a3012002f603f6",
        );
        assert_wire(
            &AmendOp::IncrementDecrement(IncrementDecrement::new(i64::MAX)),
            "a102a3011b7fffffffffffffff02f603f6",
        );
        assert_wire(
            &AmendOp::IncrementDecrement(IncrementDecrement::new(i64::MIN)),
            "a102a3013b7fffffffffffffff02f603f6",
        );
        assert_wire(
            &AmendOp::IncrementDecrement(IncrementDecrement::new(5).with_min(0).with_max(10)),
            "a102a301050200030a",
        );
        assert_wire(
            &AmendOp::IncrementDecrement(IncrementDecrement::new(-2).with_min(-3)),
            "a102a30121022203f6",
        );
        // A predicate is an array of conditions, each an `a2` of path
        // (`f6` for the entry itself) and value.
        assert_wire(
            &AmendOp::DeleteMatching(predicate([Match::entry(Value::Int(7))])),
            "a10381a201f602a10207",
        );
        assert_wire(
            &AmendOp::DeleteMatching(predicate([
                Match::at(path([Subkey::Key("id".into())]), val("x")),
                Match::at(path([Subkey::Index(0)]), Value::Bool(true)),
            ])),
            "a10382a20181a10162696402a1016178a20181a1020002a103f5",
        );
    }

    fn predicate(matches: impl IntoIterator<Item = Match>) -> Predicate {
        Predicate::try_new(matches.into_iter().collect()).unwrap()
    }

    #[test]
    fn predicate_rejects_empty() {
        assert!(Predicate::try_new(vec![]).is_err());
    }

    /// A condition looks at the entry itself, or at a path inside it; an
    /// entry the path does not reach never matches, whatever the value.
    #[test]
    fn match_compares_what_its_path_reaches() {
        let entry = Value::Map(BTreeMap::from([
            ("id".to_string(), val("x")),
            ("tags".to_string(), Value::Array(vec![Value::Int(1)])),
        ]));

        assert!(Match::entry(entry.clone()).matches(&entry));
        assert!(!Match::entry(val("x")).matches(&entry));

        let id = || path([Subkey::Key("id".into())]);
        assert!(Match::at(id(), val("x")).matches(&entry));
        assert!(!Match::at(id(), val("y")).matches(&entry));
        assert!(
            !Match::at(id(), val("x")).matches(&val("x")),
            "a leaf has no fields"
        );
        assert!(!Match::at(path([Subkey::Key("nope".into())]), val("x")).matches(&entry));

        let first_tag = || path([Subkey::Key("tags".into()), Subkey::Index(0)]);
        assert!(Match::at(first_tag(), Value::Int(1)).matches(&entry));
        assert!(
            !Match::at(
                path([Subkey::Key("tags".into()), Subkey::Index(1)]),
                Value::Int(1)
            )
            .matches(&entry)
        );
        assert!(
            !Match::at(path([Subkey::Key("id".into()), Subkey::Index(0)]), val("x"))
                .matches(&entry)
        );

        // Every condition must hold.
        assert!(
            predicate([
                Match::at(id(), val("x")),
                Match::at(first_tag(), Value::Int(1))
            ])
            .matches(&entry)
        );
        assert!(
            !predicate([
                Match::at(id(), val("x")),
                Match::at(first_tag(), Value::Int(2))
            ])
            .matches(&entry)
        );
    }

    #[test]
    fn increment_decrement_adds_then_clamps() {
        // Unclamped: plain addition, overflow on either side is None.
        assert_eq!(IncrementDecrement::new(3).apply(5), Some(8));
        assert_eq!(IncrementDecrement::new(-10).apply(5), Some(-5));
        assert_eq!(IncrementDecrement::new(i64::MAX).apply(5), None);
        assert_eq!(IncrementDecrement::new(i64::MIN).apply(-5), None);

        // Bounds only bind when the sum crosses them.
        let clamped = IncrementDecrement::new(7).with_min(0).with_max(10);
        assert_eq!(clamped.apply(1), Some(8));
        assert_eq!(clamped.apply(9), Some(10));
        assert_eq!(IncrementDecrement::new(-9).with_min(0).apply(5), Some(0));
        assert_eq!(IncrementDecrement::new(-9).with_max(10).apply(5), Some(-4));

        // A bound on the overflowing side catches the sum; a bound on
        // the other side does not.
        assert_eq!(
            IncrementDecrement::new(i64::MAX).with_max(10).apply(5),
            Some(10)
        );
        assert_eq!(
            IncrementDecrement::new(i64::MIN).with_min(0).apply(-5),
            Some(0)
        );
        assert_eq!(IncrementDecrement::new(i64::MAX).with_min(0).apply(5), None);
        assert_eq!(
            IncrementDecrement::new(i64::MIN).with_max(10).apply(-5),
            None
        );
    }

    /// `a4` (map, 4 pairs): prev, namespace key, path, then the amend op.
    #[test]
    fn amend_namespace_key_carries_a_path_and_op() {
        let amend = |path, op| {
            Msg::AmendNamespaceKey(AmendNamespaceKey {
                prev: EnvelopeDigest::from_bytes([0xab; 32]),
                key: key("a"),
                path,
                op,
            })
        };
        let at_b = || Some(path([Subkey::Key("b".into())]));

        assert_wire(
            &amend(at_b(), AmendOp::AppendEntry(val("1"))),
            &format!(
                "a104a4015820{}0261610381a101616204a101a1016131",
                "ab".repeat(32)
            ),
        );
        assert_wire(
            &amend(
                at_b(),
                AmendOp::IncrementDecrement(IncrementDecrement::new(5)),
            ),
            &format!(
                "a104a4015820{}0261610381a101616204a102a3010502f603f6",
                "ab".repeat(32)
            ),
        );
        // No path — the namespace's whole value — is `f6` (null).
        assert_wire(
            &amend(None, AmendOp::AppendEntry(val("1"))),
            &format!("a104a4015820{}02616103f604a101a1016131", "ab".repeat(32)),
        );
    }

    /// The newtype validates on the way in, so an empty key never reaches
    /// state — a peer can't smuggle one past by hand-rolling the CBOR.
    #[test]
    fn namespace_key_rejects_empty() {
        assert!(NamespaceKey::try_new("").is_err());
        assert!(NamespaceKey::try_new(" ").is_ok()); // validated, not sanitized

        // a3 01 5820… prev, 02 60 (empty text string) key, 03 … namespace
        let empty_key = format!("a102a3015820{}026003a101a1016131", "ab".repeat(32));
        assert!(crate::decode::<Msg>(&unhex(&empty_key)).is_err());

        // The same message with a one-character key (`02 6161`) decodes.
        let one_char = format!("a102a3015820{}02616103a101a1016131", "ab".repeat(32));
        assert!(crate::decode::<Msg>(&unhex(&one_char)).is_ok());
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
