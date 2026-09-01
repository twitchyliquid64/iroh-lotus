//! How an iroh address is written into the ledger and read back out.
//!
//! Behind the `iroh` feature: only the daemon and the ledger rules need to
//! dial anything, and a client reading a status should not carry a QUIC
//! stack to do it.

use core::fmt;
use std::collections::BTreeMap;

use super::{ADDRS, Value};

/// Field names an [`iroh::EndpointAddr`] takes in a [`Value::Map`], and
/// the `type` tags its transport addresses are written under. Named once
/// so both directions of the conversion stay in step.
const ENDPOINT_ID: &str = "endpoint_id";
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

    fn val(v: &str) -> Value {
        Value::String(v.to_string())
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
}
