//! Helpers shared by this crate's unit tests.

use serde::{Serialize, de::DeserializeOwned};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

/// A `SetNamespace` envelope chaining onto `prev` — the workhorse test
/// envelope, unsigned.
pub fn set(prev: EnvelopeDigest, key: &str, value: &str) -> Envelope {
    Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: NamespaceKey::try_new(key).expect("test keys are non-empty"),
        namespace: Namespace {
            value: Value::String(value.to_string()),
        },
    }))
}

pub fn digest_of(envelope: &Envelope) -> EnvelopeDigest {
    envelope.digest().expect("test envelopes digest")
}

pub fn hex_digest(digest: &EnvelopeDigest) -> String {
    digest.to_hex().as_ref().to_string()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex strings pair up");
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("test hex is valid"))
        .collect()
}

/// Asserts `value` encodes to exactly the hex given and decodes back.
pub fn assert_wire<T>(value: &T, want: &str)
where
    T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug,
{
    let encoded = wire::encode(value).expect("test values encode");
    assert_eq!(hex(&encoded), want);
    let decoded: T = wire::decode(&encoded).expect("what was encoded decodes");
    assert_eq!(&decoded, value);
}
