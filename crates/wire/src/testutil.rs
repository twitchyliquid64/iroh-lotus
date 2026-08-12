//! Shared helpers for the crate's wire-format tests.

use std::fmt::Debug;

use serde::{Serialize, de::DeserializeOwned};

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Asserts the exact wire bytes of a value, in both directions. The
/// expected hex is hand-derived from RFC 8949, not captured from output, so
/// a change in encoding fails the test rather than silently redefining the
/// format.
#[track_caller]
pub(crate) fn assert_wire<T>(value: &T, expected: &str)
where
    T: Serialize + DeserializeOwned + Debug + PartialEq,
{
    let encoded = crate::encode(value).unwrap();
    assert_eq!(hex(&encoded), expected, "encoding of {value:?}");

    let bytes = unhex(expected);
    let decoded: T = crate::decode(&bytes).unwrap();
    assert_eq!(&decoded, value, "decoding of {expected}");
}
