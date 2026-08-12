//! The crate's sanctioned CBOR entry points.
//!
//! Everything that crosses the wire or reaches the ledger goes through
//! [`encode`] and [`decode`] rather than calling `cbor2` directly.

use serde::{Deserialize, Serialize};

use crate::Error;

/// Encodes a wire value as deterministic CBOR, satisfying the core
/// deterministic encoding requirements of RFC 8949 §4.2.1. Use this
/// rather than [`cbor2::to_vec`].
pub fn encode<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    Ok(cbor2::to_canonical_vec(value)?)
}

/// Encodes a wire value as deterministic CBOR straight into `writer`.
///
/// Byte-for-byte identical to [`encode`], without collecting the output
/// into a `Vec` first.
pub fn encode_into<T, W>(value: &T, writer: W) -> Result<(), Error>
where
    T: ?Sized + Serialize,
    W: std::io::Write,
{
    Ok(cbor2::to_canonical_writer(value, writer)?)
}

/// Decodes a wire value from CBOR.
///
/// Does not require the input to be canonically encoded — only [`encode`]
/// guarantees that on the way out.
pub fn decode<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Error> {
    Ok(cbor2::from_slice(bytes)?)
}
