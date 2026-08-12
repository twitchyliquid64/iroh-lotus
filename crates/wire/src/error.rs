//! The crate's error type.

use core::fmt;

/// An error produced while moving a value on or off the wire.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A value could not be encoded as CBOR.
    Encode(cbor2::ser::Error),
    /// Bytes could not be decoded into the expected wire type.
    Decode(cbor2::de::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encode(_) => f.write_str("could not encode value as CBOR"),
            Error::Decode(_) => f.write_str("could not decode CBOR"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Error::Encode(err) => Some(err),
            Error::Decode(err) => Some(err),
        }
    }
}

impl From<cbor2::ser::Error> for Error {
    fn from(err: cbor2::ser::Error) -> Self {
        Error::Encode(err)
    }
}

impl From<cbor2::de::Error> for Error {
    fn from(err: cbor2::de::Error) -> Self {
        Error::Decode(err)
    }
}
