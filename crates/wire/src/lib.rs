//! The types for encoding/decoding messages that advance the ledger.

mod codec;
pub use codec::{decode, encode, encode_into};

mod error;
pub use error::Error;

mod envelope;
pub use envelope::{
    Envelope, EnvelopeDigest, EnvelopeSignature, SignedTimestamp, VerificationStatus,
};

pub mod msg;
pub use msg::Msg;

pub mod subkey;
pub use subkey::{Subkey, SubkeyPath};

#[cfg(test)]
mod testutil;
