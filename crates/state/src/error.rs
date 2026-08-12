//! The crate's error types.

use core::fmt;

use wire::{EnvelopeDigest, msg::NamespaceKey, subkey::SubkeyPath};

/// An error produced while working with a ledger.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An envelope's digest could not be computed.
    Wire(wire::Error),
    /// A ledger was opened from an envelope that does not start a chain.
    NotInit,
    /// A chain was replayed from nothing.
    EmptyChain,
    /// An envelope could not be applied.
    Apply(ApplyError),
}

/// An error produced while applying an envelope to a ledger.
///
/// Distinct from [`Error`] so that [`Ledger::apply`](crate::Ledger::apply)
/// admits only the failures that can actually happen mid-chain — opening a
/// ledger is not one of them.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApplyError {
    /// The envelope's digest could not be computed.
    Wire(wire::Error),
    /// An `Init` envelope arrived at a ledger that is already open.
    UnexpectedInit,
    /// The envelope chains onto an envelope other than the current head.
    ChainMismatch {
        /// The current head of the ledger.
        expected: EnvelopeDigest,
        /// The envelope the message actually points back at.
        found: EnvelopeDigest,
    },
    /// A namespace was manipulated that the ledger does not hold.
    UnknownNamespace(NamespaceKey),
    /// A path addressed something the namespace does not hold.
    UnknownPath {
        /// The namespace the path was walked from.
        key: NamespaceKey,
        /// The path that was walked.
        path: SubkeyPath,
    },
    /// A path addressed a value of the wrong shape — a key into something
    /// that is not a map, or an index into something that is not an array.
    PathTypeMismatch {
        /// The namespace the path was walked from.
        key: NamespaceKey,
        /// The path that was walked.
        path: SubkeyPath,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Wire(_) => f.write_str("could not compute an envelope digest"),
            Error::NotInit => f.write_str("ledger must be opened from an Init envelope"),
            Error::EmptyChain => f.write_str("cannot replay an empty chain"),
            Error::Apply(_) => f.write_str("could not apply an envelope"),
        }
    }
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplyError::Wire(_) => f.write_str("could not compute an envelope digest"),
            ApplyError::UnexpectedInit => f.write_str("ledger is already open"),
            ApplyError::ChainMismatch { expected, found } => write!(
                f,
                "envelope chains onto {}, but the head is {}",
                found.to_hex().as_ref(),
                expected.to_hex().as_ref(),
            ),
            ApplyError::UnknownNamespace(key) => write!(f, "no such namespace: {key}"),
            ApplyError::UnknownPath { key, path } => {
                write!(f, "namespace {key} has nothing at {path}")
            }
            ApplyError::PathTypeMismatch { key, path } => {
                write!(f, "namespace {key} cannot be walked to {path}")
            }
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Error::Wire(err) => Some(err),
            Error::Apply(err) => Some(err),
            Error::NotInit | Error::EmptyChain => None,
        }
    }
}

impl core::error::Error for ApplyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ApplyError::Wire(err) => Some(err),
            _ => None,
        }
    }
}

impl From<wire::Error> for Error {
    fn from(err: wire::Error) -> Self {
        Error::Wire(err)
    }
}

impl From<wire::Error> for ApplyError {
    fn from(err: wire::Error) -> Self {
        ApplyError::Wire(err)
    }
}

impl From<ApplyError> for Error {
    fn from(err: ApplyError) -> Self {
        Error::Apply(err)
    }
}
