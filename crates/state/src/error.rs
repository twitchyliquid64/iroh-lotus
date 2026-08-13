//! The crate's error types.

use core::fmt;

use wire::{EnvelopeDigest, msg::NamespaceKey, subkey::SubkeyPath};

/// An error produced while working with a ledger.
///
/// Generic over the storage backend's error `E`; a backend that cannot
/// fail declares `Infallible` and the impossibility shows in the type.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error<E> {
    /// An envelope's digest could not be computed.
    Wire(wire::Error),
    /// A ledger was opened from an envelope that does not start a chain.
    NotInit,
    /// A chain was replayed from nothing.
    EmptyChain,
    /// A ledger was opened at a head the store holds no version for, or
    /// a chain at a root the log holds no envelope for.
    UnknownHead(EnvelopeDigest),
    /// An envelope chains onto an envelope the store's log does not hold.
    /// Sync delivers parent-first, so this is a protocol breach, not a
    /// gap to buffer around.
    UnknownParent(EnvelopeDigest),
    /// An envelope could not be applied.
    Apply(ApplyError<E>),
    /// The storage backend failed.
    Storage(E),
}

/// An error produced while applying an envelope to a ledger.
///
/// Distinct from [`Error`] so that [`Ledger::apply`](crate::Ledger::apply)
/// admits only the failures that can actually happen mid-chain — opening a
/// ledger is not one of them.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApplyError<E> {
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
    /// The value the namespace would hold after the write violates the
    /// rules for that namespace — today, the baked-in rules for the
    /// reserved `_lotus_` keys.
    InvalidValue {
        /// The namespace whose rules refused the value.
        key: NamespaceKey,
    },
    /// The storage backend failed.
    Storage(E),
}

impl<E> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Wire(_) => f.write_str("could not compute an envelope digest"),
            Error::NotInit => f.write_str("ledger must be opened from an Init envelope"),
            Error::EmptyChain => f.write_str("cannot replay an empty chain"),
            Error::UnknownHead(head) => {
                write!(f, "store holds nothing at {}", head.to_hex().as_ref())
            }
            Error::UnknownParent(prev) => {
                write!(f, "log holds no parent envelope {}", prev.to_hex().as_ref())
            }
            Error::Apply(_) => f.write_str("could not apply an envelope"),
            Error::Storage(_) => f.write_str("storage backend failed"),
        }
    }
}

impl<E> fmt::Display for ApplyError<E> {
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
            ApplyError::InvalidValue { key } => {
                write!(f, "value not valid for namespace {key}")
            }
            ApplyError::Storage(_) => f.write_str("storage backend failed"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Error::Wire(err) => Some(err),
            Error::Apply(err) => Some(err),
            Error::Storage(err) => Some(err),
            Error::NotInit
            | Error::EmptyChain
            | Error::UnknownHead(_)
            | Error::UnknownParent(_) => None,
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ApplyError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ApplyError::Wire(err) => Some(err),
            ApplyError::Storage(err) => Some(err),
            _ => None,
        }
    }
}

impl<E> From<wire::Error> for Error<E> {
    fn from(err: wire::Error) -> Self {
        Error::Wire(err)
    }
}

impl<E> From<wire::Error> for ApplyError<E> {
    fn from(err: wire::Error) -> Self {
        ApplyError::Wire(err)
    }
}

impl<E> From<ApplyError<E>> for Error<E> {
    fn from(err: ApplyError<E>) -> Self {
        Error::Apply(err)
    }
}
