//! The wire types: what a client may ask, and what it is answered with.
//!
//! Variants are renamed to short strings to keep the encoding small, as
//! [`wire::Msg`]'s are. Request payloads are structs rather than bare
//! variants so a method can grow a field without changing shape.

use core::fmt;

use cbor2::Cbor;
use wire::EnvelopeDigest;

/// A request on the local control socket.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub enum Request {
    /// See [`GetVersion`].
    #[serde(rename = "v")]
    GetVersion(GetVersion),
    /// See [`GetChainRange`].
    #[serde(rename = "c")]
    GetChainRange(GetChainRange),
}

/// Asks the daemon for its version.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct GetVersion {}

/// Asks the daemon how much of the chain it holds.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct GetChainRange {}

/// One frame of the answer to a request.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub enum Response {
    /// Answers [`GetVersion`].
    #[serde(rename = "v")]
    Version(String),
    /// Answers [`GetChainRange`].
    #[serde(rename = "c")]
    ChainRange(ChainRange),
    /// Ends the stream: the request could not be served to completion.
    #[serde(rename = "e")]
    Failed(Failure),
}

impl Response {
    /// The name of this variant, for reporting an answer to a question
    /// nobody asked.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Response::Version(_) => "version",
            Response::ChainRange(_) => "chain range",
            Response::Failed(_) => "failure",
        }
    }
}

/// How much of the chain a node holds: everything from `root` to `head`.
///
/// Both ends come from one read, so `root` never overtakes the `head` it
/// arrives with — reading them apart could catch compaction mid-move.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub struct ChainRange {
    /// The oldest envelope still held, until compaction moves it forward.
    #[cbor(key = 1)]
    pub root: EnvelopeDigest,
    /// The canonical head the node stands at.
    #[cbor(key = 2)]
    pub head: EnvelopeDigest,
}

/// Why a request could not be served.
///
/// Coarse on purpose: the daemon's internal error types are not part of the
/// protocol, and a client can only act on the category.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Failure {
    #[cbor(key = 1)]
    pub kind: FailureKind,
    /// For an operator to read, never for a client to parse.
    #[cbor(key = 2)]
    pub message: String,
}

impl Failure {
    /// The daemon broke while serving a request it understood.
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Internal,
            message: message.into(),
        }
    }

    /// The daemon does not serve this request — an older build than the
    /// client, or a request it could not decode at all.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Unsupported,
            message: message.into(),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// The category of a [`Failure`].
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub enum FailureKind {
    /// The daemon could not carry the request out.
    #[serde(rename = "i")]
    Internal,
    /// The daemon does not serve this request.
    #[serde(rename = "u")]
    Unsupported,
}
