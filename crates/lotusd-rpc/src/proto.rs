//! The wire types: what a client may ask, and what it is answered with.
//!
//! Request payloads are structs rather than bare variants so a method can
//! grow a field without changing shape.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use cbor2::Cbor;
use wire::{EnvelopeDigest, msg::NamespaceKey, subkey::SubkeyPath};

/// A request on the local control socket.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// See [`GetVersion`].
    GetVersion(GetVersion),
    /// See [`GetChainRange`].
    GetChainRange(GetChainRange),
    /// See [`Watch`].
    Watch(Watch),
}

/// Asks the daemon for its version.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct GetVersion {}

/// Asks the daemon how much of the chain it holds.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct GetChainRange {}

/// Asks the daemon to report every movement of the chain that `selector`
/// picks out, until the connection is dropped.
///
/// One selector per watch: a connection carries one request, so a client
/// watching several things opens several connections.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Watch {
    #[cbor(key = 1)]
    pub selector: WatchSelector,
}

/// What a [`Watch`] asks to hear about.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WatchSelector {
    /// Every movement of the canonical head, whatever it changed.
    Head,
    /// Any change anywhere under a namespace.
    Namespace(NamespaceKey),
    /// A change to what a path addresses in a namespace.
    Path(WatchPath),
    /// One envelope leaving the canonical chain.
    Orphaned(EnvelopeDigest),
}

/// The path a [`WatchSelector::Path`] watches.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct WatchPath {
    #[cbor(key = 1)]
    pub key: NamespaceKey,
    #[cbor(key = 2)]
    pub path: SubkeyPath,
}

/// One frame of a [`Watch`]'s answer.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WatchEvent {
    /// The chain moved in a way the watch selects.
    Changed(Changed),
    /// A digest the watch asked about is already off the chain. An
    /// orphaned envelope never returns, so there is nothing further to
    /// say and the stream ends here.
    AlreadyOrphaned(EnvelopeDigest),
}

/// One movement of the chain, as a watcher is told about it.
///
/// A movement the watcher slept through is merged into the next one, so
/// `from` is where it was last told the head stood rather than the head
/// immediately before `head`.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Changed {
    /// The head the chain stood at before these changes.
    #[cbor(key = 1)]
    pub from: EnvelopeDigest,
    /// The head it stands at now.
    #[cbor(key = 2)]
    pub head: EnvelopeDigest,
    /// What changed, by namespace. Everything the movement did, not only
    /// the part the selector picked out.
    #[cbor(key = 3)]
    pub changes: BTreeMap<NamespaceKey, NamespaceChange>,
    /// The envelopes that left the canonical chain on the way.
    #[cbor(key = 4)]
    pub orphaned: BTreeSet<EnvelopeDigest>,
}

/// What changed inside one namespace.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceChange {
    /// The namespace was written, removed, or amended at its root.
    Whole,
    /// Only these paths were touched. No path here is a prefix of another.
    Paths(BTreeSet<SubkeyPath>),
}

/// One frame of the answer to a request.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    /// Answers [`GetVersion`].
    Version(String),
    /// Answers [`GetChainRange`].
    ChainRange(ChainRange),
    /// Answers [`Watch`], as many times as the chain moves.
    Watch(WatchEvent),
    /// Ends the stream: the request could not be served to completion.
    Failed(Failure),
}

impl Response {
    /// The name of this variant, for reporting an answer to a question
    /// nobody asked.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Response::Version(_) => "version",
            Response::ChainRange(_) => "chain range",
            Response::Watch(_) => "watch event",
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
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// The daemon could not carry the request out.
    Internal,
    /// The daemon does not serve this request.
    Unsupported,
}
