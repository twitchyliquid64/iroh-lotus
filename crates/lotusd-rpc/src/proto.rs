//! The wire types: what a client may ask, and what it is answered with.
//!
//! Request payloads are structs rather than bare variants so a method can
//! grow a field without changing shape.

use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use cbor2::Cbor;
use chrono::{DateTime, Utc};
use wire::{
    Envelope, EnvelopeDigest, VerificationStatus, keys::KeyId, msg::NamespaceKey,
    subkey::SubkeyPath,
};

/// A request on the local control socket.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// See [`GetVersion`].
    GetVersion(GetVersion),
    /// See [`GetChainRange`].
    GetChainRange(GetChainRange),
    /// See [`GetEnvelopes`].
    GetEnvelopes(GetEnvelopes),
    /// See [`Watch`].
    Watch(Watch),
}

/// Asks the daemon for its version.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct GetVersion {}

/// Asks the daemon how much of the chain it holds.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct GetChainRange {}

/// Asks the daemon for envelopes it holds.
///
/// Answered with one [`Response::Envelope`] per envelope and nothing else,
/// so a client that asked for envelopes the node does not hold learns it
/// from the stream simply ending.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct GetEnvelopes {
    #[cbor(key = 1)]
    pub select: EnvelopeSelector,
}

impl GetEnvelopes {
    /// Asks for the whole canonical chain the node still holds.
    pub fn chain() -> Self {
        Self {
            select: EnvelopeSelector::Chain(ChainWalk::default()),
        }
    }

    /// Asks for the newest `limit` envelopes of the canonical chain.
    pub fn newest(limit: u32) -> Self {
        Self::walk(ChainWalk::default().with_limit(limit))
    }

    /// Asks for the envelopes the node stored within the last `since`.
    pub fn since(since: Duration) -> Self {
        Self::walk(ChainWalk::default().with_since(since))
    }

    /// Asks for the part of the canonical chain `walk` describes.
    pub fn walk(walk: ChainWalk) -> Self {
        Self {
            select: EnvelopeSelector::Chain(walk),
        }
    }

    /// Asks for exactly these envelopes.
    pub fn digests(digests: impl IntoIterator<Item = EnvelopeDigest>) -> Self {
        Self {
            select: EnvelopeSelector::Digests(digests.into_iter().collect()),
        }
    }
}

/// Which envelopes a [`GetEnvelopes`] asks for.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeSelector {
    /// The canonical chain, oldest first.
    Chain(ChainWalk),
    /// Only these envelopes, in the order asked for and wherever they sit
    /// in the log — an orphan included. Digests the node does not hold are
    /// left out of the answer rather than reported.
    Digests(Vec<EnvelopeDigest>),
}

/// How much of the canonical chain to send.
///
/// Both bounds are counted back from the head, and both may be set: the
/// walk stops at whichever it reaches first.
#[derive(Debug, Copy, Clone, Cbor, Default, PartialEq, Eq)]
pub struct ChainWalk {
    /// At most this many envelopes, counted back from the head; `None` for
    /// everything the node still holds.
    #[cbor(key = 1)]
    pub limit: Option<u32>,
    /// Only envelopes the node stored within this many milliseconds of
    /// now, by that node's own clock; `None` for however far back its log
    /// goes.
    ///
    /// A window, not an instant, precisely because the clock is the
    /// daemon's: a client naming an absolute time would be naming it on a
    /// clock the daemon does not read.
    #[cbor(key = 2)]
    pub since_millis: Option<u64>,
}

impl ChainWalk {
    /// Stops the walk after `limit` envelopes.
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Stops the walk at the envelopes the node stored longer than `since`
    /// ago. A window past what a `u64` of milliseconds holds saturates,
    /// which reaches further back than any log goes.
    pub fn with_since(mut self, since: Duration) -> Self {
        self.since_millis = Some(u64::try_from(since.as_millis()).unwrap_or(u64::MAX));
        self
    }

    /// The window this walk asks for, if it asks for one.
    pub fn since(&self) -> Option<Duration> {
        self.since_millis.map(Duration::from_millis)
    }
}

/// One envelope of a [`GetEnvelopes`] answer.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct EnvelopeFrame {
    /// The digest the node holds this envelope under. Derivable from the
    /// envelope, and sent anyway so a client need not re-encode to name
    /// what it was given.
    #[cbor(key = 1)]
    pub digest: EnvelopeDigest,
    #[cbor(key = 2)]
    pub envelope: Envelope,
    /// What the sending node made of the signatures. Outside the
    /// envelope's canonical encoding, so it travels beside it.
    #[cbor(key = 3)]
    pub verification: Verification,
    /// When the sending node's log first stored the envelope, in
    /// milliseconds since the unix epoch on that node's clock.
    ///
    /// For an operator reading a log and nothing else. Two nodes disagree
    /// about it by construction, so nothing that decides anything may
    /// read it — the ledger's own notion of time is a signed timestamp
    /// inside the envelope.
    #[cbor(key = 4)]
    pub stored_at_millis: i64,
}

impl EnvelopeFrame {
    /// The frame carrying `envelope` as the node holds it — verification
    /// status, and when the log first saw it.
    pub fn new(digest: EnvelopeDigest, envelope: Envelope, stored_at_millis: i64) -> Self {
        Self {
            digest,
            verification: Verification::from(envelope.verification_status()),
            envelope,
            stored_at_millis,
        }
    }

    /// When the sending node first stored this envelope, as a datetime —
    /// `None` only for a number no datetime can hold, which is a peer
    /// sending nonsense rather than anything a log produces.
    ///
    /// The instant the number names, which is UTC by construction: it
    /// crosses as milliseconds since the epoch, so whoever shows it can
    /// put it into whatever zone their reader is in.
    pub fn stored_at(&self) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp_millis(self.stored_at_millis)
    }

    /// The envelope as the sending node holds it: the verification status
    /// put back where it belongs, so a reader sees what that node
    /// concluded rather than an unchecked envelope.
    pub fn into_parts(self) -> (EnvelopeDigest, Envelope) {
        let mut envelope = self.envelope;
        envelope.set_verification_status(self.verification.into());
        (self.digest, envelope)
    }
}

/// How an envelope's signatures scored on the node that holds it.
///
/// Mirrors [`wire::VerificationStatus`], which never crosses the ledger
/// wire: it is what a node concluded about an envelope, not something the
/// envelope carries.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    /// Nothing has checked the signatures yet.
    Unchecked,
    /// These keys' signatures did not verify.
    Failed(BTreeSet<KeyId>),
    /// Every signature verified, together worth this much.
    AllMatched(u32),
}

impl From<&VerificationStatus> for Verification {
    fn from(status: &VerificationStatus) -> Self {
        match status {
            VerificationStatus::Unchecked => Verification::Unchecked,
            VerificationStatus::Failed { failing_key_ids } => {
                Verification::Failed(failing_key_ids.clone())
            }
            VerificationStatus::AllMatched { total_weight } => {
                Verification::AllMatched(*total_weight)
            }
        }
    }
}

impl From<Verification> for VerificationStatus {
    fn from(verification: Verification) -> Self {
        match verification {
            Verification::Unchecked => VerificationStatus::Unchecked,
            Verification::Failed(failing_key_ids) => VerificationStatus::Failed { failing_key_ids },
            Verification::AllMatched(total_weight) => {
                VerificationStatus::AllMatched { total_weight }
            }
        }
    }
}

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
    /// Answers [`GetEnvelopes`], once per envelope sent.
    Envelope(EnvelopeFrame),
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
            Response::Envelope(_) => "envelope",
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
