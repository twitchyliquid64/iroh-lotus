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
    Envelope, EnvelopeDigest, VerificationStatus,
    keys::KeyId,
    msg::{NamespaceKey, Predicate, Value},
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
    /// See [`GetStatus`].
    GetStatus(GetStatus),
    /// See [`GetEnvelopes`].
    GetEnvelopes(GetEnvelopes),
    /// See [`Watch`].
    Watch(Watch),
    /// See [`Read`].
    Read(Read),
    /// See [`ListNamespaces`].
    ListNamespaces(ListNamespaces),
    /// See [`Query`].
    Query(Query),
    /// See [`WeakSet`].
    WeakSet(WeakSet),
    /// See [`WeakPush`].
    WeakPush(WeakPush),
    /// See [`WeakDelete`].
    WeakDelete(WeakDelete),
    /// See [`WeakIncrement`].
    WeakIncrement(WeakIncrement),
    /// See [`WeakDeleteMatching`].
    WeakDeleteMatching(WeakDeleteMatching),
    /// See [`CreateInvite`].
    CreateInvite(CreateInvite),
    /// See [`Compact`].
    Compact(Compact),
}

/// Asks the daemon for an invite: one word a blank node joins the cluster
/// by, with `lotusd bootstrap`. The daemon remembers the token in it until
/// it is redeemed or `ttl_millis` pass, whichever comes first.
///
/// Answered with one [`InviteCode`]. Refused as [`FailureKind::Rejected`]
/// when the daemon serves no peers or could not sign an admission alone.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct CreateInvite {
    /// The weight the joiner's key is trusted at.
    #[cbor(key = 1)]
    pub weight: u32,
    /// How long the invite stays good, on the daemon's clock. The daemon
    /// caps it.
    #[cbor(key = 2)]
    pub ttl_millis: u64,
}

/// Answers [`CreateInvite`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct InviteCode {
    /// The invite, ready to paste into `lotusd bootstrap`.
    #[cbor(key = 1)]
    pub text: String,
    /// How long it stays good from when it was issued, after any cap.
    #[cbor(key = 2)]
    pub expires_in_millis: u64,
}

/// Asks the daemon for the value a path addresses in a namespace, at the
/// canonical head it stands at.
///
/// Answered with one [`ValueAt`]: the head and the value are read under
/// one borrow of the chain, so the value is the one that head holds.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Read {
    #[cbor(key = 1)]
    pub key: NamespaceKey,
    /// The path within the namespace, or `None` for its whole value.
    #[cbor(key = 2)]
    pub path: Option<SubkeyPath>,
}

/// Answers [`Read`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct ValueAt {
    /// The canonical head the value was read at.
    #[cbor(key = 1)]
    pub head: EnvelopeDigest,
    /// What the path addresses, or `None` when the namespace is not held
    /// or the path stops short of anything inside it.
    #[cbor(key = 2)]
    pub value: Option<Value>,
}

/// Asks the daemon what a path holds, rather than what it is: how many
/// entries a container has, and the keys of a map.
///
/// The answer is about the shape of the value, never the values under it,
/// so counting a map of ten thousand entries costs one small answer
/// instead of the whole namespace a [`Read`] would carry back.
///
/// Answered with one [`Queried`]: the head and the answer are read under
/// one borrow of the chain, so the answer is the one that head holds.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Query {
    #[cbor(key = 1)]
    pub key: NamespaceKey,
    /// The path within the namespace, or `None` for its whole value.
    #[cbor(key = 2)]
    pub path: Option<SubkeyPath>,
    #[cbor(key = 3)]
    pub kind: QueryKind,
}

/// How much of a container a [`Query`] asks about.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryKind {
    /// How many entries it holds, and nothing about what they are.
    Len,
    /// The keys of a map, alongside the count. An array is answered with
    /// its length either way: its keys are `0..len`.
    Keys,
}

/// Answers [`Query`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Queried {
    /// The canonical head the answer was read at.
    #[cbor(key = 1)]
    pub head: EnvelopeDigest,
    /// What the path addresses, or `None` when the namespace is not held
    /// or the path stops short of anything inside it.
    #[cbor(key = 2)]
    pub meta: Option<ValueMeta>,
}

/// What a queried path holds — never the values themselves.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValueMeta {
    /// A single value — a string, an integer, a bool, or a trusted key.
    /// Nothing inside it to count or name; a [`Read`] fetches it.
    Leaf,
    /// An array, and how many entries it holds.
    Array(Len),
    /// A map: how many entries it holds, and their keys when the query
    /// asked for them.
    Map(MapMeta),
}

impl ValueMeta {
    /// How many entries the container holds; `None` for a leaf, which
    /// holds none rather than zero.
    pub fn entries(&self) -> Option<u64> {
        match self {
            ValueMeta::Leaf => None,
            ValueMeta::Array(Len { len }) => Some(*len),
            ValueMeta::Map(MapMeta { len, .. }) => Some(*len),
        }
    }

    /// The shape the path addresses.
    pub fn shape(&self) -> Shape {
        match self {
            ValueMeta::Leaf => Shape::Leaf,
            ValueMeta::Array(_) => Shape::Array,
            ValueMeta::Map(_) => Shape::Map,
        }
    }
}

/// How many entries a container holds.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub struct Len {
    #[cbor(key = 1)]
    pub len: u64,
}

/// A map, as much of it as was asked for.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct MapMeta {
    #[cbor(key = 1)]
    pub len: u64,
    /// The entry keys, in key order; `None` when the query asked for the
    /// length alone, which is not the same as a map with no entries.
    #[cbor(key = 2)]
    pub keys: Option<Vec<String>>,
}

/// Asks the daemon for every namespace the ledger holds and the shape of
/// the value each one carries.
///
/// Answered with one [`NamespaceList`]: the head and the listing are read
/// under one borrow of the chain, so the listing is the one that head
/// holds.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct ListNamespaces {}

/// Answers [`ListNamespaces`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct NamespaceList {
    /// The canonical head the listing was read at.
    #[cbor(key = 1)]
    pub head: EnvelopeDigest,
    /// Every namespace the ledger holds, in key order.
    #[cbor(key = 2)]
    pub namespaces: Vec<NamespaceEntry>,
}

/// One namespace of a [`NamespaceList`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct NamespaceEntry {
    #[cbor(key = 1)]
    pub key: NamespaceKey,
    #[cbor(key = 2)]
    pub shape: Shape,
}

/// What a namespace's value is at its root: what a path can be walked
/// into, rather than which leaf type sits there.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Shape {
    /// A single value — a string, an integer, a bool, or a trusted key.
    /// No path reaches inside one.
    Leaf,
    Array,
    Map,
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Shape::Leaf => f.write_str("leaf"),
            Shape::Array => f.write_str("array"),
            Shape::Map => f.write_str("map"),
        }
    }
}

/// Asks the daemon to write `value` where `path` addresses in `key`,
/// signed by the daemon's own key and chained onto its current head.
///
/// Weak in the sense that the write claims no precondition: it goes onto
/// whatever head the daemon stands at when it arrives, and carries one
/// node's signature only, so it is not immune to a heavier fork. The
/// chain refuses writes the ledger's rules do not allow — a path into a
/// namespace the ledger does not hold, or a reserved namespace given the
/// wrong shape — as a [`FailureKind::Rejected`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct WeakSet {
    #[cbor(key = 1)]
    pub key: NamespaceKey,
    /// The path within the namespace to set, or `None` to set the whole
    /// namespace — creating it if the ledger does not hold it.
    #[cbor(key = 2)]
    pub path: Option<SubkeyPath>,
    #[cbor(key = 3)]
    pub value: Value,
}

/// Asks the daemon to append `value` to the array `path` addresses in
/// `key` — the namespace's whole value when no path is given — signed and
/// chained like a [`WeakSet`].
///
/// A path addressing nothing under an existing map becomes a one-entry
/// array; anything else that is not an array is refused.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct WeakPush {
    #[cbor(key = 1)]
    pub key: NamespaceKey,
    #[cbor(key = 2)]
    pub path: Option<SubkeyPath>,
    #[cbor(key = 3)]
    pub value: Value,
}

/// Asks the daemon to clear what `path` addresses in `key`, or to delete
/// the whole namespace when no path is given — signed and chained like a
/// [`WeakSet`]. Clearing what is not there is refused.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct WeakDelete {
    #[cbor(key = 1)]
    pub key: NamespaceKey,
    #[cbor(key = 2)]
    pub path: Option<SubkeyPath>,
}

/// Asks the daemon to add `delta` to the integer `path` addresses in
/// `key` — the namespace's whole value when no path is given — clamping
/// the sum to whichever of `min` and `max` are set. Signed and chained
/// like a [`WeakSet`]; the integer must exist.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct WeakIncrement {
    #[cbor(key = 1)]
    pub key: NamespaceKey,
    #[cbor(key = 2)]
    pub path: Option<SubkeyPath>,
    /// Negative to decrement.
    #[cbor(key = 3)]
    pub delta: i64,
    #[cbor(key = 4)]
    pub min: Option<i64>,
    #[cbor(key = 5)]
    pub max: Option<i64>,
}

/// Asks the daemon to remove every entry of the map or array `path`
/// addresses in `key` — the namespace's whole value when no path is
/// given — that `predicate` matches. Signed and chained like a
/// [`WeakSet`]; the container must exist, but matching nothing is fine.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct WeakDeleteMatching {
    #[cbor(key = 1)]
    pub key: NamespaceKey,
    #[cbor(key = 2)]
    pub path: Option<SubkeyPath>,
    #[cbor(key = 3)]
    pub predicate: Predicate,
}

/// Answers every weak write: [`WeakSet`], [`WeakPush`], [`WeakDelete`],
/// [`WeakIncrement`] and [`WeakDeleteMatching`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Written {
    /// The digest of the envelope the write was signed into.
    #[cbor(key = 1)]
    pub digest: EnvelopeDigest,
    /// The canonical head after the write.
    #[cbor(key = 2)]
    pub head: EnvelopeDigest,
    #[cbor(key = 3)]
    pub outcome: WriteOutcome,
}

/// What a write did to the canonical head — [`state::Insert`] as the
/// control protocol spells it.
///
/// [`state::Insert`]: https://docs.rs/state
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WriteOutcome {
    /// The head moved forward onto the new envelope.
    Extended,
    /// The canonical chain switched branches, abandoning `from`.
    Reorged(Reorged),
    /// The head did not move: the envelope lost its fork.
    Unchanged,
    /// The envelope was already in the log and the head did not move.
    Duplicate,
}

impl fmt::Display for WriteOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteOutcome::Extended => f.write_str("extended"),
            WriteOutcome::Reorged(Reorged { from }) => {
                write!(f, "reorged from {}", from.to_hex().as_ref())
            }
            WriteOutcome::Unchanged => f.write_str("unchanged"),
            WriteOutcome::Duplicate => f.write_str("duplicate"),
        }
    }
}

/// The head a reorg abandoned.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Reorged {
    #[cbor(key = 1)]
    pub from: EnvelopeDigest,
}

/// Asks the daemon to prune envelopes past its retention policy, now and
/// eagerly — the periodic pass it runs anyway waits for enough to be
/// worth a sweep. What the policy keeps — the newest envelopes, the
/// ledger's min-keep-minutes floor, roots pinned by pending invites —
/// stays either way.
///
/// Answered with one [`Compacted`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Compact {}

/// Answers [`Compact`]: how the oldest held envelope moved.
#[derive(Debug, Clone, Copy, Cbor, PartialEq, Eq)]
pub struct Compacted {
    /// Where the oldest envelope stood before.
    #[cbor(key = 1)]
    pub from: EnvelopeDigest,
    /// Where it stands now — `from`, when nothing was eligible.
    #[cbor(key = 2)]
    pub to: EnvelopeDigest,
    /// How many envelopes were pruned — removed from the log.
    #[cbor(key = 3)]
    pub pruned: u64,
}

/// Asks the daemon for its version.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct GetVersion {}

/// Asks the daemon how much of the chain it holds.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct GetChainRange {}

/// Asks the daemon who it is, how much of the chain it holds, and how it
/// stands with its peers — everything `status` prints, in one answer.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct GetStatus {}

/// Answers [`GetStatus`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct NodeStatus {
    #[cbor(key = 1)]
    pub version: String,
    /// The node's id in the cluster: the id of its signing key.
    #[cbor(key = 2)]
    pub node: KeyId,
    /// The iroh endpoint it serves peers on; `None` when it runs without one.
    #[cbor(key = 3)]
    pub endpoint: Option<EndpointInfo>,
    #[cbor(key = 4)]
    pub chain: ChainRange,
    /// Every node the daemon keeps a connection to, in node id order.
    #[cbor(key = 5)]
    pub peers: Vec<PeerInfo>,
    /// How many connections from peers the daemon is serving.
    #[cbor(key = 6)]
    pub inbound: u32,
    /// Whether the ledger's listing of this node carries the address its
    /// endpoint reports; `None` when it runs without an endpoint.
    #[cbor(key = 7)]
    pub published: Option<Published>,
}

/// Where the daemon's own `cluster-nodes` listing stands against the
/// address its endpoint reports.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Published {
    /// Nothing has been compared yet.
    Unchecked(Unchecked),
    /// The ledger lists the address the endpoint reports.
    Published(Connected),
    /// The address moved; the listing is about to be, or being, updated.
    Pending(Unchecked),
    /// The ledger does not list this node.
    NotListed(Unchecked),
    /// The ledger lists this node under another endpoint id, given in
    /// z-base-32, so the listing is not this endpoint's to keep.
    OtherEndpoint(OtherEndpoint),
    /// The listing is stale and the node cannot sign the update alone.
    CannotSign(Reason),
    /// The last update failed; it is retried.
    Failed(Reason),
}

impl fmt::Display for Published {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Published::Unchecked(_) => f.write_str("not checked yet"),
            Published::Published(_) => f.write_str("published"),
            Published::Pending(_) => f.write_str("pending"),
            Published::NotListed(_) => f.write_str("not listed in the cluster"),
            Published::OtherEndpoint(OtherEndpoint { endpoint }) => {
                write!(f, "listed under another endpoint, {endpoint}")
            }
            Published::CannotSign(Reason { reason }) => {
                write!(f, "cannot sign the update: {reason}")
            }
            Published::Failed(Reason { reason }) => write!(f, "failed: {reason}"),
        }
    }
}

/// A state that carries nothing yet; a struct so it can.
#[derive(Debug, Clone, Cbor, Default, PartialEq, Eq)]
pub struct Unchecked {}

/// The endpoint id a listing names instead of the daemon's, in z-base-32.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct OtherEndpoint {
    #[cbor(key = 1)]
    pub endpoint: String,
}

/// Why a state was reached, for a person.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Reason {
    #[cbor(key = 1)]
    pub reason: String,
}

/// An iroh endpoint as the control protocol describes it: the endpoint id
/// in z-base-32, and each transport address in iroh's own `kind:addr`
/// spelling. Strings rather than iroh's types, so a client need not carry
/// iroh to read a status.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct EndpointInfo {
    #[cbor(key = 1)]
    pub id: String,
    #[cbor(key = 2)]
    pub addrs: Vec<String>,
}

/// One peer the daemon keeps a connection to.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct PeerInfo {
    /// The peer's node id, as `cluster-nodes` lists it.
    #[cbor(key = 1)]
    pub node: KeyId,
    /// The endpoint id the ledger says to reach it at, in z-base-32.
    #[cbor(key = 2)]
    pub endpoint: String,
    #[cbor(key = 3)]
    pub state: PeerState,
}

/// Where a peer's connection stands.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    /// A dial is in progress; `attempt` counts the failures before it.
    Dialing(Attempt),
    /// The connection is up.
    Connected(Connected),
    /// The last dial failed; waiting before the next one.
    Backoff(Attempt),
}

impl fmt::Display for PeerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerState::Dialing(Attempt { attempt: 0 }) => f.write_str("dialing"),
            PeerState::Dialing(Attempt { attempt }) => write!(f, "dialing (retry {attempt})"),
            PeerState::Connected(_) => f.write_str("connected"),
            PeerState::Backoff(Attempt { attempt }) => {
                write!(f, "backing off after {attempt} failed dials")
            }
        }
    }
}

/// How many dials have failed so far.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Attempt {
    #[cbor(key = 1)]
    pub attempt: u32,
}

/// A connected peer. Carries nothing yet; a struct so it can.
#[derive(Debug, Clone, Cbor, Default, PartialEq, Eq)]
pub struct Connected {}

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
    /// Answers [`GetStatus`].
    Status(NodeStatus),
    /// Answers [`GetEnvelopes`], once per envelope sent.
    Envelope(EnvelopeFrame),
    /// Answers [`Watch`], as many times as the chain moves.
    Watch(WatchEvent),
    /// Answers [`Read`].
    Value(ValueAt),
    /// Answers [`ListNamespaces`].
    Namespaces(NamespaceList),
    /// Answers [`Query`].
    Queried(Queried),
    /// Answers every weak write, [`WeakSet`] and its siblings.
    Written(Written),
    /// Answers [`CreateInvite`].
    Invite(InviteCode),
    /// Answers [`Compact`].
    Compacted(Compacted),
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
            Response::Status(_) => "status",
            Response::Envelope(_) => "envelope",
            Response::Watch(_) => "watch event",
            Response::Value(_) => "value",
            Response::Namespaces(_) => "namespace listing",
            Response::Queried(_) => "query answer",
            Response::Written(_) => "write outcome",
            Response::Invite(_) => "invite",
            Response::Compacted(_) => "compaction",
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

    /// The daemon understood the request, and the chain refused what it
    /// asked for.
    pub fn rejected(message: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Rejected,
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
    /// The chain refused what the request asked for. Asking again the
    /// same way gets the same answer; the request itself has to change.
    Rejected,
}
