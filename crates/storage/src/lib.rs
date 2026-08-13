//! Where ledger state lives.
//!
//! [`Storage`] is a content-addressed version store: every version of the
//! state is filed under the digest of the envelope that produced it, and
//! the store has no notion of a *current* head — which chain matters is
//! the caller's business. Any number of ledgers can therefore share one
//! backend at once: a chain and the rewrite recovering from it, forks
//! being weighed against each other, or an old position held open for
//! reading, all sharing the entries they have in common. Versions
//! accumulate until [`retain`](Storage::retain) prunes them.
//!
//! Beside the versions sits the envelope log: the envelopes themselves,
//! filed by digest and indexed by parent through
//! [`children`](Storage::children). The log is what fork resolution walks
//! and what a node gossips from; versions are merely what the log folds
//! down to, and any pruned version can be re-derived from it. Versions
//! hold namespaces alone — chain-level facts like the config are derived
//! from the config-bearing envelopes the log already keeps.
//!
//! The surface is namespace- and path-granular on purpose: a backend can
//! keep state on disk and page in only what an envelope touches, so
//! applying a message costs O(path), not O(state).
//!
//! Validation lives above this crate. [`NamespaceOp::Delete`] and
//! [`NamespaceOp::SetAt`] arrive pre-validated against
//! [`Storage::resolve`], so backends apply them mechanically — and every
//! backend must pass the [`conformance`] suite, so two backends can never
//! disagree about what a commit does.

use wire::{
    Envelope, EnvelopeDigest,
    msg::{Namespace, NamespaceKey, Value},
    subkey::{Subkey, SubkeyPath},
};

pub mod conformance;
mod mem;
pub mod value;

pub use mem::MemStorage;

/// What a node in a namespace's value tree holds, without its contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// A [`Value::Map`].
    Map,
    /// A [`Value::Array`].
    Array,
    /// Any other [`Value`]; nothing can be walked through it.
    Leaf,
}

/// How far a walk down a namespace's value tree got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Every segment resolved; the terminal node's kind.
    Node(NodeKind),
    /// The walk stopped short: the segment at `depth` addressed nothing.
    /// `at` is the kind of the container it stopped in — the segment's
    /// shape matched it, or this would be a [`Resolution::Mismatch`].
    Missing { depth: usize, at: NodeKind },
    /// The walk stopped short: the segment at `depth` doesn't fit the
    /// node it reached — a key into a non-map, an index into a
    /// non-array, or a step through a leaf.
    Mismatch { depth: usize },
}

/// The single namespace write a commit carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceOp {
    /// Writes a whole namespace, creating or overwriting it.
    Put(NamespaceKey, Namespace),
    /// Removes a namespace. Pre-validated: the namespace exists in the
    /// parent version.
    Delete(NamespaceKey),
    /// Sets or clears one value nested inside a namespace, without
    /// touching its siblings. Pre-validated via [`Storage::resolve`]:
    /// the namespace exists, every parent resolves, shapes match, and a
    /// missing terminal is only ever a fresh key set into a map.
    SetAt {
        key: NamespaceKey,
        path: SubkeyPath,
        /// The value to write, or `None` to remove what `path` addresses.
        /// Removing an array element shifts later indices down.
        value: Option<Value>,
    },
}

/// A storage backend for the log of messages and the state at each of their
/// digests.
///
/// Implementations only store; deciding whether an envelope may apply is
/// the caller's job, which is what keeps every backend in agreement. Two
/// contracts follow:
///
/// - The pre-validated contract on [`NamespaceOp`]: an op that doesn't
///   fit the version it is applied to is a broken invariant, never an
///   error.
/// - Except through [`contains_version`](Storage::contains_version) — the
///   existence check a ledger opens through — addressing a head the store
///   doesn't hold is a broken invariant too. A ledger must only be driven
///   against the store it was opened from, and
///   [`retain`](Storage::retain) must keep every head still in use.
pub trait Storage {
    type Error: core::error::Error + Send + Sync + 'static;

    /// Whether the store holds an envelope with the given digest.
    fn contains_version(&self, head: EnvelopeDigest) -> Result<bool, Self::Error>;

    /// Walks `path` from the root of the namespace filed under `key` in
    /// the version at `head`, yielding `None` when that version holds no
    /// such namespace. The empty path resolves to the root itself.
    ///
    /// This powers the apply path. The default materializes the namespace
    /// and walks it in memory; a backend that stores the tree decomposed
    /// should override it with an O(path) lookup.
    fn resolve(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
        path: &[Subkey],
    ) -> Result<Option<Resolution>, Self::Error> {
        Ok(self
            .namespace(head, key)?
            .map(|namespace| value::resolve(&namespace.value, path)))
    }

    /// Materializes the whole namespace filed under `key` in the version
    /// at `head`. O(namespace) — for reads and checkpoints, never needed
    /// to apply.
    fn namespace(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
    ) -> Result<Option<Namespace>, Self::Error>;

    /// Streams every namespace in the version at `head`, in key order.
    fn namespaces(
        &self,
        head: EnvelopeDigest,
    ) -> impl Iterator<Item = Result<(NamespaceKey, Namespace), Self::Error>>;

    /// Derives the version at `head` by applying `op` to the version at
    /// `parent` — or as an untouched copy when `op` is `None`, the commit
    /// of a message that writes no namespace (a config change). Atomic: a
    /// crash must never leave a half-written version. The parent version
    /// is left intact; other ledgers may be standing on it.
    fn commit(
        &mut self,
        parent: EnvelopeDigest,
        head: EnvelopeDigest,
        op: Option<NamespaceOp>,
    ) -> Result<(), Self::Error>;

    /// Installs `namespaces` as the version at `head` — the `Init` that
    /// opens a chain. Versions of other chains are unaffected.
    fn install(
        &mut self,
        head: EnvelopeDigest,
        namespaces: impl IntoIterator<Item = (NamespaceKey, Namespace)>,
    ) -> Result<(), Self::Error>;

    /// Drops every version whose head is not in `keep` — the garbage
    /// collection that bounds a store's growth. What a kept version
    /// shared with a pruned one must survive. The envelope log is not
    /// versions and is left alone; pruning it is compaction's business.
    fn retain(&mut self, keep: &[EnvelopeDigest]) -> Result<(), Self::Error>;

    /// Stores `envelope` in the log under `digest`, indexing it under its
    /// `prev` for [`children`](Storage::children).
    fn put_envelope(
        &mut self,
        digest: EnvelopeDigest,
        envelope: Envelope,
    ) -> Result<(), Self::Error>;

    /// The envelope filed under `digest`, or `None` when the log holds no
    /// such envelope.
    fn envelope(&self, digest: EnvelopeDigest) -> Result<Option<Envelope>, Self::Error>;

    /// Removes the envelope filed under `digest` from the log, unindexing
    /// it from its parent's [`children`](Storage::children). Removing what
    /// isn't filed is a no-op.
    ///
    /// For envelopes proven unable to ever be canonical — rejection is
    /// deterministic, so the log needn't keep paying for them.
    fn remove_envelope(&mut self, digest: EnvelopeDigest) -> Result<(), Self::Error>;

    /// The digests of every filed envelope whose `prev` is `parent`, in
    /// ascending digest order. Fork resolution leans on the order: the
    /// first child yielded is the fork's preferred winner.
    fn children(
        &self,
        parent: EnvelopeDigest,
    ) -> impl Iterator<Item = Result<EnvelopeDigest, Self::Error>>;
}
