//! What flows between a session machine and its driver.

use wire::{Envelope, EnvelopeDigest};

use crate::proto::MessageKind;

/// What a driver feeds a session machine.
#[derive(Debug)]
pub enum Input {
    /// A frame decoded off the peer's stream.
    Message(crate::Message),
    /// The answer to the [`Query`] of an earlier [`Effect::Ask`].
    Answer(Answer),
    /// The run of an earlier [`Effect::Ingest`] has been inserted. An
    /// insert *error* never reaches the machine: the driver adjudicates
    /// it — a storage fault is local, anything else is the peer's — and
    /// ends the session itself.
    Ingested,
}

/// What a machine instructs its driver to do. `Ask` and `Ingest` must be
/// resolved — their result fed back as an [`Input`] — before the driver
/// feeds the next frame; `Done` and `Violation` end the session.
#[derive(Debug)]
pub enum Effect<O> {
    /// Write this frame to the peer.
    Send(crate::Message),
    /// Consult the core; feed the result back as [`Input::Answer`].
    Ask(Query),
    /// Insert this parent-first run through the chain; feed the outcome
    /// back as [`Input::Ingested`]. Only pullers emit it.
    Ingest(Vec<Envelope>),
    /// The session completed.
    Done(O),
    /// The peer broke the protocol: close the stream and score the peer.
    Violation(Breach),
}

/// A question a machine asks of the core it works for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// Whether the envelope log holds this digest — any branch counts.
    ContainsEnvelope(EnvelopeDigest),
    /// This node's canonical path sampled newest-first, per
    /// [`locator::sample`](crate::locator::sample).
    Locator,
    /// The newest locator entry on this node's canonical path, per
    /// [`locator::split`](crate::locator::split).
    SplitPoint(Vec<EnvelopeDigest>),
    /// The canonical path just after `after`, parent-first, within the
    /// budgets every segment answer must respect: at most
    /// [`MAX_BATCH_ENVELOPES`](crate::MAX_BATCH_ENVELOPES) envelopes,
    /// stopping before
    /// [`SEGMENT_BYTE_BUDGET`](crate::SEGMENT_BYTE_BUDGET) encoded bytes
    /// would be exceeded. Empty when `after` is the head — or has left
    /// the canonical path, which ends the stream early and harmlessly.
    Segment { after: EnvelopeDigest },
}

/// The answer to a [`Query`], in the same shape.
#[derive(Debug, Clone)]
pub enum Answer {
    Contains(bool),
    Locator(Vec<EnvelopeDigest>),
    SplitPoint(Option<EnvelopeDigest>),
    Segment(Vec<Envelope>),
}

/// How a pull session ended for the puller.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PullOutcome {
    /// The peer's head is already in our log — nothing to fetch. The
    /// peer's own pull covers the reverse direction.
    AlreadyCurrent,
    /// Caught up to `head`, the peer's canonical tip as of the stream's
    /// end. `ingested` counts envelopes fed through the chain, overshoot
    /// duplicates included.
    Synced { head: EnvelopeDigest, ingested: u64 },
    /// The chains share nothing: a foreign cluster's peer, or one of our
    /// own past the compaction horizon — indistinguishable in-band, and
    /// only checkpoint sync (unbuilt) with out-of-band trust could go
    /// further.
    NoCommonHistory,
}

/// How a pull session ended for the server.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ServeOutcome {
    /// Nothing in the puller's locator is in our log.
    NoCommonHistory,
    /// Streamed `sent` envelopes up to `head` and said so.
    Served { head: EnvelopeDigest, sent: u64 },
}

/// How the peer broke the protocol. Grounds to close the stream and
/// score the peer down — never grounds to keep talking.
#[derive(Debug, thiserror::Error)]
pub enum Breach {
    #[error("peer speaks protocol version {theirs}, this node speaks {ours}")]
    Version { ours: u32, theirs: u32 },
    #[error("unexpected {got} while awaiting {expected}")]
    Unexpected {
        got: MessageKind,
        expected: &'static str,
    },
    #[error("split point is not an entry of the locator we sent")]
    SplitNotInLocator { at: EnvelopeDigest },
    #[error("an empty envelope batch")]
    EmptyBatch,
    #[error("a batch of {got} envelopes exceeds the cap")]
    OversizedBatch { got: usize },
    #[error("an empty locator")]
    EmptyLocator,
    #[error("a locator of {got} entries exceeds the cap")]
    OversizedLocator { got: usize },
    #[error("an envelope does not chain onto the one before it")]
    BrokenRun { expected: EnvelopeDigest },
    #[error("an envelope that cannot be digested")]
    Undigestable(#[source] wire::Error),
}
