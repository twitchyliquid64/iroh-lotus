//! Node-to-node sync: the peer wire protocol and the sans-io session
//! state machines that speak it.
//!
//! Each node offers a peer exactly one thing — its own canonical path,
//! streamed parent-first from a point the peer already holds. The
//! receiver stores what applies; fork resolution in [`state`] does all
//! merging. Losing branches are never reconciled: fork choice is a
//! per-fork maximum over known children, so a branch that lost against a
//! peer's candidate has already lost against the union of both.
//!
//! The crate is sans-io on the `quinn-proto` model, in three layers:
//!
//! - **Wire + codec.** [`Message`] and the framing [`Codec`] — a
//!   [`tokio_util::codec`] pair, which are pure `BytesMut` transforms;
//!   pairing them with a socket is the driver's business.
//! - **Session machines.** [`Puller`] and [`Server`] consume [`Input`]s
//!   and return [`Effect`]s. Storage access is an effect, not a trait
//!   bound: a machine emits [`Effect::Ask`] or [`Effect::Ingest`] and is
//!   fed the result back as an input. No sockets, no clock, no storage,
//!   no futures.
//! - **Drivers**, which live with whoever owns the store (`lotusd`),
//!   resolve effects in order and feed the next decoded frame only once
//!   the queue is drained. That order is the driver contract: an
//!   [`Input::Answer`] or [`Input::Ingested`] nothing asked for, a frame
//!   fed across an unresolved effect, or any input after the session
//!   ended is a driver bug, and the machines panic on it. Timeouts,
//!   backoff, and peer scoring are driver business too — time is I/O.
//!
//! A peer that breaks the protocol surfaces as [`Effect::Violation`]
//! carrying the [`Breach`]; the driver closes and scores. What this crate
//! does not yet carry: the announce (live gossip) message and checkpoint
//! sync for peers with no common history — both end the session cleanly
//! today ([`PullOutcome::NoCommonHistory`]).

mod error;
pub use error::Error;

mod frame;
pub use frame::{Codec, MAX_FRAME_LEN};

pub mod locator;

mod proto;
pub use proto::{CaughtUp, Envelopes, FindSplit, Hello, Message, MessageKind, NoSplit, Split};

mod session;
pub use session::{Answer, Breach, Effect, Input, PullOutcome, Query, ServeOutcome};

mod puller;
pub use puller::Puller;

mod server;
pub use server::Server;

mod trace;

#[cfg(test)]
mod testutil;

/// The protocol version spoken by this build. Exact match required: the
/// wire format is unstable and no compatibility is promised.
pub const PROTOCOL_VERSION: u32 = 1;

/// The most envelopes one [`Envelopes`] frame may carry — the count
/// budget every [`Query::Segment`] answer must respect; a puller refuses
/// batches beyond it.
pub const MAX_BATCH_ENVELOPES: u32 = 256;

/// The encoded-byte budget every [`Query::Segment`] answer must stay
/// within, sized so a full segment plus message overhead fits one frame.
pub const SEGMENT_BYTE_BUDGET: u32 = MAX_FRAME_LEN - 1024;
