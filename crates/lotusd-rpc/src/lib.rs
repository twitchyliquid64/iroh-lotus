//! The request/response protocol lotusd speaks on its local control socket.
//!
//! One connection carries one request. The daemon answers it with a stream
//! of zero or more responses and then closes, so a long-poll is an ordinary
//! request whose responses arrive late — there is no multiplexing to get
//! wrong and no request id to correlate.
//!
//! Frames are canonical CBOR, as on the ledger wire: everything moves
//! through [`wire::encode`] and [`wire::decode`].
//!
//! A method is declared once, in [`method`], which pairs the request type
//! with the response variant it is answered by. Clients reach it through
//! [`call`] or [`Call`], the daemon through [`serve`] and [`Handler`].

mod error;
pub use error::Error;

mod frame;
pub use frame::MAX_FRAME_LEN;

mod proto;
pub use proto::{
    ChainRange, ChainWalk, Changed, EnvelopeFrame, EnvelopeSelector, Failure, FailureKind,
    GetChainRange, GetEnvelopes, GetVersion, NamespaceChange, Request, Response, Verification,
    Watch, WatchEvent, WatchPath, WatchSelector,
};

mod method;
pub use method::Method;

mod client;
pub use client::{Call, call};

mod server;
pub use server::{Handler, Responses, serve};
