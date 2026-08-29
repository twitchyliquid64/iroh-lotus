//! Drives the sans-io sync session machines over a real transport.
//!
//! The [`sync`] crate's machines emit effects; this module is the thin
//! async edge that resolves them: `Send` goes out the transport through
//! the framing codec, `Ask` and `Ingest` round-trip through whatever
//! [`SyncCore`] the session runs against — the server actor via a
//! [`ServerHandle`] in the daemon, a bare [`Core`] while bootstrapping —
//! and the next frame is read only once the effect queue is drained: the
//! driver contract the machines panic on.
//!
//! The transport is anything `AsyncRead + AsyncWrite`: a duplex pipe in
//! tests, an iroh stream between machines later. Time lives here too — a
//! peer silent for longer than [`FRAME_TIMEOUT`] fails the session rather
//! than holding it open.

use std::{collections::VecDeque, time::Duration};

use sync::{Codec, Effect, Input, PullOutcome, Puller, ServeOutcome};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};
use tokio_util::{
    bytes::BytesMut,
    codec::{Decoder, Encoder},
};
use wire::{Envelope, EnvelopeDigest};

use crate::{ChainError, Core, RequestError, ServerHandle};

/// How long a quiet peer gets between frames before the session fails.
pub const FRAME_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a sync session ended without an outcome.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The server actor is gone; nothing local can be asked.
    #[error("the server is shutting down")]
    ServerGone,
    /// A frame could not be read, written, or decoded.
    #[error("framing")]
    Frame(#[from] sync::Error),
    /// The peer broke the protocol: close and score it down.
    #[error("peer breach")]
    Breach(#[source] sync::Breach),
    /// Answering a query against our own chain failed — a local fault,
    /// never the peer's.
    #[error("answering a sync query")]
    Answer(#[source] ChainError),
    /// The chain refused the peer's envelopes. The peer's fault, unless
    /// the source bottoms out in a storage error.
    #[error("ingesting the peer's envelopes")]
    Ingest(#[source] ChainError),
    /// The peer hung up between frames. On a serve this is routine: a
    /// puller that learned from `Hello` it needed nothing closes without
    /// another frame.
    #[error("peer closed the stream mid-session")]
    PeerClosed,
    /// The peer hung up inside a frame.
    #[error("the stream ended mid-frame")]
    Truncated,
    /// The peer sent nothing for longer than [`FRAME_TIMEOUT`].
    #[error("peer went silent")]
    TimedOut,
}

/// The chain a session runs against: what resolves its `Ask` and
/// `Ingest` effects.
///
/// Implemented on `&ServerHandle` — every session in the running daemon
/// goes through the mainloop — and on `&mut Core`, for a node with no
/// server yet: bootstrap pulls the chain before there is anything to
/// serve.
pub trait SyncCore {
    /// The canonical head this side stands at.
    fn head(&mut self) -> impl Future<Output = Result<EnvelopeDigest, SyncError>>;

    /// Answers one machine query against the chain.
    fn answer(
        &mut self,
        query: sync::Query,
    ) -> impl Future<Output = Result<sync::Answer, SyncError>>;

    /// Inserts a parent-first run through the chain.
    fn ingest(&mut self, run: Vec<Envelope>) -> impl Future<Output = Result<(), SyncError>>;
}

impl SyncCore for &ServerHandle {
    async fn head(&mut self) -> Result<EnvelopeDigest, SyncError> {
        ServerHandle::head(self)
            .await
            .map_err(|()| SyncError::ServerGone)
    }

    async fn answer(&mut self, query: sync::Query) -> Result<sync::Answer, SyncError> {
        self.sync_answer(query)
            .await
            .map_err(|err| err.classify(SyncError::Answer))
    }

    async fn ingest(&mut self, run: Vec<Envelope>) -> Result<(), SyncError> {
        self.insert(run)
            .await
            .map(|_| ())
            .map_err(|err| err.classify(SyncError::Ingest))
    }
}

impl SyncCore for &mut Core {
    async fn head(&mut self) -> Result<EnvelopeDigest, SyncError> {
        Ok(Core::head(self))
    }

    async fn answer(&mut self, query: sync::Query) -> Result<sync::Answer, SyncError> {
        self.sync_answer(query)
            .map_err(|err| SyncError::Answer(ChainError::Storage(err)))
    }

    async fn ingest(&mut self, run: Vec<Envelope>) -> Result<(), SyncError> {
        self.insert(run).map(|_| ()).map_err(SyncError::Ingest)
    }
}

/// Pulls this node up to date from the peer on `transport`.
pub async fn pull<T, C>(transport: T, mut core: C) -> Result<PullOutcome, SyncError>
where
    T: AsyncRead + AsyncWrite + Unpin,
    C: SyncCore,
{
    let head = core.head().await?;
    let (mut puller, opening) = Puller::new(head);
    drive(transport, core, |input| puller.handle(input), Some(opening)).await
}

/// Serves the pull of the peer on `transport`.
pub async fn serve<T, C>(transport: T, mut core: C) -> Result<ServeOutcome, SyncError>
where
    T: AsyncRead + AsyncWrite + Unpin,
    C: SyncCore,
{
    let head = core.head().await?;
    let mut server = sync::Server::new(head);
    drive(transport, core, |input| server.handle(input), None).await
}

/// The effect loop both sessions share: resolve every pending effect in
/// order, and only then read the peer's next frame.
async fn drive<T, C, O>(
    mut transport: T,
    mut core: C,
    mut machine: impl FnMut(Input) -> Vec<Effect<O>>,
    opening: Option<Effect<O>>,
) -> Result<O, SyncError>
where
    T: AsyncRead + AsyncWrite + Unpin,
    C: SyncCore,
{
    let mut codec = Codec;
    let mut inbound = BytesMut::new();
    let mut outbound = BytesMut::new();
    let mut effects: VecDeque<Effect<O>> = opening.into_iter().collect();

    loop {
        let Some(effect) = effects.pop_front() else {
            let frame = timeout(
                FRAME_TIMEOUT,
                next_frame(&mut transport, &mut codec, &mut inbound),
            )
            .await
            .map_err(|_| SyncError::TimedOut)??;
            let Some(message) = frame else {
                return Err(SyncError::PeerClosed);
            };
            effects.extend(machine(Input::Message(message)));
            continue;
        };

        match effect {
            Effect::Send(message) => {
                codec.encode(message, &mut outbound)?;
                transport
                    .write_all(&outbound)
                    .await
                    .map_err(sync::Error::Io)?;
                outbound.clear();
                transport.flush().await.map_err(sync::Error::Io)?;
            }
            Effect::Ask(query) => {
                let answer = core.answer(query).await?;
                effects.extend(machine(Input::Answer(answer)));
            }
            Effect::Ingest(run) => {
                core.ingest(run).await?;
                effects.extend(machine(Input::Ingested));
            }
            Effect::Done(outcome) => return Ok(outcome),
            Effect::Violation(breach) => return Err(SyncError::Breach(breach)),
        }
    }
}

impl RequestError {
    /// Sorts an actor error into a session error: a gone server is its
    /// own case, a chain error takes whichever variant fits the effect
    /// that hit it.
    fn classify(self, chain: impl FnOnce(ChainError) -> SyncError) -> SyncError {
        match self {
            RequestError::ServerGone => SyncError::ServerGone,
            RequestError::Chain(err) => chain(err),
        }
    }
}

/// Reads one frame off the transport, or `None` where the peer closed
/// cleanly between frames.
async fn next_frame<T>(
    transport: &mut T,
    codec: &mut Codec,
    inbound: &mut BytesMut,
) -> Result<Option<sync::Message>, SyncError>
where
    T: AsyncRead + Unpin,
{
    loop {
        if let Some(message) = codec.decode(inbound)? {
            return Ok(Some(message));
        }
        let read = transport.read_buf(inbound).await.map_err(sync::Error::Io)?;
        if read == 0 {
            return if inbound.is_empty() {
                Ok(None)
            } else {
                Err(SyncError::Truncated)
            };
        }
    }
}
