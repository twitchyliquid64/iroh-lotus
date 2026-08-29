//! One connection to a peer, whichever side dialled it: the streams it
//! carries and what each means.
//!
//! - A bi-stream the peer opens is a pull session, and is served.
//! - A bi-stream this side opens is its own pull, run when the peer
//!   announced a head this node does not stand at.
//! - A uni-stream carries one [`Announce`] frame and nothing else.
//!
//! Sessions run on tasks of their own so a long pull never holds up the
//! next announce; the [`Link`] tracks them and turns how each ended into
//! whether the connection should close over it.

use std::{io, ops::ControlFlow, time::Duration};

use iroh::endpoint::{Connection, ConnectionError, RecvStream, SendStream};
use sync::{Announce, Codec, Message, PullOutcome, ServeOutcome};
use tokio::{task::JoinSet, time::timeout};
use tokio_util::{
    bytes::BytesMut,
    codec::{Decoder, Encoder},
};
use tracing::Instrument;
use wire::EnvelopeDigest;

use crate::{
    ServerHandle,
    peer_ingress::CloseReason,
    sync_driver::{self, SyncError},
};

/// The most bytes an announce stream may carry: one frame is a length
/// prefix, a tag, and a digest, so anything near this is not an announce.
pub const ANNOUNCE_MAX_LEN: usize = 256;

/// How long an announce gets to be written or read before the peer is
/// judged stuck.
pub const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why an announce did not reach the peer.
#[derive(Debug, thiserror::Error)]
pub enum AnnounceError {
    #[error("opening the announce stream")]
    Open(#[source] ConnectionError),
    #[error("encoding the announce")]
    Encode(#[source] sync::Error),
    #[error("writing the announce")]
    Write(#[source] io::Error),
    #[error("the peer did not take the announce in time")]
    TimedOut,
}

/// How one session on the connection ended.
#[derive(Debug)]
pub(crate) enum Session {
    Served(Result<ServeOutcome, SyncError>),
    Pulled(Result<PullOutcome, SyncError>),
    /// The pull's stream could not be opened; the connection is on its
    /// way down and will say so itself.
    PullNotOpened(ConnectionError),
}

/// Whether a pull is running, and whether another is owed once it ends.
///
/// Announces that land mid-pull fold into one more pull rather than a
/// queue: whatever they announced, one session after this one catches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pull {
    Idle,
    Running,
    RunningAgain,
}

/// The sessions on one connection and the state that decides when to
/// open one.
#[derive(Debug)]
pub(crate) struct Link {
    conn: Connection,
    server: ServerHandle,
    sessions: JoinSet<Session>,
    pull: Pull,
}

impl Link {
    pub(crate) fn new(conn: Connection, server: ServerHandle) -> Self {
        Self {
            conn,
            server,
            sessions: JoinSet::new(),
            pull: Pull::Idle,
        }
    }

    /// Serves the pull the peer opened on this stream pair.
    pub(crate) fn serve(&mut self, send: SendStream, recv: RecvStream) {
        let server = self.server.clone();
        self.sessions.spawn(
            async move {
                // Dropping the send half finishes the stream, so the peer
                // sees a clean end however the session went.
                Session::Served(sync_driver::serve(tokio::io::join(recv, send), &server).await)
            }
            .in_current_span(),
        );
    }

    /// Reads the announce on `recv` and, if the peer stands at a head
    /// this node does not, sets a pull going.
    pub(crate) async fn on_announce(&mut self, mut recv: RecvStream) -> ControlFlow<CloseReason> {
        let bytes = match timeout(ANNOUNCE_TIMEOUT, recv.read_to_end(ANNOUNCE_MAX_LEN)).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "reading peer announce");
                return ControlFlow::Break(CloseReason::Breach);
            }
            Err(_) => {
                tracing::warn!("peer announce did not arrive in time");
                return ControlFlow::Break(CloseReason::Breach);
            }
        };
        let announced = match decode_announce(&bytes) {
            Ok(announce) => announce,
            Err(reason) => {
                tracing::warn!(%reason, "peer sent a malformed announce");
                return ControlFlow::Break(CloseReason::Breach);
            }
        };

        let Ok(ours) = self.server.head().await else {
            return ControlFlow::Break(CloseReason::ShuttingDown);
        };
        if announced.head == ours {
            tracing::debug!("peer announced the head we stand at");
        } else {
            tracing::info!(
                head = announced.head.to_hex().as_ref(),
                "peer announced a new head"
            );
            self.pull();
        }
        ControlFlow::Continue(())
    }

    /// Tells the peer this node's head is now `head`.
    pub(crate) async fn announce(&self, head: EnvelopeDigest) -> Result<(), AnnounceError> {
        let mut send = self.conn.open_uni().await.map_err(AnnounceError::Open)?;
        let mut frame = BytesMut::new();
        Codec
            .encode(Message::Announce(Announce { head }), &mut frame)
            .map_err(AnnounceError::Encode)?;
        timeout(ANNOUNCE_TIMEOUT, async {
            send.write_all(&frame).await?;
            send.finish().map_err(io::Error::other)
        })
        .await
        .map_err(|_| AnnounceError::TimedOut)?
        .map_err(AnnounceError::Write)
    }

    /// Opens a pull now, or owes one if a pull is already running.
    fn pull(&mut self) {
        self.pull = match self.pull {
            Pull::Idle => {
                self.spawn_pull();
                Pull::Running
            }
            Pull::Running | Pull::RunningAgain => Pull::RunningAgain,
        };
    }

    fn spawn_pull(&mut self) {
        let conn = self.conn.clone();
        let server = self.server.clone();
        self.sessions.spawn(
            async move {
                let (send, recv) = match conn.open_bi().await {
                    Ok(streams) => streams,
                    Err(e) => return Session::PullNotOpened(e),
                };
                Session::Pulled(sync_driver::pull(tokio::io::join(recv, send), &server).await)
            }
            .in_current_span(),
        );
    }

    /// The next session to end, or `None` while none is running. Pair
    /// with [`settle`](Self::settle) — in a `select!`, as
    /// `Some(session) = link.next_session()`.
    pub(crate) async fn next_session(&mut self) -> Option<Session> {
        match self.sessions.join_next().await? {
            Ok(session) => Some(session),
            Err(e) => {
                if e.is_panic() {
                    tracing::error!(error = %e, "peer session panicked");
                }
                // A cancelled session is the link going away; nothing to say.
                None
            }
        }
    }

    /// Records how a session ended and whether the connection should
    /// close over it, carrying the close reason if so.
    pub(crate) fn settle(&mut self, session: Session) -> ControlFlow<CloseReason> {
        let was_pull = !matches!(session, Session::Served(_));
        let flow = match session {
            Session::Served(Ok(outcome)) => {
                tracing::info!(?outcome, "served pull");
                ControlFlow::Continue(())
            }
            // Routine: the peer learned from `Hello` that it needed nothing.
            Session::Served(Err(SyncError::PeerClosed)) => {
                tracing::debug!("peer parted between frames");
                ControlFlow::Continue(())
            }
            Session::Served(Err(e)) => {
                let reason = close_reason(&e);
                tracing::warn!(error = %e, ?reason, "closing peer connection");
                ControlFlow::Break(reason)
            }
            Session::Pulled(Ok(outcome)) => {
                match &outcome {
                    PullOutcome::Synced { .. } => tracing::info!(?outcome, "pulled from peer"),
                    PullOutcome::AlreadyCurrent => tracing::debug!("pulled: already current"),
                    // Nothing to do until checkpoint sync exists.
                    PullOutcome::NoCommonHistory => {
                        tracing::warn!("peer shares no history with us")
                    }
                }
                ControlFlow::Continue(())
            }
            Session::Pulled(Err(e)) => {
                let reason = close_reason(&e);
                tracing::warn!(error = %e, ?reason, "closing peer connection");
                ControlFlow::Break(reason)
            }
            Session::PullNotOpened(e) => {
                tracing::debug!(error = %e, "could not open a pull stream");
                ControlFlow::Continue(())
            }
        };

        if was_pull {
            self.pull = match self.pull {
                Pull::RunningAgain if flow.is_continue() => {
                    self.spawn_pull();
                    Pull::Running
                }
                _ => Pull::Idle,
            };
        }
        flow
    }
}

/// What a session error says about who to blame: a gone server is ours,
/// a failed answer is ours, everything else is the peer's.
fn close_reason(e: &SyncError) -> CloseReason {
    match e {
        SyncError::ServerGone => CloseReason::ShuttingDown,
        SyncError::Answer(_) => CloseReason::Local,
        _ => CloseReason::Breach,
    }
}

/// Decodes the one frame an announce stream carries.
fn decode_announce(bytes: &[u8]) -> Result<Announce, String> {
    let mut buf = BytesMut::from(bytes);
    let message = Codec
        .decode(&mut buf)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "stream ended inside the frame".to_owned())?;
    if !buf.is_empty() {
        return Err("more than one frame on the announce stream".to_owned());
    }
    match message {
        Message::Announce(announce) => Ok(announce),
        other => Err(format!("expected Announce, got {}", other.kind())),
    }
}
