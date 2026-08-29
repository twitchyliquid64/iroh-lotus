//! The peer-ingress actor: accepts connections from peers on this node's
//! iroh endpoint and serves whatever protocol each one opened.
//!
//! Inbound only — dialling peers and scheduling pulls is other machinery's
//! business; this only answers. Each protocol a peer may speak has its own
//! ALPN ([`Protocol`]), so a connection carries exactly one protocol and
//! dispatch happens once, at accept. Sessions on a connection are served
//! one at a time, off the mainloop, through the same actor messages any
//! other caller uses.
//!
//! Spawned and owned by the server actor. It reaches the server through a
//! [`WeakServerHandle`], upgraded per connection: a strong handle held
//! here would keep the mainloop alive for as long as the mainloop keeps
//! this alive, and neither would ever shut down.

use std::{ops::ControlFlow, time::Duration};

use iroh::{
    Endpoint,
    endpoint::{Connection, Incoming, VarInt},
};
use tokio::{
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::{Responder, ServerHandle, peer_link::Link, server::WeakServerHandle};

/// How many peer connections are served at once; further attempts are
/// refused at the handshake.
pub const DEFAULT_CONNECTION_LIMIT: usize = 64;

/// How long open connections get to say goodbye on shutdown before their
/// tasks are aborted.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// The protocols a peer may open a connection for, one ALPN each.
///
/// The one place the daemon's ALPN set is written: the endpoint is bound
/// with [`Protocol::alpns`], and an accepted connection is routed by
/// [`Protocol::from_alpn`]. A new peer RPC is a new variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// A peer pulling our canonical path: the [`sync`] crate's protocol.
    Sync,
}

impl Protocol {
    /// Every protocol this daemon accepts.
    pub const ALL: [Protocol; 1] = [Protocol::Sync];

    /// The ALPN identifying this protocol at the handshake.
    pub fn alpn(self) -> &'static [u8] {
        match self {
            Protocol::Sync => sync::ALPN,
        }
    }

    /// The ALPN list to bind the endpoint with, in the form
    /// [`iroh::endpoint::Builder::alpns`] takes.
    pub fn alpns() -> Vec<Vec<u8>> {
        Self::ALL.iter().map(|p| p.alpn().to_vec()).collect()
    }

    /// The protocol an accepted connection negotiated, if it is one of ours.
    pub fn from_alpn(alpn: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.alpn() == alpn)
    }
}

/// Why this side closed a connection, as the QUIC application close code
/// the peer sees. Shared with the egress, so a code means one thing
/// whichever side sent it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CloseReason {
    ShuttingDown,
    Breach,
    Local,
    UnknownProtocol,
    /// The ledger no longer lists the node this connection was kept for.
    Removed,
}

impl CloseReason {
    fn code(self) -> VarInt {
        VarInt::from_u32(match self {
            CloseReason::ShuttingDown => 1,
            CloseReason::Breach => 2,
            CloseReason::Local => 3,
            CloseReason::UnknownProtocol => 4,
            CloseReason::Removed => 5,
        })
    }

    fn message(self) -> &'static [u8] {
        match self {
            CloseReason::ShuttingDown => b"shutting down",
            CloseReason::Breach => b"protocol breach",
            CloseReason::Local => b"internal error",
            CloseReason::UnknownProtocol => b"unknown protocol",
            CloseReason::Removed => b"removed from cluster",
        }
    }

    pub(crate) fn close(self, conn: &Connection) {
        conn.close(self.code(), self.message());
    }
}

#[derive(Debug)]
enum IngressMsg {
    Shutdown(Responder<(), ()>),
    Connections(Responder<usize, ()>),
}

/// The peer-ingress actor, before it is spawned.
#[derive(Debug)]
pub(crate) struct PeerIngress {
    endpoint: Endpoint,
    server: WeakServerHandle,
    limit: usize,
}

impl PeerIngress {
    pub(crate) fn new(endpoint: Endpoint, server: WeakServerHandle) -> Self {
        Self {
            endpoint,
            server,
            limit: DEFAULT_CONNECTION_LIMIT,
        }
    }

    /// Caps how many peer connections are served at once.
    pub(crate) fn with_connection_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Starts the accept loop on its own task, returning the handle the
    /// server drives it by.
    pub(crate) fn spawn(self) -> PeerIngressHandle {
        let (tx, rx) = mpsc::channel(8);
        let join = tokio::spawn(self.run(rx));
        PeerIngressHandle { tx, join }
    }

    async fn run(self, mut cmd: mpsc::Receiver<IngressMsg>) {
        let mut conns: JoinSet<()> = JoinSet::new();
        let cancel = CancellationToken::new();

        loop {
            tokio::select! {
                // Commands win over new peers, so a shutdown is not held off
                // by a busy endpoint.
                biased;

                msg = cmd.recv() => match msg {
                    Some(IngressMsg::Shutdown(r)) => {
                        Self::stop(conns, cancel).await;
                        r.respond(Ok(()));
                        return;
                    }
                    Some(IngressMsg::Connections(r)) => r.respond(Ok(conns.len())),
                    // The server dropped us: it is on its way out.
                    None => return Self::stop(conns, cancel).await,
                },
                // Reap finished connections so `conns.len()` is the live count.
                Some(res) = conns.join_next() => {
                    if let Err(e) = res && e.is_panic() {
                        tracing::error!(error = %e, "peer connection task panicked");
                    }
                }
                incoming = self.endpoint.accept() => {
                    // The endpoint was closed under us.
                    let Some(incoming) = incoming else {
                        return Self::stop(conns, cancel).await;
                    };
                    if conns.len() >= self.limit {
                        tracing::debug!(remote = ?incoming.remote_addr(), "refusing peer: at connection limit");
                        incoming.refuse();
                        continue;
                    }
                    let Some(server) = self.server.upgrade() else {
                        // Server about to be garbage collected.
                        incoming.refuse();
                        return Self::stop(conns, cancel).await;
                    };
                    conns.spawn(Self::handle_incoming(server, incoming, cancel.child_token()));
                }
            }
        }
    }

    /// Ends every connection and waits for its task, aborting what lingers.
    ///
    /// Tells the tasks to stop rather than waiting for them to finish on
    /// their own: a session mid-round-trip is waiting on the mainloop, and
    /// on shutdown the mainloop is waiting on us.
    async fn stop(mut conns: JoinSet<()>, cancel: CancellationToken) {
        cancel.cancel();
        let drained = timeout(SHUTDOWN_GRACE, async {
            while conns.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            tracing::warn!(
                lingering = conns.len(),
                "aborting peer connections that did not close in time"
            );
            conns.shutdown().await;
        }
    }

    /// Finishes the handshake with one peer and serves the protocol it opened.
    ///
    /// Handshake failures are logged and dropped: the endpoint's UDP socket
    /// takes whatever the network sends it, solicited or not.
    async fn handle_incoming(server: ServerHandle, incoming: Incoming, cancel: CancellationToken) {
        let accepting = match incoming.accept() {
            Ok(accepting) => accepting,
            Err(e) => {
                tracing::debug!(error = %e, "accepting peer connection");
                return;
            }
        };
        let conn = match accepting.await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, "peer handshake failed");
                return;
            }
        };

        let span = tracing::info_span!(
            "peer",
            remote = %conn.remote_id().fmt_short(),
            alpn = %String::from_utf8_lossy(conn.alpn()),
        );
        async {
            tracing::debug!("peer connected");
            tokio::select! {
                () = Self::serve_connection(&server, &conn) => {}
                () = cancel.cancelled() => CloseReason::ShuttingDown.close(&conn),
            }
        }
        .instrument(span)
        .await
    }

    /// Serves one connection until the peer hangs up or this side closes it.
    async fn serve_connection(server: &ServerHandle, conn: &Connection) {
        // The endpoint only completes handshakes for ALPNs it was bound
        // with, so an unknown one here is a bind that disagrees with `ALL`.
        let Some(protocol) = Protocol::from_alpn(conn.alpn()) else {
            tracing::error!(
                "connection accepted under an ALPN the endpoint should not have offered"
            );
            return CloseReason::UnknownProtocol.close(conn);
        };
        match protocol {
            Protocol::Sync => Self::serve_sync(server, conn).await,
        }
    }

    /// Serves the peer's pulls and listens for its announces until the
    /// connection ends or a session gives grounds to close it.
    ///
    /// The peer dialled us, so it is the one announcing; a head we do not
    /// stand at is pulled back over this same connection.
    async fn serve_sync(server: &ServerHandle, conn: &Connection) {
        let mut link = Link::new(conn.clone(), server.clone());
        loop {
            let flow = tokio::select! {
                bi = conn.accept_bi() => match bi {
                    Ok((send, recv)) => {
                        link.serve(send, recv);
                        ControlFlow::Continue(())
                    }
                    Err(e) => return tracing::debug!(reason = %e, "peer connection ended"),
                },
                uni = conn.accept_uni() => match uni {
                    Ok(recv) => link.on_announce(recv).await,
                    Err(e) => return tracing::debug!(reason = %e, "peer connection ended"),
                },
                Some(session) = link.next_session() => link.settle(session),
            };
            if let ControlFlow::Break(reason) = flow {
                return reason.close(conn);
            }
        }
    }
}

/// The server's handle on its ingress actor.
#[derive(Debug)]
pub(crate) struct PeerIngressHandle {
    tx: mpsc::Sender<IngressMsg>,
    join: JoinHandle<()>,
}

impl PeerIngressHandle {
    /// Stops accepting, closes every connection, and waits for the actor to
    /// exit. An actor already gone is not an error: it stopped for a reason
    /// of its own, and the outcome is the same.
    pub(crate) async fn shutdown(self) {
        let (send, recv) = Responder::channel();
        let _ = self.tx.send(IngressMsg::Shutdown(send)).await;
        let _ = recv.await;
        if let Err(e) = self.join.await
            && e.is_panic()
        {
            tracing::error!(error = %e, "peer ingress panicked");
        }
    }

    /// How many peer connections are being served right now.
    pub(crate) async fn connections(&self) -> Result<usize, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.tx.send(IngressMsg::Connections(send)).await;
        recv.await.map_err(|_| ())?
    }
}
