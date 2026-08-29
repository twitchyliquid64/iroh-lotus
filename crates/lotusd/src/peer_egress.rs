//! The peer-egress actor: keeps a connection open to every other node the
//! ledger lists, and follows the list as it changes.
//!
//! Outbound only — the counterpart of [`peer_ingress`](crate::peer_ingress).
//! It does not yet pull over the connections it keeps; it keeps them.
//!
//! Level-triggered rather than edge-triggered. A subscription on the
//! `cluster-nodes` namespace says *that* the set moved, not what each
//! entry was before and after, and a subscriber that fell behind is woken
//! once for several movements merged. So every wake re-reads the whole
//! namespace and reconciles the set it describes against the connection
//! table: entries not yet in the table are dialled, entries no longer in
//! it are closed, and an entry whose address changed is told about it.
//! Reorgs, merged wakes, and bursts of edits all collapse to the same step.
//!
//! One task per peer, owning that peer's connection and redialling it with
//! backoff. Over each connection it announces this node's head as it
//! moves — a second subscription, fanned out to the peer tasks — and
//! serves whatever pull the peer opens in answer. The actor's own loop
//! never awaits the mainloop: on shutdown the mainloop awaits *this*, so
//! a read of the ledger runs on a task of its own and posts its result
//! back here.

use std::{collections::BTreeMap, fmt, ops::ControlFlow, time::Duration};

use iroh::{Endpoint, EndpointAddr, endpoint::Connection};
use state::CLUSTER_NODES_KEY;
use tokio::{
    sync::{mpsc, watch},
    task::{Id, JoinHandle, JoinSet},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use wire::{EnvelopeDigest, KeyId, msg::NamespaceKey};

use crate::{
    ChangeFilter, RequestError, Responder, ServerHandle, SubscriptionHandle,
    peer_ingress::CloseReason, peer_link::Link, server::WeakServerHandle,
};

/// The first wait after a dial fails; each failure after doubles it.
pub const BACKOFF_BASE: Duration = Duration::from_secs(1);

/// The longest wait between dials of a peer that keeps failing.
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// How long peer tasks get to close their connections on shutdown before
/// they are aborted.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Where a peer's connection stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerState {
    /// A dial is in progress; `attempt` counts the failures before it.
    Dialing { attempt: u32 },
    /// The connection is up.
    Connected,
    /// The last dial failed; waiting before the next one.
    Backoff { attempt: u32 },
}

impl fmt::Display for PeerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerState::Dialing { attempt: 0 } => f.write_str("dialing"),
            PeerState::Dialing { attempt } => write!(f, "dialing (retry {attempt})"),
            PeerState::Connected => f.write_str("connected"),
            PeerState::Backoff { attempt } => write!(f, "backoff after {attempt} failures"),
        }
    }
}

/// One peer as the egress sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    /// The node's id in the cluster — its key in `cluster-nodes`.
    pub node: KeyId,
    /// Where the ledger says to reach it.
    pub addr: EndpointAddr,
    pub state: PeerState,
}

#[derive(Debug)]
enum EgressMsg {
    Shutdown(Responder<(), ()>),
    Peers(Responder<Vec<PeerStatus>, ()>),
    /// The refresh task's read of the ledger came back.
    Desired(Result<BTreeMap<KeyId, EndpointAddr>, RequestError>),
}

/// The peer-egress actor, before it is spawned.
#[derive(Debug)]
pub(crate) struct PeerEgress {
    endpoint: Endpoint,
    server: WeakServerHandle,
    /// This node's own id, so its own entry is never dialled.
    node: KeyId,
}

/// A peer in the table: the task keeping its connection, and the channels
/// the actor reaches it through.
#[derive(Debug)]
struct Peer {
    /// The address to dial. The task reads it fresh at every dial.
    addr: watch::Sender<EndpointAddr>,
    state: watch::Receiver<PeerState>,
    cancel: CancellationToken,
    /// Which task in the set is this peer's. A peer replaced under the same
    /// node id gets a new task, and the old one's exit must not be read as
    /// the new one's.
    task: Id,
}

impl PeerEgress {
    pub(crate) fn new(endpoint: Endpoint, server: WeakServerHandle, node: KeyId) -> Self {
        Self {
            endpoint,
            server,
            node,
        }
    }

    /// Starts the actor on its own task, returning the handle the server
    /// drives it by.
    pub(crate) fn spawn(self) -> PeerEgressHandle {
        let (tx, rx) = mpsc::channel(8);
        let join = tokio::spawn(self.run(tx.clone(), rx));
        PeerEgressHandle { tx, join }
    }

    async fn run(self, tx: mpsc::Sender<EgressMsg>, mut cmd: mpsc::Receiver<EgressMsg>) {
        // Subscribed before the first read, so nothing can move between
        // the read and the subscription taking effect.
        let Some((mut nodes, mut heads)) = self.subscribe().await else {
            return;
        };
        // Seeded from where the subscription opened: every later movement
        // arrives as a notification, so nothing is announced stale.
        let (head, _) = watch::channel(heads.opened_at());

        let mut peer_table: BTreeMap<KeyId, Peer> = BTreeMap::new();
        let mut peer_conn_tasks: JoinSet<KeyId> = JoinSet::new();
        let cancel = CancellationToken::new();
        let mut refresh = Refresh::default();
        refresh.request(&self.server, &tx);

        loop {
            tokio::select! {
                // Commands win over wakes, so a shutdown is not held off by
                // a namespace that keeps changing.
                biased;

                msg = cmd.recv() => match msg {
                    Some(EgressMsg::Shutdown(r)) => {
                        Self::stop(peer_conn_tasks, cancel).await;
                        r.respond(Ok(()));
                        return;
                    }
                    Some(EgressMsg::Peers(r)) => r.respond(Ok(Self::statuses(&peer_table))),
                    Some(EgressMsg::Desired(Ok(desired))) => {
                        self.reconcile(desired, &mut peer_table, &mut peer_conn_tasks, &cancel, &head);
                        refresh.landed(&self.server, &tx);
                    }
                    Some(EgressMsg::Desired(Err(RequestError::ServerGone))) => {
                        return Self::stop(peer_conn_tasks, cancel).await;
                    }
                    Some(EgressMsg::Desired(Err(RequestError::Chain(e)))) => {
                        // Keep what we have: the last set read is the best
                        // guess until the ledger can be read again.
                        tracing::warn!(error = %e, "reading cluster nodes");
                        refresh.landed(&self.server, &tx);
                    }
                    // The server dropped us: it is on its way out.
                    None => return Self::stop(peer_conn_tasks, cancel).await,
                },
                changed = nodes.next() => match changed {
                    Some(_) => refresh.request(&self.server, &tx),
                    // The core is gone; nothing will move the set again.
                    None => return Self::stop(peer_conn_tasks, cancel).await,
                },
                moved = heads.next() => match moved {
                    Some(moved) => {
                        head.send_replace(moved.head);
                    }
                    None => return Self::stop(peer_conn_tasks, cancel).await,
                },
                // Reap finished peer tasks. One ends only when told to, so
                // a table entry still pointing at it was replaced, not lost.
                Some(res) = peer_conn_tasks.join_next_with_id() => match res {
                    Ok((id, node)) => {
                        if peer_table.get(&node).is_some_and(|peer| peer.task == id) {
                            peer_table.remove(&node);
                        }
                    }
                    Err(e) if e.is_panic() => {
                        tracing::error!(error = %e, "peer task panicked");
                    }
                    Err(_) => {}
                },
            }
        }
    }

    /// Registers for changes to the node set and to the head, or `None`
    /// when the server is already gone.
    async fn subscribe(&self) -> Option<(SubscriptionHandle, SubscriptionHandle)> {
        let server = self.server.upgrade()?;
        let key = NamespaceKey::try_new(CLUSTER_NODES_KEY).expect("the reserved key is static");
        let nodes = server.subscribe(ChangeFilter::namespace(key)).await.ok()?;
        let heads = server.subscribe(ChangeFilter::head()).await.ok()?;
        Some((nodes, heads))
    }

    /// Brings the table in line with `desired`.
    ///
    /// A peer whose endpoint id changed is a different machine under the
    /// same node id: the old task is cancelled and a fresh one spawned. A
    /// peer whose transport addresses changed is the same machine moved,
    /// and keeps its connection; the new addresses are used at its next
    /// dial.
    fn reconcile(
        &self,
        desired: BTreeMap<KeyId, EndpointAddr>,
        table: &mut BTreeMap<KeyId, Peer>,
        tasks: &mut JoinSet<KeyId>,
        cancel: &CancellationToken,
        head: &watch::Sender<EnvelopeDigest>,
    ) {
        let desired: BTreeMap<KeyId, EndpointAddr> = desired
            .into_iter()
            .filter(|(node, addr)| *node != self.node && addr.id != self.endpoint.id())
            .collect();

        let gone: Vec<KeyId> = table
            .keys()
            .filter(|node| !desired.contains_key(node))
            .copied()
            .collect();
        for node in gone {
            if let Some(peer) = table.get(&node) {
                tracing::info!(%node, "node removed from cluster");
                peer.cancel.cancel();
            }
        }

        for (node, addr) in desired {
            match table.get(&node) {
                Some(peer) if peer.addr.borrow().id == addr.id => {
                    let moved = peer.addr.send_if_modified(|current| {
                        let changed = *current != addr;
                        if changed {
                            *current = addr;
                        }
                        changed
                    });
                    if moved {
                        tracing::info!(%node, "node addresses changed");
                    }
                }
                Some(peer) => {
                    tracing::info!(%node, "node re-keyed its endpoint");
                    peer.cancel.cancel();
                    let peer = self.spawn_peer(node, addr, tasks, cancel, head);
                    table.insert(node, peer);
                }
                None => {
                    tracing::info!(%node, "node added to cluster");
                    let peer = self.spawn_peer(node, addr, tasks, cancel, head);
                    table.insert(node, peer);
                }
            }
        }
    }

    /// Starts the task that keeps `node` connected.
    fn spawn_peer(
        &self,
        node: KeyId,
        addr: EndpointAddr,
        tasks: &mut JoinSet<KeyId>,
        cancel: &CancellationToken,
        head: &watch::Sender<EnvelopeDigest>,
    ) -> Peer {
        let (addr_tx, addr_rx) = watch::channel(addr);
        let (state_tx, state_rx) = watch::channel(PeerState::Dialing { attempt: 0 });
        let cancel = cancel.child_token();
        let span = tracing::info_span!("peer", %node);
        let task = tasks
            .spawn(
                maintain(
                    self.endpoint.clone(),
                    self.server.clone(),
                    node,
                    addr_rx,
                    head.subscribe(),
                    state_tx,
                    cancel.clone(),
                )
                .instrument(span),
            )
            .id();
        Peer {
            addr: addr_tx,
            state: state_rx,
            cancel,
            task,
        }
    }

    fn statuses(table: &BTreeMap<KeyId, Peer>) -> Vec<PeerStatus> {
        table
            .iter()
            .map(|(node, peer)| PeerStatus {
                node: *node,
                addr: peer.addr.borrow().clone(),
                state: peer.state.borrow().clone(),
            })
            .collect()
    }

    /// Ends every peer task, aborting what lingers.
    async fn stop(mut tasks: JoinSet<KeyId>, cancel: CancellationToken) {
        cancel.cancel();
        let drained = timeout(SHUTDOWN_GRACE, async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            tracing::warn!(
                lingering = tasks.len(),
                "aborting peer tasks that did not close in time"
            );
            tasks.shutdown().await;
        }
    }
}

/// Coalesces reads of the ledger: one in flight at a time, and wakes that
/// arrive meanwhile fold into one more read once it lands.
#[derive(Debug, Default)]
struct Refresh {
    in_flight: bool,
    again: bool,
}

impl Refresh {
    /// Asks for a read, or notes that one is wanted once the current one
    /// lands.
    fn request(&mut self, server: &WeakServerHandle, tx: &mpsc::Sender<EgressMsg>) {
        if self.in_flight {
            self.again = true;
            return;
        }
        self.in_flight = true;
        let server = server.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let desired = match server.upgrade() {
                Some(server) => server.peer_addresses().await,
                None => Err(RequestError::ServerGone),
            };
            // The actor going away is the only way this fails, and then
            // nobody is waiting for the answer.
            let _ = tx.send(EgressMsg::Desired(desired)).await;
        });
    }

    /// The read landed; issues the one that was waiting on it, if any.
    fn landed(&mut self, server: &WeakServerHandle, tx: &mpsc::Sender<EgressMsg>) {
        self.in_flight = false;
        if std::mem::take(&mut self.again) {
            self.request(server, tx);
        }
    }
}

/// Keeps one peer connected until cancelled: dials, holds the connection
/// until it drops, and dials again with backoff.
async fn maintain(
    endpoint: Endpoint,
    server: WeakServerHandle,
    node: KeyId,
    mut addr: watch::Receiver<EndpointAddr>,
    mut head: watch::Receiver<EnvelopeDigest>,
    state: watch::Sender<PeerState>,
    cancel: CancellationToken,
) -> KeyId {
    let mut attempt: u32 = 0;
    loop {
        let target = addr.borrow_and_update().clone();
        state.send_replace(PeerState::Dialing { attempt });
        let dialled = tokio::select! {
            dialled = endpoint.connect(target, sync::ALPN) => dialled,
            () = cancel.cancelled() => return node,
        };

        match dialled {
            Ok(conn) => {
                attempt = 0;
                state.send_replace(PeerState::Connected);
                tracing::info!("connected to peer");
                // Server about to be garbage collected.
                let Some(server) = server.upgrade() else {
                    return node;
                };
                if hold(conn, server, &mut head, &cancel).await.is_break() {
                    return node;
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, attempt, "dialling peer");
            }
        }

        // A lost connection waits like a failed dial: a peer that accepts
        // and drops us is otherwise a hot loop.
        attempt = attempt.saturating_add(1);
        state.send_replace(PeerState::Backoff { attempt });
        tokio::select! {
            () = sleep(backoff(attempt)) => {}
            // A new address is worth trying at once.
            changed = addr.changed() => if changed.is_err() {
                return node;
            },
            () = cancel.cancelled() => return node,
        }
    }
}

/// Holds `conn` until it closes or the peer is cancelled — the latter is
/// a `Break`, and the connection is closed here to say why.
///
/// Announces this node's head as it moves, starting with where it stands
/// now so a peer that was apart catches up at once, and serves the pulls
/// the peer opens in answer.
async fn hold(
    conn: Connection,
    server: ServerHandle,
    head: &mut watch::Receiver<EnvelopeDigest>,
    cancel: &CancellationToken,
) -> ControlFlow<()> {
    let mut link = Link::new(conn.clone(), server);
    // Copied out first: the watch guard must not be held across the await.
    let current = *head.borrow_and_update();
    if let Err(e) = link.announce(current).await {
        tracing::debug!(error = %e, "announcing head on connect");
    }
    loop {
        let flow = tokio::select! {
            bi = conn.accept_bi() => match bi {
                Ok((send, recv)) => {
                    link.serve(send, recv);
                    ControlFlow::Continue(())
                }
                Err(e) => {
                    tracing::info!(reason = %e, "peer connection lost");
                    return ControlFlow::Continue(());
                }
            },
            moved = head.changed() => match moved {
                Ok(()) => {
                    let moved = *head.borrow_and_update();
                    if let Err(e) = link.announce(moved).await {
                        tracing::debug!(error = %e, "announcing head");
                    }
                    ControlFlow::Continue(())
                }
                // The egress is gone; so are we.
                Err(_) => ControlFlow::Break(CloseReason::ShuttingDown),
            },
            Some(session) = link.next_session() => link.settle(session),
            closed = conn.closed() => {
                tracing::info!(reason = ?closed, "peer connection lost");
                return ControlFlow::Continue(());
            }
            () = cancel.cancelled() => ControlFlow::Break(CloseReason::Removed),
        };
        if let ControlFlow::Break(reason) = flow {
            reason.close(&conn);
            return match reason {
                // Closed over a session gone wrong: dial again.
                CloseReason::Breach | CloseReason::Local => ControlFlow::Continue(()),
                _ => ControlFlow::Break(()),
            };
        }
    }
}

/// How long to wait before dial number `attempt + 1`.
fn backoff(attempt: u32) -> Duration {
    // Doubling past the cap only overflows, so stop doubling there.
    let doublings = attempt.saturating_sub(1).min(16);
    BACKOFF_BASE.saturating_mul(1 << doublings).min(BACKOFF_MAX)
}

/// The server's handle on its egress actor.
#[derive(Debug)]
pub(crate) struct PeerEgressHandle {
    tx: mpsc::Sender<EgressMsg>,
    join: JoinHandle<()>,
}

impl PeerEgressHandle {
    /// Closes every peer connection and waits for the actor to exit. An
    /// actor already gone is not an error: it stopped for a reason of its
    /// own, and the outcome is the same.
    pub(crate) async fn shutdown(self) {
        let (send, recv) = Responder::channel();
        let _ = self.tx.send(EgressMsg::Shutdown(send)).await;
        let _ = recv.await;
        if let Err(e) = self.join.await
            && e.is_panic()
        {
            tracing::error!(error = %e, "peer egress panicked");
        }
    }

    /// Every peer in the table and where its connection stands.
    pub(crate) async fn peers(&self) -> Result<Vec<PeerStatus>, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.tx.send(EgressMsg::Peers(send)).await;
        recv.await.map_err(|_| ())?
    }
}
