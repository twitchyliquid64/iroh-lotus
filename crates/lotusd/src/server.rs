//! The server actor: one mainloop task owning the [`Core`], reached only by
//! the messages a [`ServerHandle`] sends it.

use core::fmt;
use std::{
    collections::BTreeMap,
    num::NonZeroU32,
    ops::ControlFlow,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use iroh::{Endpoint, EndpointAddr};
use lotusd_rpc as rpc;
use state::Insert;
use storage::{LogEntry, StoredAt};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use wire::{
    Envelope, EnvelopeDigest, KeyId, Msg,
    msg::{
        AmendNamespaceKey, AmendOp, DeleteNamespace, IncrementDecrement, Namespace, SetNamespace,
        SetNamespaceKey,
    },
};

use crate::{
    AdmitError, AdvertiseError, Advertised, ChainError, ChangeFilter, ChangeSelector, CompactError,
    Compacted, Core, InitError, Responder, SubscriptionHandle, VERSION,
    addr_publish::{AddrPublish, AddrPublishHandle, PublishState},
    bootstrap::{InviteError, Invites, Welcomed},
    invite::{self, Invite, Token},
    peer_egress::{PeerEgress, PeerEgressHandle, PeerState, PeerStatus},
    peer_ingress::{PeerIngress, PeerIngressHandle},
};

/// The longest an invite may be good for. A token is a bearer secret:
/// one that outlives the operator's attention is one they forgot.
pub const MAX_INVITE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How many of the newest envelopes compaction keeps regardless of age,
/// until [`Server::with_keep_envelopes`] says otherwise.
pub const DEFAULT_KEEP_ENVELOPES: NonZeroU32 = NonZeroU32::new(32).unwrap();

/// How often the mainloop looks for envelopes to prune.
const COMPACT_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The fewest prunable envelopes the periodic pass acts on: the sweep is
/// not worth paying for less. A [`ServerHandle::compact`] prunes eagerly
/// instead.
const COMPACT_MIN_PRUNE: u64 = 64;

/// A freshly issued invite and the window the sponsor will honour it for.
/// `ttl` is the granted window, capped at [`MAX_INVITE_TTL`], not a clock
/// reading: it is what the invite book enforces, so it is what to report.
#[derive(Debug, Clone)]
pub struct Issued {
    pub invite: Invite,
    pub ttl: Duration,
}

#[derive(Debug)]
enum ServerMsg {
    Shutdown(Responder<(), ()>),
    ChainRange(Responder<rpc::ChainRange, ()>),
    Envelopes(
        rpc::EnvelopeSelector,
        Responder<Vec<(EnvelopeDigest, LogEntry)>, ChainError>,
    ),
    Insert(Vec<Envelope>, Responder<Insert, ChainError>),
    SyncAnswer(sync::Query, Responder<sync::Answer, ChainError>),
    Subscribe(ChangeFilter, Responder<SubscriptionHandle, ()>),
    Contains(EnvelopeDigest, Responder<bool, ChainError>),
    Watchers(Responder<usize, ()>),
    WatchOrphaned(
        EnvelopeDigest,
        Responder<Option<SubscriptionHandle>, ChainError>,
    ),
    PeerConnections(Responder<usize, ()>),
    PeerAddresses(Responder<BTreeMap<KeyId, EndpointAddr>, ChainError>),
    Peers(Responder<Vec<PeerStatus>, ()>),
    Identity(Responder<Identity, ()>),
    Read(rpc::Read, Responder<rpc::ValueAt, ChainError>),
    WeakWrite(WeakWrite, Responder<rpc::Written, ChainError>),
    Compact(Responder<Compacted, CompactError>),
    CreateInvite(u32, Duration, Responder<Issued, InviteError>),
    RedeemInvite(Token, Responder<Welcomed, InviteError>),
    Admit(
        wire::Key,
        EndpointAddr,
        Responder<EnvelopeDigest, AdmitError>,
    ),
    Advertise(EndpointAddr, Responder<Advertised, AdvertiseError>),
    Published(Responder<Option<PublishState>, ()>),
}

/// A write a local client asks for, to be signed by this node onto its
/// current head: the control protocol's weak writes, under one roof so
/// the mainloop and the handle serve them through one path.
#[derive(Debug, Clone)]
pub enum WeakWrite {
    Set(rpc::WeakSet),
    Push(rpc::WeakPush),
    Delete(rpc::WeakDelete),
    Increment(rpc::WeakIncrement),
    DeleteMatching(rpc::WeakDeleteMatching),
}

impl From<rpc::WeakDeleteMatching> for WeakWrite {
    fn from(delete: rpc::WeakDeleteMatching) -> Self {
        WeakWrite::DeleteMatching(delete)
    }
}

impl From<rpc::WeakSet> for WeakWrite {
    fn from(set: rpc::WeakSet) -> Self {
        WeakWrite::Set(set)
    }
}

impl From<rpc::WeakPush> for WeakWrite {
    fn from(push: rpc::WeakPush) -> Self {
        WeakWrite::Push(push)
    }
}

impl From<rpc::WeakDelete> for WeakWrite {
    fn from(delete: rpc::WeakDelete) -> Self {
        WeakWrite::Delete(delete)
    }
}

impl From<rpc::WeakIncrement> for WeakWrite {
    fn from(increment: rpc::WeakIncrement) -> Self {
        WeakWrite::Increment(increment)
    }
}

impl WeakWrite {
    /// The ledger message this write is, chained onto `prev`.
    ///
    /// A path picks the nested form; none, the whole-namespace one — a
    /// pathless amend addresses the namespace's whole value, which the
    /// ledger allows when that value is one array or one integer.
    fn message(self, prev: EnvelopeDigest) -> Msg {
        match self {
            WeakWrite::Set(rpc::WeakSet {
                key,
                path: Some(path),
                value,
            }) => Msg::SetNamespaceKey(SetNamespaceKey {
                prev,
                key,
                path,
                value: Some(value),
            }),
            WeakWrite::Set(rpc::WeakSet {
                key,
                path: None,
                value,
            }) => Msg::SetNamespace(SetNamespace {
                prev,
                key,
                namespace: Namespace { value },
            }),
            WeakWrite::Push(rpc::WeakPush { key, path, value }) => {
                Msg::AmendNamespaceKey(AmendNamespaceKey {
                    prev,
                    key,
                    path,
                    op: AmendOp::AppendEntry(value),
                })
            }
            WeakWrite::Delete(rpc::WeakDelete {
                key,
                path: Some(path),
            }) => Msg::SetNamespaceKey(SetNamespaceKey {
                prev,
                key,
                path,
                value: None,
            }),
            WeakWrite::Delete(rpc::WeakDelete { key, path: None }) => {
                Msg::DeleteNamespace(DeleteNamespace { prev, key })
            }
            WeakWrite::Increment(rpc::WeakIncrement {
                key,
                path,
                delta,
                min,
                max,
            }) => Msg::AmendNamespaceKey(AmendNamespaceKey {
                prev,
                key,
                path,
                op: AmendOp::IncrementDecrement(IncrementDecrement { delta, min, max }),
            }),
            WeakWrite::DeleteMatching(rpc::WeakDeleteMatching {
                key,
                path,
                predicate,
            }) => Msg::AmendNamespaceKey(AmendNamespaceKey {
                prev,
                key,
                path,
                op: AmendOp::DeleteMatching(predicate),
            }),
        }
    }
}

/// Who a running node is: its id in the cluster, and the endpoint it
/// serves peers on, if any.
#[derive(Debug, Clone)]
pub struct Identity {
    pub node: KeyId,
    /// The endpoint's id and the addresses it is reachable at right now —
    /// what an operator compares against the ledger's entry for this node.
    pub endpoint: Option<EndpointAddr>,
}

/// The server actor, encapsulates all running/server state.
#[derive(Debug)]
pub struct Server {
    core: Core,
    local_sock: UnixListener,
    /// Bound by the caller, so a test can wire several nodes together
    /// however it likes. Without one the node has no peers: local control
    /// still works, nothing is served over the network.
    endpoint: Option<Endpoint>,
    peer_connection_limit: Option<usize>,
    advertise_settle: Option<Duration>,
    keep_envelopes: NonZeroU32,
}

impl Server {
    pub fn new(core: Core, local_sock: UnixListener) -> Result<Self, InitError> {
        Ok(Self {
            core,
            local_sock,
            endpoint: None,
            peer_connection_limit: None,
            advertise_settle: None,
            keep_envelopes: DEFAULT_KEEP_ENVELOPES,
        })
    }

    /// Serves peers on `endpoint`. It must have been bound with the ALPNs
    /// [`Protocol::alpns`] lists, or peers speaking them will be refused
    /// at the handshake.
    ///
    /// [`Protocol::alpns`]: crate::peer_ingress::Protocol::alpns
    pub fn with_endpoint(mut self, endpoint: Endpoint) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Caps how many peer connections are served at once, overriding
    /// [`DEFAULT_CONNECTION_LIMIT`](crate::peer_ingress::DEFAULT_CONNECTION_LIMIT).
    pub fn with_peer_connection_limit(mut self, limit: usize) -> Self {
        self.peer_connection_limit = Some(limit);
        self
    }

    /// How long the endpoint's address is left to settle after it moves
    /// before the node publishes it to the ledger, overriding
    /// [`DEFAULT_SETTLE`](crate::addr_publish::DEFAULT_SETTLE).
    pub fn with_advertise_settle(mut self, settle: Duration) -> Self {
        self.advertise_settle = Some(settle);
        self
    }

    /// How many of the newest envelopes compaction keeps regardless of
    /// age, overriding [`DEFAULT_KEEP_ENVELOPES`]. The ledger's
    /// min-keep-minutes floor binds either way; this knob only ever keeps
    /// more.
    pub fn with_keep_envelopes(mut self, keep: NonZeroU32) -> Self {
        self.keep_envelopes = keep;
        self
    }

    /// Consumes the initialized server and starts an async task for its mainloop, returning
    /// a handle that can be used to query and control the server.
    ///
    /// The peer ingress and egress, and the publisher of this node's own
    /// address, are spawned here as the mainloop's children, and are
    /// brought down before the mainloop returns by either route out of it.
    pub async fn run(self) -> (ServerHandle, JoinHandle<()>) {
        let Self {
            mut core,
            local_sock,
            endpoint,
            peer_connection_limit,
            advertise_settle,
            keep_envelopes,
        } = self;
        let (hnd_tx, mut hnd_recv) = mpsc::channel(8);
        let handle = ServerHandle(hnd_tx);
        let weak = handle.downgrade();

        let ingress = endpoint.clone().map(|ep| {
            let ingress = PeerIngress::new(ep, weak.clone());
            match peer_connection_limit {
                Some(limit) => ingress.with_connection_limit(limit),
                None => ingress,
            }
            .spawn()
        });
        // Both are handed the core to register their subscriptions
        // against: neither may await the mainloop before it is serving
        // its own channel, since the mainloop awaits them in turn.
        let egress = endpoint
            .clone()
            .map(|ep| PeerEgress::new(ep, weak.clone(), core.key_id()).spawn(&core));
        let publisher = endpoint.as_ref().map(|ep| {
            let publisher = AddrPublish::new(ep.watch_addr(), weak.clone(), core.key_id());
            match advertise_settle {
                Some(settle) => publisher.with_settle(settle),
                None => publisher,
            }
            .spawn(&core)
        });

        let join_hnd = tokio::spawn(async move {
            let mut peers = Peers {
                ingress,
                egress,
                publisher,
                endpoint,
            };
            let mut invites = Invites::default();
            let mut compact = tokio::time::interval(COMPACT_INTERVAL);
            compact.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    // Control messages win over new connections, so a shutdown is not held
                    // off by a socket that keeps accepting.
                    biased;

                    msg = hnd_recv.recv() => {
                        // Every handle dropped: nothing can drive us any more.
                        let Some(msg) = msg else {
                            return peers.close().await;
                        };
                        if let ControlFlow::Break(r) = Self::handle_message(&mut core, &peers, &mut invites, keep_envelopes, msg).await {
                            // Shutdown, r is to respond when we are done shutting down.
                            peers.close().await;
                            r.respond(Ok(()));
                            return;
                        }
                    }
                    conn = local_sock.accept() => match conn {
                        // Served on its own task via own handle to avoid blocking the mainloop
                        Ok((stream, _addr)) => match weak.upgrade() {
                            Some(handle) => {
                                tokio::spawn(Self::handle_connection(handle, stream));
                            }
                            // Server about to be garbage collected
                            None => drop(stream),
                        },
                        Err(e) => tracing::warn!(error = %e, "accepting local connection"),
                    },
                    // Lazy on purpose: the pass runs only when enough is
                    // prunable to be worth a sweep. `lotusctl compact`
                    // prunes eagerly.
                    _ = compact.tick() => {
                        let pinned = invites.pinned_roots(Instant::now());
                        match core.compact(keep_envelopes, COMPACT_MIN_PRUNE, &pinned).await {
                            Ok(compacted) if compacted.pruned > 0 => {
                                tracing::info!(
                                    pruned = compacted.pruned,
                                    oldest = %compacted.to.to_hex().as_ref(),
                                    "compacted the envelope log",
                                );
                            }
                            Ok(_) => {}
                            Err(e) => tracing::warn!(error = %e, "compaction failed"),
                        }
                    }
                }
            }
        });

        (handle, join_hnd)
    }

    /// Routes one message to the handler for it, lending each the components it needs.
    ///
    /// Handlers take `&mut Core` rather than `&Core`: the SQLite connection is `Send` but not
    /// `Sync`, so only a unique borrow of the core can be held across an await in the spawned
    /// mainloop.
    async fn handle_message(
        core: &mut Core,
        peers: &Peers,
        invites: &mut Invites,
        keep_envelopes: NonZeroU32,
        msg: ServerMsg,
    ) -> ControlFlow<Responder<(), ()>> {
        match msg {
            ServerMsg::Shutdown(r) => return ControlFlow::Break(r),
            ServerMsg::ChainRange(r) => Self::handle_chain_range(core, r).await,
            ServerMsg::Envelopes(select, r) => r.respond(Self::read_envelopes(core, select)),
            // Both run to completion here on the mainloop: advancing the
            // chain and registering against it are the operations whose
            // ordering against each other is the whole guarantee, so
            // neither may be handed to a task that could reorder them.
            ServerMsg::Insert(envelopes, r) => r.respond(core.insert(envelopes)),
            ServerMsg::SyncAnswer(query, r) => {
                r.respond(core.sync_answer(query).map_err(ChainError::Storage));
            }
            ServerMsg::Subscribe(filter, r) => r.respond(Ok(core.subscribe(filter))),
            ServerMsg::Contains(digest, r) => r.respond(core.contains(digest)),
            ServerMsg::Watchers(r) => r.respond(Ok(core.subscriptions().count())),
            ServerMsg::WatchOrphaned(digest, r) => r.respond(core.watch_orphaned(digest)),
            ServerMsg::PeerConnections(r) => r.handle(peers.connections()).await,
            ServerMsg::PeerAddresses(r) => r.respond(core.peer_addresses()),
            ServerMsg::Peers(r) => r.handle(peers.statuses()).await,
            ServerMsg::Identity(r) => r.respond(Ok(Identity {
                node: core.key_id(),
                endpoint: peers.endpoint.as_ref().map(Endpoint::addr),
            })),
            ServerMsg::Read(read, r) => r.respond(
                core.read(&read.key, read.path.as_ref())
                    .map(|(head, value)| rpc::ValueAt { head, value })
                    .map_err(ChainError::Storage),
            ),
            // On the mainloop for the same reason `Insert` is: the write
            // is signed onto the head the core stands at right now.
            ServerMsg::WeakWrite(write, r) => r.respond(
                core.sign_write(|prev| write.message(prev))
                    .map(|(digest, insert)| rpc::Written {
                        digest,
                        head: core.head(),
                        outcome: outcome(insert),
                    }),
            ),
            ServerMsg::Compact(r) => {
                // Eager: however little is past the policy goes.
                let pinned = invites.pinned_roots(Instant::now());
                r.respond(core.compact(keep_envelopes, 1, &pinned).await);
            }
            ServerMsg::CreateInvite(weight, ttl, r) => {
                r.respond(Self::create_invite(core, peers, invites, weight, ttl));
            }
            ServerMsg::RedeemInvite(token, r) => r.respond(
                invites
                    .redeem(&token, Instant::now())
                    .map_err(InviteError::Redeem)
                    .and_then(|redeemed| {
                        core.welcome_root()
                            .map(|(root, state)| Welcomed {
                                root,
                                state,
                                weight: redeemed.weight,
                            })
                            .map_err(InviteError::Chain)
                    }),
            ),
            // On the mainloop like any write: signed onto the head the core
            // stands at right now, both envelopes before anything else runs.
            ServerMsg::Admit(key, addr, r) => r.respond(core.admit(key, &addr)),
            ServerMsg::Advertise(addr, r) => r.respond(core.advertise(&addr)),
            ServerMsg::Published(r) => r.handle(peers.published()).await,
        }

        ControlFlow::Continue(())
    }

    /// Issues an invite admitting one node at `weight`, good for `ttl`.
    ///
    /// Refused up front when this node could not sign the admission
    /// alone: the joiner would otherwise pull the whole chain and only
    /// then learn nothing could let it in.
    fn create_invite(
        core: &Core,
        peers: &Peers,
        invites: &mut Invites,
        weight: u32,
        ttl: Duration,
    ) -> Result<Issued, InviteError> {
        let endpoint = peers
            .endpoint
            .as_ref()
            .map(Endpoint::addr)
            .ok_or(InviteError::NoEndpoint)?;
        core.signs_alone()
            .map_err(InviteError::Chain)?
            .map_err(InviteError::CannotSignAlone)?;

        let ttl = ttl.min(MAX_INVITE_TTL);
        let token = Token::from_bytes(crate::core::draw_token().map_err(InviteError::Entropy)?);
        invites.issue(token, weight, ttl, Instant::now(), core.root());

        let expires_at = SystemTime::now()
            .checked_add(ttl)
            .and_then(|at| at.duration_since(UNIX_EPOCH).ok())
            .map_or(i64::MAX, |since| {
                i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
            });
        Ok(Issued {
            invite: Invite {
                version: invite::VERSION,
                sponsor: core.key_id(),
                endpoint,
                root: core.root(),
                token,
                expires_at_millis: expires_at,
            },
            ttl,
        })
    }

    /// Reads how much of the chain the core holds.
    async fn handle_chain_range(core: &mut Core, r: Responder<rpc::ChainRange, ()>) {
        r.handle(async move {
            Ok(rpc::ChainRange {
                root: core.root(),
                head: core.head(),
            })
        })
        .await
    }

    /// Reads whatever `select` picks out of the log.
    ///
    /// A `since` window is turned into a cutoff here, against this node's
    /// clock: it is the only clock the times in the log were read from. A
    /// window too wide to subtract reaches further back than any log goes,
    /// which is the same as asking for all of it.
    fn read_envelopes(
        core: &Core,
        select: rpc::EnvelopeSelector,
    ) -> Result<Vec<(EnvelopeDigest, LogEntry)>, ChainError> {
        match select {
            rpc::EnvelopeSelector::Chain(walk) => {
                core.canonical_chain(walk.limit, walk.since().and_then(StoredAt::ago))
            }
            rpc::EnvelopeSelector::Digests(digests) => core.envelopes(digests),
        }
        .map_err(ChainError::Storage)
    }

    /// Serves one client on the local control socket.
    ///
    /// One connection, one request: dropping the stream on the way out is
    /// what ends the answer's stream.
    async fn handle_connection(handle: ServerHandle, mut stream: UnixStream) {
        if let Err(e) = rpc::serve(&mut stream, &mut Rpc(handle)).await {
            tracing::warn!(error = %e, "serving local connection");
        }
    }
}

/// What an insert did, as the control protocol spells it.
fn outcome(insert: Insert) -> rpc::WriteOutcome {
    match insert {
        Insert::Extended => rpc::WriteOutcome::Extended,
        Insert::Reorged { from } => rpc::WriteOutcome::Reorged(rpc::Reorged { from }),
        Insert::Unchanged => rpc::WriteOutcome::Unchanged,
        Insert::Duplicate => rpc::WriteOutcome::Duplicate,
    }
}

/// The mainloop's side of the network: the actors it owns and the
/// endpoint they share.
#[derive(Debug)]
struct Peers {
    ingress: Option<PeerIngressHandle>,
    egress: Option<PeerEgressHandle>,
    publisher: Option<AddrPublishHandle>,
    endpoint: Option<Endpoint>,
}

impl Peers {
    /// How many peers are connected; none, when there is no endpoint.
    async fn connections(&self) -> Result<usize, ()> {
        match &self.ingress {
            Some(ingress) => ingress.connections().await,
            None => Ok(0),
        }
    }

    /// Every peer the egress keeps; none, when there is no endpoint.
    async fn statuses(&self) -> Result<Vec<PeerStatus>, ()> {
        match &self.egress {
            Some(egress) => egress.peers().await,
            None => Ok(Vec::new()),
        }
    }

    /// Where this node's own listing stands; `None` when there is no
    /// endpoint to list.
    async fn published(&self) -> Result<Option<PublishState>, ()> {
        match &self.publisher {
            Some(publisher) => publisher.state().await.map(Some),
            None => Ok(None),
        }
    }

    /// Brings the actors down and then closes the endpoint, in that order:
    /// closing first would pull the endpoint out from under them.
    async fn close(&mut self) {
        if let Some(publisher) = self.publisher.take() {
            publisher.shutdown().await;
        }
        if let Some(egress) = self.egress.take() {
            egress.shutdown().await;
        }
        if let Some(ingress) = self.ingress.take() {
            ingress.shutdown().await;
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close().await;
        }
    }
}

/// Answers local control requests, asking the server for whatever they need.
///
/// Holds a handle rather than the core: it runs off the mainloop, so the
/// state it reports has to come back through the same actor messages any
/// other caller would use.
struct Rpc(ServerHandle);

impl rpc::Handler for Rpc {
    async fn handle(
        &mut self,
        request: rpc::Request,
        responses: &mut rpc::Responses<'_>,
    ) -> Result<(), rpc::Error> {
        match request {
            rpc::Request::GetVersion(_) => {
                responses
                    .send(rpc::Response::Version(VERSION.to_owned()))
                    .await
            }
            rpc::Request::GetChainRange(_) => {
                let range = self
                    .0
                    .chain_range()
                    .await
                    .map_err(|()| rpc::Failure::internal("the server is shutting down"))?;
                responses.send(rpc::Response::ChainRange(range)).await
            }
            rpc::Request::GetStatus(_) => {
                let status = self.status().await?;
                responses.send(rpc::Response::Status(status)).await
            }
            rpc::Request::GetEnvelopes(get) => self.envelopes(get.select, responses).await,
            rpc::Request::Watch(watch) => self.watch(watch.selector, responses).await,
            rpc::Request::Read(read) => {
                let value = self
                    .0
                    .read(read)
                    .await
                    .map_err(|err| rpc::Failure::internal(err.to_string()))?;
                responses.send(rpc::Response::Value(value)).await
            }
            rpc::Request::WeakSet(set) => self.write(set, responses).await,
            rpc::Request::WeakPush(push) => self.write(push, responses).await,
            rpc::Request::WeakDelete(delete) => self.write(delete, responses).await,
            rpc::Request::WeakIncrement(increment) => self.write(increment, responses).await,
            rpc::Request::WeakDeleteMatching(delete) => self.write(delete, responses).await,
            rpc::Request::Compact(_) => {
                let compacted = self
                    .0
                    .compact()
                    .await
                    .map_err(|err| rpc::Failure::internal(err.to_string()))?;
                responses
                    .send(rpc::Response::Compacted(rpc::Compacted {
                        from: compacted.from,
                        to: compacted.to,
                        pruned: compacted.pruned,
                    }))
                    .await
            }
            rpc::Request::CreateInvite(create) => {
                let Issued { invite, ttl } = self
                    .0
                    .create_invite(create.weight, Duration::from_millis(create.ttl_millis))
                    .await
                    .map_err(|err| match err {
                        InviteError::ServerGone | InviteError::Chain(_) => {
                            rpc::Failure::internal(err.to_string())
                        }
                        other => rpc::Failure::rejected(other.to_string()),
                    })?;
                let text = invite
                    .encode()
                    .map_err(|e| rpc::Failure::internal(format!("encoding the invite: {e}")))?;
                responses
                    .send(rpc::Response::Invite(rpc::InviteCode {
                        text,
                        expires_in_millis: u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX),
                    }))
                    .await
            }
        }
    }
}

impl Rpc {
    /// Gathers everything `status` reports.
    ///
    /// Several trips to the mainloop rather than one: none of these reads
    /// needs to be consistent with the others, and a status is a glance,
    /// not a snapshot.
    async fn status(&self) -> Result<rpc::NodeStatus, rpc::Error> {
        let gone = || rpc::Failure::internal("the server is shutting down");
        let identity = self.0.identity().await.map_err(|()| gone())?;
        let chain = self.0.chain_range().await.map_err(|()| gone())?;
        let peers = self.0.peers().await.map_err(|()| gone())?;
        let inbound = self.0.peer_connections().await.map_err(|()| gone())?;
        let published = self.0.published().await.map_err(|()| gone())?;

        Ok(rpc::NodeStatus {
            version: VERSION.to_owned(),
            node: identity.node,
            endpoint: identity.endpoint.map(|addr| rpc::EndpointInfo {
                id: addr.id.to_z32(),
                addrs: addr.addrs.iter().map(ToString::to_string).collect(),
            }),
            chain,
            peers: peers
                .into_iter()
                .map(|peer| rpc::PeerInfo {
                    node: peer.node,
                    endpoint: peer.addr.id.to_z32(),
                    state: match peer.state {
                        PeerState::Dialing { attempt } => {
                            rpc::PeerState::Dialing(rpc::Attempt { attempt })
                        }
                        PeerState::Connected => rpc::PeerState::Connected(rpc::Connected {}),
                        PeerState::Backoff { attempt } => {
                            rpc::PeerState::Backoff(rpc::Attempt { attempt })
                        }
                    },
                })
                .collect(),
            // More connections than fit a u32 is not a count anyone reads.
            inbound: u32::try_from(inbound).unwrap_or(u32::MAX),
            published: published.map(|state| match state {
                PublishState::Unchecked => rpc::Published::Unchecked(rpc::Unchecked {}),
                PublishState::Published => rpc::Published::Published(rpc::Connected {}),
                PublishState::Pending => rpc::Published::Pending(rpc::Unchecked {}),
                PublishState::NotListed => rpc::Published::NotListed(rpc::Unchecked {}),
                PublishState::OtherEndpoint(id) => {
                    rpc::Published::OtherEndpoint(rpc::OtherEndpoint {
                        endpoint: id.to_z32(),
                    })
                }
                PublishState::CannotSign(reason) => rpc::Published::CannotSign(rpc::Reason {
                    reason: reason.to_string(),
                }),
                PublishState::Failed(reason) => rpc::Published::Failed(rpc::Reason { reason }),
            }),
        })
    }

    /// Signs `write` onto the chain and answers with what that did.
    async fn write(
        &self,
        write: impl Into<WeakWrite>,
        responses: &mut rpc::Responses<'_>,
    ) -> Result<(), rpc::Error> {
        let written = self.0.weak_write(write).await.map_err(|err| match err {
            // The chain judged the write and said no: the client's to fix.
            // Anything else is the daemon's.
            RequestError::Chain(ChainError::Apply(reason)) => {
                rpc::Failure::rejected(reason.to_string())
            }
            other => rpc::Failure::internal(other.to_string()),
        })?;
        responses.send(rpc::Response::Written(written)).await
    }

    /// Streams the envelopes `select` picks out, one response frame each.
    ///
    /// Read in one trip to the mainloop and then written out: a frame per
    /// envelope keeps a long chain off the frame size limit, and it is the
    /// stream, not the answer, that is chunked.
    async fn envelopes(
        &self,
        select: rpc::EnvelopeSelector,
        responses: &mut rpc::Responses<'_>,
    ) -> Result<(), rpc::Error> {
        let envelopes = self
            .0
            .envelopes(select)
            .await
            .map_err(|err| rpc::Failure::internal(err.to_string()))?;

        for (digest, entry) in envelopes {
            responses
                .send(rpc::Response::Envelope(rpc::EnvelopeFrame::new(
                    digest,
                    entry.envelope,
                    entry.stored_at.timestamp_millis(),
                )))
                .await?;
        }
        Ok(())
    }

    /// Streams what `selector` picks out until the client hangs up or the
    /// daemon stops.
    ///
    /// Returning is what ends the stream: the connection closes, and with it
    /// the subscription, which deregisters itself as it drops.
    async fn watch(
        &self,
        selector: rpc::WatchSelector,
        responses: &mut rpc::Responses<'_>,
    ) -> Result<(), rpc::Error> {
        let mut subscription = match self.subscribe(selector).await? {
            Watching::Subscribed(subscription) => subscription,
            // Nothing further can ever be said about it, so say that and go.
            Watching::AlreadyOrphaned(digest) => {
                return responses
                    .send(rpc::Response::Watch(rpc::WatchEvent::AlreadyOrphaned(
                        digest,
                    )))
                    .await;
            }
        };

        while let Some(notification) = subscription.next().await {
            responses
                .send(rpc::Response::Watch(rpc::WatchEvent::Changed(
                    notification.to_wire(),
                )))
                .await?;
        }
        Ok(())
    }

    /// Registers `selector`, taking the orphan case through the check that
    /// makes registering it race-free.
    async fn subscribe(&self, selector: rpc::WatchSelector) -> Result<Watching, rpc::Error> {
        let gone = || rpc::Failure::internal("the server is shutting down");

        match selector {
            rpc::WatchSelector::Orphaned(digest) => Ok(self
                .0
                .watch_orphaned(digest)
                .await
                .map_err(|err| rpc::Failure::internal(err.to_string()))?
                .map_or(Watching::AlreadyOrphaned(digest), Watching::Subscribed)),
            other => Ok(Watching::Subscribed(
                self.0
                    .subscribe(ChangeSelector::from(other))
                    .await
                    .map_err(|()| gone())?,
            )),
        }
    }
}

/// What registering a watch came to.
enum Watching {
    Subscribed(SubscriptionHandle),
    /// The envelope asked about is already off the chain.
    AlreadyOrphaned(EnvelopeDigest),
}

/// A handle to a running lotusd server.
#[derive(Debug, Clone)]
pub struct ServerHandle(mpsc::Sender<ServerMsg>);

/// A handle that does not keep the server running.
///
/// The mainloop exits once every [`ServerHandle`] is gone, so anything the
/// mainloop itself owns must hold one of these instead and upgrade when it
/// has work: a strong handle there would be a cycle nothing could break.
#[derive(Debug, Clone)]
pub(crate) struct WeakServerHandle(mpsc::WeakSender<ServerMsg>);

impl WeakServerHandle {
    /// A strong handle, unless the server is already gone.
    pub(crate) fn upgrade(&self) -> Option<ServerHandle> {
        self.0.upgrade().map(ServerHandle)
    }
}

#[allow(clippy::result_unit_err)]
impl ServerHandle {
    /// A handle that does not keep the server running.
    pub(crate) fn downgrade(&self) -> WeakServerHandle {
        WeakServerHandle(self.0.downgrade())
    }

    /// Issues a server shutdown. If the server is running, this future resolves with
    /// and Ok value when shutdown is finished. If the server is not running or otherwise
    /// in a broken state, an Err value is returned immediately.
    pub async fn shutdown(&self) -> Result<(), ()> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Shutdown(send)).await;
        match recv.await {
            Ok(v) => v,
            Err(_) => Err(()),
        }
    }

    /// Reads how much of the chain this node holds.
    ///
    /// The one read both ends come from: [`head`](Self::head) and
    /// [`root`](Self::root) are conveniences over it, and asking for them
    /// separately can catch the chain mid-move.
    pub async fn chain_range(&self) -> Result<rpc::ChainRange, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::ChainRange(send)).await;
        match recv.await {
            Ok(Ok(v)) => Ok(v),
            _ => Err(()),
        }
    }

    /// Reads the current HEAD.
    pub async fn head(&self) -> Result<EnvelopeDigest, ()> {
        self.chain_range().await.map(|range| range.head)
    }

    /// Reads the oldest envelope this node still holds — the chain's root,
    /// until compaction moves it forward.
    pub async fn root(&self) -> Result<EnvelopeDigest, ()> {
        self.chain_range().await.map(|range| range.root)
    }

    /// Reads the envelopes `select` picks out of the node's log.
    pub async fn envelopes(
        &self,
        select: rpc::EnvelopeSelector,
    ) -> Result<Vec<(EnvelopeDigest, LogEntry)>, RequestError> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Envelopes(select, send)).await;
        Self::answer(recv.await)
    }

    /// Ingests a parent-first run of envelopes, waking every subscriber the
    /// head movement concerns.
    ///
    /// The run must be continuous, as [`Chain::insert_batch`] requires: each
    /// envelope chains onto the one before it, and the first one's parent is
    /// already stored.
    ///
    /// [`Chain::insert_batch`]: state::Chain::insert_batch
    pub async fn insert(
        &self,
        envelopes: impl IntoIterator<Item = Envelope>,
    ) -> Result<Insert, RequestError> {
        let (send, recv) = Responder::channel();
        let _ = self
            .0
            .send(ServerMsg::Insert(envelopes.into_iter().collect(), send))
            .await;
        Self::answer(recv.await)
    }

    /// Answers one sync-machine query against this node's chain — what
    /// the sync driver resolves an `Effect::Ask` with.
    ///
    /// [`Effect::Ask`]: sync::Effect::Ask
    pub async fn sync_answer(&self, query: sync::Query) -> Result<sync::Answer, RequestError> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::SyncAnswer(query, send)).await;
        Self::answer(recv.await)
    }

    /// Registers a subscription for the changes `filter` selects.
    ///
    /// Takes a bare [`ChangeSelector`] too, for watching just one thing.
    /// Registering happens on the mainloop, so the head the subscription
    /// [opened at](SubscriptionHandle::opened_at) is one nothing can have
    /// moved past before it was registered.
    ///
    /// [`ChangeSelector`]: crate::ChangeSelector
    pub async fn subscribe(
        &self,
        filter: impl Into<ChangeFilter>,
    ) -> Result<SubscriptionHandle, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Subscribe(filter.into(), send)).await;
        match recv.await {
            Ok(Ok(subscription)) => Ok(subscription),
            _ => Err(()),
        }
    }

    /// How many subscriptions are registered against the core.
    ///
    /// Every local watch holds one, so this counts the clients currently
    /// being told about the chain.
    pub async fn watchers(&self) -> Result<usize, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Watchers(send)).await;
        match recv.await {
            Ok(Ok(count)) => Ok(count),
            _ => Err(()),
        }
    }

    /// How many peers are connected to this node's endpoint.
    ///
    /// Zero when the server was started without an endpoint.
    pub async fn peer_connections(&self) -> Result<usize, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::PeerConnections(send)).await;
        match recv.await {
            Ok(Ok(count)) => Ok(count),
            _ => Err(()),
        }
    }

    /// How to reach each node the cluster lists, as the ledger has it now.
    pub async fn peer_addresses(&self) -> Result<BTreeMap<KeyId, EndpointAddr>, RequestError> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::PeerAddresses(send)).await;
        Self::answer(recv.await)
    }

    /// Who this node is: its id, and the endpoint it serves peers on.
    pub async fn identity(&self) -> Result<Identity, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Identity(send)).await;
        match recv.await {
            Ok(Ok(identity)) => Ok(identity),
            _ => Err(()),
        }
    }

    /// Every node the egress keeps a connection to, and where each stands.
    ///
    /// Empty when the server was started without an endpoint.
    pub async fn peers(&self) -> Result<Vec<PeerStatus>, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Peers(send)).await;
        match recv.await {
            Ok(Ok(peers)) => Ok(peers),
            _ => Err(()),
        }
    }

    /// Whether `digest` lies on the canonical chain.
    ///
    /// O(chain) in the daemon: this walks the head back to the root.
    pub async fn contains(&self, digest: EnvelopeDigest) -> Result<bool, RequestError> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Contains(digest, send)).await;
        Self::answer(recv.await)
    }

    /// Registers a subscription that fires when `digest` leaves the
    /// canonical chain, or `None` when it is not on the chain already.
    ///
    /// `None` is the answer, not a failure: an envelope that is already off
    /// the chain will never be taken off it again, so there is nothing left
    /// to wait for. The check and the registration share one trip to the
    /// mainloop, so no reorg can slip between them.
    pub async fn watch_orphaned(
        &self,
        digest: EnvelopeDigest,
    ) -> Result<Option<SubscriptionHandle>, RequestError> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::WatchOrphaned(digest, send)).await;
        Self::answer(recv.await)
    }

    /// Reads the value `read` addresses, at the head the core stands at.
    pub async fn read(&self, read: rpc::Read) -> Result<rpc::ValueAt, RequestError> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Read(read, send)).await;
        Self::answer(recv.await)
    }

    /// Signs `write` into an envelope with the node's key and inserts it
    /// onto the current head, waking every subscriber the movement
    /// concerns — the peers announce it from there like any other head
    /// movement.
    pub async fn weak_write(
        &self,
        write: impl Into<WeakWrite>,
    ) -> Result<rpc::Written, RequestError> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::WeakWrite(write.into(), send)).await;
        Self::answer(recv.await)
    }

    /// Prunes the envelope log past the daemon's retention policy,
    /// eagerly: however little is eligible goes. What the policy keeps —
    /// the newest envelopes, the ledger's min-keep floor, the roots
    /// pending invites pinned — stays either way.
    pub async fn compact(&self) -> Result<Compacted, CompactError> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Compact(send)).await;
        recv.await.map_err(|_| CompactError::ServerGone)?
    }

    /// Issues an invite admitting one node at `weight`, honoured for `ttl`
    /// (capped at [`MAX_INVITE_TTL`]). The token lives in the mainloop's
    /// memory only.
    pub async fn create_invite(&self, weight: u32, ttl: Duration) -> Result<Issued, InviteError> {
        let (send, recv) = Responder::channel();
        let _ = self
            .0
            .send(ServerMsg::CreateInvite(weight, ttl, send))
            .await;
        recv.await.map_err(|_| InviteError::ServerGone)?
    }

    /// Consumes the invite `token` names, handing back what a joiner is
    /// owed for it: the root to build on and the weight it will hold.
    pub(crate) async fn redeem_invite(&self, token: Token) -> Result<Welcomed, InviteError> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::RedeemInvite(token, send)).await;
        recv.await.map_err(|_| InviteError::ServerGone)?
    }

    /// Trusts `key` and lists `addr` under its id, signed by this node —
    /// see [`Core::admit`]. Returns the digest of the listing.
    pub async fn admit(
        &self,
        key: wire::Key,
        addr: EndpointAddr,
    ) -> Result<EnvelopeDigest, AdmitError> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Admit(key, addr, send)).await;
        recv.await.map_err(|_| AdmitError::ServerGone)?
    }

    /// Brings this node's own listing in line with `addr` — see
    /// [`Core::advertise`].
    pub async fn advertise(&self, addr: EndpointAddr) -> Result<Advertised, AdvertiseError> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Advertise(addr, send)).await;
        recv.await.map_err(|_| AdvertiseError::ServerGone)?
    }

    /// Where this node's own listing stands; `None` when it serves no
    /// endpoint.
    pub async fn published(&self) -> Result<Option<PublishState>, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Published(send)).await;
        recv.await.map_err(|_| ())?
    }

    /// Unwraps what came back down a responder, reading a dropped sender as
    /// the server having gone away.
    fn answer<T>(
        received: Result<Result<T, ChainError>, oneshot::error::RecvError>,
    ) -> Result<T, RequestError> {
        match received {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(RequestError::Chain(err)),
            Err(_) => Err(RequestError::ServerGone),
        }
    }
}

/// Why a request that touches the chain could not be answered.
#[derive(Debug)]
pub enum RequestError {
    /// The server is not running, or is on its way down.
    ServerGone,
    /// The chain refused the request, or could not answer it.
    Chain(ChainError),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestError::ServerGone => f.write_str("the server is not running"),
            RequestError::Chain(_) => f.write_str("the chain could not answer"),
        }
    }
}

impl core::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            RequestError::ServerGone => None,
            RequestError::Chain(err) => Some(err),
        }
    }
}
