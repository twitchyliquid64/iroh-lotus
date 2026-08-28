//! The server actor: one mainloop task owning the [`Core`], reached only by
//! the messages a [`ServerHandle`] sends it.

use core::fmt;
use std::ops::ControlFlow;

use lotusd_rpc as rpc;
use state::Insert;
use storage::{LogEntry, StoredAt};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use wire::{Envelope, EnvelopeDigest};

use crate::{
    ChainError, ChangeFilter, ChangeSelector, Core, InitError, Responder, SubscriptionHandle,
    VERSION,
};

#[derive(Debug)]
enum ServerMsg {
    Shutdown(Responder<(), ()>),
    ChainRange(Responder<rpc::ChainRange, ()>),
    Envelopes(
        rpc::EnvelopeSelector,
        Responder<Vec<(EnvelopeDigest, LogEntry)>, ChainError>,
    ),
    Insert(Vec<Envelope>, Responder<Insert, ChainError>),
    Subscribe(ChangeFilter, Responder<SubscriptionHandle, ()>),
    Contains(EnvelopeDigest, Responder<bool, ChainError>),
    Watchers(Responder<usize, ()>),
    WatchOrphaned(
        EnvelopeDigest,
        Responder<Option<SubscriptionHandle>, ChainError>,
    ),
}

/// The server actor, encapsulates all running/server state.
#[derive(Debug)]
pub struct Server {
    core: Core,
    local_sock: UnixListener,
}

impl Server {
    pub fn new(core: Core, local_sock: UnixListener) -> Result<Self, InitError> {
        Ok(Self { core, local_sock })
    }

    /// Consumes the initialized server and starts an async task for its mainloop, returning
    /// a handle that can be used to query and control the server.
    pub async fn run(self) -> (ServerHandle, JoinHandle<()>) {
        let Self {
            mut core,
            local_sock,
        } = self;
        let (hnd_tx, mut hnd_recv) = mpsc::channel(8);
        let weak = hnd_tx.downgrade();
        let handle = ServerHandle(hnd_tx);

        let join_hnd = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Control messages win over new connections, so a shutdown is not held
                    // off by a socket that keeps accepting.
                    biased;

                    msg = hnd_recv.recv() => {
                        // Every handle dropped: nothing can drive us any more.
                        let Some(msg) = msg else { return };
                        if let ControlFlow::Break(r) = Self::handle_message(&mut core, msg).await {
                            // Shutdown, r is to respond when we are done shutting down.
                            r.respond(Ok(()));
                            return;
                        }
                    }
                    conn = local_sock.accept() => match conn {
                        // Served on its own task via own handle to avoid blocking the mainloop
                        Ok((stream, _addr)) => match weak.upgrade() {
                            Some(sender) => {
                                tokio::spawn(Self::handle_connection(ServerHandle(sender), stream));
                            }
                            // Server about to be garbage collected
                            None => drop(stream),
                        },
                        Err(e) => tracing::warn!(error = %e, "accepting local connection"),
                    },
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
    async fn handle_message(core: &mut Core, msg: ServerMsg) -> ControlFlow<Responder<(), ()>> {
        match msg {
            ServerMsg::Shutdown(r) => return ControlFlow::Break(r),
            ServerMsg::ChainRange(r) => Self::handle_chain_range(core, r).await,
            ServerMsg::Envelopes(select, r) => r.respond(Self::read_envelopes(core, select)),
            // Both run to completion here on the mainloop: advancing the
            // chain and registering against it are the operations whose
            // ordering against each other is the whole guarantee, so
            // neither may be handed to a task that could reorder them.
            ServerMsg::Insert(envelopes, r) => r.respond(core.insert(envelopes)),
            ServerMsg::Subscribe(filter, r) => r.respond(Ok(core.subscribe(filter))),
            ServerMsg::Contains(digest, r) => r.respond(core.contains(digest)),
            ServerMsg::Watchers(r) => r.respond(Ok(core.subscriptions().count())),
            ServerMsg::WatchOrphaned(digest, r) => r.respond(core.watch_orphaned(digest)),
        }

        ControlFlow::Continue(())
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
            rpc::Request::GetEnvelopes(get) => self.envelopes(get.select, responses).await,
            rpc::Request::Watch(watch) => self.watch(watch.selector, responses).await,
        }
    }
}

impl Rpc {
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

#[allow(clippy::result_unit_err)]
impl ServerHandle {
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
