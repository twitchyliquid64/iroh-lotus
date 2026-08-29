//! The address-publishing actor: keeps this node's own `cluster-nodes`
//! listing in step with where its endpoint is actually reachable.
//!
//! The counterpart of [`peer_egress`](crate::peer_egress), which reads the
//! listings; this is the only thing that writes one for the node itself.
//!
//! Level-triggered, like the egress. Every wake — the endpoint's address
//! moving, the listing moving under us (a reorg, another node rewriting
//! it), the trusted key set changing so a write that could not carry
//! before may now — ends in the same step: hand the mainloop the address
//! the endpoint reports now and let [`Core::advertise`](crate::Core::advertise)
//! compare it with the ledger and write only when they differ. A wake
//! with nothing behind it costs one read.
//!
//! An endpoint's address flaps: every interface or relay event moves it,
//! and every publish is a signed envelope on a permanent chain. So a wake
//! arms a settle timer rather than publishing at once, and the publish
//! takes whatever the address is when the timer fires. The actor's own
//! loop never awaits the mainloop — on shutdown the mainloop awaits
//! *this* — so the publish runs on a task of its own and posts its
//! outcome back here.

use std::{fmt, pin::Pin, time::Duration};

use iroh::{EndpointAddr, Watcher};
use state::{CLUSTER_NODES_KEY, TRUSTED_KEYS_KEY};
use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{Sleep, sleep},
};
use wire::{
    KeyId,
    msg::NamespaceKey,
    subkey::{Subkey, SubkeyPath},
};

use crate::{
    AdvertiseError, Advertised, CannotSignAlone, ChangeFilter, Responder, SubscriptionHandle,
    server::WeakServerHandle,
};

/// How long the address is left to settle after it moves before it is
/// published. Every publish is a signed envelope on a permanent chain, so
/// this errs long: a connection that flaps for a minute costs one
/// envelope, not one per flap. Peers still reach a node whose listing is
/// stale meanwhile by its endpoint id, through discovery.
pub const DEFAULT_SETTLE: Duration = Duration::from_secs(60);

/// Where this node's listing stands, as far as the actor knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishState {
    /// Nothing has been compared yet.
    Unchecked,
    /// The ledger lists the address the endpoint reports.
    Published,
    /// The address moved; a publish is due once it settles, or under way.
    Pending,
    /// The ledger does not list this node, so there is nothing to keep.
    NotListed,
    /// The ledger lists this node under another endpoint id, so the
    /// listing is not this endpoint's to keep.
    OtherEndpoint(iroh::EndpointId),
    /// The listing is stale and this node cannot sign the update alone.
    CannotSign(CannotSignAlone),
    /// The last publish failed for the reason given; it is retried on the
    /// next wake.
    Failed(String),
}

impl fmt::Display for PublishState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublishState::Unchecked => f.write_str("not checked yet"),
            PublishState::Published => f.write_str("published"),
            PublishState::Pending => f.write_str("pending"),
            PublishState::NotListed => f.write_str("not listed in the cluster"),
            PublishState::OtherEndpoint(id) => {
                write!(f, "listed under another endpoint, {}", id.to_z32())
            }
            PublishState::CannotSign(reason) => write!(f, "cannot sign the update: {reason}"),
            PublishState::Failed(reason) => write!(f, "failed: {reason}"),
        }
    }
}

#[derive(Debug)]
enum PublishMsg {
    Shutdown(Responder<(), ()>),
    State(Responder<PublishState, ()>),
    /// The publish task's trip to the mainloop came back.
    Landed(Result<Advertised, AdvertiseError>),
}

/// The address-publishing actor, before it is spawned.
///
/// Generic over the watcher rather than taking an [`iroh::Endpoint`], so
/// what the endpoint reports can be stood in for.
#[derive(Debug)]
pub(crate) struct AddrPublish<W> {
    addr: W,
    server: WeakServerHandle,
    /// This node's own id — the entry it keeps.
    node: KeyId,
    settle: Duration,
}

impl<W> AddrPublish<W>
where
    W: Watcher<Value = EndpointAddr> + Send + Unpin + 'static,
{
    pub(crate) fn new(addr: W, server: WeakServerHandle, node: KeyId) -> Self {
        Self {
            addr,
            server,
            node,
            settle: DEFAULT_SETTLE,
        }
    }

    /// How long the address is left to settle before it is published.
    pub(crate) fn with_settle(mut self, settle: Duration) -> Self {
        self.settle = settle;
        self
    }

    /// Starts the actor on its own task, returning the handle the server
    /// drives it by.
    pub(crate) fn spawn(self) -> AddrPublishHandle {
        let (tx, rx) = mpsc::channel(8);
        let join = tokio::spawn(self.run(tx.clone(), rx));
        AddrPublishHandle { tx, join }
    }

    async fn run(mut self, tx: mpsc::Sender<PublishMsg>, mut cmd: mpsc::Receiver<PublishMsg>) {
        // Subscribed before the first publish, so nothing can move between
        // the compare and the subscription taking effect.
        let Some(mut ledger) = Self::subscribe(&self.server, self.node).await else {
            return;
        };
        let mut state = PublishState::Unchecked;
        let mut publish = Publish::default();
        let mut timer = Settle::default();
        // The first check runs at once: the listing may have been stale
        // since before this node came up.
        timer.arm(Duration::ZERO);

        loop {
            tokio::select! {
                // Commands win over wakes, so a shutdown is not held off by
                // an address that keeps moving.
                biased;

                msg = cmd.recv() => match msg {
                    Some(PublishMsg::Shutdown(r)) => return r.respond(Ok(())),
                    Some(PublishMsg::State(r)) => r.respond(Ok(state.clone())),
                    Some(PublishMsg::Landed(outcome)) => {
                        state = Self::settle_outcome(outcome);
                        if publish.landed() {
                            timer.arm(self.settle);
                        }
                    }
                    // The server dropped us: it is on its way out.
                    None => return,
                },
                () = timer.fired() => {
                    let addr = self.addr.get();
                    if publish.request(&self.server, &tx, addr) {
                        state = PublishState::Pending;
                    }
                }
                moved = self.addr.updated() => match moved {
                    Ok(_) => {
                        state = PublishState::Pending;
                        timer.arm(self.settle);
                    }
                    // The endpoint is gone; nothing will move the address again.
                    Err(_) => return,
                },
                changed = ledger.next() => match changed {
                    Some(_) => timer.arm(self.settle),
                    // The core is gone; nothing will move the listing again.
                    None => return,
                },
            }
        }
    }

    /// Registers for changes to this node's own listing and to the trusted
    /// key set, or `None` when the server is already gone.
    async fn subscribe(server: &WeakServerHandle, node: KeyId) -> Option<SubscriptionHandle> {
        let server = server.upgrade()?;
        let nodes = NamespaceKey::try_new(CLUSTER_NODES_KEY).expect("the reserved key is static");
        let keys = NamespaceKey::try_new(TRUSTED_KEYS_KEY).expect("the reserved key is static");
        let own = SubkeyPath::try_new(vec![Subkey::Key(node.to_hex().as_ref().to_owned())])
            .expect("one segment is not empty");
        server
            .subscribe(ChangeFilter::path(nodes, own).and_namespace(keys))
            .await
            .ok()
    }

    /// What a publish outcome leaves the state at, logged as it deserves.
    fn settle_outcome(outcome: Result<Advertised, AdvertiseError>) -> PublishState {
        match outcome {
            Ok(Advertised::Unchanged) => PublishState::Published,
            Ok(Advertised::Written(digest)) => {
                tracing::info!(envelope = %digest.to_hex().as_ref(), "published this node's address");
                PublishState::Published
            }
            Ok(Advertised::NotListed) => {
                tracing::debug!("this node is not listed in the cluster; not publishing");
                PublishState::NotListed
            }
            Ok(Advertised::OtherEndpoint(id)) => {
                tracing::warn!(
                    listed = %id.fmt_short(),
                    "the ledger lists this node under another endpoint id; not publishing"
                );
                PublishState::OtherEndpoint(id)
            }
            Ok(Advertised::CannotSign(reason)) => {
                tracing::warn!(%reason, "this node's listed address is stale and it cannot update it alone");
                PublishState::CannotSign(reason)
            }
            Err(e) => {
                tracing::warn!(error = %e, "publishing this node's address");
                PublishState::Failed(e.to_string())
            }
        }
    }
}

/// The settle timer: unarmed until a wake arms it, and left alone by
/// wakes that find it armed, so an address that never stops moving is
/// published once per window rather than never.
#[derive(Default)]
struct Settle(Option<Pin<Box<Sleep>>>);

impl Settle {
    fn arm(&mut self, after: Duration) {
        if self.0.is_none() {
            self.0 = Some(Box::pin(sleep(after)));
        }
    }

    /// Resolves when the armed timer fires, disarming it; pends forever
    /// while unarmed.
    async fn fired(&mut self) {
        match &mut self.0 {
            Some(timer) => {
                timer.as_mut().await;
                self.0 = None;
            }
            None => std::future::pending().await,
        }
    }
}

/// Coalesces trips to the mainloop: one in flight at a time, and a wake
/// that arrives meanwhile folds into one more once it lands.
#[derive(Debug, Default)]
struct Publish {
    in_flight: bool,
    again: bool,
}

impl Publish {
    /// Sends `addr` to the mainloop, or notes that another trip is wanted
    /// once the current one lands. Returns whether a trip was started.
    fn request(
        &mut self,
        server: &WeakServerHandle,
        tx: &mpsc::Sender<PublishMsg>,
        addr: EndpointAddr,
    ) -> bool {
        if self.in_flight {
            self.again = true;
            return false;
        }
        self.in_flight = true;
        let server = server.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let outcome = match server.upgrade() {
                Some(server) => server.advertise(addr).await,
                None => Err(AdvertiseError::ServerGone),
            };
            // The actor going away is the only way this fails, and then
            // nobody is waiting for the answer.
            let _ = tx.send(PublishMsg::Landed(outcome)).await;
        });
        true
    }

    /// The trip landed; returns whether another was waiting on it.
    fn landed(&mut self) -> bool {
        self.in_flight = false;
        std::mem::take(&mut self.again)
    }
}

/// The server's handle on its address-publishing actor.
#[derive(Debug)]
pub(crate) struct AddrPublishHandle {
    tx: mpsc::Sender<PublishMsg>,
    join: JoinHandle<()>,
}

impl AddrPublishHandle {
    /// Stops the actor and waits for it to exit. An actor already gone is
    /// not an error: it stopped for a reason of its own, and the outcome
    /// is the same.
    pub(crate) async fn shutdown(self) {
        let (send, recv) = Responder::channel();
        let _ = self.tx.send(PublishMsg::Shutdown(send)).await;
        let _ = recv.await;
        if let Err(e) = self.join.await
            && e.is_panic()
        {
            tracing::error!(error = %e, "address publisher panicked");
        }
    }

    /// Where this node's listing stands.
    pub(crate) async fn state(&self) -> Result<PublishState, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.tx.send(PublishMsg::State(send)).await;
        recv.await.map_err(|_| ())?
    }
}
