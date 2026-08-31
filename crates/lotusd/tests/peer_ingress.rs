//! Daemons reaching each other over real iroh endpoints on an in-memory
//! network: the ingress actor's accept path, its bounds, and its place in
//! the server's lifecycle.

use std::{collections::BTreeMap, path::Path, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey,
    endpoint::{Connection, presets},
    test_utils::test_transport::TestNetwork,
};
use lotusd::{
    Core, IfInitialized, NodeKeys, Server, ServerHandle,
    peer_ingress::Protocol,
    sync_driver::{self, SyncError},
};
use state::CLUSTER_NODES_KEY;
use sync::PullOutcome;
use tempfile::TempDir;
use tokio::{net::UnixListener, task::JoinHandle, time::timeout};
use wire::{
    Envelope, EnvelopeDigest, KeyId, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

/// How long a step gets before we call it hung. Generous: this bounds a
/// test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(10);

/// A write onto `prev`, signed by the cluster's one node key — both nodes
/// here run off a copy of the same state dir.
fn set_ns(keys: &NodeKeys, prev: EnvelopeDigest, k: &str, v: &str) -> Envelope {
    keys.sign(Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: NamespaceKey::try_new(k).unwrap(),
        namespace: Namespace {
            value: Value::String(v.to_string()),
        },
    })))
    .unwrap()
}

/// A linear run of `n` envelopes chaining onto `prev`.
fn run_of(keys: &NodeKeys, prev: EnvelopeDigest, label: &str, n: usize) -> Vec<Envelope> {
    let mut cursor = prev;
    (0..n)
        .map(|i| {
            let envelope = set_ns(keys, cursor, &format!("{label}{i}"), "v");
            cursor = envelope.digest().unwrap();
            envelope
        })
        .collect()
}

/// The `cluster-nodes` value listing `entries`.
fn cluster_nodes(entries: impl IntoIterator<Item = (KeyId, EndpointAddr)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(node, addr)| {
                (
                    node.to_hex().as_ref().to_owned(),
                    Value::Map(BTreeMap::from_iter([(
                        "iroh".to_owned(),
                        Value::try_from(&addr).unwrap(),
                    )])),
                )
            })
            .collect(),
    )
}

/// Copies every regular file in `from` into `to` — how a second node
/// comes to share a genesis before any join mechanism exists.
fn copy_state_dir(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

/// An endpoint on `network` only: no sockets, no relay, and the network's
/// own address lookup, so peers dial each other by id alone.
async fn endpoint(network: &TestNetwork, secret: SecretKey) -> Endpoint {
    let transport = network.create_transport(secret.public()).unwrap();
    Endpoint::builder(presets::Minimal)
        .preset(transport)
        .secret_key(secret)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .alpns(Protocol::alpns())
        .bind()
        .await
        .unwrap()
}

/// A running node: its server, and the endpoint peers reach it on.
struct Node {
    handle: ServerHandle,
    join: JoinHandle<()>,
    endpoint: Endpoint,
    _dir: TempDir,
}

impl Node {
    /// Starts a server over the cluster state in `dir`, serving peers on
    /// `secret`'s endpoint on `network`.
    async fn start(
        dir: TempDir,
        network: &TestNetwork,
        secret: SecretKey,
        peer_limit: Option<usize>,
    ) -> Self {
        let core = Core::init_with_state_dir(dir.path().to_path_buf())
            .await
            .unwrap();
        // Short name on purpose: a unix socket path has to fit in SUN_LEN.
        let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
        let endpoint = endpoint(network, secret).await;
        let server = Server::new(core, listener)
            .unwrap()
            .with_endpoint(endpoint.clone());
        let server = match peer_limit {
            Some(limit) => server.with_peer_connection_limit(limit),
            None => server,
        };
        let (handle, join) = server.run().await;
        Node {
            handle,
            join,
            endpoint,
            _dir: dir,
        }
    }

    /// Replaces this node's `cluster-nodes` with `entries`.
    async fn list(
        &self,
        keys: &NodeKeys,
        entries: impl IntoIterator<Item = (KeyId, EndpointAddr)>,
    ) {
        let prev = self.handle.head().await.unwrap();
        let envelope = keys
            .sign(Envelope::new(Msg::SetNamespace(SetNamespace {
                prev,
                key: NamespaceKey::try_new(CLUSTER_NODES_KEY).unwrap(),
                namespace: Namespace {
                    value: cluster_nodes(entries),
                },
            })))
            .unwrap();
        self.handle.insert([envelope]).await.unwrap();
    }

    /// This node's address as the ledger would carry it: id only, since
    /// the test network resolves ids itself.
    fn addr(&self) -> EndpointAddr {
        EndpointAddr::new(self.endpoint.id())
    }

    /// Pulls from `other` over a connection of its own, giving back
    /// nothing at all if any step of it was refused.
    async fn try_pull(&self, other: &Node) -> Option<PullOutcome> {
        let conn = self
            .endpoint
            .connect(other.endpoint.id(), sync::ALPN)
            .await
            .ok()?;
        let (send, recv) = conn.open_bi().await.ok()?;
        sync_driver::pull(tokio::io::join(recv, send), &self.handle)
            .await
            .ok()
    }

    /// Opens a sync connection to `other`, as a puller would.
    async fn connect(&self, other: &Node) -> Connection {
        self.endpoint
            .connect(other.endpoint.id(), sync::ALPN)
            .await
            .unwrap()
    }

    /// Pulls from `other` over one stream of `conn`.
    async fn pull_over(&self, conn: &Connection) -> Result<PullOutcome, SyncError> {
        let (send, recv) = conn.open_bi().await.unwrap();
        sync_driver::pull(tokio::io::join(recv, send), &self.handle).await
    }

    /// Waits for `other` to be serving `n` connections: accepting runs
    /// behind the handshake the dialler returned from.
    async fn wait_for_peers(&self, n: usize) {
        timeout(GRACE, async {
            while self.handle.peer_connections().await.unwrap() != n {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("expected {n} peer connections"));
    }
}

/// Two nodes of one cluster, alongside its genesis head and the key they
/// both sign with. The first gets `a_limit` as its peer connection cap.
///
/// `b` is the one that dials here, so `b` runs on the endpoint the
/// genesis lists — a node serves only peers its own ledger names, and the
/// genesis names the founding node under its own iroh key. The copied
/// state dirs share that key, so `a` takes a fresh one: two endpoints
/// under one id cannot tell each other apart.
async fn cluster_pair(a_limit: Option<usize>) -> (Node, Node, EnvelopeDigest, NodeKeys) {
    let (mut nodes, genesis, keys) = cluster(2, a_limit).await;
    let b = nodes.pop().unwrap();
    let a = nodes.pop().unwrap();
    (a, b, genesis, keys)
}

/// `n` nodes of one cluster, alongside its genesis head and the key they
/// all sign with. The first gets `a_limit` as its peer connection cap.
///
/// Only the second runs on the endpoint the genesis lists, and it is the
/// one that dials in these tests: a node serves only peers its own ledger
/// names, and the genesis names the founding node under its own iroh key.
/// The copied state dirs share that key, so every other node takes a
/// fresh one — two endpoints under one id cannot tell each other apart —
/// and is therefore a peer the ledger does not list.
async fn cluster(n: usize, a_limit: Option<usize>) -> (Vec<Node>, EnvelopeDigest, NodeKeys) {
    let dirs: Vec<TempDir> = (0..n).map(|_| TempDir::new().unwrap()).collect();
    let (genesis, keys, listed) = {
        let core = Core::create_in_state_dir(dirs[0].path().to_path_buf(), IfInitialized::Fail)
            .await
            .unwrap();
        (core.head(), core.keys().clone(), core.iroh_secret().clone())
        // The core drops here, closing its store before the copies.
    };
    for dir in &dirs[1..] {
        copy_state_dir(dirs[0].path(), dir.path());
    }

    let network = TestNetwork::new();
    let mut nodes = Vec::with_capacity(n);
    for (i, dir) in dirs.into_iter().enumerate() {
        let secret = match i {
            1 => listed.clone(),
            _ => SecretKey::generate(),
        };
        let limit = (i == 0).then_some(a_limit).flatten();
        nodes.push(Node::start(dir, &network, secret, limit).await);
    }
    (nodes, genesis, keys)
}

#[tokio::test]
async fn a_behind_node_pulls_over_iroh() {
    let (a, b, genesis, keys) = cluster_pair(None).await;
    a.handle
        .insert(run_of(&keys, genesis, "a", 3))
        .await
        .unwrap();

    let conn = b.connect(&a).await;
    let pulled = b.pull_over(&conn).await.unwrap();

    let head = a.handle.head().await.unwrap();
    assert_eq!(pulled, PullOutcome::Synced { head, ingested: 3 });
    assert_eq!(b.handle.head().await.unwrap(), head);
}

/// One connection, many sessions: each pull is its own stream, served in
/// turn, and the connection outlives them all.
#[tokio::test]
async fn one_connection_serves_pull_after_pull() {
    let (a, b, genesis, keys) = cluster_pair(None).await;
    let conn = b.connect(&a).await;

    a.handle
        .insert(run_of(&keys, genesis, "a", 2))
        .await
        .unwrap();
    let first = b.pull_over(&conn).await.unwrap();
    let second = b.pull_over(&conn).await.unwrap();

    let head = a.handle.head().await.unwrap();
    assert_eq!(first, PullOutcome::Synced { head, ingested: 2 });
    assert_eq!(second, PullOutcome::AlreadyCurrent);

    a.handle
        .insert(run_of(&keys, head, "more", 1))
        .await
        .unwrap();
    let third = b.pull_over(&conn).await.unwrap();
    assert_eq!(
        third,
        PullOutcome::Synced {
            head: a.handle.head().await.unwrap(),
            ingested: 1
        }
    );
}

#[tokio::test]
async fn peer_connections_counts_the_peers_being_served() {
    let (a, b, _genesis, _keys) = cluster_pair(None).await;
    assert_eq!(a.handle.peer_connections().await.unwrap(), 0);

    let conn = b.connect(&a).await;
    a.wait_for_peers(1).await;

    drop(conn);
    a.wait_for_peers(0).await;
}

#[tokio::test]
async fn a_node_without_an_endpoint_has_no_peers() {
    let dir = TempDir::new().unwrap();
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    let (handle, _join) = Server::new(core, listener).unwrap().run().await;

    assert_eq!(handle.peer_connections().await.unwrap(), 0);
}

/// Over the cap, the handshake itself is refused: the dialler never gets
/// a connection to open streams on.
#[tokio::test]
async fn connections_over_the_limit_are_refused() {
    let (a, b, _genesis, _keys) = cluster_pair(Some(1)).await;

    let _held = b.connect(&a).await;
    a.wait_for_peers(1).await;

    let refused = timeout(GRACE, b.endpoint.connect(a.endpoint.id(), sync::ALPN))
        .await
        .expect("a refusal should come back promptly");
    assert!(refused.is_err(), "second connection should be refused");
}

/// A shutdown with a peer mid-connection still completes, and leaves the
/// endpoint closed behind it.
#[tokio::test]
async fn shutdown_completes_with_a_live_peer_connection() {
    let (a, b, _genesis, _keys) = cluster_pair(None).await;
    let conn = b.connect(&a).await;
    a.wait_for_peers(1).await;

    // Open a stream and say nothing: the server side is parked in the
    // session, waiting on our first frame.
    let _idle = conn.open_bi().await.unwrap();

    timeout(GRACE, a.handle.shutdown())
        .await
        .expect("shutdown should not hang on a live peer")
        .unwrap();
    timeout(GRACE, a.join).await.unwrap().unwrap();
    assert!(a.endpoint.is_closed());

    // The peer learns the connection is gone rather than hanging on it.
    assert!(timeout(GRACE, conn.closed()).await.is_ok());
}

#[tokio::test]
async fn dropping_the_last_handle_closes_the_endpoint() {
    let (a, _b, _genesis, _keys) = cluster_pair(None).await;
    let Node {
        handle,
        join,
        endpoint,
        _dir,
    } = a;

    drop(handle);
    timeout(GRACE, join)
        .await
        .expect("mainloop should exit once every handle is gone")
        .unwrap();
    assert!(endpoint.is_closed());
}

/// A peer the ledger does not list is not served: the cluster's chain
/// goes to the nodes it names, not to whoever asks for it.
#[tokio::test]
async fn an_unlisted_peer_cannot_pull() {
    let (mut nodes, genesis, keys) = cluster(3, None).await;
    let stranger = nodes.pop().unwrap();
    let a = nodes.swap_remove(0);
    a.handle
        .insert(run_of(&keys, genesis, "a", 3))
        .await
        .unwrap();

    assert!(
        stranger.try_pull(&a).await.is_none(),
        "an unlisted peer should not be served"
    );
    assert_eq!(
        stranger.handle.head().await.unwrap(),
        genesis,
        "the stranger learnt nothing"
    );
    // Refused connections are not held open either.
    a.wait_for_peers(0).await;
}

/// The same endpoint, listed: what the stranger was refused for is
/// membership, not anything about how it asked.
#[tokio::test]
async fn a_peer_the_ledger_lists_is_served() {
    let (mut nodes, genesis, keys) = cluster(3, None).await;
    let stranger = nodes.pop().unwrap();
    let a = nodes.swap_remove(0);
    a.handle
        .insert(run_of(&keys, genesis, "a", 3))
        .await
        .unwrap();
    a.list(&keys, [(KeyId::from_bytes([1; 32]), stranger.addr())])
        .await;

    let head = a.handle.head().await.unwrap();
    assert_eq!(
        stranger.try_pull(&a).await,
        Some(PullOutcome::Synced { head, ingested: 4 })
    );
}

/// Membership is read at every accept, not settled once: a node the
/// ledger stops listing is refused the next time it connects.
#[tokio::test]
async fn a_delisted_peer_is_refused_on_its_next_connection() {
    let (a, b, genesis, keys) = cluster_pair(None).await;
    a.handle
        .insert(run_of(&keys, genesis, "a", 2))
        .await
        .unwrap();
    let head = a.handle.head().await.unwrap();
    assert_eq!(
        b.try_pull(&a).await,
        Some(PullOutcome::Synced { head, ingested: 2 })
    );

    a.list(&keys, []).await;

    assert!(
        b.try_pull(&a).await.is_none(),
        "a delisted peer should not be served"
    );
    assert_eq!(
        b.handle.head().await.unwrap(),
        head,
        "b did not get the write that delisted it"
    );
}
