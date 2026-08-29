//! Daemons reaching each other over real iroh endpoints on an in-memory
//! network: the ingress actor's accept path, its bounds, and its place in
//! the server's lifecycle.

use std::{path::Path, time::Duration};

use iroh::{
    Endpoint, RelayMode, SecretKey,
    endpoint::{Connection, presets},
    test_utils::test_transport::TestNetwork,
};
use lotusd::{
    Core, IfInitialized, Server, ServerHandle,
    peer_ingress::Protocol,
    sync_driver::{self, SyncError},
};
use sync::PullOutcome;
use tempfile::TempDir;
use tokio::{net::UnixListener, task::JoinHandle, time::timeout};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

/// How long a step gets before we call it hung. Generous: this bounds a
/// test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(10);

fn set_ns(prev: EnvelopeDigest, k: &str, v: &str) -> Envelope {
    Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: NamespaceKey::try_new(k).unwrap(),
        namespace: Namespace {
            value: Value::String(v.to_string()),
        },
    }))
}

/// A linear run of `n` envelopes chaining onto `prev`.
fn run_of(prev: EnvelopeDigest, label: &str, n: usize) -> Vec<Envelope> {
    let mut cursor = prev;
    (0..n)
        .map(|i| {
            let envelope = set_ns(cursor, &format!("{label}{i}"), "v");
            cursor = envelope.digest().unwrap();
            envelope
        })
        .collect()
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
///
/// Fresh key each time rather than the core's: the copied state dirs
/// share one, and two endpoints under one id cannot tell each other apart.
async fn endpoint(network: &TestNetwork) -> Endpoint {
    let secret = SecretKey::generate();
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
    /// Starts a server over the cluster state in `dir`, serving peers on a
    /// fresh endpoint on `network`.
    async fn start(dir: TempDir, network: &TestNetwork, peer_limit: Option<usize>) -> Self {
        let core = Core::init_with_state_dir(dir.path().to_path_buf())
            .await
            .unwrap();
        // Short name on purpose: a unix socket path has to fit in SUN_LEN.
        let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
        let endpoint = endpoint(network).await;
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

/// Two nodes of one cluster, alongside its genesis head. The first gets
/// `a_limit` as its peer connection cap.
async fn cluster_pair(a_limit: Option<usize>) -> (Node, Node, EnvelopeDigest) {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let genesis = {
        let core = Core::create_in_state_dir(dir_a.path().to_path_buf(), IfInitialized::Fail)
            .await
            .unwrap();
        core.head()
        // The core drops here, closing its store before the copy.
    };
    copy_state_dir(dir_a.path(), dir_b.path());

    let network = TestNetwork::new();
    let a = Node::start(dir_a, &network, a_limit).await;
    let b = Node::start(dir_b, &network, None).await;
    (a, b, genesis)
}

#[tokio::test]
async fn a_behind_node_pulls_over_iroh() {
    let (a, b, genesis) = cluster_pair(None).await;
    a.handle.insert(run_of(genesis, "a", 3)).await.unwrap();

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
    let (a, b, genesis) = cluster_pair(None).await;
    let conn = b.connect(&a).await;

    a.handle.insert(run_of(genesis, "a", 2)).await.unwrap();
    let first = b.pull_over(&conn).await.unwrap();
    let second = b.pull_over(&conn).await.unwrap();

    let head = a.handle.head().await.unwrap();
    assert_eq!(first, PullOutcome::Synced { head, ingested: 2 });
    assert_eq!(second, PullOutcome::AlreadyCurrent);

    a.handle.insert(run_of(head, "more", 1)).await.unwrap();
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
    let (a, b, _genesis) = cluster_pair(None).await;
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
    let (a, b, _genesis) = cluster_pair(Some(1)).await;

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
    let (a, b, _genesis) = cluster_pair(None).await;
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
    let (a, _b, _genesis) = cluster_pair(None).await;
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
