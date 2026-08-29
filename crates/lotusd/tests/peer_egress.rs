//! A daemon following the `cluster-nodes` namespace: dialling what the
//! ledger lists, dropping what it stops listing, and surviving what it
//! changes — and, over the connections it keeps, announcing its head so
//! listed peers pull it. All over real iroh endpoints on an in-memory
//! network.

use std::{collections::BTreeMap, path::Path, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey, endpoint::presets,
    test_utils::test_transport::TestNetwork,
};
use lotusd::{
    Core, IfInitialized, Server, ServerHandle,
    peer_egress::{PeerState, PeerStatus},
    peer_ingress::Protocol,
};
use state::CLUSTER_NODES_KEY;
use tempfile::TempDir;
use tokio::{net::UnixListener, task::JoinHandle, time::timeout};
use wire::{
    Envelope, EnvelopeDigest, KeyId, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

/// How long a step gets before we call it hung. Generous: this bounds a
/// test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(10);

/// How long to let the actor act on something it should ignore before
/// concluding it did.
const SETTLE: Duration = Duration::from_millis(300);

/// Copies every regular file in `from` into `to` — how a second node
/// comes to share a genesis before any join mechanism exists.
fn copy_state_dir(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

/// An endpoint on `network` only, dialled by id alone.
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

/// An envelope that writes `v` under `k`, chaining onto `prev`.
fn set_ns(prev: EnvelopeDigest, k: &str, v: &str) -> Envelope {
    Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: NamespaceKey::try_new(k).unwrap(),
        namespace: Namespace {
            value: Value::String(v.to_string()),
        },
    }))
}

/// A node id that is nobody's key: the ledger keys `cluster-nodes` by
/// node id, and the copied state dirs all share one real one.
fn node_id(n: u8) -> KeyId {
    KeyId::from_bytes([n; 32])
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

/// A running node: its server, and the endpoint peers reach it on.
struct Node {
    handle: ServerHandle,
    join: JoinHandle<()>,
    endpoint: Endpoint,
    /// Its real node id — the key its own genesis entry sits under.
    id: KeyId,
    _dir: TempDir,
}

impl Node {
    /// Starts a server over the cluster state in `dir` on a fresh endpoint.
    async fn start(dir: TempDir, network: &TestNetwork) -> Self {
        let core = Core::init_with_state_dir(dir.path().to_path_buf())
            .await
            .unwrap();
        let id = core.key_id();
        // Short name on purpose: a unix socket path has to fit in SUN_LEN.
        let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
        let endpoint = endpoint(network).await;
        let (handle, join) = Server::new(core, listener)
            .unwrap()
            .with_endpoint(endpoint.clone())
            .run()
            .await;
        Node {
            handle,
            join,
            endpoint,
            id,
            _dir: dir,
        }
    }

    /// This node's address as the ledger would carry it: id only, since
    /// the test network resolves ids itself.
    fn addr(&self) -> EndpointAddr {
        EndpointAddr::new(self.endpoint.id())
    }

    /// Replaces this node's `cluster-nodes` with `entries`.
    async fn list(&self, entries: impl IntoIterator<Item = (KeyId, EndpointAddr)>) {
        let prev = self.handle.head().await.unwrap();
        let envelope = Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: NamespaceKey::try_new(CLUSTER_NODES_KEY).unwrap(),
            namespace: Namespace {
                value: cluster_nodes(entries),
            },
        }));
        self.handle.insert([envelope]).await.unwrap();
    }

    /// Waits until `accept` is true of this node's peer table.
    async fn wait_for_peers(&self, what: &str, accept: impl Fn(&[PeerStatus]) -> bool) {
        timeout(GRACE, async {
            loop {
                if accept(&self.handle.peers().await.unwrap()) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    /// Extends this node's chain by one envelope, returning the new head.
    async fn extend(&self, label: &str) -> EnvelopeDigest {
        let prev = self.handle.head().await.unwrap();
        let envelope = set_ns(prev, label, "v");
        let head = envelope.digest().unwrap();
        self.handle.insert([envelope]).await.unwrap();
        head
    }

    /// Waits until this node stands at `head`.
    async fn wait_for_head(&self, head: EnvelopeDigest) {
        timeout(GRACE, async {
            while self.handle.head().await.unwrap() != head {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for head {}", head.to_hex().as_ref()));
    }

    /// Waits until this node is serving `n` inbound connections.
    async fn wait_for_connections(&self, n: usize) {
        timeout(GRACE, async {
            while self.handle.peer_connections().await.unwrap() != n {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("expected {n} inbound connections"));
    }
}

/// `n` nodes of one cluster on one network. None lists any other yet.
async fn cluster(n: usize) -> Vec<Node> {
    let dirs: Vec<TempDir> = (0..n).map(|_| TempDir::new().unwrap()).collect();
    {
        // The core drops here, closing its store before the copies.
        Core::create_in_state_dir(dirs[0].path().to_path_buf(), IfInitialized::Fail)
            .await
            .unwrap();
    }
    for dir in &dirs[1..] {
        copy_state_dir(dirs[0].path(), dir.path());
    }

    let network = TestNetwork::new();
    let mut nodes = Vec::with_capacity(n);
    for dir in dirs {
        nodes.push(Node::start(dir, &network).await);
    }
    nodes
}

fn connected_to(peers: &[PeerStatus], node: KeyId, endpoint: &Endpoint) -> bool {
    peers
        .iter()
        .any(|p| p.node == node && p.addr.id == endpoint.id() && p.state == PeerState::Connected)
}

#[tokio::test]
async fn a_node_listed_in_the_ledger_is_dialled() {
    let nodes = cluster(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    assert!(a.handle.peers().await.unwrap().is_empty());

    a.list([(node_id(1), b.addr())]).await;

    a.wait_for_peers("a connected to b", |peers| {
        connected_to(peers, node_id(1), &b.endpoint)
    })
    .await;
    b.wait_for_connections(1).await;
    // Listing is one-way: b lists nobody, so b dials nobody.
    assert!(b.handle.peers().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_node_delisted_has_its_connection_closed() {
    let nodes = cluster(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    a.list([(node_id(1), b.addr())]).await;
    b.wait_for_connections(1).await;

    a.list([]).await;

    a.wait_for_peers("a to forget b", |peers| peers.is_empty())
        .await;
    b.wait_for_connections(0).await;
}

#[tokio::test]
async fn a_nodes_own_entries_are_never_dialled() {
    let nodes = cluster(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);

    // Both ways a node can be listed as itself: under its own node id, or
    // under another id but at its own endpoint.
    a.list([(a.id, b.addr()), (node_id(1), a.addr())]).await;

    tokio::time::sleep(SETTLE).await;
    assert!(a.handle.peers().await.unwrap().is_empty());
    assert_eq!(a.handle.peer_connections().await.unwrap(), 0);
    assert_eq!(b.handle.peer_connections().await.unwrap(), 0);
}

/// Same endpoint, new transport addresses: the node moved, and the
/// connection to it is kept rather than redialled.
#[tokio::test]
async fn changed_addresses_keep_the_connection() {
    let nodes = cluster(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    a.list([(node_id(1), b.addr())]).await;
    b.wait_for_connections(1).await;

    let moved = b.addr().with_ip_addr("127.0.0.1:4433".parse().unwrap());
    a.list([(node_id(1), moved.clone())]).await;

    a.wait_for_peers("a to learn b's new address", |peers| {
        peers.iter().any(|p| p.addr == moved)
    })
    .await;
    tokio::time::sleep(SETTLE).await;
    assert!(connected_to(
        &a.handle.peers().await.unwrap(),
        node_id(1),
        &b.endpoint
    ));
    assert_eq!(b.handle.peer_connections().await.unwrap(), 1);
}

/// Same node id, different endpoint: a different machine, so the old
/// connection goes and the new one is dialled.
#[tokio::test]
async fn a_rekeyed_node_is_redialled() {
    let nodes = cluster(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    a.list([(node_id(1), b.addr())]).await;
    b.wait_for_connections(1).await;

    a.list([(node_id(1), c.addr())]).await;

    a.wait_for_peers("a connected to c", |peers| {
        peers.len() == 1 && connected_to(peers, node_id(1), &c.endpoint)
    })
    .await;
    c.wait_for_connections(1).await;
    b.wait_for_connections(0).await;
}

#[tokio::test]
async fn a_node_added_later_is_dialled_alongside() {
    let nodes = cluster(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    a.list([(node_id(1), b.addr())]).await;
    b.wait_for_connections(1).await;

    a.list([(node_id(1), b.addr()), (node_id(2), c.addr())])
        .await;

    a.wait_for_peers("a connected to both", |peers| {
        connected_to(peers, node_id(1), &b.endpoint) && connected_to(peers, node_id(2), &c.endpoint)
    })
    .await;
    assert_eq!(b.handle.peer_connections().await.unwrap(), 1);
    c.wait_for_connections(1).await;
}

#[tokio::test]
async fn shutdown_closes_the_connections_the_egress_keeps() {
    let mut nodes = cluster(2).await;
    let b = nodes.pop().unwrap();
    let a = nodes.pop().unwrap();
    a.list([(node_id(1), b.addr())]).await;
    b.wait_for_connections(1).await;

    timeout(GRACE, a.handle.shutdown())
        .await
        .expect("shutdown should not hang on kept connections")
        .unwrap();
    timeout(GRACE, a.join).await.unwrap().unwrap();

    b.wait_for_connections(0).await;
}

#[tokio::test]
async fn a_node_without_an_endpoint_keeps_no_peers() {
    let dir = TempDir::new().unwrap();
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    let (handle, _join) = Server::new(core, listener).unwrap().run().await;

    assert!(handle.peers().await.unwrap().is_empty());
}

/// The gossip path end to end: a listed peer hears the new head over the
/// connection kept to it, finds it differs from its own, and pulls it
/// back over that same connection.
#[tokio::test]
async fn a_new_head_is_announced_and_pulled_by_the_listed_peer() {
    let nodes = cluster(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    a.list([(node_id(1), b.addr())]).await;
    b.wait_for_connections(1).await;
    // Listing moved a's head; let b catch that up before measuring.
    b.wait_for_head(a.handle.head().await.unwrap()).await;

    let head = a.extend("cfg").await;

    b.wait_for_head(head).await;
    // The pull went the other way over a's dialled connection: b dialled
    // nobody, and a serves nothing inbound.
    assert!(b.handle.peers().await.unwrap().is_empty());
    assert_eq!(a.handle.peer_connections().await.unwrap(), 0);
}

/// A peer that connects late is announced the current head on connect,
/// so it does not have to wait for the next change.
#[tokio::test]
async fn a_peer_is_caught_up_on_connect() {
    let nodes = cluster(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    a.extend("early").await;
    a.extend("earlier-still").await;

    a.list([(node_id(1), b.addr())]).await;

    b.wait_for_head(a.handle.head().await.unwrap()).await;
}

/// One list, shared by gossip, makes a full mesh: every node dials every
/// other, so a change made at any of them reaches all of them.
#[tokio::test]
async fn a_change_anywhere_in_the_mesh_reaches_everyone() {
    let nodes = cluster(3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);

    // Listed under ids that are nobody's: each node skips its own entry
    // by endpoint id and dials the other two.
    a.list([
        (node_id(0), a.addr()),
        (node_id(1), b.addr()),
        (node_id(2), c.addr()),
    ])
    .await;
    let listed = a.handle.head().await.unwrap();
    b.wait_for_head(listed).await;
    c.wait_for_head(listed).await;
    for node in [a, b, c] {
        node.wait_for_peers("two peers connected", |peers| {
            peers.len() == 2 && peers.iter().all(|p| p.state == PeerState::Connected)
        })
        .await;
    }

    let from_b = b.extend("by-b").await;
    a.wait_for_head(from_b).await;
    c.wait_for_head(from_b).await;

    let from_c = c.extend("by-c").await;
    a.wait_for_head(from_c).await;
    b.wait_for_head(from_c).await;
}

/// Several changes in quick succession collapse into however many pulls
/// it takes, not one per change, and the peer still lands on the last.
#[tokio::test]
async fn a_burst_of_changes_lands_the_peer_on_the_last() {
    let nodes = cluster(2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    a.list([(node_id(1), b.addr())]).await;
    b.wait_for_connections(1).await;

    let mut head = a.handle.head().await.unwrap();
    for i in 0..5 {
        head = a.extend(&format!("burst{i}")).await;
    }

    b.wait_for_head(head).await;
}
