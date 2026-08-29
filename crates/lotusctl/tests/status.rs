//! `lotusctl status`, driven end to end: the real CLI binary, over a real
//! control socket, against a real daemon — alone, and with a peer it keeps
//! a connection to over an in-memory iroh network.

use std::{collections::BTreeMap, path::Path, process::Stdio, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey, endpoint::presets,
    test_utils::test_transport::TestNetwork,
};
use lotusd::{Core, IfInitialized, Server, ServerHandle, peer_ingress::Protocol};
use state::CLUSTER_NODES_KEY;
use tempfile::TempDir;
use tokio::{net::UnixListener, process::Command, task::JoinHandle, time::timeout};
use wire::{
    Envelope, EnvelopeDigest, KeyId, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

/// How long a step gets before we call it hung. Generous: this bounds a
/// test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(20);

/// What `lotusctl --state-dir dir <args>` printed, and whether it succeeded.
async fn run(dir: &TempDir, args: &[&str]) -> (bool, String) {
    let out = timeout(
        GRACE,
        Command::new(env!("CARGO_BIN_EXE_lotusctl"))
            .arg("--state-dir")
            .arg(dir.path())
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the CLI binary is built alongside this test")
            .wait_with_output(),
    )
    .await
    .expect("the CLI did not exit")
    .expect("waiting on the CLI");

    (
        out.status.success(),
        String::from_utf8(out.stdout).expect("the CLI writes text"),
    )
}

/// The same, failing the test on a non-zero exit.
async fn output(dir: &TempDir, args: &[&str]) -> String {
    let (ok, text) = run(dir, args).await;
    assert!(ok, "lotusctl {args:?} failed, printing {text}");
    text
}

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

/// A running node, on the socket `lotusctl --state-dir dir` looks for.
struct Node {
    dir: TempDir,
    handle: ServerHandle,
    _join: JoinHandle<()>,
    endpoint: Option<Endpoint>,
    id: KeyId,
    genesis: EnvelopeDigest,
}

impl Node {
    /// Starts a daemon over the cluster state in `dir`, on an endpoint on
    /// `network` if one is given.
    async fn start(dir: TempDir, network: Option<&TestNetwork>) -> Self {
        let core = Core::init_with_state_dir(dir.path().to_path_buf())
            .await
            .unwrap();
        let (id, genesis) = (core.key_id(), core.root());
        let listener = UnixListener::bind(dir.path().join("local.sock")).unwrap();
        let endpoint = match network {
            Some(network) => Some(endpoint(network).await),
            None => None,
        };
        let server = Server::new(core, listener).unwrap();
        let server = match &endpoint {
            Some(endpoint) => server.with_endpoint(endpoint.clone()),
            None => server,
        };
        let (handle, join) = server.run().await;
        Node {
            dir,
            handle,
            _join: join,
            endpoint,
            id,
            genesis,
        }
    }

    fn endpoint(&self) -> &Endpoint {
        self.endpoint.as_ref().expect("started with an endpoint")
    }

    /// Lists `entries` as this node's `cluster-nodes`.
    async fn list(&self, entries: impl IntoIterator<Item = (KeyId, EndpointAddr)>) {
        let prev = self.handle.head().await.unwrap();
        let value = Value::Map(
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
        );
        let envelope = Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: NamespaceKey::try_new(CLUSTER_NODES_KEY).unwrap(),
            namespace: Namespace { value },
        }));
        self.handle.insert([envelope]).await.unwrap();
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

/// A fresh single-node cluster.
async fn alone() -> Node {
    let dir = TempDir::new().unwrap();
    Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    Node::start(dir, None).await
}

/// Two nodes of one cluster on one network, the first keeping a
/// connection to the second.
async fn pair() -> (Node, Node) {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    {
        // The core drops here, closing its store before the copy.
        Core::create_in_state_dir(dir_a.path().to_path_buf(), IfInitialized::Fail)
            .await
            .unwrap();
    }
    copy_state_dir(dir_a.path(), dir_b.path());

    let network = TestNetwork::new();
    let a = Node::start(dir_a, Some(&network)).await;
    let b = Node::start(dir_b, Some(&network)).await;
    a.list([(
        KeyId::from_bytes([1; 32]),
        EndpointAddr::new(b.endpoint().id()),
    )])
    .await;
    b.wait_for_connections(1).await;
    (a, b)
}

fn hex(digest: EnvelopeDigest) -> String {
    digest.to_hex().as_ref().to_string()
}

#[tokio::test]
async fn status_names_the_node_and_the_chain_it_holds() {
    let node = alone().await;

    let text = output(&node.dir, &["status"]).await;

    assert!(
        text.contains(&format!("version    {}\n", lotusd::VERSION)),
        "got {text}"
    );
    assert!(
        text.contains(&format!("node id    {}\n", node.id.to_hex().as_ref())),
        "got {text}"
    );
    assert!(
        text.contains(&format!("root       {}\n", hex(node.genesis))),
        "got {text}"
    );
    assert!(
        text.contains(&format!("head       {}\n", hex(node.genesis))),
        "got {text}"
    );
}

#[tokio::test]
async fn status_says_when_the_node_serves_no_peers() {
    let node = alone().await;

    let text = output(&node.dir, &["status"]).await;

    assert!(
        text.contains("endpoint   none (not serving peers)\n"),
        "got {text}"
    );
    assert!(text.contains("inbound    0 connections\n"), "got {text}");
    assert!(text.contains("peers      0 kept\n"), "got {text}");
}

/// The node that dials lists its peer as connected; the node dialled
/// counts the connection as inbound and keeps none of its own.
#[tokio::test]
async fn status_shows_each_side_of_a_kept_connection() {
    let (a, b) = pair().await;

    let a_text = output(&a.dir, &["status"]).await;
    let b_text = output(&b.dir, &["status"]).await;

    assert!(
        a_text.contains(&format!("endpoint   {}\n", a.endpoint().id().to_z32())),
        "got {a_text}"
    );
    assert!(a_text.contains("peers      1 kept\n"), "got {a_text}");
    assert!(
        a_text.contains(&format!(
            "           {}  {}  connected\n",
            KeyId::from_bytes([1; 32]).to_hex().as_ref(),
            b.endpoint().id().to_z32(),
        )),
        "got {a_text}"
    );
    assert!(
        a_text.contains("inbound    0 connections\n"),
        "got {a_text}"
    );
    // Where the listing stands depends on whether the publisher has
    // looked since the fixture relisted the nodes; only that it reports.
    assert!(a_text.contains("\nlisting    "), "got {a_text}");

    assert!(b_text.contains("inbound    1 connection\n"), "got {b_text}");
    assert!(b_text.contains("peers      0 kept\n"), "got {b_text}");
}

#[tokio::test]
async fn status_renders_json_when_asked() {
    let (a, b) = pair().await;

    let text = output(&a.dir, &["--format", "json", "status"]).await;
    let json: serde_json::Value = serde_json::from_str(&text).expect("one JSON document");

    assert_eq!(json["version"], lotusd::VERSION);
    assert_eq!(json["endpoint"]["id"], a.endpoint().id().to_z32());
    assert_eq!(json["inbound"], 0);
    assert!(json["published"].is_object(), "got {json}");
    assert_eq!(json["peers"].as_array().map(Vec::len), Some(1));
    assert_eq!(json["peers"][0]["endpoint"], b.endpoint().id().to_z32());
    assert_eq!(
        json["peers"][0]["state"],
        serde_json::json!({ "connected": {} })
    );
}
