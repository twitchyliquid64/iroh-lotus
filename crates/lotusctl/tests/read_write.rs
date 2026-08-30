//! `lotusctl read` and `lotusctl weak-set`, driven end to end: the real CLI
//! binary, over a real control socket, against a real daemon — alone, and
//! against a pair of nodes so a write on one is read back from the other.

use std::{collections::BTreeMap, path::Path, process::Stdio, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey, endpoint::presets,
    test_utils::test_transport::TestNetwork,
};
use lotusd::{Core, IfInitialized, NodeKeys, Server, ServerHandle, peer_ingress::Protocol};
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
async fn run(dir: &TempDir, args: &[&str]) -> (bool, String, String) {
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
        String::from_utf8(out.stderr).expect("the CLI writes text"),
    )
}

/// The same, failing the test on a non-zero exit.
async fn output(dir: &TempDir, args: &[&str]) -> String {
    let (ok, text, err) = run(dir, args).await;
    assert!(ok, "lotusctl {args:?} failed, printing {text}{err}");
    text
}

/// The same, as one JSON document.
async fn json(dir: &TempDir, args: &[&str]) -> serde_json::Value {
    let text = output(dir, &[&["--format", "json"], args].concat()).await;
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("not one JSON document ({e}): {text}"))
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
    /// The key it signs the envelopes these tests write with.
    keys: NodeKeys,
    genesis: EnvelopeDigest,
}

impl Node {
    /// Starts a daemon over the cluster state in `dir`, on an endpoint on
    /// `network` if one is given.
    async fn start(dir: TempDir, network: Option<&TestNetwork>) -> Self {
        let core = Core::init_with_state_dir(dir.path().to_path_buf())
            .await
            .unwrap();
        let genesis = core.root();
        let keys = core.keys().clone();
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
            keys,
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
        let envelope = self
            .keys
            .sign(Envelope::new(Msg::SetNamespace(SetNamespace {
                prev,
                key: NamespaceKey::try_new(CLUSTER_NODES_KEY).unwrap(),
                namespace: Namespace { value },
            })))
            .unwrap();
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

    /// Waits until this node stands at `head`.
    async fn wait_for_head(&self, head: &str) {
        timeout(GRACE, async {
            while hex(self.handle.head().await.unwrap()) != head {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for head {head}"));
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

/// Two nodes of one cluster on one network, each keeping a connection to
/// the other, so a head movement on either reaches both.
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
    a.list([
        (
            KeyId::from_bytes([1; 32]),
            EndpointAddr::new(a.endpoint().id()),
        ),
        (
            KeyId::from_bytes([2; 32]),
            EndpointAddr::new(b.endpoint().id()),
        ),
    ])
    .await;
    b.wait_for_connections(1).await;
    // B pulls the listing back over that connection and dials A in turn.
    a.wait_for_connections(1).await;
    (a, b)
}

fn hex(digest: EnvelopeDigest) -> String {
    digest.to_hex().as_ref().to_string()
}

/// A digest as `--format json` writes it.
fn json_digest(digest: EnvelopeDigest) -> serde_json::Value {
    serde_json::to_value(digest).unwrap()
}

/// The digest `field` of a JSON document, in hex.
fn digest_in(json: &serde_json::Value, field: &str) -> String {
    hex(serde_json::from_value(json[field].clone())
        .unwrap_or_else(|e| panic!("{field} is not a digest ({e}): {json}")))
}

#[tokio::test]
async fn reading_what_is_not_set_says_so() {
    let node = alone().await;

    let text = output(&node.dir, &["read", "cfg"]).await;

    assert_eq!(
        text,
        format!("head   {}\nvalue  — (not set)\n", hex(node.genesis))
    );

    let json = json(&node.dir, &["read", "cfg"]).await;
    assert_eq!(json["head"], json_digest(node.genesis));
    assert_eq!(json["value"], serde_json::Value::Null);
}

/// A namespace written whole reads back whole, and by path.
#[tokio::test]
async fn a_namespace_written_by_weak_set_reads_back() {
    let node = alone().await;

    let written = json(
        &node.dir,
        &[
            "weak-set",
            "cfg",
            r#"{"servers": [{"host": "a.example", "port": 80}], "on": true}"#,
        ],
    )
    .await;
    assert_eq!(written["outcome"], "extended");
    let head = digest_in(&written, "head");
    assert_eq!(digest_in(&written, "envelope"), head);
    assert_ne!(head, hex(node.genesis));

    let read = json(&node.dir, &["read", "cfg"]).await;
    assert_eq!(digest_in(&read, "head"), head);
    assert_eq!(
        read["value"],
        serde_json::json!({"servers": [{"host": "a.example", "port": 80}], "on": true})
    );

    let text = output(&node.dir, &["read", "cfg", "servers[0].host"]).await;
    assert_eq!(text, format!("head   {head}\nvalue  \"a.example\"\n"));

    let text = output(&node.dir, &["read", "cfg", "servers[0].port"]).await;
    assert_eq!(text, format!("head   {head}\nvalue  80\n"));
}

/// A write at a path replaces that value and nothing beside it.
#[tokio::test]
async fn weak_set_at_a_path_replaces_one_value() {
    let node = alone().await;
    json(
        &node.dir,
        &["weak-set", "cfg", r#"{"host": "a", "port": 80}"#],
    )
    .await;

    let text = output(&node.dir, &["weak-set", "cfg", "--path", "port", "443"]).await;
    assert!(text.contains("outcome   extended\n"), "got {text}");

    let read = json(&node.dir, &["read", "cfg"]).await;
    assert_eq!(read["value"], serde_json::json!({"host": "a", "port": 443}));
}

/// The value is JSON and nothing else: a string is quoted, a bare word is
/// refused rather than guessed at.
#[tokio::test]
async fn a_value_is_always_json() {
    let node = alone().await;

    json(&node.dir, &["weak-set", "cfg", "\"hello\""]).await;
    assert_eq!(json(&node.dir, &["read", "cfg"]).await["value"], "hello");

    json(&node.dir, &["weak-set", "cfg", "\"7\""]).await;
    assert_eq!(json(&node.dir, &["read", "cfg"]).await["value"], "7");

    json(&node.dir, &["weak-set", "cfg", "7"]).await;
    assert_eq!(json(&node.dir, &["read", "cfg"]).await["value"], 7);

    let (ok, _out, err) = run(&node.dir, &["weak-set", "cfg", "hello"]).await;
    assert!(!ok, "a bare word should be refused");
    assert!(err.contains("is not JSON"), "got {err}");
    assert_eq!(json(&node.dir, &["read", "cfg"]).await["value"], 7);
}

/// The tagged form writes and reads every value type by name.
#[tokio::test]
async fn the_tagged_form_round_trips() {
    let node = alone().await;

    json(
        &node.dir,
        &[
            "weak-set",
            "cfg",
            "--tagged",
            r#"{"type": "array", "value": [{"type": "int", "value": 1}]}"#,
        ],
    )
    .await;

    let read = json(&node.dir, &["read", "cfg", "--tagged"]).await;
    assert_eq!(
        read["value"],
        serde_json::json!({"type": "array", "value": [{"type": "int", "value": 1}]})
    );
    let read = json(&node.dir, &["read", "cfg"]).await;
    assert_eq!(read["value"], serde_json::json!([1]));
}

/// A value the ledger cannot hold is refused before anything is sent.
#[tokio::test]
async fn a_value_the_ledger_cannot_hold_is_refused() {
    let node = alone().await;

    for bad in ["null", "1.5", "[null]", r#"{"a": 1e30}"#] {
        let (ok, _out, err) = run(&node.dir, &["weak-set", "cfg", bad]).await;
        assert!(!ok, "`{bad}` should be refused");
        assert!(err.contains("Error"), "got {err}");
    }
    assert_eq!(
        json(&node.dir, &["read", "cfg"]).await["value"],
        serde_json::Value::Null
    );
}

/// A write the chain refuses is reported as such, and the head stays put.
#[tokio::test]
async fn a_write_the_chain_refuses_fails() {
    let node = alone().await;

    let (ok, _out, err) = run(&node.dir, &["weak-set", "cfg", "--path", "port", "443"]).await;
    assert!(!ok);
    assert!(err.contains("Rejected"), "got {err}");

    let read = json(&node.dir, &["read", "cfg"]).await;
    assert_eq!(read["head"], json_digest(node.genesis));
}

/// A write on one node is announced to its peer, which pulls it and reads
/// it back at the same head.
#[tokio::test]
async fn a_write_on_one_node_is_read_from_its_peer() {
    let (a, b) = pair().await;

    let written = json(&a.dir, &["weak-set", "cfg", r#"{"host": "a.example"}"#]).await;
    let head = digest_in(&written, "head");
    b.wait_for_head(&head).await;

    let read = json(&b.dir, &["read", "cfg", "host"]).await;
    assert_eq!(digest_in(&read, "head"), head);
    assert_eq!(read["value"], "a.example");

    // And the other way round, onto the head both now share.
    let written = json(
        &b.dir,
        &["weak-set", "cfg", "--path", "host", "\"b.example\""],
    )
    .await;
    let head = digest_in(&written, "head");
    a.wait_for_head(&head).await;

    let read = json(&a.dir, &["read", "cfg"]).await;
    assert_eq!(read["value"], serde_json::json!({"host": "b.example"}));
}

/// `weak-push` appends, `weak-increment` adds within bounds, and
/// `weak-delete` clears a value or the whole namespace.
#[tokio::test]
async fn push_increment_and_delete_edit_in_place() {
    let node = alone().await;
    let value = async |path: &[&str]| {
        json(&node.dir, &[&["read", "cfg"], path].concat()).await["value"].clone()
    };

    json(&node.dir, &["weak-set", "cfg", r#"{"n": 1, "tags": []}"#]).await;

    let text = output(&node.dir, &["weak-push", "cfg", "-p", "tags", "\"a\""]).await;
    assert!(text.contains("outcome   extended\n"), "got {text}");
    json(&node.dir, &["weak-push", "cfg", "--path", "tags", "2"]).await;
    assert_eq!(value(&["tags"]).await, serde_json::json!(["a", 2]));

    json(&node.dir, &["weak-increment", "cfg", "-p", "n", "5"]).await;
    assert_eq!(value(&["n"]).await, 6);
    json(
        &node.dir,
        &["weak-increment", "cfg", "-p", "n", "-10", "--min", "0"],
    )
    .await;
    assert_eq!(value(&["n"]).await, 0);
    json(
        &node.dir,
        &["weak-increment", "cfg", "-p", "n", "9", "--max", "3"],
    )
    .await;
    assert_eq!(value(&["n"]).await, 3);

    json(&node.dir, &["weak-delete", "cfg", "-p", "tags[0]"]).await;
    assert_eq!(value(&[]).await, serde_json::json!({"n": 3, "tags": [2]}));

    let written = json(&node.dir, &["weak-delete", "cfg"]).await;
    assert_eq!(written["outcome"], "extended");
    let read = json(&node.dir, &["read", "cfg"]).await;
    assert_eq!(read["head"], written["head"]);
    assert_eq!(read["value"], serde_json::Value::Null);
}

/// An edit the ledger cannot make is reported as rejected.
#[tokio::test]
async fn an_edit_the_chain_refuses_fails() {
    let node = alone().await;
    json(&node.dir, &["weak-set", "cfg", r#"{"n": 1}"#]).await;

    for args in [
        &["weak-push", "cfg", "-p", "n", "1"][..],
        &["weak-increment", "cfg", "-p", "missing", "1"],
        &["weak-delete", "cfg", "-p", "missing"],
        &["weak-delete", "gone"],
    ] {
        let (ok, _out, err) = run(&node.dir, args).await;
        assert!(!ok, "{args:?} should be refused");
        assert!(err.contains("Rejected"), "{args:?} got {err}");
    }
    assert_eq!(
        json(&node.dir, &["read", "cfg"]).await["value"],
        serde_json::json!({"n": 1})
    );
}
