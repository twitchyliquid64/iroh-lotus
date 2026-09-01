//! `lotusctl get` and the write verbs, driven end to end: the real CLI
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
    ///
    /// `secret` of `None` puts the node on the endpoint its own genesis
    /// names, which is what makes it a node its peers' ledgers already
    /// list — a node serves only peers its ledger names, so a pair whose
    /// endpoints are both strangers to it could never introduce itself.
    /// The copied state dirs share that key, so a second node must pass
    /// one of its own.
    async fn start(dir: TempDir, network: Option<&TestNetwork>, secret: Option<SecretKey>) -> Self {
        let core = Core::init_with_state_dir(dir.path().to_path_buf())
            .await
            .unwrap();
        let genesis = core.root();
        let keys = core.keys().clone();
        let listener = UnixListener::bind(dir.path().join("local.sock")).unwrap();
        let secret = secret.unwrap_or_else(|| core.iroh_secret().clone());
        let endpoint = match network {
            Some(network) => Some(endpoint(network, secret).await),
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
    Node::start(dir, None, None).await
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
    let a = Node::start(dir_a, Some(&network), None).await;
    let b = Node::start(dir_b, Some(&network), Some(SecretKey::generate())).await;
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

    let text = output(&node.dir, &["get", "cfg"]).await;

    assert_eq!(
        text,
        format!("head   {}\nvalue  — (not set)\n", hex(node.genesis))
    );

    let json = json(&node.dir, &["get", "cfg"]).await;
    assert_eq!(json["head"], json_digest(node.genesis));
    assert_eq!(json["value"], serde_json::Value::Null);
}

/// The global options are global: they parse after the subcommand and its
/// arguments, not only in front of it, and take effect from there.
#[tokio::test]
async fn the_global_options_may_trail_the_subcommand() {
    let node = alone().await;
    json(&node.dir, &["set", "cfg", r#"{"port": 80}"#]).await;

    // --state-dir is what points these at the node at all, so reaching the
    // daemon is itself the proof it was read from the tail.
    let text = output(
        &node.dir,
        &["get", "cfg", "port", "--format", "json", "--color", "never"],
    )
    .await;
    let read: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"));
    assert_eq!(read["value"], 80);

    // Given in both places, the one after the subcommand wins: clap
    // propagates a global from the deepest level it was named at.
    let text = output(
        &node.dir,
        &["--format", "json", "get", "cfg", "--format", "text"],
    )
    .await;
    assert!(
        text.starts_with("head   "),
        "expected text output, got {text}"
    );
}

/// `list` names every namespace the ledger holds, at the head it was read
/// at, with the shape of each one's value.
#[tokio::test]
async fn list_names_every_namespace_and_its_shape() {
    let node = alone().await;
    json(&node.dir, &["set", "cfg", r#"{"port": 80}"#]).await;
    json(&node.dir, &["set", "hosts", r#"["a.example"]"#]).await;
    let written = json(&node.dir, &["set", "region", "\"eu\""]).await;
    let head = digest_in(&written, "head");

    let listed = json(&node.dir, &["list"]).await;
    assert_eq!(digest_in(&listed, "head"), head);
    assert_eq!(
        listed["namespaces"],
        serde_json::json!([
            // The reserved namespaces the genesis installs are listed in
            // key order like any other.
            {"key": "_lotus_min_envelope_signatures", "shape": "leaf"},
            {"key": "_lotus_nodes", "shape": "map"},
            {"key": "_lotus_trusted_keys", "shape": "map"},
            {"key": "cfg", "shape": "map"},
            {"key": "hosts", "shape": "array"},
            {"key": "region", "shape": "leaf"},
        ])
    );

    let text = output(&node.dir, &["list"]).await;
    assert_eq!(
        text,
        format!(
            "head  {head}\n\
             _lotus_min_envelope_signatures  leaf\n\
             _lotus_nodes                    map\n\
             _lotus_trusted_keys             map\n\
             cfg                             map\n\
             hosts                           array\n\
             region                          leaf\n"
        )
    );
}

/// `len` reports the size of what a path addresses, and `keys` names its
/// entries, at the head each was read at.
#[tokio::test]
async fn len_and_keys_report_a_container_without_its_values() {
    let node = alone().await;
    let written = json(
        &node.dir,
        &["set", "cfg", r#"{"servers": ["a.example", "b.example"]}"#],
    )
    .await;
    let head = digest_in(&written, "head");

    let counted = json(&node.dir, &["len", "cfg", "servers"]).await;
    assert_eq!(digest_in(&counted, "head"), head);
    assert_eq!(counted["shape"], "array");
    assert_eq!(counted["len"], 2);

    let listed = json(&node.dir, &["keys", "cfg"]).await;
    assert_eq!(digest_in(&listed, "head"), head);
    assert_eq!(listed["keys"], serde_json::json!(["servers"]));

    // An array is named by the indices its length covers.
    let listed = json(&node.dir, &["keys", "cfg", "servers"]).await;
    assert_eq!(listed["keys"], serde_json::json!(["0", "1"]));

    assert_eq!(
        output(&node.dir, &["len", "cfg", "servers"]).await,
        format!("head   {head}\nshape  array\nlen    2\n")
    );
    assert_eq!(
        output(&node.dir, &["keys", "cfg", "servers"]).await,
        format!("head  {head}\n0\n1\n")
    );
}

/// A leaf holds no entries and has no keys, and a path addressing nothing
/// says so rather than reporting an empty container.
#[tokio::test]
async fn len_and_keys_tell_a_leaf_and_a_missing_path_apart() {
    let node = alone().await;
    let written = json(&node.dir, &["set", "cfg", r#"{"port": 80}"#]).await;
    let head = digest_in(&written, "head");

    let counted = json(&node.dir, &["len", "cfg", "port"]).await;
    assert_eq!(counted["shape"], "leaf");
    assert_eq!(counted["len"], serde_json::Value::Null);
    assert_eq!(
        output(&node.dir, &["keys", "cfg", "port"]).await,
        format!("head  {head}\n— (a leaf has no keys)\n")
    );

    let counted = json(&node.dir, &["len", "cfg", "nope"]).await;
    assert_eq!(counted["shape"], serde_json::Value::Null);
    assert_eq!(counted["len"], serde_json::Value::Null);
    assert_eq!(
        output(&node.dir, &["len", "cfg", "nope"]).await,
        format!("head   {head}\nshape  — (not set)\n")
    );
    assert_eq!(
        json(&node.dir, &["keys", "missing"]).await["keys"],
        serde_json::Value::Null
    );
}

/// A namespace deleted leaves the listing.
#[tokio::test]
async fn list_drops_a_deleted_namespace() {
    let node = alone().await;
    json(&node.dir, &["set", "cfg", "7"]).await;
    let keys = |listed: &serde_json::Value| -> Vec<String> {
        listed["namespaces"]
            .as_array()
            .expect("an array of namespaces")
            .iter()
            .map(|entry| entry["key"].as_str().expect("a key").to_owned())
            .collect()
    };
    assert!(keys(&json(&node.dir, &["list"]).await).contains(&"cfg".to_owned()));

    json(&node.dir, &["unset", "cfg"]).await;
    assert!(!keys(&json(&node.dir, &["list"]).await).contains(&"cfg".to_owned()));
}

/// A namespace written whole reads back whole, and by path.
#[tokio::test]
async fn a_namespace_written_by_set_reads_back() {
    let node = alone().await;

    let written = json(
        &node.dir,
        &[
            "set",
            "cfg",
            r#"{"servers": [{"host": "a.example", "port": 80}], "on": true}"#,
        ],
    )
    .await;
    assert_eq!(written["outcome"], "extended");
    let head = digest_in(&written, "head");
    assert_eq!(digest_in(&written, "envelope"), head);
    assert_ne!(head, hex(node.genesis));

    let read = json(&node.dir, &["get", "cfg"]).await;
    assert_eq!(digest_in(&read, "head"), head);
    assert_eq!(
        read["value"],
        serde_json::json!({"servers": [{"host": "a.example", "port": 80}], "on": true})
    );

    let text = output(&node.dir, &["get", "cfg", "servers[0].host"]).await;
    assert_eq!(text, format!("head   {head}\nvalue  \"a.example\"\n"));

    let text = output(&node.dir, &["get", "cfg", "servers[0].port"]).await;
    assert_eq!(text, format!("head   {head}\nvalue  80\n"));
}

/// A write at a path replaces that value and nothing beside it.
#[tokio::test]
async fn set_at_a_path_replaces_one_value() {
    let node = alone().await;
    json(&node.dir, &["set", "cfg", r#"{"host": "a", "port": 80}"#]).await;

    let text = output(&node.dir, &["set", "cfg", "port", "443"]).await;
    assert!(text.contains("outcome   extended\n"), "got {text}");

    let read = json(&node.dir, &["get", "cfg"]).await;
    assert_eq!(read["value"], serde_json::json!({"host": "a", "port": 443}));
}

/// The value is JSON and nothing else: a string is quoted, a bare word is
/// refused rather than guessed at.
#[tokio::test]
async fn a_value_is_always_json() {
    let node = alone().await;

    json(&node.dir, &["set", "cfg", "\"hello\""]).await;
    assert_eq!(json(&node.dir, &["get", "cfg"]).await["value"], "hello");

    json(&node.dir, &["set", "cfg", "\"7\""]).await;
    assert_eq!(json(&node.dir, &["get", "cfg"]).await["value"], "7");

    json(&node.dir, &["set", "cfg", "7"]).await;
    assert_eq!(json(&node.dir, &["get", "cfg"]).await["value"], 7);

    let (ok, _out, err) = run(&node.dir, &["set", "cfg", "hello"]).await;
    assert!(!ok, "a bare word should be refused");
    assert!(err.contains("is not JSON"), "got {err}");
    assert_eq!(json(&node.dir, &["get", "cfg"]).await["value"], 7);
}

/// The tagged form writes and reads every value type by name.
#[tokio::test]
async fn the_tagged_form_round_trips() {
    let node = alone().await;

    json(
        &node.dir,
        &[
            "set",
            "cfg",
            "--tagged",
            r#"{"type": "array", "value": [{"type": "int", "value": 1}]}"#,
        ],
    )
    .await;

    let read = json(&node.dir, &["get", "cfg", "--tagged"]).await;
    assert_eq!(
        read["value"],
        serde_json::json!({"type": "array", "value": [{"type": "int", "value": 1}]})
    );
    let read = json(&node.dir, &["get", "cfg"]).await;
    assert_eq!(read["value"], serde_json::json!([1]));
}

/// A value the ledger cannot hold is refused before anything is sent.
#[tokio::test]
async fn a_value_the_ledger_cannot_hold_is_refused() {
    let node = alone().await;

    for bad in ["null", "1.5", "[null]", r#"{"a": 1e30}"#] {
        let (ok, _out, err) = run(&node.dir, &["set", "cfg", bad]).await;
        assert!(!ok, "`{bad}` should be refused");
        assert!(err.contains("Error"), "got {err}");
    }
    assert_eq!(
        json(&node.dir, &["get", "cfg"]).await["value"],
        serde_json::Value::Null
    );
}

/// A write the chain refuses is reported as such, and the head stays put.
#[tokio::test]
async fn a_write_the_chain_refuses_fails() {
    let node = alone().await;

    let (ok, _out, err) = run(&node.dir, &["set", "cfg", "port", "443"]).await;
    assert!(!ok);
    assert!(err.contains("Rejected"), "got {err}");

    let read = json(&node.dir, &["get", "cfg"]).await;
    assert_eq!(read["head"], json_digest(node.genesis));
}

/// A write on one node is announced to its peer, which pulls it and reads
/// it back at the same head.
#[tokio::test]
async fn a_write_on_one_node_is_read_from_its_peer() {
    let (a, b) = pair().await;

    let written = json(&a.dir, &["set", "cfg", r#"{"host": "a.example"}"#]).await;
    let head = digest_in(&written, "head");
    b.wait_for_head(&head).await;

    let read = json(&b.dir, &["get", "cfg", "host"]).await;
    assert_eq!(digest_in(&read, "head"), head);
    assert_eq!(read["value"], "a.example");

    // And the other way round, onto the head both now share.
    let written = json(&b.dir, &["set", "cfg", "host", "\"b.example\""]).await;
    let head = digest_in(&written, "head");
    a.wait_for_head(&head).await;

    let read = json(&a.dir, &["get", "cfg"]).await;
    assert_eq!(read["value"], serde_json::json!({"host": "b.example"}));
}

/// `append` appends, `increment` adds within bounds, and `unset` clears
/// a value or the whole namespace.
#[tokio::test]
async fn append_increment_and_unset_edit_in_place() {
    let node = alone().await;
    let value = async |path: &[&str]| {
        json(&node.dir, &[&["get", "cfg"], path].concat()).await["value"].clone()
    };

    json(&node.dir, &["set", "cfg", r#"{"n": 1, "tags": []}"#]).await;

    let text = output(&node.dir, &["append", "cfg", "tags", "\"a\""]).await;
    assert!(text.contains("outcome   extended\n"), "got {text}");
    json(&node.dir, &["append", "cfg", "tags", "2"]).await;
    assert_eq!(value(&["tags"]).await, serde_json::json!(["a", 2]));

    json(&node.dir, &["increment", "cfg", "n", "5"]).await;
    assert_eq!(value(&["n"]).await, 6);
    json(&node.dir, &["increment", "cfg", "n", "-10", "--min", "0"]).await;
    assert_eq!(value(&["n"]).await, 0);
    json(&node.dir, &["increment", "cfg", "n", "9", "--max", "3"]).await;
    assert_eq!(value(&["n"]).await, 3);

    json(&node.dir, &["unset", "cfg", "tags[0]"]).await;
    assert_eq!(value(&[]).await, serde_json::json!({"n": 3, "tags": [2]}));

    let written = json(&node.dir, &["unset", "cfg"]).await;
    assert_eq!(written["outcome"], "extended");
    let read = json(&node.dir, &["get", "cfg"]).await;
    assert_eq!(read["head"], written["head"]);
    assert_eq!(read["value"], serde_json::Value::Null);
}

/// An edit the ledger cannot make is reported as rejected.
#[tokio::test]
async fn an_edit_the_chain_refuses_fails() {
    let node = alone().await;
    json(&node.dir, &["set", "cfg", r#"{"n": 1}"#]).await;

    for args in [
        &["append", "cfg", "n", "1"][..],
        &["increment", "cfg", "missing", "1"],
        &["unset", "cfg", "missing"],
        &["unset", "gone"],
    ] {
        let (ok, _out, err) = run(&node.dir, args).await;
        assert!(!ok, "{args:?} should be refused");
        assert!(err.contains("Rejected"), "{args:?} got {err}");
    }
    assert_eq!(
        json(&node.dir, &["get", "cfg"]).await["value"],
        serde_json::json!({"n": 1})
    );
}

/// The value is always the last argument, so a lone one writes the
/// namespace whole and a pair names a path first.
#[tokio::test]
async fn a_write_names_its_path_before_its_value() {
    let node = alone().await;

    json(&node.dir, &["set", "cfg", r#"{"port": 80}"#]).await;
    assert_eq!(
        json(&node.dir, &["get", "cfg"]).await["value"],
        serde_json::json!({"port": 80})
    );

    json(&node.dir, &["set", "cfg", "port", "443"]).await;
    assert_eq!(json(&node.dir, &["get", "cfg", "port"]).await["value"], 443);

    // A path that is not one is refused rather than read as a value.
    let (ok, _out, err) = run(&node.dir, &["set", "cfg", "port[", "443"]).await;
    assert!(!ok, "an unparseable path should be refused");
    assert!(err.contains("is not a path"), "got {err}");
}

/// `delete` removes whichever entries meet every condition: a field of an
/// entry with `PATH=VALUE`, the entry itself with `=VALUE`.
#[tokio::test]
async fn delete_removes_the_entries_that_match() {
    let node = alone().await;
    json(
        &node.dir,
        &[
            "set",
            "cfg",
            r#"{"nodes": [{"id": "web-1", "on": true}, {"id": "web-2", "on": true}], "xs": [1, 7, 3]}"#,
        ],
    )
    .await;

    json(
        &node.dir,
        &["delete", "cfg", "nodes", "--where", r#"id="web-1""#],
    )
    .await;
    assert_eq!(
        json(&node.dir, &["get", "cfg", "nodes"]).await["value"],
        serde_json::json!([{"id": "web-2", "on": true}])
    );

    json(&node.dir, &["delete", "cfg", "xs", "--where", "=7"]).await;
    assert_eq!(
        json(&node.dir, &["get", "cfg", "xs"]).await["value"],
        serde_json::json!([1, 3])
    );

    // Every condition must hold, and matching nothing still lands.
    let written = json(
        &node.dir,
        &[
            "delete",
            "cfg",
            "nodes",
            "--where",
            r#"id="web-2""#,
            "--where",
            "on=false",
        ],
    )
    .await;
    assert_eq!(written["outcome"], "extended");
    assert_eq!(
        json(&node.dir, &["get", "cfg", "nodes"]).await["value"],
        serde_json::json!([{"id": "web-2", "on": true}])
    );

    // A condition that is not [PATH]=VALUE is refused before anything is
    // sent, and a delete with no condition at all is refused by clap.
    let (ok, _out, err) = run(&node.dir, &["delete", "cfg", "nodes", "--where", "id"]).await;
    assert!(!ok);
    assert!(err.contains("is not [PATH]=VALUE"), "got {err}");
    let (ok, _out, _err) = run(&node.dir, &["delete", "cfg", "nodes"]).await;
    assert!(!ok, "a delete with no --where should be refused");
}
