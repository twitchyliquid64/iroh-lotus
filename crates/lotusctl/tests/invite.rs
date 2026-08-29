//! `lotusctl invite`, driven end to end: the real CLI binary, over a real
//! control socket, against a real daemon on an in-memory iroh network.

use std::{process::Stdio, time::Duration};

use iroh::{Endpoint, RelayMode, endpoint::presets, test_utils::test_transport::TestNetwork};
use lotusd::{Core, IfInitialized, Server, ServerHandle, invite::Invite, peer_ingress::Protocol};
use tempfile::TempDir;
use tokio::{net::UnixListener, process::Command, task::JoinHandle, time::timeout};
use wire::{EnvelopeDigest, KeyId};

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

/// A running node, on the socket `lotusctl --state-dir dir` looks for.
struct Node {
    dir: TempDir,
    _handle: ServerHandle,
    _join: JoinHandle<()>,
    id: KeyId,
    genesis: EnvelopeDigest,
}

impl Node {
    /// A fresh single-node cluster, serving peers on `network` if given.
    async fn start(network: Option<&TestNetwork>) -> Self {
        let dir = TempDir::new().unwrap();
        let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
            .await
            .unwrap();
        let (id, genesis) = (core.key_id(), core.root());
        let listener = UnixListener::bind(dir.path().join("local.sock")).unwrap();
        let endpoint = match network {
            Some(network) => {
                let secret = core.iroh_secret().clone();
                let transport = network.create_transport(secret.public()).unwrap();
                Some(
                    Endpoint::builder(presets::Minimal)
                        .preset(transport)
                        .secret_key(secret)
                        .relay_mode(RelayMode::Disabled)
                        .clear_ip_transports()
                        .alpns(Protocol::alpns())
                        .bind()
                        .await
                        .unwrap(),
                )
            }
            None => None,
        };
        let server = Server::new(core, listener).unwrap();
        let server = match endpoint {
            Some(endpoint) => server.with_endpoint(endpoint),
            None => server,
        };
        let (handle, join) = server.run().await;
        Node {
            dir,
            _handle: handle,
            _join: join,
            id,
            genesis,
        }
    }
}

/// The one invite word in `text`, wherever it sits.
fn word(text: &str) -> &str {
    text.split_whitespace()
        .find(|w| w.starts_with("lotus1"))
        .expect("the output carries an invite")
}

#[tokio::test]
async fn invite_prints_a_word_that_names_the_node_and_its_root() {
    let network = TestNetwork::new();
    let node = Node::start(Some(&network)).await;

    let (ok, out, _) = run(&node.dir, &["invite", "--weight", "2", "--ttl", "5m"]).await;
    assert!(ok, "{out}");

    assert!(out.contains("lotusd bootstrap lotus1"), "{out}");
    assert!(out.contains("expires in 5m"), "{out}");
    let invite = Invite::decode(word(&out)).unwrap();
    assert_eq!(invite.sponsor, node.id);
    assert_eq!(invite.root, node.genesis);
}

#[tokio::test]
async fn invite_as_json_carries_the_word_and_the_ttl() {
    let network = TestNetwork::new();
    let node = Node::start(Some(&network)).await;

    let (ok, out, _) = run(&node.dir, &["--format", "json", "invite", "--ttl", "90s"]).await;
    assert!(ok, "{out}");

    let json: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["expires_in_millis"], 90_000);
    Invite::decode(json["invite"].as_str().unwrap()).unwrap();
}

#[tokio::test]
async fn invite_fails_on_a_node_serving_no_peers() {
    let node = Node::start(None).await;

    let (ok, out, err) = run(&node.dir, &["invite"]).await;

    assert!(!ok, "{out}");
    assert!(err.contains("serves no peers"), "{err}");
}
