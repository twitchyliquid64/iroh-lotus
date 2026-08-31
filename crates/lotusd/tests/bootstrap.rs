//! Joining a cluster from a blank state directory, end to end over real
//! iroh endpoints on an in-memory network: the invite issued on a running
//! node, the pull, the admission, and the node serving afterwards.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
    path::PathBuf,
    time::Duration,
};

use iroh::{Endpoint, RelayMode, endpoint::presets, test_utils::test_transport::TestNetwork};
use lotusd::{
    Core, IfInitialized, NodeKeys, Server, ServerHandle, WeakWrite,
    bootstrap::{self, InviteError, JoinError, Joined},
    invite::{Invite, Token},
    peer_ingress::Protocol,
};
use lotusd_rpc::WeakSet;
use state::MIN_ENVELOPE_WEIGHT_KEY;
use storage::StoredAt;
use tempfile::TempDir;
use tokio::{net::UnixListener, task::JoinHandle, time::timeout};
use wire::{
    Envelope, EnvelopeDigest, KeyId, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

/// How long a step gets before we call it hung. Generous: this bounds a
/// test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(10);

/// An endpoint on `network` under `secret`, bound as the daemon binds
/// its own: no sockets, no relay, the network's own address lookup.
async fn endpoint(network: &TestNetwork, secret: iroh::SecretKey) -> Endpoint {
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
    _join: JoinHandle<()>,
    id: KeyId,
    /// The key it signs the envelopes these tests write with.
    keys: NodeKeys,
    _dir: TempDir,
}

impl Node {
    /// Starts a server over `core`, serving peers on `endpoint` if given.
    async fn start(dir: TempDir, core: Core, endpoint: Option<Endpoint>) -> Self {
        let id = core.key_id();
        let keys = core.keys().clone();
        // Short name on purpose: a unix socket path has to fit in SUN_LEN.
        let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
        let server = Server::new(core, listener).unwrap();
        let server = match &endpoint {
            Some(endpoint) => server.with_endpoint(endpoint.clone()),
            None => server,
        };
        let (handle, join) = server.run().await;
        Node {
            handle,
            _join: join,
            id,
            keys,
            _dir: dir,
        }
    }

    /// A fresh single-node cluster on `network`.
    async fn founder(network: &TestNetwork) -> Self {
        let dir = TempDir::new().unwrap();
        let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
            .await
            .unwrap();
        let endpoint = endpoint(network, core.iroh_secret().clone()).await;
        Self::start(dir, core, Some(endpoint)).await
    }

    /// Extends this node's chain by one envelope, returning the new head.
    async fn extend(&self, label: &str) -> EnvelopeDigest {
        let prev = self.handle.head().await.unwrap();
        let envelope = self.sign(Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: NamespaceKey::try_new(label).unwrap(),
            namespace: Namespace {
                value: Value::String("v".to_owned()),
            },
        })));
        let head = envelope.digest().unwrap();
        self.handle.insert([envelope]).await.unwrap();
        head
    }

    /// The node's signature over `envelope`: the chain takes no envelope
    /// without one.
    fn sign(&self, envelope: Envelope) -> Envelope {
        self.keys.sign(envelope).unwrap()
    }

    /// Writes `label` signed by this node's own key.
    async fn write(&self, label: &str) -> EnvelopeDigest {
        self.handle
            .weak_write(WeakWrite::Set(WeakSet {
                key: NamespaceKey::try_new(label).unwrap(),
                path: None,
                value: Value::Int(1),
            }))
            .await
            .unwrap()
            .digest
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

    async fn invite(&self, weight: u32) -> Invite {
        self.handle
            .create_invite(weight, Duration::from_secs(600))
            .await
            .unwrap()
            .invite
    }
}

/// A blank node with its keys laid down and its endpoint on `network`,
/// ready to join.
struct Blank {
    dir: TempDir,
    keys: NodeKeys,
    endpoint: Endpoint,
}

impl Blank {
    async fn new(network: &TestNetwork) -> Self {
        let dir = TempDir::new().unwrap();
        let keys = Core::prepare_join(dir.path().to_path_buf(), IfInitialized::Fail)
            .await
            .unwrap();
        let endpoint = endpoint(network, keys.iroh_secret().clone()).await;
        Self {
            dir,
            keys,
            endpoint,
        }
    }

    fn state_dir(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    async fn join(&self, invite: &Invite) -> Result<Joined, JoinError> {
        timeout(
            GRACE,
            bootstrap::join(self.state_dir(), &self.keys, invite, &self.endpoint),
        )
        .await
        .expect("the join did not finish")
    }
}

/// A sponsor that compacted its `Init` away still takes a joiner: the
/// invite pins the cut, and the welcome carries the checkpoint the pruned
/// history folded down to.
#[tokio::test]
async fn a_blank_node_joins_a_compacted_sponsor() {
    let network = TestNetwork::new();
    let dir = TempDir::new().unwrap();
    let mut core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    for label in ["one", "two", "three", "four"] {
        core.sign_write(|prev| {
            Msg::SetNamespace(SetNamespace {
                prev,
                key: NamespaceKey::try_new(label).unwrap(),
                namespace: Namespace {
                    value: Value::String("v".to_owned()),
                },
            })
        })
        .unwrap();
    }
    // Compact the `Init` away: only the two newest envelopes stay. The
    // cutoff is far future so the test needn't wait out the real floor.
    let compacted = core
        .compact_before(
            StoredAt::from_timestamp_millis(4_102_444_800_000),
            NonZeroU32::new(2).unwrap(),
            1,
            &BTreeSet::new(),
        )
        .await
        .unwrap();
    assert!(compacted.pruned > 0, "the fixture must actually compact");
    let endpoint = endpoint(&network, core.iroh_secret().clone()).await;
    let a = Node::start(dir, core, Some(endpoint)).await;

    let invite = a.invite(3).await;
    assert_eq!(invite.root, a.handle.root().await.unwrap());

    let b = Blank::new(&network).await;
    let joined = b.join(&invite).await.unwrap();

    assert_eq!(joined.core.root(), invite.root);
    assert_eq!(joined.core.head(), a.handle.head().await.unwrap());
    let trusted = joined.core.trusted_keys().unwrap();
    assert_eq!(trusted[&b.keys.key_id()].weight(), 3);
}

#[tokio::test]
async fn a_blank_node_joins_and_is_admitted() {
    let network = TestNetwork::new();
    let a = Node::founder(&network).await;
    a.extend("early").await;
    let head = a.extend("later").await;
    let invite = a.invite(3).await;
    assert_eq!(invite.sponsor, a.id);
    assert_eq!(invite.root, a.handle.root().await.unwrap());

    let b = Blank::new(&network).await;
    let joined = b.join(&invite).await.unwrap();

    // The admission moved the sponsor's head past `head`; b stands there.
    let admitted_head = a.handle.head().await.unwrap();
    assert_ne!(admitted_head, head);
    assert_eq!(joined.core.head(), admitted_head);
    assert_eq!(joined.core.root(), invite.root);
    assert!(joined.core.contains(joined.admitted).unwrap());

    let trusted = joined.core.trusted_keys().unwrap();
    assert_eq!(trusted[&b.keys.key_id()].weight(), 3);
    assert!(trusted.contains_key(&a.id));
    let nodes = joined.core.peer_addresses().unwrap();
    assert_eq!(nodes[&b.keys.key_id()].id, b.endpoint.id());
}

/// Once joined, the node is an ordinary member: the sponsor dials it off
/// the listing, changes flow both ways, and what it signs is trusted.
#[tokio::test]
async fn a_joined_node_serves_as_a_member() {
    let network = TestNetwork::new();
    let a = Node::founder(&network).await;
    let invite = a.invite(1).await;
    let blank = Blank::new(&network).await;
    let joined = blank.join(&invite).await.unwrap();

    let Blank { dir, endpoint, .. } = blank;
    let b = Node::start(dir, joined.core, Some(endpoint)).await;

    let from_a = a.extend("by-a").await;
    b.wait_for_head(from_a).await;

    let from_b = b.write("by-b").await;
    a.wait_for_head(from_b).await;
    let (_, entry) = a
        .handle
        .envelopes(lotusd_rpc::EnvelopeSelector::Digests(vec![from_b]))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        entry.envelope.verified_signers(),
        1,
        "b's signature verifies on a"
    );
}

#[tokio::test]
async fn an_invite_admits_one_node_only() {
    let network = TestNetwork::new();
    let a = Node::founder(&network).await;
    let invite = a.invite(1).await;

    Blank::new(&network).await.join(&invite).await.unwrap();
    let again = Blank::new(&network).await.join(&invite).await;

    assert!(
        matches!(&again, Err(JoinError::Refused(reason)) if reason.contains("used already")),
        "{again:?}"
    );
}

#[tokio::test]
async fn a_forged_token_is_refused_and_admits_nothing() {
    let network = TestNetwork::new();
    let a = Node::founder(&network).await;
    let head = a.handle.head().await.unwrap();
    let mut invite = a.invite(1).await;
    invite.token = Token::from_bytes([0; 32]);

    let b = Blank::new(&network).await;
    let refused = b.join(&invite).await;

    assert!(matches!(refused, Err(JoinError::Refused(_))), "{refused:?}");
    assert_eq!(a.handle.head().await.unwrap(), head, "nothing was written");
    assert!(
        !a.handle
            .peer_addresses()
            .await
            .unwrap()
            .contains_key(&b.keys.key_id())
    );
}

#[tokio::test]
async fn an_expired_invite_is_refused() {
    let network = TestNetwork::new();
    let a = Node::founder(&network).await;
    let invite = a
        .handle
        .create_invite(1, Duration::ZERO)
        .await
        .unwrap()
        .invite;

    let refused = Blank::new(&network).await.join(&invite).await;

    assert!(
        matches!(&refused, Err(JoinError::Refused(reason)) if reason.contains("expired")),
        "{refused:?}"
    );
}

/// The invite pins the root; a sponsor handing over any other chain is
/// caught before a byte of it is stored.
#[tokio::test]
async fn a_root_other_than_the_pinned_one_is_refused_by_the_joiner() {
    let network = TestNetwork::new();
    let a = Node::founder(&network).await;
    let mut invite = a.invite(1).await;
    invite.root = EnvelopeDigest::from_bytes([9; 32]);

    let b = Blank::new(&network).await;
    let refused = b.join(&invite).await;

    assert!(
        matches!(refused, Err(JoinError::RootMismatch { .. })),
        "{refused:?}"
    );
    assert!(
        !b.dir.path().join(lotusd::OLDEST_ENVELOPE_FILENAME).exists(),
        "the state dir stays uninitialized"
    );
}

#[tokio::test]
async fn a_node_serving_no_peers_cannot_invite() {
    let dir = TempDir::new().unwrap();
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let node = Node::start(dir, core, None).await;

    let refused = node.handle.create_invite(1, Duration::from_secs(60)).await;

    assert!(
        matches!(refused, Err(InviteError::NoEndpoint)),
        "{refused:?}"
    );
}

/// An admission is one node's signature; a ledger that demands more than
/// this node's key carries refuses the invite before anyone pulls.
#[tokio::test]
async fn a_node_that_cannot_sign_alone_cannot_invite() {
    let network = TestNetwork::new();
    let a = Node::founder(&network).await;
    let prev = a.handle.head().await.unwrap();
    a.handle
        .insert([a.sign(Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: NamespaceKey::try_new(MIN_ENVELOPE_WEIGHT_KEY).unwrap(),
            namespace: Namespace {
                // The founding key weighs 2.
                value: Value::Int(5),
            },
        })))])
        .await
        .unwrap();

    let refused = a.handle.create_invite(1, Duration::from_secs(60)).await;

    assert!(
        matches!(refused, Err(InviteError::CannotSignAlone(_))),
        "{refused:?}"
    );
}

/// The invite survives its text form: what the sponsor issues is what
/// `lotusd bootstrap` reads back off the command line.
#[tokio::test]
async fn an_invite_joins_from_its_text_form() {
    let network = TestNetwork::new();
    let a = Node::founder(&network).await;
    let text = a.invite(1).await.encode().unwrap();

    let invite = Invite::decode(&text).unwrap();
    let joined = Blank::new(&network).await.join(&invite).await.unwrap();

    assert_eq!(joined.core.head(), a.handle.head().await.unwrap());
}

#[tokio::test]
async fn a_prepared_join_can_be_retried_after_a_failure() {
    let network = TestNetwork::new();
    let a = Node::founder(&network).await;
    let bad = {
        let mut invite = a.invite(1).await;
        invite.token = Token::from_bytes([0; 32]);
        invite
    };
    let dir = TempDir::new().unwrap();
    let keys = Core::prepare_join(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let ep = endpoint(&network, keys.iroh_secret().clone()).await;
    assert!(
        bootstrap::join(dir.path().to_path_buf(), &keys, &bad, &ep)
            .await
            .is_err()
    );

    // Fresh keys, same directory: nothing from the failed attempt is in
    // the way.
    let keys = Core::prepare_join(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    ep.close().await;
    let ep = endpoint(&network, keys.iroh_secret().clone()).await;
    let good = a.invite(1).await;
    let joined = bootstrap::join(dir.path().to_path_buf(), &keys, &good, &ep)
        .await
        .unwrap();
    assert_eq!(joined.core.key_id(), keys.key_id());
    let _: BTreeMap<KeyId, _> = joined.core.peer_addresses().unwrap();
}
