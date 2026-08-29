//! A node keeping its own `cluster-nodes` listing in step with where its
//! endpoint is reachable: what `Core::advertise` writes and refuses, and
//! the daemon doing it unprompted over a real endpoint.

use std::{collections::BTreeMap, time::Duration};

use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr, endpoint::presets};
use lotusd::{Advertised, Core, IfInitialized, Server, ServerHandle, addr_publish::PublishState};
use state::{CLUSTER_NODES_KEY, MIN_ENVELOPE_WEIGHT_KEY};
use tempfile::TempDir;
use tokio::{net::UnixListener, task::JoinHandle, time::timeout};
use wire::{
    Envelope, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, SetNamespaceKey, Value},
    subkey::{Subkey, SubkeyPath},
};

/// How long a step gets before we call it hung. Generous: this bounds a
/// test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(10);

/// How long to let the daemon act on something it should ignore before
/// concluding it did.
const SETTLE: Duration = Duration::from_millis(300);

async fn core() -> (TempDir, Core) {
    let dir = TempDir::new().unwrap();
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    (dir, core)
}

fn nodes_key() -> NamespaceKey {
    NamespaceKey::try_new(CLUSTER_NODES_KEY).unwrap()
}

/// An address for this node's own endpoint with one transport on it.
fn with_transport(core: &Core, port: u16) -> EndpointAddr {
    EndpointAddr::from_parts(
        core.iroh_secret().public(),
        [TransportAddr::Ip(([10, 0, 0, 1], port).into())],
    )
}

/// The `iroh` address the ledger lists this node at, if it lists it.
fn listed(core: &Core) -> Option<EndpointAddr> {
    core.peer_addresses().unwrap().get(&core.key_id()).cloned()
}

/// This node's whole `cluster-nodes` entry.
fn own_entry(core: &Core) -> Option<Value> {
    let path = SubkeyPath::try_new(vec![Subkey::Key(
        core.key_id().to_hex().as_ref().to_owned(),
    )])
    .unwrap();
    core.read(&nodes_key(), Some(&path)).unwrap().1
}

#[tokio::test]
async fn an_address_the_ledger_already_lists_is_not_rewritten() {
    let (_dir, mut core) = core().await;
    let head = core.head();
    let listed_now = listed(&core).unwrap();

    assert_eq!(core.advertise(&listed_now).unwrap(), Advertised::Unchanged);
    assert_eq!(core.head(), head, "no envelope must be written");
}

#[tokio::test]
async fn a_moved_address_is_written_as_one_envelope() {
    let (_dir, mut core) = core().await;
    let head = core.head();
    let moved = with_transport(&core, 1);

    let Advertised::Written(digest) = core.advertise(&moved).unwrap() else {
        panic!("expected a write");
    };

    assert_eq!(core.head(), digest);
    assert_ne!(head, digest);
    assert_eq!(listed(&core), Some(moved));
}

#[tokio::test]
async fn advertising_rewrites_only_the_iroh_field() {
    let (_dir, mut core) = core().await;
    let id = core.key_id().to_hex().as_ref().to_owned();
    let path = SubkeyPath::try_new(vec![Subkey::Key(id), Subkey::Key("label".to_owned())]).unwrap();
    core.sign_write(|prev| {
        Msg::SetNamespaceKey(SetNamespaceKey {
            prev,
            key: nodes_key(),
            path,
            value: Some(Value::String("rack 3".to_owned())),
        })
    })
    .unwrap();

    core.advertise(&with_transport(&core, 2)).unwrap();

    let Some(Value::Map(entry)) = own_entry(&core) else {
        panic!("the entry must still be a map");
    };
    assert_eq!(
        entry.get("label"),
        Some(&Value::String("rack 3".to_owned()))
    );
    assert_eq!(listed(&core), Some(with_transport(&core, 2)));
}

#[tokio::test]
async fn a_delisted_node_does_not_relist_itself() {
    let (_dir, mut core) = core().await;
    core.sign_write(|prev| {
        Msg::SetNamespace(SetNamespace {
            prev,
            key: nodes_key(),
            namespace: Namespace {
                value: Value::Map(BTreeMap::new()),
            },
        })
    })
    .unwrap();
    let head = core.head();

    assert_eq!(
        core.advertise(&with_transport(&core, 3)).unwrap(),
        Advertised::NotListed
    );
    assert_eq!(core.head(), head);
    assert_eq!(listed(&core), None);
}

#[tokio::test]
async fn a_listing_under_another_endpoint_is_left_alone() {
    let (_dir, mut core) = core().await;
    let other = SecretKey::generate().public();
    let id = core.key_id().to_hex().as_ref().to_owned();
    let path = SubkeyPath::try_new(vec![Subkey::Key(id), Subkey::Key("iroh".to_owned())]).unwrap();
    core.sign_write(|prev| {
        Msg::SetNamespaceKey(SetNamespaceKey {
            prev,
            key: nodes_key(),
            path,
            value: Some(Value::try_from(&EndpointAddr::new(other)).unwrap()),
        })
    })
    .unwrap();
    let head = core.head();

    assert_eq!(
        core.advertise(&with_transport(&core, 4)).unwrap(),
        Advertised::OtherEndpoint(other)
    );
    assert_eq!(core.head(), head);
    assert_eq!(listed(&core), Some(EndpointAddr::new(other)));
}

#[tokio::test]
async fn a_node_that_cannot_sign_alone_leaves_the_listing_stale() {
    let (_dir, mut core) = core().await;
    // The founding key weighs 2; a floor above it makes any lone write
    // insufficient — including the one that would lower it back.
    core.sign_write(|prev| {
        Msg::SetNamespace(SetNamespace {
            prev,
            key: NamespaceKey::try_new(MIN_ENVELOPE_WEIGHT_KEY).unwrap(),
            namespace: Namespace {
                value: Value::Int(3),
            },
        })
    })
    .unwrap();
    let head = core.head();
    let stale = listed(&core).unwrap();

    let outcome = core.advertise(&with_transport(&core, 5)).unwrap();

    assert!(
        matches!(outcome, Advertised::CannotSign(_)),
        "got {outcome:?}"
    );
    assert_eq!(core.head(), head);
    assert_eq!(listed(&core), Some(stale));
}

/// A daemon on an endpoint bound to its own iroh key, on the loopback and
/// LAN addresses of this machine: the one setup where the endpoint reports
/// transports the genesis does not yet list.
struct Node {
    handle: ServerHandle,
    join: JoinHandle<()>,
    endpoint: Endpoint,
    id: wire::KeyId,
    _dir: TempDir,
}

impl Node {
    async fn start() -> Self {
        let (dir, core) = core().await;
        drop(core);
        let core = Core::init_with_state_dir(dir.path().to_path_buf())
            .await
            .unwrap();
        let id = core.key_id();
        // Short name on purpose: a unix socket path has to fit in SUN_LEN.
        let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(core.iroh_secret().clone())
            .relay_mode(RelayMode::Disabled)
            .alpns(lotusd::peer_ingress::Protocol::alpns())
            .bind()
            .await
            .unwrap();
        let (handle, join) = Server::new(core, listener)
            .unwrap()
            .with_endpoint(endpoint.clone())
            .with_advertise_settle(Duration::from_millis(50))
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

    /// The address the endpoint reports right now.
    fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Waits until the endpoint reports at least one transport.
    async fn wait_for_transports(&self) -> EndpointAddr {
        timeout(GRACE, async {
            loop {
                let addr = self.addr();
                if !addr.addrs.is_empty() {
                    return addr;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a local endpoint reports its interface addresses")
    }

    /// What the ledger lists this node at, if it lists it.
    async fn listed(&self) -> Option<EndpointAddr> {
        self.handle
            .peer_addresses()
            .await
            .unwrap()
            .get(&self.id)
            .cloned()
    }

    /// Waits until the ledger lists this node at `addr`.
    async fn wait_listed(&self, addr: &EndpointAddr) {
        timeout(GRACE, async {
            while self.listed().await.as_ref() != Some(addr) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for the ledger to list {addr:?}"));
    }

    /// Waits until the publisher reports `state`.
    async fn wait_state(&self, state: PublishState) {
        timeout(GRACE, async {
            while self.handle.published().await.unwrap() != Some(state.clone()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for the publisher to be {state}"));
    }

    /// Replaces this node's `cluster-nodes` with `entries`.
    async fn list(&self, entries: impl IntoIterator<Item = (wire::KeyId, EndpointAddr)>) {
        let prev = self.handle.head().await.unwrap();
        let envelope = Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: nodes_key(),
            namespace: Namespace {
                value: Value::Map(
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
                ),
            },
        }));
        self.handle.insert([envelope]).await.unwrap();
    }

    async fn stop(self) {
        self.handle.shutdown().await.unwrap();
        self.join.await.unwrap();
        self.endpoint.close().await;
    }
}

#[tokio::test]
async fn a_daemon_publishes_the_address_its_endpoint_reports() {
    let node = Node::start().await;
    let addr = node.wait_for_transports().await;

    node.wait_listed(&addr).await;
    node.wait_state(PublishState::Published).await;

    node.stop().await;
}

#[tokio::test]
async fn a_listing_rewritten_under_the_daemon_is_published_again() {
    let node = Node::start().await;
    let addr = node.wait_for_transports().await;
    node.wait_listed(&addr).await;

    node.list([(node.id, EndpointAddr::new(node.endpoint.id()))])
        .await;

    node.wait_listed(&addr).await;
    node.stop().await;
}

#[tokio::test]
async fn a_daemon_delisted_stays_delisted() {
    let node = Node::start().await;
    let addr = node.wait_for_transports().await;
    node.wait_listed(&addr).await;

    node.list([]).await;

    node.wait_state(PublishState::NotListed).await;
    tokio::time::sleep(SETTLE).await;
    assert_eq!(node.listed().await, None);
    node.stop().await;
}

#[tokio::test]
async fn a_daemon_listed_under_another_endpoint_leaves_it() {
    let node = Node::start().await;
    let addr = node.wait_for_transports().await;
    node.wait_listed(&addr).await;
    let other = EndpointAddr::new(SecretKey::generate().public());

    node.list([(node.id, other.clone())]).await;

    node.wait_state(PublishState::OtherEndpoint(other.id)).await;
    tokio::time::sleep(SETTLE).await;
    assert_eq!(node.listed().await, Some(other));
    node.stop().await;
}

#[tokio::test]
async fn a_daemon_without_an_endpoint_publishes_nothing() {
    let (dir, core) = core().await;
    let head = core.head();
    let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    let (handle, join) = Server::new(core, listener).unwrap().run().await;

    tokio::time::sleep(SETTLE).await;

    assert_eq!(handle.published().await.unwrap(), None);
    assert_eq!(handle.head().await.unwrap(), head);
    handle.shutdown().await.unwrap();
    join.await.unwrap();
}
