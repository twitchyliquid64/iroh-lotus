//! The client, driven end to end over a real control socket against a
//! real daemon holding a real chain.

use std::time::Duration;

use lotus_sdk::{
    Client, EnvelopeDigest, GetEnvelopes, NamespaceChange, NamespaceKey, QueryKind, Shape,
    SubkeyPath, Value, ValueMeta, WatchEvent, WatchSelector, WriteOutcome,
};
use lotusd::{Core, IfInitialized, Server, ServerHandle};
use tempfile::TempDir;
use tokio::{net::UnixListener, task::JoinHandle, time::timeout};
use tokio_stream::StreamExt;

/// How long a step gets before we call it hung. Generous: this bounds a
/// test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(20);

/// A daemon on a fresh state dir, and a client at its socket.
struct Node {
    // Held so the socket outlives the test.
    _dir: TempDir,
    genesis: EnvelopeDigest,
    client: Client,
    // Both held so the mainloop outlives the test: the server stops when
    // its last handle drops.
    _handle: ServerHandle,
    _join: JoinHandle<()>,
}

async fn node() -> Node {
    let dir = TempDir::new().unwrap();
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let genesis = core.head();

    let listener = UnixListener::bind(lotus_sdk::socket_in(dir.path())).unwrap();
    let (handle, join) = Server::new(core, listener).unwrap().run().await;

    Node {
        client: Client::in_state_dir(dir.path()),
        _dir: dir,
        genesis,
        _handle: handle,
        _join: join,
    }
}

fn key(text: &str) -> NamespaceKey {
    NamespaceKey::try_new(text).unwrap()
}

fn path(text: &str) -> SubkeyPath {
    text.parse().unwrap()
}

#[tokio::test]
async fn version_and_status_come_from_the_daemon() {
    let node = node().await;

    assert_eq!(node.client.version().await.unwrap(), lotusd::VERSION);

    let status = node.client.status().await.unwrap();
    assert_eq!(status.chain.head, node.genesis);
    assert_eq!(status.chain.root, node.genesis);
    assert!(status.endpoint.is_none(), "the test daemon has no endpoint");
}

#[tokio::test]
async fn a_write_is_read_back_at_the_head_it_made() {
    let node = node().await;
    let cfg = key("cfg");

    let written = node
        .client
        .set(
            cfg.clone(),
            None,
            Value::from_iter([("host", "a.example"), ("port", "443")]),
        )
        .await
        .unwrap();
    assert_eq!(written.outcome, WriteOutcome::Extended);
    assert_ne!(written.head, node.genesis);

    let at = node.client.read(cfg.clone(), path("host")).await.unwrap();
    assert_eq!(at.head, written.head);
    assert_eq!(at.value, Some(Value::from("a.example")));

    let written = node
        .client
        .set(cfg.clone(), path("host"), "b.example")
        .await
        .unwrap();
    let at = node.client.read(cfg, None).await.unwrap();
    assert_eq!(at.head, written.head);
    assert_eq!(
        at.value,
        Some(Value::from_iter([("host", "b.example"), ("port", "443")]))
    );
}

#[tokio::test]
async fn a_query_describes_a_value_without_carrying_it() {
    let node = node().await;
    let cfg = key("cfg");
    node.client
        .set(cfg.clone(), None, Value::from_iter([("a", 1i64), ("b", 2)]))
        .await
        .unwrap();

    let queried = node
        .client
        .query(cfg.clone(), None, QueryKind::Keys)
        .await
        .unwrap();
    let meta = queried.meta.expect("the namespace is held");
    assert_eq!(meta.shape(), Shape::Map);
    assert_eq!(meta.entries(), Some(2));
    let ValueMeta::Map(map) = meta else {
        panic!("a map, not {meta:?}");
    };
    assert_eq!(map.keys, Some(vec!["a".to_string(), "b".to_string()]));

    let listing = node.client.list_namespaces().await.unwrap();
    assert!(
        listing
            .namespaces
            .iter()
            .any(|entry| entry.key == cfg && entry.shape == Shape::Map)
    );
}

#[tokio::test]
async fn a_write_the_chain_refuses_is_rejected() {
    let node = node().await;

    // A path into a namespace the ledger does not hold.
    let err = node
        .client
        .set(key("cfg"), path("port"), 443i64)
        .await
        .unwrap_err();
    assert!(err.is_rejected(), "got {err:?}");
    assert!(err.failure().is_some());
    assert!(!err.is_daemon_unreachable());

    let range = node.client.chain_range().await.unwrap();
    assert_eq!(range.head, node.genesis, "the head stays put");
}

#[tokio::test]
async fn a_watch_sees_a_write_made_after_it_opened() {
    let node = node().await;
    let cfg = key("cfg");

    let mut watch = node
        .client
        .watch(WatchSelector::Namespace(cfg.clone()))
        .await
        .unwrap();
    // Unrelated to the watch; it must not be reported.
    node.client.set(key("other"), None, "x").await.unwrap();
    let written = node.client.set(cfg.clone(), None, "hello").await.unwrap();

    let event = timeout(GRACE, watch.next())
        .await
        .expect("an event arrives")
        .unwrap()
        .expect("the stream is open");
    let WatchEvent::Changed(changed) = event else {
        panic!("a change, not {event:?}");
    };
    assert_eq!(changed.head, written.head);
    assert_eq!(changed.changes.get(&cfg), Some(&NamespaceChange::Whole));

    // The same stream through the `Stream` trait.
    let written = node.client.set(cfg.clone(), None, "again").await.unwrap();
    let event = timeout(GRACE, StreamExt::next(&mut watch))
        .await
        .expect("an event arrives")
        .expect("the stream is open")
        .unwrap();
    let WatchEvent::Changed(changed) = event else {
        panic!("a change, not {event:?}");
    };
    assert_eq!(changed.head, written.head);
}

#[tokio::test]
async fn envelopes_stream_the_chain_oldest_first() {
    let node = node().await;
    let written = node.client.set(key("cfg"), None, "hello").await.unwrap();

    let frames = node
        .client
        .envelopes(GetEnvelopes::chain())
        .await
        .unwrap()
        .collect()
        .await
        .unwrap();
    let digests: Vec<_> = frames.iter().map(|frame| frame.digest).collect();
    assert_eq!(digests, vec![node.genesis, written.digest]);

    let newest = node
        .client
        .envelopes(GetEnvelopes::newest(1))
        .await
        .unwrap()
        .collect()
        .await
        .unwrap();
    assert_eq!(newest.len(), 1);
    assert_eq!(newest[0].digest, written.digest);
}

#[tokio::test]
async fn a_missing_daemon_is_told_apart() {
    let dir = TempDir::new().unwrap();

    // No socket at all.
    let err = Client::in_state_dir(dir.path())
        .version()
        .await
        .unwrap_err();
    assert!(err.is_daemon_unreachable(), "got {err:?}");
    assert!(err.failure().is_none());

    // A socket file a daemon left behind.
    drop(UnixListener::bind(lotus_sdk::socket_in(dir.path())).unwrap());
    let err = Client::in_state_dir(dir.path())
        .version()
        .await
        .unwrap_err();
    assert!(err.is_daemon_unreachable(), "got {err:?}");
}
