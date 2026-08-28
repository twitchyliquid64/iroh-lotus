//! Two real daemons syncing over an in-memory pipe: the full stack —
//! actor, storage, framing — with only the network swapped out.

use std::path::Path;

use lotusd::{
    Core, IfInitialized, Server, ServerHandle,
    sync_driver::{self, SyncError},
};
use sync::{Message, PullOutcome, ServeOutcome};
use tempfile::TempDir;
use tokio::{io::AsyncWriteExt, net::UnixListener};
use tokio_util::{bytes::BytesMut, codec::Encoder};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

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

/// Starts a server over the cluster state in `dir`.
async fn serve_dir(dir: &TempDir) -> ServerHandle {
    let core = Core::init_with_state_dir(dir.path().to_path_buf())
        .await
        .unwrap();
    // Short name on purpose: a unix socket path has to fit in SUN_LEN.
    let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    let (handle, _join) = Server::new(core, listener).unwrap().run().await;
    handle
}

/// `n` running nodes of one cluster, alongside its genesis head.
async fn cluster(n: usize) -> (Vec<TempDir>, EnvelopeDigest, Vec<ServerHandle>) {
    let dirs: Vec<TempDir> = (0..n).map(|_| TempDir::new().unwrap()).collect();

    let genesis = {
        let core = Core::create_in_state_dir(dirs[0].path().to_path_buf(), IfInitialized::Fail)
            .await
            .unwrap();
        core.head()
        // The core drops here, closing its store before the copies.
    };
    for dir in &dirs[1..] {
        copy_state_dir(dirs[0].path(), dir.path());
    }

    let mut handles = Vec::with_capacity(n);
    for dir in &dirs {
        handles.push(serve_dir(dir).await);
    }
    (dirs, genesis, handles)
}

/// Two running nodes of one cluster, alongside its genesis head.
async fn cluster_pair() -> (TempDir, TempDir, EnvelopeDigest, ServerHandle, ServerHandle) {
    let (mut dirs, genesis, mut handles) = cluster(2).await;
    let (dir_b, dir_a) = (dirs.pop().unwrap(), dirs.pop().unwrap());
    let (b, a) = (handles.pop().unwrap(), handles.pop().unwrap());
    (dir_a, dir_b, genesis, a, b)
}

/// One sync session between two nodes over a pipe: `puller` pulls from
/// `server`, both driver ends running concurrently.
async fn sync_once(
    puller: &ServerHandle,
    server: &ServerHandle,
) -> (
    Result<PullOutcome, SyncError>,
    Result<ServeOutcome, SyncError>,
) {
    let (pull_end, serve_end) = tokio::io::duplex(64 * 1024);
    tokio::join!(
        sync_driver::pull(pull_end, puller),
        sync_driver::serve(serve_end, server),
    )
}

#[tokio::test]
async fn a_behind_node_pulls_the_missing_suffix() {
    let (_da, _db, genesis, a, b) = cluster_pair().await;
    a.insert(run_of(genesis, "a", 3)).await.unwrap();

    let (pulled, served) = sync_once(&b, &a).await;

    let head = a.head().await.unwrap();
    assert_eq!(pulled.unwrap(), PullOutcome::Synced { head, ingested: 3 });
    assert_eq!(served.unwrap(), ServeOutcome::Served { head, sent: 3 });
    assert_eq!(b.head().await.unwrap(), head);
}

/// The most common session of all: nothing to do. The puller learns as
/// much from `Hello` and hangs up, which the serving side reports as the
/// routine `PeerClosed`.
#[tokio::test]
async fn an_identical_pair_parts_at_hello() {
    let (_da, _db, _genesis, a, b) = cluster_pair().await;

    let (pulled, served) = sync_once(&b, &a).await;

    assert_eq!(pulled.unwrap(), PullOutcome::AlreadyCurrent);
    assert!(matches!(served, Err(SyncError::PeerClosed)));
}

/// Partition heal: both nodes extended the same parent apart; after each
/// pulls the other, fork choice lands both on the same head.
#[tokio::test]
async fn forked_nodes_converge_after_pulling_each_other() {
    let (_da, _db, genesis, a, b) = cluster_pair().await;
    a.insert([set_ns(genesis, "a", "ours")]).await.unwrap();
    b.insert([set_ns(genesis, "b", "theirs")]).await.unwrap();

    let (pulled, _) = sync_once(&b, &a).await;
    assert!(matches!(pulled, Ok(PullOutcome::Synced { .. })));
    // Whether the reverse pull fetches anything depends on which branch
    // won the first fork — when ours did, b's head is already ours and
    // the pull is a no-op. Either way it must succeed and converge.
    let (pulled, _) = sync_once(&a, &b).await;
    pulled.unwrap();

    let head = a.head().await.unwrap();
    assert_eq!(b.head().await.unwrap(), head);
    let winner = [set_ns(genesis, "a", "ours"), set_ns(genesis, "b", "theirs")]
        .into_iter()
        .map(|envelope| envelope.digest().unwrap())
        .max()
        .unwrap();
    assert_eq!(head, winner, "the higher digest wins the fork");
}

/// A second pull right after converging is a no-op.
#[tokio::test]
async fn a_second_pull_is_already_current() {
    let (_da, _db, genesis, a, b) = cluster_pair().await;
    a.insert(run_of(genesis, "a", 2)).await.unwrap();

    let (pulled, _) = sync_once(&b, &a).await;
    assert!(matches!(pulled, Ok(PullOutcome::Synced { .. })));
    let (pulled, _) = sync_once(&b, &a).await;
    assert_eq!(pulled.unwrap(), PullOutcome::AlreadyCurrent);
}

/// Sync is transitive: a change relays hop by hop through a node that
/// never talks to the writer — in both directions. The epidemic step the
/// convergence argument rests on.
#[tokio::test]
async fn a_change_relays_through_a_middle_node() {
    let (_dirs, genesis, handles) = cluster(3).await;
    let [one, two, three]: [ServerHandle; 3] = handles.try_into().unwrap();

    // Written at one end, pulled hop by hop to the other…
    one.insert([set_ns(genesis, "a", "forward")]).await.unwrap();
    let head = one.head().await.unwrap();

    let (pulled, _) = sync_once(&two, &one).await;
    assert!(matches!(
        pulled,
        Ok(PullOutcome::Synced { head: at, ingested: 1 }) if at == head
    ));
    let (pulled, _) = sync_once(&three, &two).await;
    assert!(matches!(
        pulled,
        Ok(PullOutcome::Synced { head: at, ingested: 1 }) if at == head
    ));
    assert_eq!(two.head().await.unwrap(), head);
    assert_eq!(three.head().await.unwrap(), head);

    // …and a write at the far end relays back the other way.
    three.insert([set_ns(head, "a", "backward")]).await.unwrap();
    let head = three.head().await.unwrap();

    let (pulled, _) = sync_once(&two, &three).await;
    assert!(matches!(
        pulled,
        Ok(PullOutcome::Synced { head: at, ingested: 1 }) if at == head
    ));
    let (pulled, _) = sync_once(&one, &two).await;
    assert!(matches!(
        pulled,
        Ok(PullOutcome::Synced { head: at, ingested: 1 }) if at == head
    ));
    assert_eq!(one.head().await.unwrap(), head);
    assert_eq!(two.head().await.unwrap(), head);
    assert_eq!(three.head().await.unwrap(), head);
}

/// A peer claiming an impossible frame length is refused before a byte
/// of its body is read.
#[tokio::test]
async fn an_oversized_frame_claim_fails_the_session() {
    let (_da, _db, _genesis, _a, b) = cluster_pair().await;

    let (pull_end, mut peer) = tokio::io::duplex(64 * 1024);
    // `peer` stays open in this scope: the failure must come from the
    // claim, not a close.
    let pulled = tokio::join!(sync_driver::pull(pull_end, &b), async {
        peer.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    })
    .0;

    assert!(matches!(pulled, Err(SyncError::Frame(_))));
}

/// A peer speaking another protocol version is a breach at `Hello`.
#[tokio::test]
async fn a_version_mismatch_is_a_breach() {
    let (_da, _db, _genesis, _a, b) = cluster_pair().await;
    let head = b.head().await.unwrap();

    let (pull_end, mut peer) = tokio::io::duplex(64 * 1024);
    let pulled = tokio::join!(sync_driver::pull(pull_end, &b), async {
        let mut frame = BytesMut::new();
        sync::Codec
            .encode(
                Message::Hello(sync::Hello { version: 999, head }),
                &mut frame,
            )
            .unwrap();
        peer.write_all(&frame).await.unwrap();
    })
    .0;

    assert!(matches!(
        pulled,
        Err(SyncError::Breach(sync::Breach::Version { theirs: 999, .. }))
    ));
}

/// A peer that hangs up mid-frame is truncated, not merely closed.
#[tokio::test]
async fn a_close_mid_frame_is_truncated() {
    let (_da, _db, _genesis, _a, b) = cluster_pair().await;

    let (pull_end, mut peer) = tokio::io::duplex(64 * 1024);
    let pulled = tokio::join!(sync_driver::pull(pull_end, &b), async {
        // A frame claiming 100 bytes, then a half-close: EOF lands
        // mid-frame while the puller's own writes still have somewhere
        // to go — a full drop could break its `Hello` write first.
        peer.write_all(&100u32.to_be_bytes()).await.unwrap();
        peer.shutdown().await.unwrap();
    })
    .0;

    assert!(matches!(pulled, Err(SyncError::Truncated)));
}
