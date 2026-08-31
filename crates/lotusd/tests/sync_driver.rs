//! Two real daemons syncing over an in-memory pipe: the full stack —
//! actor, storage, framing — with only the network swapped out.

use std::{collections::BTreeSet, num::NonZeroU32, path::Path};

use lotusd::{
    Core, IfInitialized, NodeKeys, Server, ServerHandle,
    sync_driver::{self, SyncError},
};
use storage::StoredAt;
use sync::{Message, PullOutcome, ServeOutcome};
use tempfile::TempDir;
use tokio::{io::AsyncWriteExt, net::UnixListener};
use tokio_util::{bytes::BytesMut, codec::Encoder};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

/// A write onto `prev`, signed by the cluster's one node key — every node
/// here runs off a copy of the same state dir.
fn set_ns(keys: &NodeKeys, prev: EnvelopeDigest, k: &str, v: &str) -> Envelope {
    keys.sign(Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: NamespaceKey::try_new(k).unwrap(),
        namespace: Namespace {
            value: Value::String(v.to_string()),
        },
    })))
    .unwrap()
}

/// A linear run of `n` envelopes chaining onto `prev`.
fn run_of(keys: &NodeKeys, prev: EnvelopeDigest, label: &str, n: usize) -> Vec<Envelope> {
    let mut cursor = prev;
    (0..n)
        .map(|i| {
            let envelope = set_ns(keys, cursor, &format!("{label}{i}"), "v");
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

/// `n` running nodes of one cluster, alongside its genesis head and the
/// key every one of them signs with.
async fn cluster(n: usize) -> (Vec<TempDir>, EnvelopeDigest, NodeKeys, Vec<ServerHandle>) {
    let dirs: Vec<TempDir> = (0..n).map(|_| TempDir::new().unwrap()).collect();

    let (genesis, keys) = {
        let core = Core::create_in_state_dir(dirs[0].path().to_path_buf(), IfInitialized::Fail)
            .await
            .unwrap();
        (core.head(), core.keys().clone())
        // The core drops here, closing its store before the copies.
    };
    for dir in &dirs[1..] {
        copy_state_dir(dirs[0].path(), dir.path());
    }

    let mut handles = Vec::with_capacity(n);
    for dir in &dirs {
        handles.push(serve_dir(dir).await);
    }
    (dirs, genesis, keys, handles)
}

/// Two running nodes of one cluster, alongside its genesis head and the
/// key they sign with.
async fn cluster_pair() -> (
    TempDir,
    TempDir,
    EnvelopeDigest,
    NodeKeys,
    ServerHandle,
    ServerHandle,
) {
    let (mut dirs, genesis, keys, mut handles) = cluster(2).await;
    let (dir_b, dir_a) = (dirs.pop().unwrap(), dirs.pop().unwrap());
    let (b, a) = (handles.pop().unwrap(), handles.pop().unwrap());
    (dir_a, dir_b, genesis, keys, a, b)
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

/// A compacted node still serves a peer standing at or above its cut:
/// the shared envelope anchors the session and the pull is an ordinary
/// suffix.
#[tokio::test]
async fn a_compacted_node_serves_a_peer_above_the_horizon() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    // B copies the cluster two envelopes in; A then moves on two more
    // and compacts down to the three newest — the cut lands exactly on
    // B's head, so they still share it.
    let mut core = Core::create_in_state_dir(dir_a.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let keys = core.keys().clone();
    let genesis = core.head();
    core.insert(run_of(&keys, genesis, "s", 2)).unwrap();
    let shared = core.head();
    drop(core); // closes the store before the copy
    copy_state_dir(dir_a.path(), dir_b.path());

    let mut core = Core::init_with_state_dir(dir_a.path().to_path_buf())
        .await
        .unwrap();
    core.insert(run_of(&keys, shared, "t", 2)).unwrap();
    let compacted = core
        .compact_before(
            StoredAt::from_timestamp_millis(4_102_444_800_000),
            NonZeroU32::new(3).unwrap(),
            1,
            &BTreeSet::new(),
        )
        .await
        .unwrap();
    assert_eq!(compacted.to, shared, "the cut must land on the shared head");
    assert_eq!(compacted.pruned, 2, "the genesis and the first write go");
    let listener = UnixListener::bind(dir_a.path().join("a.sock")).unwrap();
    let (a, _join) = Server::new(core, listener).unwrap().run().await;

    let b = serve_dir(&dir_b).await;
    let (pulled, served) = sync_once(&b, &a).await;

    let head = a.head().await.unwrap();
    assert_eq!(pulled.unwrap(), PullOutcome::Synced { head, ingested: 2 });
    assert_eq!(served.unwrap(), ServeOutcome::Served { head, sent: 2 });
    assert_eq!(b.head().await.unwrap(), head);
}

/// The other direction: a compacted node pulls what it lacks from a peer
/// that moved on — its locator ends at the cut, which the peer still
/// holds, so the session anchors there.
#[tokio::test]
async fn a_compacted_node_pulls_what_it_lacks_from_a_peer() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let mut core = Core::create_in_state_dir(dir_a.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let keys = core.keys().clone();
    let genesis = core.head();
    core.insert(run_of(&keys, genesis, "s", 2)).unwrap();
    let shared = core.head();
    drop(core); // closes the store before the copy
    copy_state_dir(dir_a.path(), dir_b.path());

    // B moves on; A compacts down to its two newest and pulls.
    let b = serve_dir(&dir_b).await;
    b.insert(run_of(&keys, shared, "t", 2)).await.unwrap();

    let mut core = Core::init_with_state_dir(dir_a.path().to_path_buf())
        .await
        .unwrap();
    let compacted = core
        .compact_before(
            StoredAt::from_timestamp_millis(4_102_444_800_000),
            NonZeroU32::new(2).unwrap(),
            1,
            &BTreeSet::new(),
        )
        .await
        .unwrap();
    assert_eq!(compacted.pruned, 1, "the genesis goes");
    let listener = UnixListener::bind(dir_a.path().join("a.sock")).unwrap();
    let (a, _join) = Server::new(core, listener).unwrap().run().await;

    let (pulled, served) = sync_once(&a, &b).await;

    let head = b.head().await.unwrap();
    assert_eq!(pulled.unwrap(), PullOutcome::Synced { head, ingested: 2 });
    assert_eq!(served.unwrap(), ServeOutcome::Served { head, sent: 2 });
    assert_eq!(a.head().await.unwrap(), head);
}

/// A node that lagged past a peer's compaction horizon shares no held
/// history with it any more: the pull ends with `NoCommonHistory` on
/// both ends, and only a re-join by invite could recover it.
#[tokio::test]
async fn a_node_behind_the_horizon_cannot_pull() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    // B copies the cluster while it holds only the genesis; A then moves
    // on and compacts the genesis away — the cutoff far future so the
    // test needn't wait out the floor.
    let core = Core::create_in_state_dir(dir_a.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let genesis = core.head();
    let keys = core.keys().clone();
    drop(core); // closes the store before the copy
    copy_state_dir(dir_a.path(), dir_b.path());

    let mut core = Core::init_with_state_dir(dir_a.path().to_path_buf())
        .await
        .unwrap();
    core.insert(run_of(&keys, genesis, "a", 4)).unwrap();
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
    let listener = UnixListener::bind(dir_a.path().join("a.sock")).unwrap();
    let (a, _join) = Server::new(core, listener).unwrap().run().await;

    let b = serve_dir(&dir_b).await;
    let (pulled, served) = sync_once(&b, &a).await;

    assert_eq!(pulled.unwrap(), PullOutcome::NoCommonHistory);
    assert_eq!(served.unwrap(), ServeOutcome::NoCommonHistory);
    assert_eq!(b.head().await.unwrap(), genesis, "b stands where it stood");
}

#[tokio::test]
async fn a_behind_node_pulls_the_missing_suffix() {
    let (_da, _db, genesis, keys, a, b) = cluster_pair().await;
    a.insert(run_of(&keys, genesis, "a", 3)).await.unwrap();

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
    let (_da, _db, _genesis, _keys, a, b) = cluster_pair().await;

    let (pulled, served) = sync_once(&b, &a).await;

    assert_eq!(pulled.unwrap(), PullOutcome::AlreadyCurrent);
    assert!(matches!(served, Err(SyncError::PeerClosed)));
}

/// Partition heal: both nodes extended the same parent apart; after each
/// pulls the other, fork choice lands both on the same head.
#[tokio::test]
async fn forked_nodes_converge_after_pulling_each_other() {
    let (_da, _db, genesis, keys, a, b) = cluster_pair().await;
    a.insert([set_ns(&keys, genesis, "a", "ours")])
        .await
        .unwrap();
    b.insert([set_ns(&keys, genesis, "b", "theirs")])
        .await
        .unwrap();

    let (pulled, _) = sync_once(&b, &a).await;
    assert!(matches!(pulled, Ok(PullOutcome::Synced { .. })));
    // Whether the reverse pull fetches anything depends on which branch
    // won the first fork — when ours did, b's head is already ours and
    // the pull is a no-op. Either way it must succeed and converge.
    let (pulled, _) = sync_once(&a, &b).await;
    pulled.unwrap();

    let head = a.head().await.unwrap();
    assert_eq!(b.head().await.unwrap(), head);
    let winner = [
        set_ns(&keys, genesis, "a", "ours"),
        set_ns(&keys, genesis, "b", "theirs"),
    ]
    .into_iter()
    .map(|envelope| envelope.digest().unwrap())
    .max()
    .unwrap();
    assert_eq!(head, winner, "the higher digest wins the fork");
}

/// A second pull right after converging is a no-op.
#[tokio::test]
async fn a_second_pull_is_already_current() {
    let (_da, _db, genesis, keys, a, b) = cluster_pair().await;
    a.insert(run_of(&keys, genesis, "a", 2)).await.unwrap();

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
    let (_dirs, genesis, keys, handles) = cluster(3).await;
    let [one, two, three]: [ServerHandle; 3] = handles.try_into().unwrap();

    // Written at one end, pulled hop by hop to the other…
    one.insert([set_ns(&keys, genesis, "a", "forward")])
        .await
        .unwrap();
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
    three
        .insert([set_ns(&keys, head, "a", "backward")])
        .await
        .unwrap();
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
    let (_da, _db, _genesis, _keys, _a, b) = cluster_pair().await;

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
    let (_da, _db, _genesis, _keys, _a, b) = cluster_pair().await;
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
    let (_da, _db, _genesis, _keys, _a, b) = cluster_pair().await;

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
