//! Compaction through the core and the server: pruning, the retention
//! floor, restarts, and a joiner adopting a compacted root.

use std::{collections::BTreeSet, num::NonZeroU32, path::Path};

use lotusd::{Core, IfInitialized, Server};
use storage::StoredAt;
use tempfile::TempDir;
use tokio::net::UnixListener;
use wire::{
    EnvelopeDigest, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

const KEEP_TWO: NonZeroU32 = NonZeroU32::new(2).unwrap();

/// A cutoff far past anything a test stores, so only the count clause
/// holds envelopes — how a test compacts without waiting out the ledger's
/// five-day floor.
fn far_future() -> Option<StoredAt> {
    // 2100-01-01, comfortably inside the range a datetime holds.
    StoredAt::from_timestamp_millis(4_102_444_800_000)
}

/// A fresh single-node cluster in `dir`, its chain extended by `labels`.
async fn cluster(dir: &Path, labels: &[&str]) -> Core {
    let mut core = Core::create_in_state_dir(dir.to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    for label in labels {
        write(&mut core, label);
    }
    core
}

/// One signed whole-namespace write, returning its digest.
fn write(core: &mut Core, label: &str) -> EnvelopeDigest {
    let (digest, _) = core
        .sign_write(|prev| {
            Msg::SetNamespace(SetNamespace {
                prev,
                key: NamespaceKey::try_new(label).unwrap(),
                namespace: Namespace {
                    value: Value::String("v".to_owned()),
                },
            })
        })
        .unwrap();
    digest
}

/// The canonical digests this core still holds, oldest first.
fn held(core: &Core) -> Vec<EnvelopeDigest> {
    core.canonical_chain(None, None)
        .unwrap()
        .into_iter()
        .map(|(digest, _)| digest)
        .collect()
}

#[tokio::test]
async fn compaction_prunes_and_survives_a_restart() {
    let dir = TempDir::new().unwrap();
    let mut core = cluster(dir.path(), &["a", "b", "c", "d"]).await;
    let before = held(&core);
    assert_eq!(before.len(), 5, "the genesis and four writes");

    let compacted = core
        .compact_before(far_future(), KEEP_TWO, 1, &BTreeSet::new())
        .await
        .unwrap();

    assert_eq!(compacted.pruned, 3);
    assert_eq!(compacted.to, before[3], "the cut is the second-newest");
    assert_eq!(core.root(), before[3]);
    assert_eq!(held(&core), &before[3..]);
    // The pruned envelopes are gone from the log, not merely off the walk.
    assert!(core.envelopes(before[..3].to_vec()).unwrap().is_empty());

    // A restart reopens at the cut and keeps advancing.
    let head = core.head();
    drop(core);
    let mut reopened = Core::init_with_state_dir(dir.path().to_path_buf())
        .await
        .unwrap();
    assert_eq!(reopened.head(), head);
    assert_eq!(reopened.root(), before[3]);
    let next = write(&mut reopened, "e");
    assert_eq!(reopened.head(), next);
}

#[tokio::test]
async fn compaction_defers_below_the_min_prune_threshold() {
    let dir = TempDir::new().unwrap();
    let mut core = cluster(dir.path(), &["a", "b", "c", "d"]).await;
    let root = core.root();

    let compacted = core
        .compact_before(far_future(), KEEP_TWO, 100, &BTreeSet::new())
        .await
        .unwrap();

    assert_eq!(compacted.pruned, 0);
    assert_eq!((compacted.from, compacted.to), (root, root));
    assert_eq!(core.root(), root);
}

/// The real policy: everything here was stored moments ago, so the
/// ledger's five-day floor holds every envelope however small the count
/// knob is.
#[tokio::test]
async fn the_ledger_floor_holds_fresh_envelopes() {
    let dir = TempDir::new().unwrap();
    let mut core = cluster(dir.path(), &["a", "b", "c", "d"]).await;
    let root = core.root();

    let compacted = core
        .compact(NonZeroU32::MIN, 1, &BTreeSet::new())
        .await
        .unwrap();

    assert_eq!(compacted.pruned, 0);
    assert_eq!(core.root(), root);
}

#[tokio::test]
async fn a_pinned_root_is_not_pruned_past() {
    let dir = TempDir::new().unwrap();
    let mut core = cluster(dir.path(), &["a", "b", "c", "d"]).await;
    let pinned = core.root();

    let compacted = core
        .compact_before(far_future(), KEEP_TWO, 1, &BTreeSet::from([pinned]))
        .await
        .unwrap();

    assert_eq!(compacted.pruned, 0);
    assert_eq!(core.root(), pinned);
}

/// A full daemon comes up over compacted on-disk state: the server
/// starts from the reopened core, reports the moved root, and still
/// takes writes.
#[tokio::test]
async fn a_server_starts_from_compacted_state_on_disk() {
    let dir = TempDir::new().unwrap();
    let mut core = cluster(dir.path(), &["a", "b", "c", "d"]).await;
    let compacted = core
        .compact_before(far_future(), KEEP_TWO, 1, &BTreeSet::new())
        .await
        .unwrap();
    assert!(compacted.pruned > 0, "the fixture must actually compact");
    let head = core.head();
    drop(core); // closes the store; the server below starts from disk

    let reopened = Core::init_with_state_dir(dir.path().to_path_buf())
        .await
        .unwrap();
    let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    let (handle, _join) = Server::new(reopened, listener).unwrap().run().await;

    let range = handle.chain_range().await.unwrap();
    assert_eq!(range.root, compacted.to);
    assert_eq!(range.head, head);

    // Still a working node: a write lands and moves the head.
    let written = handle
        .weak_write(lotusd::WeakWrite::Set(lotusd_rpc::WeakSet {
            key: NamespaceKey::try_new("e").unwrap(),
            path: None,
            value: Value::String("v".to_owned()),
        }))
        .await
        .unwrap();
    assert_eq!(handle.head().await.unwrap(), written.digest);
    handle.shutdown().await.unwrap();
}

/// The plumbing end to end: `lotusctl compact` reaches the core through
/// the server actor and reports the move — nothing here, with every
/// envelope inside the ledger's floor.
#[tokio::test]
async fn compact_over_the_server_handle() {
    let dir = TempDir::new().unwrap();
    let core = cluster(dir.path(), &["a", "b"]).await;
    let root = core.root();

    let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    let (handle, _join) = Server::new(core, listener).unwrap().run().await;

    let compacted = handle.compact().await.unwrap();
    assert_eq!(compacted.pruned, 0);
    assert_eq!((compacted.from, compacted.to), (root, root));

    let range = handle.chain_range().await.unwrap();
    assert_eq!(range.root, root);
    handle.shutdown().await.unwrap();
}

/// What bootstrap does after the sponsor compacted, minus the network:
/// the cut envelope and the checkpoint reopen the chain on a blank node,
/// and the tail syncs in as any pull would.
#[tokio::test]
async fn a_joiner_adopts_a_compacted_root() {
    let sponsor_dir = TempDir::new().unwrap();
    let mut sponsor = cluster(sponsor_dir.path(), &["a", "b", "c", "d"]).await;
    sponsor
        .compact_before(far_future(), KEEP_TWO, 1, &BTreeSet::new())
        .await
        .unwrap();

    let (root, state) = sponsor.welcome_root().unwrap();
    assert!(state.is_some(), "a compacted root travels with its state");

    let joiner_dir = TempDir::new().unwrap();
    Core::prepare_join(joiner_dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let mut joiner = Core::join_in_state_dir(joiner_dir.path().to_path_buf(), root, state)
        .await
        .unwrap();
    assert_eq!(joiner.root(), sponsor.root());

    // The pull, without the wire: the envelopes past the joiner's head.
    let tail: Vec<_> = held(&sponsor)
        .into_iter()
        .skip(1)
        .map(|digest| sponsor.envelopes([digest]).unwrap().remove(0).1.envelope)
        .collect();
    joiner.insert(tail).unwrap();
    assert_eq!(joiner.head(), sponsor.head());
}
