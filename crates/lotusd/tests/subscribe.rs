//! Advancing a core's chain must reach the subscribers watching it.

use lotusd::{ChangeFilter, Core, IfInitialized};
use state::Insert;
use tempfile::TempDir;
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, SetNamespaceKey, Value},
    subkey::{Subkey, SubkeyPath},
};

async fn core(dir: &TempDir) -> Core {
    Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap()
}

fn key(k: &str) -> NamespaceKey {
    NamespaceKey::try_new(k).unwrap()
}

fn keys(segments: &[&str]) -> SubkeyPath {
    SubkeyPath::try_new(
        segments
            .iter()
            .map(|k| Subkey::Key((*k).to_string()))
            .collect(),
    )
    .unwrap()
}

/// A namespace with two leaves, so writes inside it can miss each other.
fn pair() -> Namespace {
    Namespace {
        value: Value::Map(
            [
                ("host".to_string(), Value::String("one".to_string())),
                ("port".to_string(), Value::Int(1)),
            ]
            .into(),
        ),
    }
}

fn set_ns(prev: EnvelopeDigest, k: &str, namespace: Namespace) -> Envelope {
    Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: key(k),
        namespace,
    }))
}

fn set_key(prev: EnvelopeDigest, k: &str, path: SubkeyPath, value: Value) -> Envelope {
    Envelope::new(Msg::SetNamespaceKey(SetNamespaceKey {
        prev,
        key: key(k),
        path,
        value: Some(value),
    }))
}

#[tokio::test]
async fn inserting_notifies_a_subscriber_watching_the_namespace() {
    let dir = TempDir::new().unwrap();
    let mut core = core(&dir).await;
    let mut subscription = core.subscribe(ChangeFilter::namespace(key("a")));
    assert_eq!(subscription.opened_at(), core.head());

    let envelope = set_ns(core.head(), "a", pair());
    assert_eq!(core.insert([envelope]).unwrap(), Insert::Extended);

    let notification = subscription.next().await.unwrap();
    assert_eq!(notification.from, subscription.opened_at());
    assert_eq!(notification.head, core.head());
    assert!(notification.movement.changes.touches(&key("a"), None));
}

/// A subscriber watching one path is left alone by a write to its sibling,
/// and woken by the next write to its own.
#[tokio::test]
async fn a_path_subscriber_hears_only_about_its_own_path() {
    let dir = TempDir::new().unwrap();
    let mut core = core(&dir).await;

    let envelope = set_ns(core.head(), "a", pair());
    core.insert([envelope]).unwrap();

    let mut subscription = core.subscribe(ChangeFilter::path(key("a"), keys(&["host"])));

    let sibling = set_key(core.head(), "a", keys(&["port"]), Value::Int(2));
    core.insert([sibling]).unwrap();

    let watched = set_key(
        core.head(),
        "a",
        keys(&["host"]),
        Value::String("two".to_string()),
    );
    core.insert([watched]).unwrap();

    // Woken by the second insert alone, and spanning only from it.
    let notification = subscription.next().await.unwrap();
    assert_eq!(notification.head, core.head());
    assert!(
        notification
            .movement
            .changes
            .touches(&key("a"), Some(&keys(&["host"])))
    );
    assert!(
        !notification
            .movement
            .changes
            .touches(&key("a"), Some(&keys(&["port"])))
    );
}

/// A fork that loses moves nothing, so there is nothing to say about it.
#[tokio::test]
async fn a_losing_fork_wakes_nobody() {
    let dir = TempDir::new().unwrap();
    let mut core = core(&dir).await;
    let root = core.head();

    let (winner, loser) = {
        let (one, two) = (set_ns(root, "a", pair()), set_ns(root, "b", pair()));
        if one.digest().unwrap() > two.digest().unwrap() {
            (one, two)
        } else {
            (two, one)
        }
    };
    core.insert([winner]).unwrap();

    let mut subscription = core.subscribe(ChangeFilter::head());
    assert_eq!(core.insert([loser]).unwrap(), Insert::Unchanged);

    drop(core);
    assert!(subscription.next().await.is_none());
}

/// A reorg is a change to both branches: the write rolled back is as much
/// news as the write taking its place.
#[tokio::test]
async fn a_reorg_notifies_about_the_branch_left_behind() {
    let dir = TempDir::new().unwrap();
    let mut core = core(&dir).await;
    let root = core.head();

    let (winner, loser) = {
        let (one, two) = (set_ns(root, "a", pair()), set_ns(root, "b", pair()));
        if one.digest().unwrap() > two.digest().unwrap() {
            (one, two)
        } else {
            (two, one)
        }
    };
    let (winner_key, loser_key) = match (winner.payload(), loser.payload()) {
        (Msg::SetNamespace(w), Msg::SetNamespace(l)) => (w.key.clone(), l.key.clone()),
        _ => unreachable!("both envelopes are SetNamespace"),
    };
    core.insert([loser]).unwrap();

    // Watching only the namespace the losing branch wrote.
    let mut subscription = core.subscribe(ChangeFilter::namespace(loser_key.clone()));

    let from = core.head();
    core.insert([winner]).unwrap();

    let notification = subscription.next().await.unwrap();
    assert_eq!(notification.from, from);
    assert!(notification.movement.changes.touches(&loser_key, None));
    assert!(notification.movement.changes.touches(&winner_key, None));
}

#[tokio::test]
async fn a_dropped_subscription_leaves_nothing_registered() {
    let dir = TempDir::new().unwrap();
    let core = core(&dir).await;

    let subscription = core.subscribe(ChangeFilter::head());
    assert_eq!(core.subscriptions().count(), 1);

    drop(subscription);
    assert_eq!(core.subscriptions().count(), 0);
}
