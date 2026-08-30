//! Advancing the chain and watching it, both through the server actor.

use std::time::Duration;

use lotusd::{
    ChangeFilter, ChangeNotification, ChangeSelector, Core, IfInitialized, NodeKeys, RequestError,
    Server, ServerHandle, SubscriptionHandle,
};
use state::{ApplyError, Error as ChainError, Insert};
use tempfile::TempDir;
use tokio::{net::UnixListener, task::JoinHandle, time::timeout};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{FullCheckpoint, InitMsg, Namespace, NamespaceKey, SetNamespace, SetNamespaceKey, Value},
    subkey::{Subkey, SubkeyPath},
};

/// How long a notification gets before we call it lost. Generous: this
/// bounds a test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(5);

/// The next notification, failing rather than hanging when none comes.
async fn woken(subscription: &mut SubscriptionHandle) -> ChangeNotification {
    timeout(GRACE, subscription.next())
        .await
        .expect("a notification was expected")
        .expect("the subscription ended without one")
}

/// Starts a server on a fresh cluster in `dir`, alongside the head it began
/// at and the node's keys — the cluster takes no envelope this node has not
/// signed.
async fn serve(dir: &TempDir) -> (EnvelopeDigest, NodeKeys, ServerHandle, JoinHandle<()>) {
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let head = core.head();
    let signer = core.keys().clone();

    // Short name on purpose: a unix socket path has to fit in SUN_LEN.
    let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    let (handle, join) = Server::new(core, listener).unwrap().run().await;

    (head, signer, handle, join)
}

fn key(k: &str) -> NamespaceKey {
    NamespaceKey::try_new(k).unwrap()
}

fn set_ns(signer: &NodeKeys, prev: EnvelopeDigest, k: &str, v: &str) -> Envelope {
    signed(
        signer,
        Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: key(k),
            namespace: Namespace {
                value: Value::String(v.to_string()),
            },
        })),
    )
}

/// The node's signature over `envelope`: the chain takes no envelope
/// without one.
fn signed(signer: &NodeKeys, envelope: Envelope) -> Envelope {
    signer.sign(envelope).unwrap()
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
fn pair(signer: &NodeKeys, prev: EnvelopeDigest, k: &str) -> Envelope {
    signed(
        signer,
        Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: key(k),
            namespace: Namespace {
                value: Value::Map(
                    [
                        ("host".to_string(), Value::String("one".to_string())),
                        ("port".to_string(), Value::Int(1)),
                    ]
                    .into(),
                ),
            },
        })),
    )
}

fn set_key(
    signer: &NodeKeys,
    prev: EnvelopeDigest,
    k: &str,
    path: SubkeyPath,
    v: &str,
) -> Envelope {
    signed(
        signer,
        Envelope::new(Msg::SetNamespaceKey(SetNamespaceKey {
            prev,
            key: key(k),
            path,
            value: Some(Value::String(v.to_string())),
        })),
    )
}

/// Splits two sibling envelopes into (winner, loser) by the fork rule:
/// both carry the same single signature, so the higher digest wins.
fn ranked(a: Envelope, b: Envelope) -> (Envelope, Envelope) {
    if a.digest().unwrap() > b.digest().unwrap() {
        (a, b)
    } else {
        (b, a)
    }
}

/// Brings the server down so a subscription that was never woken can say so
/// by ending rather than by hanging.
async fn stop(handle: &ServerHandle, join: JoinHandle<()>) {
    handle.shutdown().await.unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn inserting_through_the_handle_moves_the_head() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, _join) = serve(&dir).await;
    let envelope = set_ns(&signer, head, "a", "1");

    assert_eq!(
        handle.insert([envelope.clone()]).await.unwrap(),
        Insert::Extended
    );
    assert_eq!(handle.head().await.unwrap(), envelope.digest().unwrap());
}

#[tokio::test]
async fn a_run_of_envelopes_is_inserted_as_one_batch() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, _join) = serve(&dir).await;

    let first = set_ns(&signer, head, "a", "1");
    let second = set_ns(&signer, first.digest().unwrap(), "b", "2");

    assert_eq!(
        handle.insert([first, second.clone()]).await.unwrap(),
        Insert::Extended
    );
    assert_eq!(handle.head().await.unwrap(), second.digest().unwrap());
}

/// The chain's refusal reaches the caller rather than being swallowed by
/// the actor, and the head stays where it was.
#[tokio::test]
async fn an_envelope_the_chain_refuses_comes_back_as_an_error() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, _join) = serve(&dir).await;
    let orphan = set_ns(&signer, EnvelopeDigest::from_bytes([0xaa; 32]), "a", "1");

    let err = handle.insert([orphan]).await.unwrap_err();

    assert!(matches!(err, RequestError::Chain(_)), "{err:?}");
    assert_eq!(handle.head().await.unwrap(), head);
}

#[tokio::test]
async fn a_subscription_registered_through_the_handle_is_notified() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, _join) = serve(&dir).await;

    let mut subscription = handle
        .subscribe(ChangeFilter::namespace(key("a")))
        .await
        .unwrap();
    assert_eq!(subscription.opened_at(), head);

    handle
        .insert([set_ns(&signer, head, "a", "1")])
        .await
        .unwrap();

    let notification = woken(&mut subscription).await;
    assert_eq!(notification.from, head);
    assert_eq!(notification.head, handle.head().await.unwrap());
    assert!(notification.movement.changes.touches(&key("a"), None));
}

/// Watching one thing needs no filter built by hand.
#[tokio::test]
async fn subscribing_accepts_a_bare_selector() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, _join) = serve(&dir).await;

    let mut subscription = handle.subscribe(ChangeSelector::Head).await.unwrap();
    handle
        .insert([set_ns(&signer, head, "a", "1")])
        .await
        .unwrap();

    assert_eq!(
        woken(&mut subscription).await.head,
        handle.head().await.unwrap()
    );
}

/// A subscription outlives the server it was registered with: what was
/// already pending arrives, and then the stream ends.
#[tokio::test]
async fn a_subscription_ends_when_the_server_shuts_down() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, join) = serve(&dir).await;

    let mut subscription = handle.subscribe(ChangeSelector::Head).await.unwrap();
    handle
        .insert([set_ns(&signer, head, "a", "1")])
        .await
        .unwrap();
    handle.shutdown().await.unwrap();
    join.await.unwrap();

    assert!(timeout(GRACE, subscription.next()).await.unwrap().is_some());
    assert!(subscription.next().await.is_none());
}

#[tokio::test]
async fn a_shut_down_server_accepts_no_inserts() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, _join) = serve(&dir).await;
    handle.shutdown().await.unwrap();

    let err = handle
        .insert([set_ns(&signer, head, "a", "1")])
        .await
        .unwrap_err();

    assert!(matches!(err, RequestError::ServerGone), "{err:?}");
    assert!(handle.subscribe(ChangeSelector::Head).await.is_err());
}

/// A write inside one namespace is not this subscriber's business, however
/// much the head moved.
#[tokio::test]
async fn a_write_to_one_namespace_leaves_a_subscriber_on_another_asleep() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, join) = serve(&dir).await;
    handle.insert([pair(&signer, head, "a")]).await.unwrap();

    let mut subscription = handle
        .subscribe(ChangeFilter::namespace(key("b")))
        .await
        .unwrap();

    let head = handle.head().await.unwrap();
    let write = set_key(&signer, head, "a", keys(&["host"]), "two");
    handle.insert([write.clone()]).await.unwrap();

    // The chain did move — the subscriber simply had no stake in it.
    assert_eq!(handle.head().await.unwrap(), write.digest().unwrap());
    stop(&handle, join).await;
    assert!(subscription.next().await.is_none());
}

/// An envelope chaining onto another cluster's genesis has no parent here.
#[tokio::test]
async fn an_envelope_from_another_cluster_is_refused() {
    let dir = TempDir::new().unwrap();
    let (head, _signer, handle, join) = serve(&dir).await;
    let mut subscription = handle.subscribe(ChangeSelector::Head).await.unwrap();

    let elsewhere = TempDir::new().unwrap();
    let (foreign_head, foreign_signer, foreign, foreign_join) = serve(&elsewhere).await;

    let err = handle
        .insert([set_ns(&foreign_signer, foreign_head, "a", "1")])
        .await
        .unwrap_err();

    assert!(
        matches!(
            err,
            RequestError::Chain(ChainError::UnknownParent(prev)) if prev == foreign_head
        ),
        "{err:?}"
    );
    assert_eq!(handle.head().await.unwrap(), head);
    stop(&foreign, foreign_join).await;
    stop(&handle, join).await;
    assert!(subscription.next().await.is_none());
}

/// A write into a namespace that is not there is refused, and nothing about
/// the chain moves.
#[tokio::test]
async fn a_write_to_an_unknown_namespace_is_refused() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, join) = serve(&dir).await;
    let mut subscription = handle.subscribe(ChangeSelector::Head).await.unwrap();

    let err = handle
        .insert([set_key(&signer, head, "nope", keys(&["host"]), "one")])
        .await
        .unwrap_err();

    assert!(
        matches!(
            err,
            RequestError::Chain(ChainError::Apply(ApplyError::UnknownNamespace(_)))
        ),
        "{err:?}"
    );
    assert_eq!(handle.head().await.unwrap(), head);
    stop(&handle, join).await;
    assert!(subscription.next().await.is_none());
}

/// An `Init` opens a chain and cannot be applied to one already open.
#[tokio::test]
async fn an_init_envelope_cannot_be_inserted_into_an_open_chain() {
    let dir = TempDir::new().unwrap();
    let (head, _signer, handle, _join) = serve(&dir).await;

    let genesis = Envelope::new(Msg::Init(InitMsg {
        state: FullCheckpoint::default(),
    }));
    let err = handle.insert([genesis]).await.unwrap_err();

    assert!(
        matches!(
            err,
            RequestError::Chain(ChainError::Apply(ApplyError::UnexpectedInit))
        ),
        "{err:?}"
    );
    assert_eq!(handle.head().await.unwrap(), head);
}

/// A run that breaks part-way keeps the prefix it already stored, so the
/// refusal comes back alongside a head that moved — and subscribers are
/// told about the part that landed.
#[tokio::test]
async fn a_batch_with_a_gap_keeps_its_prefix_and_still_notifies() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, _join) = serve(&dir).await;
    let mut subscription = handle.subscribe(ChangeSelector::Head).await.unwrap();

    let landed = set_ns(&signer, head, "a", "1");
    let orphan = set_ns(&signer, EnvelopeDigest::from_bytes([0xaa; 32]), "b", "2");
    let err = handle.insert([landed.clone(), orphan]).await.unwrap_err();

    assert!(
        matches!(
            err,
            RequestError::Chain(ChainError::Apply(ApplyError::ChainMismatch { .. }))
        ),
        "{err:?}"
    );
    assert_eq!(handle.head().await.unwrap(), landed.digest().unwrap());

    let notification = woken(&mut subscription).await;
    assert_eq!(notification.head, landed.digest().unwrap());
    assert!(notification.movement.changes.touches(&key("a"), None));
    assert!(!notification.movement.changes.touches(&key("b"), None));
}

/// A fork that loses is no error — it is reported as the head not having
/// moved, and nothing is woken.
#[tokio::test]
async fn a_losing_fork_is_reported_unchanged_and_wakes_nobody() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, join) = serve(&dir).await;
    let (winner, loser) = ranked(
        set_ns(&signer, head, "a", "1"),
        set_ns(&signer, head, "b", "2"),
    );
    handle.insert([winner.clone()]).await.unwrap();

    let mut subscription = handle.subscribe(ChangeSelector::Head).await.unwrap();

    assert_eq!(handle.insert([loser]).await.unwrap(), Insert::Unchanged);
    assert_eq!(handle.head().await.unwrap(), winner.digest().unwrap());
    stop(&handle, join).await;
    assert!(subscription.next().await.is_none());
}

/// An envelope already in the log moves nothing the second time around.
#[tokio::test]
async fn a_duplicate_envelope_is_reported_and_wakes_nobody() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, join) = serve(&dir).await;
    let envelope = set_ns(&signer, head, "a", "1");
    handle.insert([envelope.clone()]).await.unwrap();

    let mut subscription = handle.subscribe(ChangeSelector::Head).await.unwrap();

    assert_eq!(handle.insert([envelope]).await.unwrap(), Insert::Duplicate);
    stop(&handle, join).await;
    assert!(subscription.next().await.is_none());
}

/// The other side of the fork: the winner arriving second reorgs, which is
/// reported as such and is news to a subscriber on either branch.
#[tokio::test]
async fn a_winning_fork_is_reported_as_a_reorg_and_wakes_subscribers() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, _join) = serve(&dir).await;
    let (winner, loser) = ranked(
        set_ns(&signer, head, "a", "1"),
        set_ns(&signer, head, "b", "2"),
    );
    handle.insert([loser.clone()]).await.unwrap();

    let mut subscription = handle.subscribe(ChangeSelector::Head).await.unwrap();

    assert_eq!(
        handle.insert([winner.clone()]).await.unwrap(),
        Insert::Reorged {
            from: loser.digest().unwrap()
        }
    );

    let notification = woken(&mut subscription).await;
    assert_eq!(notification.from, loser.digest().unwrap());
    assert_eq!(notification.head, winner.digest().unwrap());
}

/// The point of the whole thing: an envelope that was canonical and is
/// rewritten out of history wakes whoever was watching it.
#[tokio::test]
async fn a_watcher_is_woken_when_its_envelope_is_reorged_out() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, _join) = serve(&dir).await;
    let (winner, loser) = ranked(
        set_ns(&signer, head, "a", "1"),
        set_ns(&signer, head, "b", "2"),
    );
    handle.insert([loser.clone()]).await.unwrap();

    let orphan = loser.digest().unwrap();
    let mut subscription = handle.watch_orphaned(orphan).await.unwrap().unwrap();

    handle.insert([winner.clone()]).await.unwrap();

    let notification = woken(&mut subscription).await;
    assert!(notification.movement.orphaned.contains(&orphan));
    assert_eq!(notification.head, winner.digest().unwrap());
    // And the chain agrees with what it was told.
    assert!(!handle.contains(orphan).await.unwrap());
}

/// Everything above the fork goes, not only the envelope that was the head.
#[tokio::test]
async fn a_watcher_below_the_head_is_woken_by_a_deep_reorg() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, _join) = serve(&dir).await;
    let base = set_ns(&signer, head, "base", "0");
    handle.insert([base.clone()]).await.unwrap();

    let (winner, loser) = ranked(
        set_ns(&signer, base.digest().unwrap(), "a", "1"),
        set_ns(&signer, base.digest().unwrap(), "b", "2"),
    );
    let tail = set_ns(&signer, loser.digest().unwrap(), "c", "3");
    handle.insert([loser.clone(), tail.clone()]).await.unwrap();

    // Watching the envelope one below the head, not the head itself.
    let orphan = loser.digest().unwrap();
    let mut subscription = handle.watch_orphaned(orphan).await.unwrap().unwrap();

    handle.insert([winner]).await.unwrap();

    let notification = woken(&mut subscription).await;
    assert_eq!(
        notification.movement.orphaned,
        [orphan, tail.digest().unwrap()].into()
    );
    // The fork point never left the chain.
    assert!(handle.contains(base.digest().unwrap()).await.unwrap());
}

/// The fork point survives a reorg, so a watcher on it stays asleep.
#[tokio::test]
async fn a_watcher_on_a_surviving_envelope_sleeps_through_a_reorg() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, join) = serve(&dir).await;
    let base = set_ns(&signer, head, "base", "0");
    handle.insert([base.clone()]).await.unwrap();

    let (winner, loser) = ranked(
        set_ns(&signer, base.digest().unwrap(), "a", "1"),
        set_ns(&signer, base.digest().unwrap(), "b", "2"),
    );
    handle.insert([loser]).await.unwrap();

    let mut subscription = handle
        .watch_orphaned(base.digest().unwrap())
        .await
        .unwrap()
        .unwrap();

    handle.insert([winner]).await.unwrap();

    stop(&handle, join).await;
    assert!(subscription.next().await.is_none());
}

/// Watching an envelope that is already off the chain answers `None`: it
/// will never be taken off again, so there is nothing to wait for.
#[tokio::test]
async fn watching_an_envelope_already_off_the_chain_answers_none() {
    let dir = TempDir::new().unwrap();
    let (head, signer, handle, _join) = serve(&dir).await;
    let (winner, loser) = ranked(
        set_ns(&signer, head, "a", "1"),
        set_ns(&signer, head, "b", "2"),
    );
    handle.insert([winner]).await.unwrap();

    // The loser never became canonical.
    handle.insert([loser.clone()]).await.unwrap();
    let orphan = loser.digest().unwrap();

    assert!(!handle.contains(orphan).await.unwrap());
    assert!(handle.watch_orphaned(orphan).await.unwrap().is_none());
}

/// An envelope the log never held is off the chain like any other.
#[tokio::test]
async fn watching_an_unknown_envelope_answers_none() {
    let dir = TempDir::new().unwrap();
    let (_head, _signer, handle, _join) = serve(&dir).await;
    let unknown = EnvelopeDigest::from_bytes([0xaa; 32]);

    assert!(!handle.contains(unknown).await.unwrap());
    assert!(handle.watch_orphaned(unknown).await.unwrap().is_none());
}

/// Registering leaves nothing behind when it answers `None`.
#[tokio::test]
async fn a_refused_watch_registers_no_subscription() {
    let dir = TempDir::new().unwrap();
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let unknown = EnvelopeDigest::from_bytes([0xaa; 32]);

    assert!(core.watch_orphaned(unknown).unwrap().is_none());
    assert_eq!(core.subscriptions().count(), 0);
}

#[tokio::test]
async fn a_shut_down_server_answers_no_chain_reads() {
    let dir = TempDir::new().unwrap();
    let (head, _signer, handle, _join) = serve(&dir).await;
    handle.shutdown().await.unwrap();

    assert!(matches!(
        handle.contains(head).await.unwrap_err(),
        RequestError::ServerGone
    ));
    assert!(matches!(
        handle.watch_orphaned(head).await.unwrap_err(),
        RequestError::ServerGone
    ));
}
