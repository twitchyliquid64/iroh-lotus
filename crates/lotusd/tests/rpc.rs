//! The local control socket, end to end: a client connects, asks one
//! question, and the running daemon answers it out of its core.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use lotusd::{Core, IfInitialized, Server, ServerHandle, VERSION};
use lotusd_rpc::{
    Call, ChainWalk, EnvelopeFrame, GetChainRange, GetEnvelopes, GetVersion, Verification, Watch,
    WatchSelector, call,
};
use tempfile::TempDir;
use tokio::{net::UnixStream, task::JoinHandle, time::timeout};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

/// How long a step gets before we call it hung. Generous: this bounds a
/// test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(5);

/// Waits for the daemon to be holding exactly `count` subscriptions.
async fn watchers(handle: &ServerHandle, count: usize) {
    timeout(GRACE, async {
        while handle.watchers().await.unwrap() != count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("expected {count} watchers"));
}

/// Starts a server on a fresh cluster in `dir`, alongside the head it began
/// at — the genesis, which is also its root — and the socket clients reach
/// it on.
///
/// The handle comes back for the caller to hold: the mainloop stops as soon
/// as the last one is dropped.
async fn serve(dir: &TempDir) -> (EnvelopeDigest, PathBuf, ServerHandle, JoinHandle<()>) {
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let head = core.head();

    // Short name on purpose: a unix socket path has to fit in SUN_LEN.
    let path = dir.path().join("s.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (handle, join) = Server::new(core, listener).unwrap().run().await;

    (head, path, handle, join)
}

/// A write onto `prev`, distinct per `value` so two of them fork.
fn set_ns(prev: EnvelopeDigest, value: &str) -> Envelope {
    Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: NamespaceKey::try_new("cfg").unwrap(),
        namespace: Namespace {
            value: Value::String(value.to_string()),
        },
    }))
}

/// Splits two siblings into (winner, loser) by the fork rule: equal
/// signature weight, so the higher digest wins.
fn ranked(a: Envelope, b: Envelope) -> (Envelope, Envelope) {
    if a.digest().unwrap() > b.digest().unwrap() {
        (a, b)
    } else {
        (b, a)
    }
}

/// Reads a whole `GetEnvelopes` answer, which arrives a frame at a time.
async fn envelopes(path: &Path, request: GetEnvelopes) -> Vec<EnvelopeFrame> {
    let stream = UnixStream::connect(path).await.unwrap();
    let mut call = Call::send(stream, request).await.unwrap();

    let mut frames = Vec::new();
    while let Some(frame) = call.next().await.unwrap() {
        frames.push(frame);
    }
    frames
}

#[tokio::test]
async fn get_version_answers_with_the_daemon_version() {
    let dir = TempDir::new().unwrap();
    let (_head, path, _handle, _join) = serve(&dir).await;

    let stream = UnixStream::connect(&path).await.unwrap();
    assert_eq!(call(stream, GetVersion {}).await.unwrap(), VERSION);
}

#[tokio::test]
async fn get_chain_range_answers_with_the_range_the_core_holds() {
    let dir = TempDir::new().unwrap();
    let (head, path, _handle, _join) = serve(&dir).await;

    let stream = UnixStream::connect(&path).await.unwrap();
    let range = call(stream, GetChainRange {}).await.unwrap();

    // A cluster one envelope old stands at its own genesis.
    assert_eq!(range.head, head);
    assert_eq!(range.root, head);
}

#[tokio::test]
async fn each_connection_carries_its_own_request() {
    let dir = TempDir::new().unwrap();
    let (head, path, _handle, _join) = serve(&dir).await;

    for _ in 0..3 {
        let stream = UnixStream::connect(&path).await.unwrap();
        assert_eq!(call(stream, GetChainRange {}).await.unwrap().head, head);
    }
}

#[tokio::test]
async fn connections_are_served_off_the_mainloop() {
    let dir = TempDir::new().unwrap();
    let (head, path, _handle, _join) = serve(&dir).await;

    // More at once than the mainloop's message channel is deep. Each answer
    // comes back through that channel, so serving these on the mainloop
    // itself would be it waiting on its own reply.
    let calls: Vec<_> = (0..16)
        .map(|_| {
            let path = path.clone();
            tokio::spawn(async move {
                let stream = UnixStream::connect(&path).await.unwrap();
                call(stream, GetChainRange {}).await.unwrap().head
            })
        })
        .collect();

    for answer in calls {
        assert_eq!(answer.await.unwrap(), head);
    }
}

/// A watch registers a subscription against the core for as long as its
/// connection is open.
#[tokio::test]
async fn a_watch_registers_a_subscription() {
    let dir = TempDir::new().unwrap();
    let (_head, path, handle, _join) = serve(&dir).await;
    assert_eq!(handle.watchers().await.unwrap(), 0);

    let stream = UnixStream::connect(&path).await.unwrap();
    let _call = Call::send(
        stream,
        Watch {
            selector: WatchSelector::Head,
        },
    )
    .await
    .unwrap();

    watchers(&handle, 1).await;
}

/// A client that hangs up must take its subscription with it. Nothing tells
/// the daemon it went — no shutdown, no further request — so the connection
/// dropping has to be enough on its own.
#[tokio::test]
async fn a_dropped_connection_deregisters_its_subscription() {
    let dir = TempDir::new().unwrap();
    let (_head, path, handle, _join) = serve(&dir).await;

    let stream = UnixStream::connect(&path).await.unwrap();
    let call = Call::send(
        stream,
        Watch {
            selector: WatchSelector::Head,
        },
    )
    .await
    .unwrap();
    watchers(&handle, 1).await;

    drop(call);

    // Without the chain moving: a watcher that leaves while nothing is
    // happening is exactly the one that would linger unnoticed.
    watchers(&handle, 0).await;
}

/// Several watchers come and go independently.
#[tokio::test]
async fn watchers_are_deregistered_one_at_a_time() {
    let dir = TempDir::new().unwrap();
    let (_head, path, handle, _join) = serve(&dir).await;

    let mut calls = Vec::new();
    for _ in 0..3 {
        let stream = UnixStream::connect(&path).await.unwrap();
        calls.push(
            Call::send(
                stream,
                Watch {
                    selector: WatchSelector::Head,
                },
            )
            .await
            .unwrap(),
        );
    }
    watchers(&handle, 3).await;

    calls.pop();
    watchers(&handle, 2).await;

    calls.clear();
    watchers(&handle, 0).await;
}

/// The chain comes back oldest first, genesis included — the same order
/// the daemon walks it in on disk.
#[tokio::test]
async fn get_envelopes_answers_with_the_canonical_chain_oldest_first() {
    let dir = TempDir::new().unwrap();
    let (head, path, handle, _join) = serve(&dir).await;

    let first = set_ns(head, "one");
    handle.insert([first.clone()]).await.unwrap();
    let second = set_ns(first.digest().unwrap(), "two");
    handle.insert([second.clone()]).await.unwrap();

    let digests: Vec<_> = envelopes(&path, GetEnvelopes::chain())
        .await
        .into_iter()
        .map(|frame| frame.digest)
        .collect();

    assert_eq!(
        digests,
        [head, first.digest().unwrap(), second.digest().unwrap()],
    );
}

/// A limit counts back from the head, so it keeps the newest end — the
/// part an operator is asking about.
#[tokio::test]
async fn get_envelopes_limits_from_the_head_end() {
    let dir = TempDir::new().unwrap();
    let (head, path, handle, _join) = serve(&dir).await;

    let first = set_ns(head, "one");
    handle.insert([first.clone()]).await.unwrap();
    let second = set_ns(first.digest().unwrap(), "two");
    handle.insert([second.clone()]).await.unwrap();

    let digests: Vec<_> = envelopes(&path, GetEnvelopes::newest(2))
        .await
        .into_iter()
        .map(|frame| frame.digest)
        .collect();

    assert_eq!(digests, [first.digest().unwrap(), second.digest().unwrap()]);

    // A limit past the chain's length is not an error, just the whole chain.
    assert_eq!(envelopes(&path, GetEnvelopes::newest(99)).await.len(), 3);
    assert!(envelopes(&path, GetEnvelopes::newest(0)).await.is_empty());
}

/// By digest reads the log, not the canonical chain: an envelope rewritten
/// out of history is exactly the one an operator needs to look at.
#[tokio::test]
async fn get_envelopes_by_digest_reaches_an_orphan() {
    let dir = TempDir::new().unwrap();
    let (head, path, handle, _join) = serve(&dir).await;

    let (winner, loser) = ranked(set_ns(head, "one"), set_ns(head, "two"));
    handle.insert([loser.clone()]).await.unwrap();
    handle.insert([winner.clone()]).await.unwrap();
    let orphan = loser.digest().unwrap();

    // Gone from the chain...
    assert!(
        !envelopes(&path, GetEnvelopes::chain())
            .await
            .iter()
            .any(|frame| frame.digest == orphan)
    );
    // ...and still readable by name.
    let frames = envelopes(&path, GetEnvelopes::digests([orphan])).await;
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].digest, orphan);
    assert_eq!(frames[0].envelope.payload(), loser.payload());
}

/// Digests are answered in the order asked for, and one the node does not
/// hold is left out rather than reported.
#[tokio::test]
async fn get_envelopes_answers_in_the_order_asked_and_skips_what_it_lacks() {
    let dir = TempDir::new().unwrap();
    let (head, path, handle, _join) = serve(&dir).await;

    let first = set_ns(head, "one");
    handle.insert([first.clone()]).await.unwrap();
    let unknown = EnvelopeDigest::from_bytes([0xab; 32]);

    let digests: Vec<_> = envelopes(
        &path,
        GetEnvelopes::digests([first.digest().unwrap(), unknown, head]),
    )
    .await
    .into_iter()
    .map(|frame| frame.digest)
    .collect();

    assert_eq!(digests, [first.digest().unwrap(), head]);
    assert!(
        envelopes(&path, GetEnvelopes::digests([unknown]))
            .await
            .is_empty()
    );
}

/// The verification status never crosses the ledger wire, so a fetched
/// envelope would read as unchecked unless the protocol carried it — and
/// a printout that called every envelope unchecked would be a lie.
#[tokio::test]
async fn a_fetched_envelope_keeps_the_verification_status_the_node_gave_it() {
    let dir = TempDir::new().unwrap();
    let (head, path, _handle, _join) = serve(&dir).await;

    let frames = envelopes(&path, GetEnvelopes::digests([head])).await;
    let [frame] = frames.as_slice() else {
        panic!("expected the genesis back, got {frames:?}");
    };

    // The genesis is signed by the key the cluster was founded on.
    assert_eq!(frame.verification, Verification::AllMatched(2));

    let (digest, envelope) = frame.clone().into_parts();
    assert_eq!(digest, head);
    assert_eq!(envelope.verification_status().signature_weight(), 2);
}

/// How long a `since` test waits before inserting, and the window it then
/// asks for. Generous on both sides: the wait has to outlast the window,
/// and the inserts after it have to fit inside one.
const OLD: Duration = Duration::from_millis(250);
const WINDOW: Duration = Duration::from_millis(150);

/// The log stamps what it stores, and the stamp reaches a client — the
/// whole point of recording it, since nothing else may read it.
#[tokio::test]
async fn get_envelopes_reports_when_the_node_stored_each_envelope() {
    let dir = TempDir::new().unwrap();
    let (head, path, handle, _join) = serve(&dir).await;

    // Compared in milliseconds: a reading taken straight off chrono here
    // carries nanoseconds a `StoredAt` does not.
    let before = chrono::Utc::now().timestamp_millis();
    let inserted = set_ns(head, "one");
    handle.insert([inserted.clone()]).await.unwrap();
    let after = chrono::Utc::now().timestamp_millis();

    let frames = envelopes(&path, GetEnvelopes::chain()).await;
    let frame = frames
        .iter()
        .find(|frame| frame.digest == inserted.digest().unwrap())
        .expect("the envelope just inserted");
    let stored = frame.stored_at_millis;

    assert!(
        before <= stored && stored <= after,
        "{stored} is outside {before}..{after}",
    );
    assert!(
        frame.stored_at().is_some(),
        "the number reads back as a time"
    );

    // The genesis went in before this test read the clock at all.
    let genesis = frames[0].stored_at_millis;
    assert!(genesis <= stored);
}

/// A window keeps the envelopes the node took recently and stops at the
/// first one older than it — a contiguous run ending at the head, never a
/// chain with holes in it.
#[tokio::test]
async fn get_envelopes_since_keeps_only_what_arrived_in_the_window() {
    let dir = TempDir::new().unwrap();
    let (head, path, handle, _join) = serve(&dir).await;

    // The genesis ages out of the window; what follows lands inside it.
    tokio::time::sleep(OLD).await;
    let first = set_ns(head, "one");
    handle.insert([first.clone()]).await.unwrap();
    let second = set_ns(first.digest().unwrap(), "two");
    handle.insert([second.clone()]).await.unwrap();

    let recent: Vec<_> = envelopes(&path, GetEnvelopes::since(WINDOW))
        .await
        .into_iter()
        .map(|frame| frame.digest)
        .collect();

    assert_eq!(recent, [first.digest().unwrap(), second.digest().unwrap()]);

    // A window wide enough reaches the genesis, and no window at all is
    // the whole chain.
    assert_eq!(
        envelopes(&path, GetEnvelopes::since(Duration::from_secs(3600)))
            .await
            .len(),
        3,
    );
    assert_eq!(envelopes(&path, GetEnvelopes::chain()).await.len(), 3);
}

/// Both bounds may be set at once; the walk stops at whichever it reaches
/// first.
#[tokio::test]
async fn a_window_and_a_limit_bound_the_same_walk() {
    let dir = TempDir::new().unwrap();
    let (head, path, handle, _join) = serve(&dir).await;

    tokio::time::sleep(OLD).await;
    let first = set_ns(head, "one");
    handle.insert([first.clone()]).await.unwrap();
    let second = set_ns(first.digest().unwrap(), "two");
    handle.insert([second.clone()]).await.unwrap();

    // The limit bites first: one envelope, from the head end.
    let by_limit: Vec<_> = envelopes(
        &path,
        GetEnvelopes::walk(ChainWalk::default().with_limit(1).with_since(WINDOW)),
    )
    .await
    .into_iter()
    .map(|frame| frame.digest)
    .collect();
    assert_eq!(by_limit, [second.digest().unwrap()]);

    // The window bites first: the limit would have reached the genesis.
    let by_window: Vec<_> = envelopes(
        &path,
        GetEnvelopes::walk(ChainWalk::default().with_limit(3).with_since(WINDOW)),
    )
    .await
    .into_iter()
    .map(|frame| frame.digest)
    .collect();
    assert_eq!(
        by_window,
        [first.digest().unwrap(), second.digest().unwrap()]
    );
}

/// A window nothing fits in is an empty answer, not the whole chain: a
/// bound that silently stopped applying would be worse than no bound.
#[tokio::test]
async fn a_window_nothing_falls_inside_answers_with_nothing() {
    let dir = TempDir::new().unwrap();
    let (head, path, handle, _join) = serve(&dir).await;
    handle.insert([set_ns(head, "one")]).await.unwrap();

    tokio::time::sleep(OLD).await;

    assert!(
        envelopes(&path, GetEnvelopes::since(WINDOW))
            .await
            .is_empty()
    );
}
