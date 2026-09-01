//! The local control socket, end to end: a client connects, asks one
//! question, and the running daemon answers it out of its core.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use lotusd::{Core, IfInitialized, NodeKeys, Server, ServerHandle, VERSION};
use lotusd_rpc::{
    Call, ChainWalk, EnvelopeFrame, Error, FailureKind, GetChainRange, GetEnvelopes, GetVersion,
    Len, MapMeta, Query, QueryKind, Read, ValueMeta, Verification, Watch, WatchSelector,
    WeakDelete, WeakDeleteMatching, WeakIncrement, WeakPush, WeakSet, WriteOutcome, Written, call,
};
use std::collections::BTreeMap;
use tempfile::TempDir;
use tokio::{net::UnixStream, task::JoinHandle, time::timeout};

use wire::{
    Envelope, EnvelopeDigest, Msg, VerificationStatus,
    msg::{Match, Namespace, NamespaceKey, Predicate, SetNamespace, Value},
    subkey::SubkeyPath,
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
/// at — the genesis, which is also its root — the node's keys, and the
/// socket clients reach it on.
///
/// The handle comes back for the caller to hold: the mainloop stops as soon
/// as the last one is dropped.
async fn serve(
    dir: &TempDir,
) -> (
    EnvelopeDigest,
    NodeKeys,
    PathBuf,
    ServerHandle,
    JoinHandle<()>,
) {
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let head = core.head();
    let keys = core.keys().clone();

    // Short name on purpose: a unix socket path has to fit in SUN_LEN.
    let path = dir.path().join("s.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (handle, join) = Server::new(core, listener).unwrap().run().await;

    (head, keys, path, handle, join)
}

/// A write onto `prev`, distinct per `value` so two of them fork, signed
/// by the node so the chain accepts it.
fn set_ns(keys: &NodeKeys, prev: EnvelopeDigest, value: &str) -> Envelope {
    keys.sign(Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: NamespaceKey::try_new("cfg").unwrap(),
        namespace: Namespace {
            value: Value::String(value.to_string()),
        },
    })))
    .unwrap()
}

/// Splits two siblings into (winner, loser) by the fork rule: both carry
/// the same single signature, so the higher digest wins.
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
    let (_head, _keys, path, _handle, _join) = serve(&dir).await;

    let stream = UnixStream::connect(&path).await.unwrap();
    assert_eq!(call(stream, GetVersion {}).await.unwrap(), VERSION);
}

#[tokio::test]
async fn get_chain_range_answers_with_the_range_the_core_holds() {
    let dir = TempDir::new().unwrap();
    let (head, _keys, path, _handle, _join) = serve(&dir).await;

    let stream = UnixStream::connect(&path).await.unwrap();
    let range = call(stream, GetChainRange {}).await.unwrap();

    // A cluster one envelope old stands at its own genesis.
    assert_eq!(range.head, head);
    assert_eq!(range.root, head);
}

#[tokio::test]
async fn each_connection_carries_its_own_request() {
    let dir = TempDir::new().unwrap();
    let (head, _keys, path, _handle, _join) = serve(&dir).await;

    for _ in 0..3 {
        let stream = UnixStream::connect(&path).await.unwrap();
        assert_eq!(call(stream, GetChainRange {}).await.unwrap().head, head);
    }
}

#[tokio::test]
async fn connections_are_served_off_the_mainloop() {
    let dir = TempDir::new().unwrap();
    let (head, _keys, path, _handle, _join) = serve(&dir).await;

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
    let (_head, _keys, path, handle, _join) = serve(&dir).await;
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
    let (_head, _keys, path, handle, _join) = serve(&dir).await;

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
    let (_head, _keys, path, handle, _join) = serve(&dir).await;

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
    let (head, keys, path, handle, _join) = serve(&dir).await;

    let first = set_ns(&keys, head, "one");
    handle.insert([first.clone()]).await.unwrap();
    let second = set_ns(&keys, first.digest().unwrap(), "two");
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
    let (head, keys, path, handle, _join) = serve(&dir).await;

    let first = set_ns(&keys, head, "one");
    handle.insert([first.clone()]).await.unwrap();
    let second = set_ns(&keys, first.digest().unwrap(), "two");
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
    let (head, keys, path, handle, _join) = serve(&dir).await;

    let (winner, loser) = ranked(set_ns(&keys, head, "one"), set_ns(&keys, head, "two"));
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
    let (head, keys, path, handle, _join) = serve(&dir).await;

    let first = set_ns(&keys, head, "one");
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
    let (head, _keys, path, _handle, _join) = serve(&dir).await;

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

/// How long the `since` test waits before inserting, and the window it
/// then asks for. What has to fit inside the window is one in-process
/// round trip over a unix socket, so the margin either side is enormous
/// — where the boundary actually falls is settled in `chain_walk.rs`,
/// against the log's own stamps rather than against a clock.
const OLD: Duration = Duration::from_millis(500);
const WINDOW: Duration = Duration::from_millis(250);

/// The log stamps what it stores, and the stamp reaches a client — the
/// whole point of recording it, since nothing else may read it.
#[tokio::test]
async fn get_envelopes_reports_when_the_node_stored_each_envelope() {
    let dir = TempDir::new().unwrap();
    let (head, keys, path, handle, _join) = serve(&dir).await;

    // Compared in milliseconds: a reading taken straight off chrono here
    // carries nanoseconds a `StoredAt` does not.
    let before = chrono::Utc::now().timestamp_millis();
    let inserted = set_ns(&keys, head, "one");
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

/// The window crosses the wire and is applied against the daemon's own
/// clock, which is the only clock the stamps were read from.
#[tokio::test]
async fn get_envelopes_applies_the_window_it_was_sent() {
    let dir = TempDir::new().unwrap();
    let (head, keys, path, handle, _join) = serve(&dir).await;

    // The genesis ages out of the window; what follows lands inside it.
    tokio::time::sleep(OLD).await;
    let first = set_ns(&keys, head, "one");
    handle.insert([first.clone()]).await.unwrap();
    let second = set_ns(&keys, first.digest().unwrap(), "two");
    handle.insert([second.clone()]).await.unwrap();

    let recent: Vec<_> = envelopes(&path, GetEnvelopes::since(WINDOW))
        .await
        .into_iter()
        .map(|frame| frame.digest)
        .collect();

    assert_eq!(recent, [first.digest().unwrap(), second.digest().unwrap()]);

    // A window wide enough reaches the genesis, and no window at all is
    // the whole chain — a bound has to differ from those to be doing
    // anything.
    assert_eq!(
        envelopes(&path, GetEnvelopes::since(Duration::from_secs(3600)))
            .await
            .len(),
        3,
    );
    assert_eq!(envelopes(&path, GetEnvelopes::chain()).await.len(), 3);

    // Both bounds travel together, and the tighter one wins.
    let bounded = envelopes(
        &path,
        GetEnvelopes::walk(ChainWalk::default().with_limit(1).with_since(WINDOW)),
    )
    .await;
    assert_eq!(
        bounded
            .into_iter()
            .map(|frame| frame.digest)
            .collect::<Vec<_>>(),
        [second.digest().unwrap()],
    );
}

fn key(k: &str) -> NamespaceKey {
    NamespaceKey::try_new(k).unwrap()
}

fn path(text: &str) -> SubkeyPath {
    text.parse().unwrap()
}

/// Reads `key` at `path` over the socket.
async fn read(socket: &Path, key: NamespaceKey, path: Option<SubkeyPath>) -> lotusd_rpc::ValueAt {
    let stream = UnixStream::connect(socket).await.unwrap();
    call(stream, Read { key, path }).await.unwrap()
}

/// Writes `value` to `key` at `path` over the socket.
async fn weak_set(
    socket: &Path,
    key: NamespaceKey,
    path: Option<SubkeyPath>,
    value: Value,
) -> Result<Written, Error> {
    let stream = UnixStream::connect(socket).await.unwrap();
    call(stream, WeakSet { key, path, value }).await
}

/// Sends any weak write over the socket.
async fn write<M>(socket: &Path, request: M) -> Result<Written, Error>
where
    M: lotusd_rpc::Method<Response = Written>,
{
    let stream = UnixStream::connect(socket).await.unwrap();
    call(stream, request).await
}

/// The value `key` holds at `path`.
async fn value_at(socket: &Path, key: NamespaceKey, path: Option<SubkeyPath>) -> Option<Value> {
    read(socket, key, path).await.value
}

/// Whether a write came back rejected, as opposed to done or broken.
fn rejected(result: Result<Written, Error>) -> bool {
    matches!(result, Err(Error::Failed(failure)) if failure.kind == FailureKind::Rejected)
}

/// Asks what `key` holds at `path`, in as much detail as `kind`.
async fn query(
    socket: &Path,
    key: NamespaceKey,
    path: Option<SubkeyPath>,
    kind: QueryKind,
) -> lotusd_rpc::Queried {
    let stream = UnixStream::connect(socket).await.unwrap();
    call(stream, Query { key, path, kind }).await.unwrap()
}

/// A query reports the size and the keys of what a path addresses, and
/// none of the values under it.
#[tokio::test]
async fn a_query_answers_with_the_size_and_keys_of_a_container() {
    let dir = TempDir::new().unwrap();
    let (_genesis, _keys, socket, _handle, _join) = serve(&dir).await;

    let value = Value::Map(BTreeMap::from([
        (
            "servers".to_owned(),
            Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]),
        ),
        ("name".to_owned(), Value::String("edge".to_owned())),
    ]));
    let written = weak_set(&socket, key("cfg"), None, value).await.unwrap();

    let queried = query(&socket, key("cfg"), None, QueryKind::Keys).await;
    assert_eq!(queried.head, written.head);
    assert_eq!(
        queried.meta,
        Some(ValueMeta::Map(MapMeta {
            len: 2,
            keys: Some(vec!["name".to_owned(), "servers".to_owned()]),
        }))
    );

    // The same map counted rather than named: the keys stay behind.
    assert_eq!(
        query(&socket, key("cfg"), None, QueryKind::Len).await.meta,
        Some(ValueMeta::Map(MapMeta { len: 2, keys: None })),
    );

    assert_eq!(
        query(&socket, key("cfg"), Some(path("servers")), QueryKind::Keys)
            .await
            .meta,
        Some(ValueMeta::Array(Len { len: 3 })),
    );

    // A leaf holds no entries, which is not the same as holding none.
    assert_eq!(
        query(&socket, key("cfg"), Some(path("name")), QueryKind::Len)
            .await
            .meta,
        Some(ValueMeta::Leaf),
    );
}

/// A query about what the ledger does not hold answers with nothing, at
/// the head the node stands at.
#[tokio::test]
async fn querying_what_is_not_there_answers_nothing() {
    let dir = TempDir::new().unwrap();
    let (head, _keys, socket, _handle, _join) = serve(&dir).await;

    let queried = query(&socket, key("cfg"), None, QueryKind::Keys).await;
    assert_eq!(queried.head, head);
    assert_eq!(queried.meta, None);

    weak_set(&socket, key("cfg"), None, Value::Int(7))
        .await
        .unwrap();
    assert_eq!(
        query(&socket, key("cfg"), Some(path("nope")), QueryKind::Len)
            .await
            .meta,
        None,
    );
}

/// A namespace the ledger does not hold reads as nothing, at the head the
/// node stands at.
#[tokio::test]
async fn reading_what_is_not_there_answers_nothing() {
    let dir = TempDir::new().unwrap();
    let (head, _keys, path, _handle, _join) = serve(&dir).await;

    let at = read(&path, key("cfg"), None).await;
    assert_eq!(at.head, head);
    assert_eq!(at.value, None);
}

/// A weak set of a whole namespace creates it, and reads back at the
/// head the write moved the chain to.
#[tokio::test]
async fn a_weak_set_of_a_namespace_is_read_back() {
    let dir = TempDir::new().unwrap();
    let (genesis, _keys, socket, handle, _join) = serve(&dir).await;

    let value = Value::Map(BTreeMap::from([(
        "servers".to_owned(),
        Value::Array(vec![Value::Map(BTreeMap::from([(
            "host".to_owned(),
            Value::String("a.example".to_owned()),
        )]))]),
    )]));
    let written = weak_set(&socket, key("cfg"), None, value.clone())
        .await
        .unwrap();
    assert_eq!(written.outcome, WriteOutcome::Extended);
    assert_eq!(written.head, written.digest);
    assert_ne!(written.head, genesis);
    assert_eq!(handle.head().await.unwrap(), written.head);

    let at = read(&socket, key("cfg"), None).await;
    assert_eq!(at.head, written.head);
    assert_eq!(at.value, Some(value));

    let at = read(&socket, key("cfg"), Some(path("servers[0].host"))).await;
    assert_eq!(at.value, Some(Value::String("a.example".to_owned())));

    let at = read(&socket, key("cfg"), Some(path("servers[1]"))).await;
    assert_eq!(at.value, None);
}

/// A weak set at a path replaces only what the path addresses.
#[tokio::test]
async fn a_weak_set_at_a_path_replaces_only_that_value() {
    let dir = TempDir::new().unwrap();
    let (_genesis, _keys, socket, _handle, _join) = serve(&dir).await;

    let map = |host: &str, port: i64| {
        Value::Map(BTreeMap::from([
            ("host".to_owned(), Value::String(host.to_owned())),
            ("port".to_owned(), Value::Int(port)),
        ]))
    };
    weak_set(&socket, key("cfg"), None, map("a.example", 80))
        .await
        .unwrap();

    let written = weak_set(&socket, key("cfg"), Some(path("port")), Value::Int(443))
        .await
        .unwrap();
    assert_eq!(written.outcome, WriteOutcome::Extended);

    let at = read(&socket, key("cfg"), None).await;
    assert_eq!(at.head, written.head);
    assert_eq!(at.value, Some(map("a.example", 443)));
}

/// The envelope a weak set writes carries the node's own signature, and
/// the chain verified it against the trusted key set.
#[tokio::test]
async fn a_weak_set_is_signed_by_the_node() {
    let dir = TempDir::new().unwrap();
    let (_genesis, _keys, socket, handle, _join) = serve(&dir).await;
    let node = handle.identity().await.unwrap().node;

    let written = weak_set(&socket, key("cfg"), None, Value::Bool(true))
        .await
        .unwrap();

    let frames = envelopes(&socket, GetEnvelopes::digests([written.digest])).await;
    let (_digest, envelope) = frames.into_iter().next().unwrap().into_parts();
    assert!(envelope.signatures().contains_key(&node));
    assert!(matches!(
        envelope.verification_status(),
        VerificationStatus::AllMatched { total_weight } if *total_weight > 0
    ));
}

/// A write the chain refuses — a path into a namespace that is not there —
/// is reported as rejected, and the head stays put.
#[tokio::test]
async fn a_weak_set_the_chain_refuses_is_rejected() {
    let dir = TempDir::new().unwrap();
    let (genesis, _keys, socket, handle, _join) = serve(&dir).await;

    let err = weak_set(&socket, key("cfg"), Some(path("port")), Value::Int(443))
        .await
        .unwrap_err();

    let Error::Failed(failure) = err else {
        panic!("expected a reported failure, got {err:?}");
    };
    assert_eq!(failure.kind, FailureKind::Rejected);
    assert_eq!(handle.head().await.unwrap(), genesis);
}

/// A weak set moves the head like any insert, so a watcher hears of it.
#[tokio::test]
async fn a_weak_set_wakes_a_watcher() {
    let dir = TempDir::new().unwrap();
    let (genesis, _keys, socket, _handle, _join) = serve(&dir).await;

    let stream = UnixStream::connect(&socket).await.unwrap();
    let mut watch = Call::send(
        stream,
        Watch {
            selector: WatchSelector::Namespace(key("cfg")),
        },
    )
    .await
    .unwrap();

    let written = weak_set(&socket, key("cfg"), None, Value::Int(1))
        .await
        .unwrap();

    let event = timeout(GRACE, watch.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let lotusd_rpc::WatchEvent::Changed(changed) = event else {
        panic!("expected a change, got {event:?}");
    };
    assert_eq!(changed.from, genesis);
    assert_eq!(changed.head, written.head);
}

/// A push appends to an array at a path, starts one under a map where
/// there was nothing, and extends a namespace that is one array.
#[tokio::test]
async fn a_weak_push_appends_to_an_array() {
    let dir = TempDir::new().unwrap();
    let (_genesis, _keys, socket, _handle, _join) = serve(&dir).await;
    let push = |path: Option<SubkeyPath>, n: i64| WeakPush {
        key: key("cfg"),
        path,
        value: Value::Int(n),
    };

    weak_set(&socket, key("cfg"), None, Value::Map(BTreeMap::new()))
        .await
        .unwrap();
    write(&socket, push(Some(path("xs")), 1)).await.unwrap();
    let written = write(&socket, push(Some(path("xs")), 2)).await.unwrap();
    assert_eq!(written.outcome, WriteOutcome::Extended);
    assert_eq!(
        value_at(&socket, key("cfg"), Some(path("xs"))).await,
        Some(Value::Array(vec![Value::Int(1), Value::Int(2)]))
    );

    weak_set(&socket, key("list"), None, Value::Array(vec![]))
        .await
        .unwrap();
    write(&socket, push(None, 7).with_key("list"))
        .await
        .unwrap();
    assert_eq!(
        value_at(&socket, key("list"), None).await,
        Some(Value::Array(vec![Value::Int(7)]))
    );
}

/// A push onto something that is not an array is rejected.
#[tokio::test]
async fn a_weak_push_onto_a_non_array_is_rejected() {
    let dir = TempDir::new().unwrap();
    let (_genesis, _keys, socket, _handle, _join) = serve(&dir).await;

    weak_set(&socket, key("cfg"), None, Value::Int(1))
        .await
        .unwrap();
    assert!(rejected(
        write(
            &socket,
            WeakPush {
                key: key("cfg"),
                path: None,
                value: Value::Int(2),
            },
        )
        .await
    ));
    assert_eq!(
        value_at(&socket, key("cfg"), None).await,
        Some(Value::Int(1))
    );
}

/// A delete at a path removes that value; without one it removes the
/// namespace. Deleting what is not there is rejected.
#[tokio::test]
async fn a_weak_delete_clears_a_value_or_a_namespace() {
    let dir = TempDir::new().unwrap();
    let (_genesis, _keys, socket, _handle, _join) = serve(&dir).await;
    let delete = |path: Option<SubkeyPath>| WeakDelete {
        key: key("cfg"),
        path,
    };

    weak_set(
        &socket,
        key("cfg"),
        None,
        Value::Map(BTreeMap::from([
            ("a".to_owned(), Value::Int(1)),
            ("b".to_owned(), Value::Int(2)),
        ])),
    )
    .await
    .unwrap();

    let written = write(&socket, delete(Some(path("a")))).await.unwrap();
    assert_eq!(written.outcome, WriteOutcome::Extended);
    assert_eq!(
        value_at(&socket, key("cfg"), None).await,
        Some(Value::Map(BTreeMap::from([(
            "b".to_owned(),
            Value::Int(2)
        )])))
    );
    assert!(rejected(write(&socket, delete(Some(path("a")))).await));

    write(&socket, delete(None)).await.unwrap();
    assert_eq!(value_at(&socket, key("cfg"), None).await, None);
    assert!(rejected(write(&socket, delete(None)).await));
}

/// A delete-matching removes the entries a predicate picks out of an
/// array by their content, lands even when nothing matches, and is
/// rejected where there is no container to search.
#[tokio::test]
async fn a_weak_delete_matching_removes_entries_by_content() {
    let dir = TempDir::new().unwrap();
    let (_genesis, _keys, socket, _handle, _join) = serve(&dir).await;
    let server = |id: &str| {
        Value::Map(BTreeMap::from([(
            "id".to_owned(),
            Value::String(id.to_owned()),
        )]))
    };
    let delete = |path: Option<SubkeyPath>, id: &str| WeakDeleteMatching {
        key: key("cfg"),
        path,
        predicate: Predicate::try_new(vec![Match::at(
            "id".parse().unwrap(),
            Value::String(id.to_owned()),
        )])
        .unwrap(),
    };

    weak_set(
        &socket,
        key("cfg"),
        None,
        Value::Map(BTreeMap::from([(
            "servers".to_owned(),
            Value::Array(vec![server("a"), server("b"), server("c")]),
        )])),
    )
    .await
    .unwrap();

    let written = write(&socket, delete(Some(path("servers")), "b"))
        .await
        .unwrap();
    assert_eq!(written.outcome, WriteOutcome::Extended);
    assert_eq!(
        value_at(&socket, key("cfg"), Some(path("servers"))).await,
        Some(Value::Array(vec![server("a"), server("c")]))
    );

    let written = write(&socket, delete(Some(path("servers")), "b"))
        .await
        .unwrap();
    assert_eq!(written.outcome, WriteOutcome::Extended, "idempotent");
    assert_eq!(
        value_at(&socket, key("cfg"), Some(path("servers"))).await,
        Some(Value::Array(vec![server("a"), server("c")]))
    );

    assert!(rejected(
        write(&socket, delete(Some(path("servers[0].id")), "a")).await
    ));
    assert!(rejected(
        write(&socket, delete(Some(path("nope")), "a")).await
    ));
}

/// An increment adds to the integer at a path, clamps to the bounds
/// given, and is rejected where there is no integer to add to.
#[tokio::test]
async fn a_weak_increment_adds_and_clamps() {
    let dir = TempDir::new().unwrap();
    let (_genesis, _keys, socket, _handle, _join) = serve(&dir).await;
    let increment = |path: Option<SubkeyPath>, delta: i64, max: Option<i64>| WeakIncrement {
        key: key("cfg"),
        path,
        delta,
        min: None,
        max,
    };

    weak_set(
        &socket,
        key("cfg"),
        None,
        Value::Map(BTreeMap::from([("n".to_owned(), Value::Int(5))])),
    )
    .await
    .unwrap();

    let written = write(&socket, increment(Some(path("n")), -2, None))
        .await
        .unwrap();
    assert_eq!(written.outcome, WriteOutcome::Extended);
    assert_eq!(
        value_at(&socket, key("cfg"), Some(path("n"))).await,
        Some(Value::Int(3))
    );

    write(&socket, increment(Some(path("n")), 100, Some(10)))
        .await
        .unwrap();
    assert_eq!(
        value_at(&socket, key("cfg"), Some(path("n"))).await,
        Some(Value::Int(10))
    );

    assert!(rejected(
        write(&socket, increment(Some(path("m")), 1, None)).await
    ));
    assert!(rejected(write(&socket, increment(None, 1, None)).await));

    weak_set(&socket, key("count"), None, Value::Int(0))
        .await
        .unwrap();
    write(&socket, increment(None, 1, None).with_key("count"))
        .await
        .unwrap();
    assert_eq!(
        value_at(&socket, key("count"), None).await,
        Some(Value::Int(1))
    );
}

/// Retargets a request built for one namespace at another.
trait WithKey {
    fn with_key(self, key: &str) -> Self;
}

impl WithKey for WeakPush {
    fn with_key(mut self, k: &str) -> Self {
        self.key = key(k);
        self
    }
}

impl WithKey for WeakIncrement {
    fn with_key(mut self, k: &str) -> Self {
        self.key = key(k);
        self
    }
}
