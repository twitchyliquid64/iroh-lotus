//! The local control socket, end to end: a client connects, asks one
//! question, and the running daemon answers it out of its core.

use std::{path::PathBuf, time::Duration};

use lotusd::{Core, IfInitialized, Server, ServerHandle, VERSION};
use lotusd_rpc::{Call, GetChainRange, GetVersion, Watch, WatchSelector, call};
use tempfile::TempDir;
use tokio::{net::UnixStream, task::JoinHandle, time::timeout};
use wire::EnvelopeDigest;

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
