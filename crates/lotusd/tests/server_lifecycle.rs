//! The mainloop `Server::run` spawns must answer queries while it is up and
//! come down cleanly, by either route out of the loop: an explicit shutdown,
//! or the last handle being dropped.

use std::time::Duration;

use iroh::{Endpoint, RelayMode, endpoint::presets};
use lotusd::{Core, IfInitialized, Server, ServerHandle, peer_ingress::Protocol};
use tempfile::TempDir;
use tokio::{net::UnixListener, task::JoinHandle, time::timeout};
use wire::EnvelopeDigest;

/// How long a lifecycle step gets before we call it hung. Generous: this
/// bounds a test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(5);

/// Starts a server on a fresh cluster in `dir`, alongside the head it began at.
async fn serve(dir: &TempDir) -> (EnvelopeDigest, ServerHandle, JoinHandle<()>) {
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let head = core.head();

    // Short name on purpose: a unix socket path has to fit in SUN_LEN.
    let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    let (handle, join) = Server::new(core, listener).unwrap().run().await;

    (head, handle, join)
}

/// Starts a server serving peers on its own endpoint, so the mainloop has
/// the child actors under it that a bare one has not.
async fn serve_with_peers(dir: &TempDir) -> (ServerHandle, JoinHandle<()>) {
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .alpns(Protocol::alpns())
        .bind()
        .await
        .unwrap();
    Server::new(core, listener)
        .unwrap()
        .with_endpoint(endpoint)
        .run()
        .await
}

/// The first thing asked of a just-started server is answered — the
/// child actors have not been polled yet, so an actor that had to ask
/// the mainloop for anything before serving its own channel would wedge
/// the pair: the mainloop waiting on the actor, the actor on the mainloop.
#[tokio::test]
async fn the_first_query_after_start_is_answered_before_the_actors_run() {
    let dir = TempDir::new().unwrap();
    let (handle, _join) = serve_with_peers(&dir).await;

    let peers = timeout(GRACE, handle.peers())
        .await
        .expect("peers deadlocked against the actors starting")
        .unwrap();
    assert!(peers.is_empty());
    timeout(GRACE, handle.peer_connections())
        .await
        .expect("peer connections deadlocked against the actors starting")
        .unwrap();
    timeout(GRACE, handle.published())
        .await
        .expect("published deadlocked against the actors starting")
        .unwrap();
}

/// Same race, on the way out: a shutdown that lands before the actors
/// have run must still bring them down.
#[tokio::test]
async fn shutdown_before_the_actors_run_still_completes() {
    let dir = TempDir::new().unwrap();
    let (handle, join) = serve_with_peers(&dir).await;

    timeout(GRACE, handle.shutdown())
        .await
        .expect("shutdown deadlocked against the actors starting")
        .unwrap();
    timeout(GRACE, join).await.unwrap().unwrap();
}

#[tokio::test]
async fn head_answers_with_the_head_the_core_started_at() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;

    assert_eq!(handle.head().await.unwrap(), head);
}

#[tokio::test]
async fn root_answers_with_the_genesis_a_fresh_cluster_was_founded_on() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;

    // One envelope in, so the chain's oldest is also the head.
    assert_eq!(handle.root().await.unwrap(), head);
}

#[tokio::test]
async fn chain_range_answers_with_both_ends_at_once() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;

    let range = handle.chain_range().await.unwrap();
    assert_eq!(range.root, head);
    assert_eq!(range.head, head);
}

#[tokio::test]
async fn head_is_answerable_more_than_once() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;

    for _ in 0..3 {
        assert_eq!(handle.head().await.unwrap(), head);
    }
}

#[tokio::test]
async fn shutdown_resolves_once_the_mainloop_is_done() {
    let dir = TempDir::new().unwrap();
    let (_head, handle, join) = serve(&dir).await;

    // The sequence `main` runs on SIGINT.
    assert!(handle.shutdown().await.is_ok());
    timeout(GRACE, join)
        .await
        .expect("mainloop should exit once shutdown is acknowledged")
        .unwrap();
}

#[tokio::test]
async fn a_shut_down_server_answers_nothing() {
    let dir = TempDir::new().unwrap();
    let (_head, handle, _join) = serve(&dir).await;
    handle.shutdown().await.unwrap();

    assert!(handle.head().await.is_err());
    assert!(handle.root().await.is_err());
    assert!(handle.shutdown().await.is_err());
}

#[tokio::test]
async fn dropping_the_last_handle_stops_the_mainloop() {
    let dir = TempDir::new().unwrap();
    let (_head, handle, join) = serve(&dir).await;

    let clone = handle.clone();
    drop(handle);
    // Still one handle alive, so the loop is still up.
    assert!(clone.head().await.is_ok());

    drop(clone);
    timeout(GRACE, join)
        .await
        .expect("mainloop should exit once every handle is gone")
        .unwrap();
}
