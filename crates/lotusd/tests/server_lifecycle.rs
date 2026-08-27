//! The mainloop `Server::run` spawns must answer queries while it is up and
//! come down cleanly, by either route out of the loop: an explicit shutdown,
//! or the last handle being dropped.

use std::time::Duration;

use lotusd::{Core, IfInitialized, Server, ServerHandle};
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
