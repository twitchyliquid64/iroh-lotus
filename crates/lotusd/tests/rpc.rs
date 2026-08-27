//! The local control socket, end to end: a client connects, asks one
//! question, and the running daemon answers it out of its core.

use std::path::PathBuf;

use lotusd::{Core, IfInitialized, Server, ServerHandle, VERSION};
use lotusd_rpc::{GetHead, GetVersion, call};
use tempfile::TempDir;
use tokio::{net::UnixStream, task::JoinHandle};
use wire::EnvelopeDigest;

/// Starts a server on a fresh cluster in `dir`, alongside the head it began
/// at and the socket clients reach it on.
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
async fn get_head_answers_with_the_head_the_core_stands_at() {
    let dir = TempDir::new().unwrap();
    let (head, path, _handle, _join) = serve(&dir).await;

    let stream = UnixStream::connect(&path).await.unwrap();
    assert_eq!(call(stream, GetHead {}).await.unwrap(), head);
}

#[tokio::test]
async fn each_connection_carries_its_own_request() {
    let dir = TempDir::new().unwrap();
    let (head, path, _handle, _join) = serve(&dir).await;

    for _ in 0..3 {
        let stream = UnixStream::connect(&path).await.unwrap();
        assert_eq!(call(stream, GetHead {}).await.unwrap(), head);
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
                call(stream, GetHead {}).await.unwrap()
            })
        })
        .collect();

    for answer in calls {
        assert_eq!(answer.await.unwrap(), head);
    }
}
