//! `lotusctl watch`, driven end to end: the real CLI binary, over a real
//! control socket, against a real daemon advancing a real chain.

use std::{process::Stdio, time::Duration};

use lotusd::{Core, IfInitialized, Server, ServerHandle};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::UnixListener,
    process::{Child, Command},
    task::JoinHandle,
    time::timeout,
};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, SetNamespaceKey, Value},
    subkey::SubkeyPath,
};

/// How long a step gets before we call it hung. Generous: this bounds a
/// test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(20);

/// Starts a daemon in `dir`, on the socket `lotusctl --state-dir dir` looks
/// for. The join handle is returned so the mainloop outlives the test.
async fn serve(dir: &TempDir) -> (EnvelopeDigest, ServerHandle, JoinHandle<()>) {
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let head = core.head();

    let listener = UnixListener::bind(dir.path().join("local.sock")).unwrap();
    let (handle, join) = Server::new(core, listener).unwrap().run().await;

    (head, handle, join)
}

/// Runs `lotusctl --state-dir dir --format json watch <args>`, with its
/// output piped back.
fn watch(dir: &TempDir, args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_lotusctl"))
        .arg("--state-dir")
        .arg(dir.path())
        .args(["--format", "json", "watch"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the CLI binary is built alongside this test")
}

/// Waits until the CLI's watch has reached the daemon, so an insert after
/// this is one the CLI is registered for.
async fn watching(handle: &ServerHandle) {
    timeout(GRACE, async {
        while handle.watchers().await.unwrap() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the CLI never registered a watch");
}

/// The next line the CLI printed, parsed.
async fn line(child: &mut Child) -> serde_json::Value {
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut lines = BufReader::new(stdout).lines();
    let line = timeout(GRACE, lines.next_line())
        .await
        .expect("the CLI printed nothing")
        .expect("reading the CLI's output")
        .expect("the CLI closed without printing");

    serde_json::from_str(&line).expect("each event is one JSON object")
}

/// The same, in the default text format a person reads.
fn watch_text(dir: &TempDir, args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_lotusctl"))
        .arg("--state-dir")
        .arg(dir.path())
        .arg("watch")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the CLI binary is built alongside this test")
}

/// Every line the CLI printed before exiting.
async fn output(child: Child) -> String {
    let out = timeout(GRACE, child.wait_with_output())
        .await
        .expect("the CLI did not exit")
        .expect("waiting on the CLI");
    assert!(out.status.success(), "lotusctl exited with {}", out.status);
    String::from_utf8(out.stdout).expect("the CLI writes text")
}

/// Waits for the CLI to exit, failing on a non-zero status.
async fn finish(mut child: Child) {
    let status = timeout(GRACE, child.wait())
        .await
        .expect("the CLI did not exit")
        .expect("waiting on the CLI");
    assert!(status.success(), "lotusctl exited with {status}");
}

fn key(k: &str) -> NamespaceKey {
    NamespaceKey::try_new(k).unwrap()
}

fn path(text: &str) -> SubkeyPath {
    text.parse().unwrap()
}

/// A namespace with two leaves, so writes inside it can miss each other.
fn pair(prev: EnvelopeDigest, k: &str) -> Envelope {
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
    }))
}

fn set_ns(prev: EnvelopeDigest, k: &str, v: &str) -> Envelope {
    Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: key(k),
        namespace: Namespace {
            value: Value::String(v.to_string()),
        },
    }))
}

fn set_key(prev: EnvelopeDigest, k: &str, p: &str, v: &str) -> Envelope {
    Envelope::new(Msg::SetNamespaceKey(SetNamespaceKey {
        prev,
        key: key(k),
        path: path(p),
        value: Some(Value::String(v.to_string())),
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

/// How a digest is written in the CLI's JSON: the same `ed:`-prefixed hex
/// the rest of the protocol uses.
fn wire_hex(digest: EnvelopeDigest) -> String {
    format!("ed:{}", digest.to_hex().as_ref())
}

#[tokio::test]
async fn watch_head_reports_the_movement_it_saw() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;

    let mut child = watch(&dir, &["head", "-n", "1"]);
    watching(&handle).await;

    let envelope = set_ns(head, "a", "1");
    handle.insert([envelope.clone()]).await.unwrap();

    let event = line(&mut child).await;
    assert_eq!(event["event"], "changed");
    assert_eq!(event["from"], wire_hex(head));
    assert_eq!(event["head"], wire_hex(envelope.digest().unwrap()));
    assert!(event["changes"]["a"].is_array());
    finish(child).await;
}

/// A namespace watch stays quiet for a write elsewhere and reports the one
/// it was asked about — what makes it a filter rather than a feed.
#[tokio::test]
async fn watch_namespace_skips_the_namespaces_it_was_not_asked_about() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;

    let mut child = watch(&dir, &["namespace", "b", "-n", "1"]);
    watching(&handle).await;

    handle.insert([set_ns(head, "a", "1")]).await.unwrap();
    let watched = set_ns(handle.head().await.unwrap(), "b", "2");
    handle.insert([watched.clone()]).await.unwrap();

    let event = line(&mut child).await;
    assert_eq!(event["event"], "changed");
    // Woken by the second insert, so the first is behind it.
    assert_eq!(event["head"], wire_hex(watched.digest().unwrap()));
    assert!(event["changes"]["b"].is_array());
    finish(child).await;
}

/// The path form the CLI takes is the one the daemon reports back.
#[tokio::test]
async fn watch_path_reports_the_path_that_changed() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;
    handle.insert([pair(head, "a")]).await.unwrap();

    let mut child = watch(&dir, &["path", "a", "host", "-n", "1"]);
    watching(&handle).await;

    // A sibling first: the watch must sleep through it.
    let sibling = set_key(handle.head().await.unwrap(), "a", "port", "9");
    handle.insert([sibling]).await.unwrap();
    let watched = set_key(handle.head().await.unwrap(), "a", "host", "two");
    handle.insert([watched.clone()]).await.unwrap();

    let event = line(&mut child).await;
    assert_eq!(event["head"], wire_hex(watched.digest().unwrap()));
    assert_eq!(event["changes"]["a"], serde_json::json!(["host"]));
    finish(child).await;
}

/// A namespace written whole reports no paths, which is how the two shapes
/// of a change are told apart.
#[tokio::test]
async fn a_whole_namespace_write_reports_no_paths() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;

    let mut child = watch(&dir, &["namespace", "a", "-n", "1"]);
    watching(&handle).await;

    handle.insert([set_ns(head, "a", "1")]).await.unwrap();

    let event = line(&mut child).await;
    assert_eq!(event["changes"]["a"], serde_json::json!([]));
    finish(child).await;
}

/// The headline case: an envelope rewritten out of history reaches whoever
/// was watching it.
#[tokio::test]
async fn watch_orphaned_reports_the_envelope_leaving_the_chain() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;
    let (winner, loser) = ranked(set_ns(head, "a", "1"), set_ns(head, "b", "2"));
    handle.insert([loser.clone()]).await.unwrap();

    let orphan = loser.digest().unwrap();
    let mut child = watch(&dir, &["orphaned", orphan.to_hex().as_ref(), "-n", "1"]);
    watching(&handle).await;

    handle.insert([winner]).await.unwrap();

    let event = line(&mut child).await;
    assert_eq!(event["event"], "changed");
    assert_eq!(
        event["orphaned"],
        serde_json::json!([orphan.to_hex().as_ref()])
    );
    finish(child).await;
}

/// Watching an envelope already off the chain is answered at once and the
/// stream closed, rather than left open on an event that can never come.
/// No `-n` needed: the daemon ends it.
#[tokio::test]
async fn watch_orphaned_answers_at_once_for_an_envelope_already_gone() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;
    let (winner, loser) = ranked(set_ns(head, "a", "1"), set_ns(head, "b", "2"));
    handle.insert([winner]).await.unwrap();
    // The loser never became canonical.
    handle.insert([loser.clone()]).await.unwrap();
    let orphan = loser.digest().unwrap();

    let mut child = watch(&dir, &["orphaned", orphan.to_hex().as_ref()]);

    let event = line(&mut child).await;
    assert_eq!(event["event"], "already_orphaned");
    assert_eq!(event["digest"], orphan.to_hex().as_ref());
    finish(child).await;
}

/// The daemon going away ends the watch rather than hanging the CLI.
#[tokio::test]
async fn a_watch_ends_when_the_daemon_shuts_down() {
    let dir = TempDir::new().unwrap();
    let (_head, handle, join) = serve(&dir).await;

    let child = watch(&dir, &["head"]);
    watching(&handle).await;

    handle.shutdown().await.unwrap();
    join.await.unwrap();

    finish(child).await;
}

/// The default format is the one a person reads, so it gets a look too.
#[tokio::test]
async fn watch_renders_a_readable_block_by_default() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;
    handle.insert([pair(head, "a")]).await.unwrap();

    let child = watch_text(&dir, &["head", "-n", "1"]);
    watching(&handle).await;

    let from = handle.head().await.unwrap();
    let watched = set_key(from, "a", "host", "two");
    handle.insert([watched.clone()]).await.unwrap();

    let text = output(child).await;
    assert_eq!(
        text,
        format!(
            "changed  {} -> {}\n  a  host\n",
            from.to_hex().as_ref(),
            watched.digest().unwrap().to_hex().as_ref(),
        ),
    );
}

/// A namespace written whole says so rather than listing nothing.
#[tokio::test]
async fn a_whole_namespace_write_reads_as_such() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;

    let child = watch_text(&dir, &["namespace", "a", "-n", "1"]);
    watching(&handle).await;

    handle.insert([set_ns(head, "a", "1")]).await.unwrap();

    assert!(
        output(child).await.contains("  a  (whole namespace)"),
        "the whole-namespace case must be named, not left blank",
    );
}
