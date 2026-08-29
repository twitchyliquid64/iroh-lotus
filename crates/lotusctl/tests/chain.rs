//! `lotusctl chain` and `lotusctl show`, driven end to end: the real CLI
//! binary, over a real control socket, against a real daemon holding a
//! real chain.

use std::{process::Stdio, time::Duration};

use lotusd::{Core, IfInitialized, Server, ServerHandle};
use tempfile::TempDir;
use tokio::{net::UnixListener, process::Command, task::JoinHandle, time::timeout};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
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

/// A write onto `prev`.
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

/// What `lotusctl --state-dir dir <args>` printed, and whether it succeeded.
async fn run(dir: &TempDir, args: &[&str]) -> (bool, String) {
    let out = timeout(
        GRACE,
        Command::new(env!("CARGO_BIN_EXE_lotusctl"))
            .arg("--state-dir")
            .arg(dir.path())
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the CLI binary is built alongside this test")
            .wait_with_output(),
    )
    .await
    .expect("the CLI did not exit")
    .expect("waiting on the CLI");

    (
        out.status.success(),
        String::from_utf8(out.stdout).expect("the CLI writes text"),
    )
}

/// The same, failing the test on a non-zero exit.
async fn output(dir: &TempDir, args: &[&str]) -> String {
    let (ok, text) = run(dir, args).await;
    assert!(ok, "lotusctl {args:?} failed, printing {text}");
    text
}

fn hex(digest: EnvelopeDigest) -> String {
    digest.to_hex().as_ref().to_string()
}

/// A cluster three envelopes deep, with the daemon serving it.
async fn chain_of_three(dir: &TempDir) -> ([EnvelopeDigest; 3], ServerHandle, JoinHandle<()>) {
    let (head, handle, join) = serve(dir).await;

    let first = set_ns(head, "one");
    handle.insert([first.clone()]).await.unwrap();
    let second = set_ns(first.digest().unwrap(), "two");
    handle.insert([second.clone()]).await.unwrap();

    (
        [head, first.digest().unwrap(), second.digest().unwrap()],
        handle,
        join,
    )
}

/// The whole chain, oldest first, with both ends marked — the printout an
/// operator reaches for first.
#[tokio::test]
async fn chain_prints_every_envelope_the_daemon_holds() {
    let dir = TempDir::new().unwrap();
    let ([root, middle, head], _handle, _join) = chain_of_three(&dir).await;

    let text = output(&dir, &["chain"]).await;

    assert!(
        text.starts_with(&format!(
            "3 envelopes on {}\n\n#0 {}  [root]\n",
            dir.path().join("local.sock").display(),
            hex(root),
        )),
        "got {text}",
    );
    assert!(
        text.contains(&format!("#1 {}\n", hex(middle))),
        "got {text}"
    );
    assert!(
        text.contains(&format!("#2 {}  [head]\n", hex(head))),
        "got {text}",
    );
    // The genesis is signed at init, so the weight it carries has to survive
    // the trip over the socket.
    assert!(
        text.contains("verification   all matched, weight 2"),
        "got {text}",
    );
}

/// When the daemon's log took each envelope is shown — the reason for
/// recording it at all, since nothing else may read it.
#[tokio::test]
async fn chain_shows_when_the_daemon_stored_each_envelope() {
    let dir = TempDir::new().unwrap();
    let (_digests, _handle, _join) = chain_of_three(&dir).await;
    // Local, as the renderer prints it: a UTC date is tomorrow's for part of
    // every evening west of Greenwich.
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();

    let text = output(&dir, &["chain"]).await;

    assert_eq!(
        text.matches("   stored         ").count(),
        3,
        "every envelope carries the time it was stored: {text}",
    );
    assert_eq!(
        text.matches(&format!("   stored         {today} ")).count(),
        3,
        "got {text}",
    );
}

/// The window is parsed here and applied by the daemon: a wide one takes
/// in the whole chain, a zero one takes in nothing, and a limit still
/// bounds what the window let through.
///
/// Where the boundary falls between those two is settled in the daemon's
/// own tests. From here it cannot be: the window is measured from when
/// the daemon serves the request, and everything between the insert and
/// that point — spawning this process, linking it, connecting — is time
/// no window can be sized against.
#[tokio::test]
async fn chain_since_bounds_what_is_printed() {
    let dir = TempDir::new().unwrap();
    let ([root, _middle, head], _handle, _join) = chain_of_three(&dir).await;

    let text = output(&dir, &["chain", "--since", "1h"]).await;
    assert!(text.starts_with("3 envelopes on "), "got {text}");
    assert!(
        text.contains(&hex(root)) && text.contains(&hex(head)),
        "got {text}"
    );

    // Nothing was stored after the request went out, and starting a
    // process takes far longer than the millisecond the stamps are kept
    // to, so nothing falls inside a window that ends on arrival.
    let text = output(&dir, &["chain", "--since", "0s"]).await;
    assert!(text.starts_with("0 envelopes on "), "got {text}");

    // The two bounds combine, the tighter one winning.
    let text = output(&dir, &["chain", "--since", "1h", "-n", "1"]).await;
    assert!(text.starts_with("1 envelope on "), "got {text}");
    assert!(
        text.contains(&format!("#0 {}  [head]\n", hex(head))),
        "got {text}"
    );
}

/// A window nobody could have meant is refused before the daemon is asked,
/// rather than read as some other window.
#[tokio::test]
async fn chain_refuses_a_window_it_cannot_read() {
    let dir = TempDir::new().unwrap();
    let (_digests, _handle, _join) = chain_of_three(&dir).await;

    let (ok, _text) = run(&dir, &["chain", "--since", "yesterday"]).await;
    assert!(!ok, "an unreadable window must not exit zero");

    let (ok, _text) = run(&dir, &["chain", "--since", "5w"]).await;
    assert!(!ok, "an unsupported unit must not exit zero");
}

/// The limit keeps the newest end, so the head is always in what is shown.
#[tokio::test]
async fn chain_takes_a_limit_from_the_head_end() {
    let dir = TempDir::new().unwrap();
    let ([root, middle, head], _handle, _join) = chain_of_three(&dir).await;

    let text = output(&dir, &["chain", "-n", "2"]).await;

    assert!(text.starts_with("2 envelopes on "), "got {text}");
    assert!(
        text.contains(&format!("#0 {}\n", hex(middle))),
        "got {text}"
    );
    assert!(
        text.contains(&format!("#1 {}  [head]\n", hex(head))),
        "got {text}"
    );
    // Still named as the middle envelope's parent, but no longer shown.
    assert!(!text.contains(&format!("#0 {}", hex(root))), "got {text}");
}

/// JSON carries the envelope itself, not a summary of it: the verification
/// status rides beside the envelope, since the ledger encoding has no room
/// for it.
#[tokio::test]
async fn chain_renders_json_when_asked() {
    let dir = TempDir::new().unwrap();
    let ([root, _middle, _head], _handle, _join) = chain_of_three(&dir).await;

    let text = output(&dir, &["--format", "json", "chain"]).await;
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("one JSON document");

    let entries = parsed.as_array().expect("an array of envelopes");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["digest"], format!("ed:{}", hex(root)));
    assert_eq!(entries[0]["verification"]["all_matched"], 2);
    // The wire crate's own JSON representation, not a shape invented here.
    assert_eq!(entries[0]["envelope"]["payload"]["type"], "init");
    assert!(entries[0]["envelope"]["signatures"].is_object());
}

/// Nothing is coloured unless asked: the tests, and every pipe, read the
/// plain rendering.
#[tokio::test]
async fn colour_is_off_when_the_output_is_not_a_terminal() {
    let dir = TempDir::new().unwrap();
    let (_digests, _handle, _join) = chain_of_three(&dir).await;

    assert!(!output(&dir, &["chain"]).await.contains('\x1b'));

    let forced = output(&dir, &["--color", "always", "chain"]).await;
    assert!(forced.contains("\x1b["), "nothing was coloured");
    assert!(forced.contains("\x1b[0m"), "nothing was reset");
}

/// `show` reads the log rather than the chain, which is the only way to
/// look at an envelope a reorg has rewritten out of history.
#[tokio::test]
async fn show_prints_an_envelope_that_has_left_the_chain() {
    let dir = TempDir::new().unwrap();
    let (head, handle, _join) = serve(&dir).await;

    let (winner, loser) = ranked(set_ns(head, "one"), set_ns(head, "two"));
    handle.insert([loser.clone()]).await.unwrap();
    handle.insert([winner]).await.unwrap();
    let orphan = loser.digest().unwrap();

    assert!(!output(&dir, &["chain"]).await.contains(&hex(orphan)));

    let text = output(&dir, &["show", &hex(orphan)]).await;
    // Unnumbered: nothing says where an envelope off the chain sits.
    assert!(
        text.starts_with(&format!("{}\n", hex(orphan))),
        "got {text}"
    );
    assert!(
        text.contains("message        set namespace cfg"),
        "got {text}"
    );
}

/// Several digests print in the order asked for.
#[tokio::test]
async fn show_prints_what_it_was_asked_for_in_order() {
    let dir = TempDir::new().unwrap();
    let ([root, _middle, head], _handle, _join) = chain_of_three(&dir).await;

    let text = output(&dir, &["show", &hex(head), &hex(root)]).await;

    assert!(text.find(&hex(head)) < text.find(&hex(root)), "got {text}",);
    assert!(text.contains("[head]"), "got {text}");
    assert!(text.contains("[root]"), "got {text}");
}

/// A digest the daemon does not hold is an error, not a silent success —
/// but it does not cost the answer to the digests that were held.
#[tokio::test]
async fn show_reports_a_digest_the_daemon_does_not_hold() {
    let dir = TempDir::new().unwrap();
    let ([root, _middle, _head], _handle, _join) = chain_of_three(&dir).await;
    let unknown = hex(EnvelopeDigest::from_bytes([0xab; 32]));

    let (ok, text) = run(&dir, &["show", &hex(root), &unknown]).await;

    assert!(!ok, "a missing envelope must not exit zero");
    assert!(text.contains(&hex(root)), "got {text}");
}
