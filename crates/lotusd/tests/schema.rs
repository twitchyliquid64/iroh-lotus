//! Schemas, end to end: written over the control socket like any other
//! value, and from then on the daemon refuses what breaks them.

use std::path::{Path, PathBuf};

use lotusd::{Core, IfInitialized, Server, ServerHandle};
use lotusd_rpc::{
    AnsweredOnce, Error, FailureKind, Method, Read, WeakDelete, WeakIncrement, WeakPush, WeakSet,
    Written, call,
};
use state::SCHEMA_KEY;
use tempfile::TempDir;
use tokio::{net::UnixStream, task::JoinHandle};
use wire::{
    msg::{NamespaceKey, Value},
    subkey::SubkeyPath,
};

/// Starts a server on the cluster in `core`, alongside the socket clients
/// reach it on.
///
/// The handle comes back for the caller to hold: the mainloop stops as soon
/// as the last one is dropped.
async fn serve(dir: &TempDir, core: Core) -> (PathBuf, ServerHandle, JoinHandle<()>) {
    // Short name on purpose: a unix socket path has to fit in SUN_LEN.
    let path = dir.path().join("s.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (handle, join) = Server::new(core, listener).unwrap().run().await;
    (path, handle, join)
}

/// Starts a server on a fresh cluster in `dir`.
async fn fresh(dir: &TempDir) -> (PathBuf, ServerHandle, JoinHandle<()>) {
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    serve(dir, core).await
}

fn key(k: &str) -> NamespaceKey {
    NamespaceKey::try_new(k).unwrap()
}

fn path(text: &str) -> Option<SubkeyPath> {
    Some(text.parse().unwrap())
}

fn map(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    entries.into_iter().collect()
}

/// Sends any weak write over the socket.
async fn write<M>(socket: &Path, request: M) -> Result<Written, Error>
where
    M: AnsweredOnce + Method<Response = Written>,
{
    let stream = UnixStream::connect(socket).await.unwrap();
    call(stream, request).await
}

/// Writes `value` to `k` at `path` over the socket.
async fn set(
    socket: &Path,
    k: &str,
    path: Option<SubkeyPath>,
    value: Value,
) -> Result<Written, Error> {
    write(
        socket,
        WeakSet {
            key: key(k),
            path,
            value,
        },
    )
    .await
}

/// The value `k` holds at `path`.
async fn value_at(socket: &Path, k: &str, path: Option<SubkeyPath>) -> Option<Value> {
    let stream = UnixStream::connect(socket).await.unwrap();
    call(stream, Read { key: key(k), path })
        .await
        .unwrap()
        .value
}

/// What the daemon said when it rejected a write — as opposed to doing
/// it, or breaking.
fn rejection(result: Result<Written, Error>) -> String {
    match result {
        Err(Error::Failed(failure)) if failure.kind == FailureKind::Rejected => failure.message,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

/// `{host: "a.example", port: 80, tags: ["x"]}`.
fn cfg() -> Value {
    map([
        ("host", "a.example".into()),
        ("port", 80.into()),
        ("tags", ["x"].into_iter().collect()),
    ])
}

/// The schema [`cfg`] conforms to: `host` required, `port` a port number,
/// `tags` at most two strings.
fn cfg_schema() -> Value {
    map([
        ("type", "struct".into()),
        ("required", ["host"].into_iter().collect()),
        (
            "fields",
            map([
                (
                    "host",
                    map([("type", "string".into()), ("min_len", 1.into())]),
                ),
                (
                    "port",
                    map([
                        ("type", "int".into()),
                        ("min", 1.into()),
                        ("max", 65535.into()),
                    ]),
                ),
                (
                    "tags",
                    map([
                        ("type", "array".into()),
                        ("items", map([("type", "string".into())])),
                        ("max_len", 2.into()),
                    ]),
                ),
            ]),
        ),
    ])
}

/// A daemon holding [`cfg`] under `cfg`, with [`cfg_schema`] in force.
async fn governed(dir: &TempDir) -> (PathBuf, ServerHandle, JoinHandle<()>) {
    let (socket, handle, join) = fresh(dir).await;
    set(&socket, "cfg", None, cfg()).await.unwrap();
    set(&socket, SCHEMA_KEY, None, map([("cfg", cfg_schema())]))
        .await
        .unwrap();
    (socket, handle, join)
}

/// A schema is written like any value, and reads back as one.
#[tokio::test]
async fn a_schema_is_written_and_read_like_any_value() {
    let dir = TempDir::new().unwrap();
    let (socket, _handle, _join) = governed(&dir).await;

    assert_eq!(
        value_at(&socket, SCHEMA_KEY, path("cfg")).await,
        Some(cfg_schema())
    );
    assert_eq!(
        value_at(&socket, SCHEMA_KEY, path("cfg.fields.port.max")).await,
        Some(Value::Int(65535))
    );
}

#[tokio::test]
async fn writes_that_keep_to_the_schema_are_accepted() {
    let dir = TempDir::new().unwrap();
    let (socket, _handle, _join) = governed(&dir).await;

    set(&socket, "cfg", path("port"), Value::Int(443))
        .await
        .unwrap();
    write(
        &socket,
        WeakPush {
            key: key("cfg"),
            path: path("tags"),
            value: "y".into(),
        },
    )
    .await
    .unwrap();

    assert_eq!(
        value_at(&socket, "cfg", None).await,
        Some(map([
            ("host", "a.example".into()),
            ("port", 443.into()),
            ("tags", ["x", "y"].into_iter().collect()),
        ]))
    );
}

/// A write that breaks the schema is rejected with where and how, and
/// neither the head nor the value moves.
#[tokio::test]
async fn a_write_that_breaks_the_schema_is_rejected() {
    let dir = TempDir::new().unwrap();
    let (socket, handle, _join) = governed(&dir).await;
    let head = handle.head().await.unwrap();

    assert_eq!(
        rejection(set(&socket, "cfg", path("port"), Value::Int(70000)).await),
        "namespace cfg breaks its schema: 70000 is out of range, must be 1 to 65535 at port"
    );
    assert_eq!(
        rejection(set(&socket, "cfg", None, "flat".into()).await),
        "namespace cfg breaks its schema: expected map, found string"
    );
    assert_eq!(
        rejection(set(&socket, "cfg", path("colour"), "red".into()).await),
        "namespace cfg breaks its schema: unknown field `colour`"
    );

    assert_eq!(handle.head().await.unwrap(), head);
    assert_eq!(value_at(&socket, "cfg", None).await, Some(cfg()));
}

/// Amends and deletes are judged by what they would leave behind.
#[tokio::test]
async fn amends_and_deletes_are_held_to_the_schema() {
    let dir = TempDir::new().unwrap();
    let (socket, _handle, _join) = governed(&dir).await;
    let push = |value: Value| WeakPush {
        key: key("cfg"),
        path: path("tags"),
        value,
    };

    assert_eq!(
        rejection(write(&socket, push(7.into())).await),
        "namespace cfg breaks its schema: expected string, found int at tags[1]"
    );
    write(&socket, push("y".into())).await.unwrap();
    assert_eq!(
        rejection(write(&socket, push("z".into())).await),
        "namespace cfg breaks its schema: length 3 is out of range, must be at most 2 at tags"
    );

    let increment = WeakIncrement {
        key: key("cfg"),
        path: path("port"),
        delta: 70000,
        min: None,
        max: None,
    };
    assert_eq!(
        rejection(write(&socket, increment).await),
        "namespace cfg breaks its schema: 70080 is out of range, must be 1 to 65535 at port"
    );

    let delete = |at: &str| WeakDelete {
        key: key("cfg"),
        path: path(at),
    };
    assert_eq!(
        rejection(write(&socket, delete("host")).await),
        "namespace cfg breaks its schema: required field `host` is missing"
    );
    write(&socket, delete("port")).await.unwrap();
}

/// A schema the namespace already breaks is rejected, so what a schema
/// governs always conforms to it.
#[tokio::test]
async fn a_schema_its_namespace_breaks_is_rejected() {
    let dir = TempDir::new().unwrap();
    let (socket, _handle, _join) = fresh(&dir).await;
    set(&socket, "cfg", None, cfg()).await.unwrap();

    let schemas = map([("cfg", map([("type", "int".into())]))]);
    assert_eq!(
        rejection(set(&socket, SCHEMA_KEY, None, schemas).await),
        "namespace cfg breaks its schema: expected int, found map"
    );
    assert_eq!(value_at(&socket, SCHEMA_KEY, None).await, None);

    // Tightening one keyword in place is the same question.
    set(&socket, SCHEMA_KEY, None, map([("cfg", cfg_schema())]))
        .await
        .unwrap();
    assert_eq!(
        rejection(set(&socket, SCHEMA_KEY, path("cfg.fields.port.max"), 79.into()).await),
        "namespace cfg breaks its schema: 80 is out of range, must be 1 to 79 at port"
    );
}

#[tokio::test]
async fn a_malformed_schema_is_rejected() {
    let dir = TempDir::new().unwrap();
    let (socket, _handle, _join) = governed(&dir).await;

    let schemas = map([("cfg", map([("type", "float".into())]))]);
    assert_eq!(
        rejection(set(&socket, SCHEMA_KEY, None, schemas).await),
        "namespace _lotus_schema refused the value: \
         the schema for cfg is invalid: unknown type `float`"
    );
    assert_eq!(
        rejection(
            set(
                &socket,
                SCHEMA_KEY,
                path("cfg.fields.host.pattern"),
                ".*".into()
            )
            .await
        ),
        "namespace _lotus_schema refused the value: \
         the schema for cfg is invalid: unknown keyword `pattern` at fields.host"
    );
    let reserved = map([("type", "any".into())]);
    assert_eq!(
        rejection(set(&socket, SCHEMA_KEY, path("_lotus_nodes"), reserved).await),
        "namespace _lotus_schema refused the value: \
         _lotus_nodes is reserved and cannot be given a schema"
    );

    assert_eq!(
        value_at(&socket, SCHEMA_KEY, None).await,
        Some(map([("cfg", cfg_schema())]))
    );
}

#[tokio::test]
async fn removing_a_schema_lifts_it() {
    let dir = TempDir::new().unwrap();
    let (socket, _handle, _join) = governed(&dir).await;

    write(
        &socket,
        WeakDelete {
            key: key(SCHEMA_KEY),
            path: path("cfg"),
        },
    )
    .await
    .unwrap();

    set(&socket, "cfg", None, "flat".into()).await.unwrap();
    assert_eq!(value_at(&socket, "cfg", None).await, Some("flat".into()));
}

#[tokio::test]
async fn a_schema_leaves_other_namespaces_alone() {
    let dir = TempDir::new().unwrap();
    let (socket, _handle, _join) = governed(&dir).await;

    set(&socket, "other", None, "anything".into())
        .await
        .unwrap();
}

/// The schema is ledger state, so it binds a daemon reopened on the same
/// state directory as it bound the one that wrote it.
#[tokio::test]
async fn a_schema_still_binds_after_a_restart() {
    let dir = TempDir::new().unwrap();
    let (socket, handle, join) = governed(&dir).await;
    handle.shutdown().await.unwrap();
    join.await.unwrap();
    std::fs::remove_file(&socket).unwrap();

    let core = Core::init_with_state_dir(dir.path().to_path_buf())
        .await
        .unwrap();
    let (socket, _handle, _join) = serve(&dir, core).await;

    assert_eq!(
        rejection(set(&socket, "cfg", path("port"), Value::Int(0)).await),
        "namespace cfg breaks its schema: 0 is out of range, must be 1 to 65535 at port"
    );
    set(&socket, "cfg", path("port"), Value::Int(8080))
        .await
        .unwrap();
}
