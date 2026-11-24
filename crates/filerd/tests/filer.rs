//! A filer end to end: against a real daemon over its control socket, and
//! real iroh endpoints on an in-memory network.

use std::time::Duration;

use filer_client::{Session, Ticket};
use filer_proto::{
    Close, Hello, Mode, VolumeName, Welcome,
    fs::{Create, Errno, Lookup, Name, NodeId, Read, Reply, Request, Write},
    read_frame, write_frame,
};
use filerd::{
    Backing, Filer, FilerHandle, Standing, View,
    ledger::{self, ALLOWED_CLIENTS, ENDPOINT},
};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey,
    endpoint::{Connection, ConnectionError, presets},
    test_utils::test_transport::TestNetwork,
};
use lotus_sdk::{Client, NamespaceKey, SubkeyPath, Value, schema::SCHEMA_KEY};
use lotusd::{Core, IfInitialized, Server, ServerHandle};
use tempfile::TempDir;
use tokio::{net::UnixListener, task::JoinHandle, time::timeout};

/// How long a step gets before we call it hung. Generous: this bounds a
/// test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(20);

/// A daemon on a fresh state dir, and a client at its socket.
struct Daemon {
    client: Client,
    /// The directory a filer started by [`filer`] serves as `scratch`.
    volume: TempDir,
    // Held so the socket and the mainloop outlive the test.
    _dir: TempDir,
    _handle: ServerHandle,
    _join: JoinHandle<()>,
}

async fn daemon() -> Daemon {
    let dir = TempDir::new().unwrap();
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let listener = UnixListener::bind(lotus_sdk::socket_in(dir.path())).unwrap();
    let (handle, join) = Server::new(core, listener).unwrap().run().await;
    Daemon {
        client: Client::in_state_dir(dir.path()),
        volume: TempDir::new().unwrap(),
        _dir: dir,
        _handle: handle,
        _join: join,
    }
}

fn secret(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// An endpoint on `network` only, dialled by id alone.
async fn endpoint(network: &TestNetwork, secret: SecretKey) -> Endpoint {
    let transport = network.create_transport(secret.public()).unwrap();
    Endpoint::builder(presets::Minimal)
        .preset(transport)
        .secret_key(secret)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .alpns(vec![filer_proto::ALPN.to_vec()])
        .bind()
        .await
        .unwrap()
}

fn scratch() -> VolumeName {
    VolumeName::try_new("scratch").unwrap()
}

fn path(text: &str) -> SubkeyPath {
    text.parse().unwrap()
}

/// A filer serving `scratch` on `endpoint`.
fn filer(daemon: &Daemon, endpoint: &Endpoint) -> Filer {
    Filer::new(daemon.client.clone(), endpoint.clone())
        .with_volume(scratch(), Backing::open(daemon.volume.path()).unwrap())
}

/// Waits for `scratch`'s listing to reach a standing `wanted` accepts.
async fn standing(handle: &FilerHandle, wanted: impl Fn(&Standing) -> bool) -> Standing {
    let mut standings = handle.standings();
    let reached = timeout(
        GRACE,
        standings.wait_for(|standings| standings.get(&scratch()).is_some_and(&wanted)),
    )
    .await
    .expect("the volume reaches the standing")
    .unwrap();
    reached[&scratch()].clone()
}

/// Waits for the filer to have read what `scratch` permits `client`.
async fn sees(handle: &FilerHandle, client: EndpointId, wanted: Option<Mode>) {
    let mut view = handle.view();
    timeout(
        GRACE,
        view.wait_for(|view| match view {
            View::Read(volumes) => {
                volumes
                    .get(&scratch())
                    .and_then(|entry| entry.allowed.grant(client))
                    .map(|grant| grant.mode)
                    == wanted
            }
            View::Unreadable => false,
        }),
    )
    .await
    .expect("the filer reads the change")
    .unwrap();
}

/// The endpoint id the ledger names for `scratch`.
async fn listed(daemon: &Daemon) -> Option<EndpointId> {
    daemon
        .client
        .read(ledger::namespace(), path("scratch.endpoint"))
        .await
        .unwrap()
        .value
        .map(|endpoint| EndpointAddr::try_from(&endpoint).unwrap().id)
}

/// Permits `client` on `scratch` under `name`, at `mode` as the ledger
/// spells one.
async fn permit(daemon: &Daemon, name: &str, client: EndpointId, mode: &str) {
    daemon
        .client
        .set(
            ledger::namespace(),
            path(&format!("scratch.{ALLOWED_CLIENTS}.{name}")),
            Value::from_iter([("endpoint_id", client.to_z32()), ("mode", mode.to_owned())]),
        )
        .await
        .unwrap();
}

/// Lists `scratch` with no clients, under `endpoint` when given.
async fn list(daemon: &Daemon, endpoint: Option<EndpointId>) {
    let entry = Value::Map(
        [(ALLOWED_CLIENTS.to_owned(), Value::Map(Default::default()))]
            .into_iter()
            .chain(endpoint.map(|id| {
                (
                    ENDPOINT.to_owned(),
                    Value::try_from(&EndpointAddr::new(id)).unwrap(),
                )
            }))
            .collect(),
    );
    daemon
        .client
        .set(
            ledger::namespace(),
            None,
            Value::from_iter([("scratch", entry)]),
        )
        .await
        .unwrap();
}

/// Why the far side closed `conn`, as one of the protocol's reasons.
async fn closed(conn: &Connection) -> Close {
    match timeout(GRACE, conn.closed())
        .await
        .expect("the filer hangs up")
    {
        ConnectionError::ApplicationClosed(close) => {
            Close::from_code(close.error_code.into_inner()).expect("a code of the protocol's")
        }
        other => panic!("expected an application close, got {other:?}"),
    }
}

/// Connects `from` to the filer at `to` and asks for `scratch`.
async fn connect(from: &Endpoint, to: EndpointId) -> Result<(Connection, Welcome), Close> {
    let conn = timeout(
        GRACE,
        from.connect(EndpointAddr::new(to), filer_proto::ALPN),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_frame(&mut send, &Hello { volume: scratch() })
        .await
        .unwrap();
    match timeout(GRACE, read_frame::<Welcome, _>(&mut recv))
        .await
        .unwrap()
    {
        Ok(welcome) => Ok((conn, welcome)),
        Err(_) => Err(closed(&conn).await),
    }
}

#[tokio::test]
async fn an_unlisted_volume_is_claimed_and_its_schema_installed() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;

    let handle = filer(&daemon, &endpoint).spawn();
    standing(&handle, |s| *s == Standing::Published).await;

    assert_eq!(listed(&daemon).await, Some(endpoint.id()));
    let schema = daemon
        .client
        .read(
            NamespaceKey::try_new(SCHEMA_KEY).unwrap(),
            path(ledger::NAMESPACE),
        )
        .await
        .unwrap();
    assert_eq!(schema.value, Some(ledger::schema()));

    handle.shutdown().await;
}

#[tokio::test]
async fn a_volume_an_operator_listed_is_claimed_without_losing_its_clients() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    list(&daemon, None).await;
    permit(&daemon, "laptop", secret(2).public(), "rw").await;

    let handle = filer(&daemon, &endpoint).spawn();
    standing(&handle, |s| *s == Standing::Published).await;

    assert_eq!(listed(&daemon).await, Some(endpoint.id()));
    sees(&handle, secret(2).public(), Some(Mode::ReadWrite)).await;

    handle.shutdown().await;
}

#[tokio::test]
async fn another_filers_volume_is_left_alone_and_not_served() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    let client = client_endpoint(&network, 2).await;
    let other = secret(9).public();
    list(&daemon, Some(other)).await;
    permit(&daemon, "laptop", client.id(), "rw").await;

    let handle = filer(&daemon, &endpoint).spawn();
    assert_eq!(standing(&handle, |_| true).await, Standing::Other(other));
    assert_eq!(listed(&daemon).await, Some(other));
    assert_eq!(
        connect(&client, endpoint.id()).await.unwrap_err(),
        Close::Unavailable
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn a_takeover_claims_another_filers_volume() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    list(&daemon, Some(secret(9).public())).await;

    let handle = filer(&daemon, &endpoint).with_takeover(true).spawn();
    standing(&handle, |s| *s == Standing::Published).await;

    assert_eq!(listed(&daemon).await, Some(endpoint.id()));

    handle.shutdown().await;
}

async fn client_endpoint(network: &TestNetwork, seed: u8) -> Endpoint {
    endpoint(network, secret(seed)).await
}

#[tokio::test]
async fn a_permitted_client_is_welcomed_at_its_mode_and_others_refused() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    let writer = client_endpoint(&network, 2).await;
    let reader = client_endpoint(&network, 3).await;
    let stranger = client_endpoint(&network, 4).await;

    let handle = filer(&daemon, &endpoint).spawn();
    standing(&handle, |s| *s == Standing::Published).await;
    daemon
        .client
        .set(
            ledger::namespace(),
            path(&format!("scratch.{ALLOWED_CLIENTS}")),
            Value::Map(Default::default()),
        )
        .await
        .unwrap();
    permit(&daemon, "writer", writer.id(), "rw").await;
    permit(&daemon, "reader", reader.id(), "ro").await;
    sees(&handle, reader.id(), Some(Mode::ReadOnly)).await;

    let (_conn, welcome) = connect(&writer, endpoint.id()).await.unwrap();
    assert_eq!(welcome.mode, Mode::ReadWrite);
    let (_conn, welcome) = connect(&reader, endpoint.id()).await.unwrap();
    assert_eq!(welcome.mode, Mode::ReadOnly);
    assert_eq!(
        connect(&stranger, endpoint.id()).await.unwrap_err(),
        Close::NotPermitted
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn revoking_one_client_hangs_up_on_it_alone() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    let kept = client_endpoint(&network, 2).await;
    let dropped = client_endpoint(&network, 3).await;
    list(&daemon, None).await;
    permit(&daemon, "kept", kept.id(), "rw").await;
    permit(&daemon, "dropped", dropped.id(), "rw").await;

    let handle = filer(&daemon, &endpoint).spawn();
    standing(&handle, |s| *s == Standing::Published).await;
    sees(&handle, dropped.id(), Some(Mode::ReadWrite)).await;
    let (kept_conn, _) = connect(&kept, endpoint.id()).await.unwrap();
    let (dropped_conn, _) = connect(&dropped, endpoint.id()).await.unwrap();

    daemon
        .client
        .delete(
            ledger::namespace(),
            path(&format!("scratch.{ALLOWED_CLIENTS}.dropped")),
        )
        .await
        .unwrap();

    assert_eq!(closed(&dropped_conn).await, Close::Revoked);
    assert_eq!(kept_conn.close_reason(), None);
    assert_eq!(
        connect(&dropped, endpoint.id()).await.unwrap_err(),
        Close::NotPermitted
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn narrowing_a_grant_hangs_up_and_the_client_returns_read_only() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    let client = client_endpoint(&network, 2).await;
    list(&daemon, None).await;
    permit(&daemon, "laptop", client.id(), "rw").await;

    let handle = filer(&daemon, &endpoint).spawn();
    standing(&handle, |s| *s == Standing::Published).await;
    sees(&handle, client.id(), Some(Mode::ReadWrite)).await;
    let (conn, _) = connect(&client, endpoint.id()).await.unwrap();

    permit(&daemon, "laptop", client.id(), "ro").await;

    assert_eq!(closed(&conn).await, Close::Revoked);
    let (_conn, welcome) = connect(&client, endpoint.id()).await.unwrap();
    assert_eq!(welcome.mode, Mode::ReadOnly);

    handle.shutdown().await;
}

#[tokio::test]
async fn shutting_down_hangs_up_on_clients() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    let client = client_endpoint(&network, 2).await;
    list(&daemon, None).await;
    permit(&daemon, "laptop", client.id(), "rw").await;

    let handle = filer(&daemon, &endpoint).spawn();
    standing(&handle, |s| *s == Standing::Published).await;
    sees(&handle, client.id(), Some(Mode::ReadWrite)).await;
    let (conn, _) = connect(&client, endpoint.id()).await.unwrap();

    timeout(GRACE, handle.shutdown()).await.unwrap();

    assert_eq!(closed(&conn).await, Close::ShuttingDown);
}

/// Sends one operation on its own stream and reads the answer.
async fn op(conn: &Connection, request: Request) -> Reply {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_frame(&mut send, &request).await.unwrap();
    timeout(GRACE, read_frame(&mut recv))
        .await
        .unwrap()
        .unwrap()
}

fn name(text: &str) -> Name {
    Name::try_new(text).unwrap()
}

/// A filer serving `scratch` to `writer` read-write and `reader` read-only.
async fn shared(
    daemon: &Daemon,
    endpoint: &Endpoint,
    writer: EndpointId,
    reader: EndpointId,
) -> FilerHandle {
    list(daemon, None).await;
    permit(daemon, "writer", writer, "rw").await;
    permit(daemon, "reader", reader, "ro").await;
    let handle = filer(daemon, endpoint).spawn();
    standing(&handle, |s| *s == Standing::Published).await;
    sees(&handle, reader, Some(Mode::ReadOnly)).await;
    handle
}

#[tokio::test]
async fn what_one_client_writes_another_reads() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    let writer = client_endpoint(&network, 2).await;
    let reader = client_endpoint(&network, 3).await;
    let handle = shared(&daemon, &endpoint, writer.id(), reader.id()).await;
    let (writing, _) = connect(&writer, endpoint.id()).await.unwrap();
    let (reading, _) = connect(&reader, endpoint.id()).await.unwrap();

    let Reply::Attr(created) = op(
        &writing,
        Request::Create(Create {
            parent: NodeId::ROOT,
            name: name("notes"),
            mode: 0o644,
            exclusive: true,
        }),
    )
    .await
    else {
        panic!("expected the created file");
    };
    let written = op(
        &writing,
        Request::Write(Write {
            node: created.node,
            offset: 0,
            data: b"over iroh".to_vec().into(),
        }),
    )
    .await;
    assert!(matches!(written, Reply::Done(_)), "{written:?}");

    let Reply::Attr(found) = op(
        &reading,
        Request::Lookup(Lookup {
            parent: NodeId::ROOT,
            name: name("notes"),
        }),
    )
    .await
    else {
        panic!("expected the file to be found");
    };
    assert_eq!((found.node, found.size), (created.node, 9));
    assert_eq!(
        op(
            &reading,
            Request::Read(Read {
                node: found.node,
                offset: 5,
                len: 100,
            }),
        )
        .await,
        Reply::Data(b"iroh".to_vec().into())
    );
    assert_eq!(
        std::fs::read(daemon.volume.path().join("notes")).unwrap(),
        b"over iroh"
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn a_read_only_client_changes_nothing() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    let writer = client_endpoint(&network, 2).await;
    let reader = client_endpoint(&network, 3).await;
    let handle = shared(&daemon, &endpoint, writer.id(), reader.id()).await;
    std::fs::write(daemon.volume.path().join("notes"), b"as it was").unwrap();
    let (reading, _) = connect(&reader, endpoint.id()).await.unwrap();

    let Reply::Attr(found) = op(
        &reading,
        Request::Lookup(Lookup {
            parent: NodeId::ROOT,
            name: name("notes"),
        }),
    )
    .await
    else {
        panic!("expected the file to be found");
    };
    assert_eq!(
        op(
            &reading,
            Request::Write(Write {
                node: found.node,
                offset: 0,
                data: b"scribble".to_vec().into(),
            }),
        )
        .await,
        Reply::Error(Errno::ReadOnly)
    );
    assert_eq!(
        op(
            &reading,
            Request::Create(Create {
                parent: NodeId::ROOT,
                name: name("planted"),
                mode: 0o644,
                exclusive: false,
            }),
        )
        .await,
        Reply::Error(Errno::ReadOnly)
    );

    assert_eq!(
        std::fs::read(daemon.volume.path().join("notes")).unwrap(),
        b"as it was"
    );
    assert!(!daemon.volume.path().join("planted").exists());

    handle.shutdown().await;
}

#[tokio::test]
async fn operations_run_side_by_side_on_one_connection() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    let writer = client_endpoint(&network, 2).await;
    let reader = client_endpoint(&network, 3).await;
    let handle = shared(&daemon, &endpoint, writer.id(), reader.id()).await;
    let (conn, _) = connect(&writer, endpoint.id()).await.unwrap();

    let created = (0..32).map(|i| {
        let conn = conn.clone();
        tokio::spawn(async move {
            op(
                &conn,
                Request::Create(Create {
                    parent: NodeId::ROOT,
                    name: name(&format!("file-{i}")),
                    mode: 0o644,
                    exclusive: true,
                }),
            )
            .await
        })
    });
    for reply in created.collect::<Vec<_>>() {
        assert!(matches!(reply.await.unwrap(), Reply::Attr(_)));
    }
    assert_eq!(std::fs::read_dir(daemon.volume.path()).unwrap().count(), 32);

    handle.shutdown().await;
}

/// A session from `from` for `scratch` on the filer at `to`.
fn session(from: &Endpoint, to: EndpointId) -> Session {
    Session::new(
        from.clone(),
        Ticket {
            volume: scratch(),
            filer: EndpointAddr::new(to),
        },
    )
}

#[tokio::test]
async fn a_session_walks_lists_and_reads() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    let writer = client_endpoint(&network, 2).await;
    let reader = client_endpoint(&network, 3).await;
    let handle = shared(&daemon, &endpoint, writer.id(), reader.id()).await;
    std::fs::create_dir(daemon.volume.path().join("docs")).unwrap();
    std::fs::write(daemon.volume.path().join("docs/b"), b"second").unwrap();
    std::fs::write(daemon.volume.path().join("docs/a"), b"first").unwrap();
    let session = session(&reader, endpoint.id());

    assert_eq!(session.connect().await.unwrap(), Mode::ReadOnly);
    let docs = session.walk("/docs/").await.unwrap();
    let listed = session.list(docs.node).await.unwrap();
    assert_eq!(
        listed.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
    let file = session.walk("docs/b").await.unwrap();
    let data = session
        .data(Request::Read(Read {
            node: file.node,
            offset: 0,
            len: 100,
        }))
        .await
        .unwrap();
    assert_eq!(data.as_slice(), b"second");
    assert_eq!(
        session.walk("docs/missing").await.unwrap_err().errno(),
        Some(Errno::NotFound)
    );
    assert_eq!(
        session.walk("docs/../..").await.unwrap_err().errno(),
        Some(Errno::Invalid)
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn a_session_refused_says_why() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    let writer = client_endpoint(&network, 2).await;
    let reader = client_endpoint(&network, 3).await;
    let stranger = client_endpoint(&network, 4).await;
    let handle = shared(&daemon, &endpoint, writer.id(), reader.id()).await;

    let refused = session(&stranger, endpoint.id()).connect().await;
    assert!(
        matches!(
            refused,
            Err(filer_client::Error::Refused(Close::NotPermitted))
        ),
        "{refused:?}"
    );

    handle.shutdown().await;
}

/// The filer keeps nothing per connection, so one that restarts costs a
/// session nothing but the dial.
#[tokio::test]
async fn a_session_carries_on_across_a_filer_restart() {
    let daemon = daemon().await;
    let network = TestNetwork::new();
    let endpoint = endpoint(&network, secret(1)).await;
    let writer = client_endpoint(&network, 2).await;
    let reader = client_endpoint(&network, 3).await;
    let handle = shared(&daemon, &endpoint, writer.id(), reader.id()).await;
    std::fs::write(daemon.volume.path().join("notes"), b"still here").unwrap();
    let session = session(&reader, endpoint.id());
    let before = session.walk("notes").await.unwrap();

    handle.shutdown().await;
    let handle = filer(&daemon, &endpoint).spawn();
    standing(&handle, |s| *s == Standing::Published).await;
    sees(&handle, reader.id(), Some(Mode::ReadOnly)).await;

    let after = timeout(GRACE, session.walk("notes"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.node, before.node);

    handle.shutdown().await;
}
