//! A filer end to end: against a real daemon over its control socket, and
//! real iroh endpoints on an in-memory network.

use std::time::Duration;

use filer_proto::{Close, Hello, Mode, VolumeName, Welcome, read_frame, write_frame};
use filerd::{
    Filer, FilerHandle, Standing, View,
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
    Filer::new(daemon.client.clone(), endpoint.clone()).with_volume(scratch(), "/nonexistent")
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
