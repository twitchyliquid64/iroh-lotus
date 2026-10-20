//! An endpoint bound by `--bind`: the sockets it binds, the
//! addresses it advertises, the names it resolves and the addresses it
//! dials.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use iroh::{
    Endpoint, EndpointAddr, RelayMode, RelayUrl, SecretKey, TransportAddr, endpoint::presets,
};
use lotusd::ip_family::{self, IpFamily};
use tokio::time::{Instant, sleep};

/// How long to wait for the endpoint to discover its own addresses.
const DISCOVERY: Duration = Duration::from_secs(5);

const V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
const V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);

async fn endpoint(bind: &[SocketAddr]) -> Endpoint {
    ip_family::bind(
        Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled),
        bind,
    )
    .unwrap()
    .bind()
    .await
    .unwrap()
}

/// The IP addresses `endpoint` advertises, once it has found any or
/// [`DISCOVERY`] has passed.
async fn advertised_ips(endpoint: &Endpoint) -> Vec<SocketAddr> {
    let deadline = Instant::now() + DISCOVERY;
    loop {
        let ips: Vec<SocketAddr> = endpoint.addr().ip_addrs().copied().collect();
        if !ips.is_empty() || Instant::now() >= deadline {
            return ips;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn ipv6_binds_no_ipv4_socket() {
    let ep = endpoint(&[V6]).await;

    let bound = ep.bound_sockets();
    assert!(!bound.is_empty());
    assert!(bound.iter().all(SocketAddr::is_ipv6), "bound {bound:?}");
    assert_eq!(IpFamily::of(&ep), Some(IpFamily::Ipv6));
}

#[tokio::test]
async fn ipv6_advertises_no_ipv4_address() {
    let ep = endpoint(&[V6]).await;

    let ips = advertised_ips(&ep).await;
    assert!(ips.iter().all(SocketAddr::is_ipv6), "advertised {ips:?}");
}

#[tokio::test]
async fn ipv6_resolves_no_a_records() {
    let ep = endpoint(&[V6]).await;

    let found: Vec<IpAddr> = ep
        .dns_resolver()
        .unwrap()
        .lookup_ipv4("relay.example", Duration::from_secs(1))
        .await
        .unwrap()
        .collect();
    assert!(found.is_empty(), "resolved {found:?}");
}

#[tokio::test]
async fn ipv6_dials_no_ipv4_address() {
    let ep = endpoint(&[V6]).await;
    let relay: RelayUrl = "https://relay.example".parse().unwrap();
    let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 1));
    let peer = EndpointAddr::from_parts(
        SecretKey::from_bytes(&[1; 32]).public(),
        [
            TransportAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 1))),
            TransportAddr::Ip(v6),
            TransportAddr::Relay(relay.clone()),
        ],
    );

    let dialled = ip_family::reachable(&ep, peer);
    assert_eq!(
        dialled.addrs.into_iter().collect::<Vec<_>>(),
        [TransportAddr::Relay(relay), TransportAddr::Ip(v6)]
    );
}

#[tokio::test]
async fn ipv4_binds_no_ipv6_socket() {
    let ep = endpoint(&[V4]).await;

    let bound = ep.bound_sockets();
    assert!(!bound.is_empty());
    assert!(bound.iter().all(SocketAddr::is_ipv4), "bound {bound:?}");
    let ips = advertised_ips(&ep).await;
    assert!(ips.iter().all(SocketAddr::is_ipv4), "advertised {ips:?}");
}

#[tokio::test]
async fn no_bind_keeps_both() {
    let ep = endpoint(&[]).await;

    assert_eq!(IpFamily::of(&ep), Some(IpFamily::Dual));
}

#[tokio::test]
async fn both_families_bind_where_asked() {
    let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let ep = endpoint(&[v4, V6]).await;

    let bound = ep.bound_sockets();
    assert!(
        bound.iter().any(|addr| addr.ip() == v4.ip()),
        "bound {bound:?}"
    );
    assert_eq!(IpFamily::of(&ep), Some(IpFamily::Dual));
}

#[test]
fn two_addresses_of_one_family_are_refused() {
    let builder = Endpoint::builder(presets::Minimal);
    let other = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));

    assert!(ip_family::bind(builder, &[V6, other]).is_err());
}
