//! The peers page: who this node is on the network, and how it stands with
//! every other node the cluster lists — what `lotusctl status` prints.
//!
//! Each peer, and the node's own listing, wears a dot coloured by where it
//! stands: green when up, amber while it is being worked on, red when the
//! last try failed, grey when there is nothing to try. The page polls
//! itself, so the dots move without a reload.

use lotus_sdk::{
    KeyId, NamespaceKey, NodeStatus, Subkey,
    rpc::{Attempt, EndpointInfo, OtherEndpoint, PeerInfo, PeerState, Published, Reason},
};
use maud::{Markup, html};

use crate::{Location, chain, view};

/// Where the peers are shown.
pub const PEERS_URL: &str = "/peers";

/// How often the page asks for itself again.
const POLL: &str = "every 5s";

/// The namespace the cluster lists its nodes in, as `state` reserves it.
const CLUSTER_NODES_KEY: &str = "_lotus_nodes";

/// How much of an endpoint id is shown; the rest is a hover away.
const SHORT_ENDPOINT: usize = 12;

/// Where something stands, as its dot shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Health {
    /// Up: connected, or published.
    Up,
    /// Being worked on: a dial in flight, an update about to land.
    Pending,
    /// The last try failed.
    Down,
    /// Nothing to try.
    Idle,
}

impl Health {
    fn class(self) -> &'static str {
        match self {
            Health::Up => "dot up",
            Health::Pending => "dot pending",
            Health::Down => "dot down",
            Health::Idle => "dot idle",
        }
    }
}

impl From<&PeerState> for Health {
    fn from(state: &PeerState) -> Self {
        match state {
            PeerState::Connected(_) => Health::Up,
            PeerState::Dialing(_) => Health::Pending,
            PeerState::Backoff(_) => Health::Down,
        }
    }
}

impl From<&Published> for Health {
    fn from(published: &Published) -> Self {
        match published {
            Published::Published(_) => Health::Up,
            Published::Unchecked(_) | Published::Pending(_) => Health::Pending,
            Published::NotListed(_) | Published::OtherEndpoint(_) => Health::Idle,
            Published::CannotSign(_) | Published::Failed(_) => Health::Down,
        }
    }
}

/// `inner`, inside the element that polls for the page again. The poll
/// swaps the whole pane, so it survives a failure and picks back up when
/// the daemon does.
pub fn polling(inner: Markup) -> Markup {
    html! {
        section.peers hx-get=(PEERS_URL) hx-trigger=(POLL) {
            (inner)
        }
    }
}

/// The peers page: this node, then every peer it keeps a connection to.
pub fn pane(status: &NodeStatus) -> Markup {
    let connected = status
        .peers
        .iter()
        .filter(|peer| matches!(peer.state, PeerState::Connected(_)))
        .count();
    let head = &status.chain.head;
    html! {
        header.pane-head {
            h1 { "Peers" }
            span.badge { (connected) " of " (status.peers.len()) " connected" }
            span.head title=(head.to_hex().as_ref()) {
                "head " a href=(chain::CHAIN_URL) hx-get=(chain::CHAIN_URL) hx-push-url="true" {
                    code { (view::short(head)) }
                }
            }
        }
        (this_node(status))
        h2 { "Cluster" }
        (peers(status))
    }
}

/// Who this node is, where it can be reached, and whether the cluster's
/// listing of it says so.
fn this_node(status: &NodeStatus) -> Markup {
    html! {
        h2 { "This node" }
        dl.status {
            dt { "node id" }
            dd { (node(&status.node)) }
            @match &status.endpoint {
                None => {
                    dt { "endpoint" }
                    dd.absent { "none — not serving peers" }
                }
                Some(endpoint) => (endpoint_rows(endpoint, status.published.as_ref())),
            }
            dt { "inbound" }
            dd { (status.inbound) " " (if status.inbound == 1 { "connection" } else { "connections" }) }
            dt { "chain" }
            dd {
                "root " code title=(status.chain.root.to_hex().as_ref()) { (view::short(&status.chain.root)) }
                " · head " code title=(status.chain.head.to_hex().as_ref()) { (view::short(&status.chain.head)) }
            }
            dt { "version" }
            dd { (status.version) }
        }
    }
}

fn endpoint_rows(endpoint: &EndpointInfo, published: Option<&Published>) -> Markup {
    html! {
        dt { "endpoint" }
        dd { code { (endpoint.id) } }
        dt { "addresses" }
        dd {
            @if endpoint.addrs.is_empty() { span.absent { "none known yet" } }
            @for addr in &endpoint.addrs { code.addr { (addr) } }
        }
        @if let Some(family) = endpoint.ip_family {
            dt { "ip family" }
            dd { (family) }
        }
        @if let Some(published) = published {
            dt { "listing" }
            dd { (dot(published.into())) (listing(published)) }
        }
    }
}

/// The node's own listing, in words.
fn listing(published: &Published) -> Markup {
    html! {
        @match published {
            Published::Unchecked(_) => "not checked yet",
            Published::Published(_) => "published",
            Published::Pending(_) => "address moved; update pending",
            Published::NotListed(_) => "not listed in the cluster",
            Published::OtherEndpoint(OtherEndpoint { endpoint }) => {
                "listed under another endpoint, " code { (endpoint) }
            }
            Published::CannotSign(Reason { reason }) => {
                "stale, and this node cannot sign the update: " (reason)
            }
            Published::Failed(Reason { reason }) => { "update failed, retrying: " (reason) }
        }
    }
}

/// The table of peers, or why there are none.
fn peers(status: &NodeStatus) -> Markup {
    html! {
        @if status.endpoint.is_none() {
            p.empty { "This daemon runs without an endpoint, so it keeps no peers." }
        } @else if status.peers.is_empty() {
            p.empty { "No other node is listed in the cluster." }
        } @else {
            table.entries.peers {
                thead { tr { th { "State" } th { "Node" } th { "Endpoint" } } }
                tbody {
                    @for peer in &status.peers { (row(peer)) }
                }
            }
        }
    }
}

fn row(peer: &PeerInfo) -> Markup {
    let short: String = peer.endpoint.chars().take(SHORT_ENDPOINT).collect();
    html! {
        tr {
            td.state { (dot((&peer.state).into())) (state(&peer.state)) }
            td.name { (node(&peer.node)) }
            td.endpoint { code title=(peer.endpoint) { (short) } }
        }
    }
}

/// A peer's connection, in words.
fn state(state: &PeerState) -> String {
    match state {
        PeerState::Connected(_) => "connected".into(),
        PeerState::Dialing(Attempt { attempt: 0 }) => "dialing".into(),
        PeerState::Dialing(Attempt { attempt }) => format!("dialing, retry {attempt}"),
        PeerState::Backoff(Attempt { attempt }) => format!(
            "backing off after {attempt} failed {}",
            if *attempt == 1 { "dial" } else { "dials" }
        ),
    }
}

fn dot(health: Health) -> Markup {
    html! { span class=(health.class()) aria-hidden="true" {} }
}

/// A node id in short, the whole a hover away, linking to its entry in the
/// cluster's listing.
fn node(id: &KeyId) -> Markup {
    let hex = id.to_hex();
    let short: String = hex.as_ref().chars().take(SHORT_ENDPOINT).collect();
    let listing = NamespaceKey::try_new(CLUSTER_NODES_KEY)
        .map(|key| Location::namespace(key).child(Subkey::Key(hex.as_ref().to_owned())))
        .expect("the reserved key is a namespace name");
    let url = listing.url();
    html! {
        a href=(url) hx-get=(url) hx-push-url="true" title=(hex.as_ref()) { code { (short) } }
    }
}

#[cfg(test)]
mod tests {
    use lotus_sdk::{
        ChainRange, EnvelopeDigest, IpFamily,
        rpc::{Connected, Unchecked},
    };

    use super::*;

    fn status(endpoint: bool, peers: Vec<PeerInfo>, published: Option<Published>) -> NodeStatus {
        NodeStatus {
            version: "0.0.0-test".into(),
            node: KeyId::from_bytes([1; 32]),
            endpoint: endpoint.then(|| EndpointInfo {
                id: "endpointzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".into(),
                addrs: vec!["ip:192.0.2.1:7000".into()],
                ip_family: Some(IpFamily::Dual),
            }),
            chain: ChainRange {
                root: EnvelopeDigest::from_bytes([2; 32]),
                head: EnvelopeDigest::from_bytes([3; 32]),
            },
            peers,
            inbound: 1,
            published,
        }
    }

    fn peer(byte: u8, state: PeerState) -> PeerInfo {
        PeerInfo {
            node: KeyId::from_bytes([byte; 32]),
            endpoint: format!("peer{byte}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            state,
        }
    }

    #[test]
    fn each_peer_wears_the_dot_its_state_calls_for() {
        let page = pane(&status(
            true,
            vec![
                peer(4, PeerState::Connected(Connected {})),
                peer(5, PeerState::Dialing(Attempt { attempt: 0 })),
                peer(6, PeerState::Backoff(Attempt { attempt: 3 })),
            ],
            Some(Published::Published(Connected {})),
        ))
        .into_string();

        assert!(page.contains("1 of 3 connected"), "{page}");
        for (dot, words) in [
            ("dot up", "connected"),
            ("dot pending", "dialing"),
            ("dot down", "backing off after 3 failed dials"),
        ] {
            let cell = format!(r#"<span class="{dot}" aria-hidden="true"></span>{words}<"#);
            assert!(page.contains(&cell), "no `{cell}` in {page}");
        }
    }

    #[test]
    fn a_peer_links_to_its_listing_in_the_cluster() {
        let page = pane(&status(
            true,
            vec![peer(4, PeerState::Connected(Connected {}))],
            None,
        ))
        .into_string();
        let id = KeyId::from_bytes([4; 32]);
        let hex = id.to_hex();
        assert!(
            page.contains(&format!(r#"href="/ns/_lotus_nodes/{}""#, hex.as_ref())),
            "{page}"
        );
    }

    #[test]
    fn the_listing_is_coloured_by_where_it_stands() {
        for (published, dot) in [
            (Published::Published(Connected {}), "dot up"),
            (Published::Pending(Unchecked {}), "dot pending"),
            (Published::NotListed(Unchecked {}), "dot idle"),
            (
                Published::Failed(Reason {
                    reason: "no quorum".into(),
                }),
                "dot down",
            ),
        ] {
            let page = pane(&status(true, vec![], Some(published))).into_string();
            assert!(page.contains(dot), "no `{dot}` in {page}");
        }
    }

    #[test]
    fn a_node_without_an_endpoint_says_why_it_has_no_peers() {
        let page = pane(&status(false, vec![], None)).into_string();
        assert!(page.contains("not serving peers"), "{page}");
        assert!(page.contains("keeps no peers"), "{page}");
        assert!(!page.contains("<table"), "{page}");
    }

    #[test]
    fn a_node_alone_in_the_cluster_says_so() {
        let page = pane(&status(true, vec![], None)).into_string();
        assert!(page.contains("No other node is listed"), "{page}");
    }
}
