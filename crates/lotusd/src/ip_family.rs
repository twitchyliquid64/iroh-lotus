//! Which IP families an iroh endpoint uses.
//!
//! iroh binds an IPv4 and an IPv6 socket by default. An endpoint bound to
//! one family only has no socket of the other, so it learns, advertises
//! and sends to no address of it, which keeps it off QAD, the portmapper
//! and peers' direct addresses. Relays are dialled over TCP outside those
//! sockets, so the resolver is narrowed too: it answers lookups of the
//! other family with nothing.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
};

use iroh::{
    Endpoint, EndpointAddr, TransportAddr,
    dns::{BoxIter, DNS_TIMEOUT, DnsError, DnsResolver, Resolver, TxtRecordData},
    endpoint::{Builder, InvalidSocketAddr, PortmapperConfig},
};

/// The IP families an endpoint has sockets bound for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    Dual,
    Ipv6,
    Ipv4,
}

/// Bind returns `builder` bound to exactly `addrs` in place of iroh's
/// `0.0.0.0:0` and `[::]:0`, and kept off any family `addrs` leaves out.
/// Empty `addrs` leaves it as it is.
///
/// Fails on two addresses of one family: iroh routes each family through
/// one socket.
pub fn bind(builder: Builder, addrs: &[SocketAddr]) -> Result<Builder, InvalidSocketAddr> {
    let Some(family) = IpFamily::of_addrs(addrs) else {
        return Ok(builder);
    };
    let builder = addrs
        .iter()
        .try_fold(builder.clear_ip_transports(), |builder, addr| {
            builder.bind_addr(*addr)
        })?;
    let narrowed = |builder: Builder| {
        builder.dns_resolver(DnsResolver::custom(OneFamily {
            inner: DnsResolver::new(),
            family,
        }))
    };
    Ok(match family {
        IpFamily::Dual => builder,
        // UPnP, PCP and NAT-PMP map IPv4 ports only.
        IpFamily::Ipv6 => narrowed(builder).portmapper_config(PortmapperConfig::Disabled),
        IpFamily::Ipv4 => narrowed(builder),
    })
}

impl IpFamily {
    /// OfAddrs returns the families `addrs` span, or `None` when empty.
    fn of_addrs(addrs: &[SocketAddr]) -> Option<Self> {
        match (
            addrs.iter().any(SocketAddr::is_ipv4),
            addrs.iter().any(SocketAddr::is_ipv6),
        ) {
            (true, true) => Some(IpFamily::Dual),
            (false, true) => Some(IpFamily::Ipv6),
            (true, false) => Some(IpFamily::Ipv4),
            (false, false) => None,
        }
    }

    /// Of returns the family `endpoint` has IP sockets bound for, or `None`
    /// when it has none.
    pub fn of(endpoint: &Endpoint) -> Option<Self> {
        Self::of_addrs(&endpoint.bound_sockets())
    }

    /// Admits reports whether this family covers `ip`.
    pub fn admits(self, ip: IpAddr) -> bool {
        match self {
            IpFamily::Dual => true,
            IpFamily::Ipv6 => ip.to_canonical().is_ipv6(),
            IpFamily::Ipv4 => ip.to_canonical().is_ipv4(),
        }
    }
}

/// Reachable returns `addr` without the IP addresses `endpoint` has no
/// socket of the family for, so a listing written by a node of another
/// family is never dialled where it cannot go. Relay and custom
/// transports pass, and so does everything when `endpoint` has no IP
/// sockets at all.
pub fn reachable(endpoint: &Endpoint, mut addr: EndpointAddr) -> EndpointAddr {
    if let Some(family) = IpFamily::of(endpoint) {
        addr.addrs.retain(|transport| match transport {
            TransportAddr::Ip(ip) => family.admits(ip.ip()),
            _ => true,
        });
    }
    addr
}

/// A resolver that answers only for one family's addresses, deferring to
/// `inner` for the rest.
#[derive(Debug)]
struct OneFamily {
    inner: DnsResolver,
    family: IpFamily,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl OneFamily {
    /// Lookup resolves `host` through `inner` when this family covers
    /// the record type, and to nothing otherwise.
    fn lookup<A, F>(
        &self,
        wanted: bool,
        lookup: impl FnOnce(DnsResolver) -> F + Send + 'static,
    ) -> BoxFuture<Result<BoxIter<A>, DnsError>>
    where
        A: Send + 'static,
        F: Future<Output = Result<Vec<A>, DnsError>> + Send + 'static,
    {
        let inner = self.inner.clone();
        Box::pin(async move {
            let found = if wanted {
                lookup(inner).await?
            } else {
                Vec::new()
            };
            Ok(Box::new(found.into_iter()) as BoxIter<A>)
        })
    }
}

impl Resolver for OneFamily {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        self.lookup(self.family != IpFamily::Ipv6, |inner| async move {
            Ok(inner
                .lookup_ipv4(host, DNS_TIMEOUT)
                .await?
                .filter_map(|ip| match ip {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                })
                .collect())
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        self.lookup(self.family != IpFamily::Ipv4, |inner| async move {
            Ok(inner
                .lookup_ipv6(host, DNS_TIMEOUT)
                .await?
                .filter_map(|ip| match ip {
                    IpAddr::V6(ip) => Some(ip),
                    IpAddr::V4(_) => None,
                })
                .collect())
        })
    }

    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        self.lookup(true, |inner| async move {
            Ok(inner.lookup_txt(host, DNS_TIMEOUT).await?.collect())
        })
    }

    fn clear_cache(&self) {
        self.inner.clear_cache();
    }

    fn reset(&self) -> Box<dyn Resolver> {
        self.inner.reset();
        Box::new(OneFamily {
            inner: self.inner.clone(),
            family: self.family,
        })
    }
}
