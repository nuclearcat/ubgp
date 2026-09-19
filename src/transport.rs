use std::net::{IpAddr, SocketAddr, SocketAddrV6};

/// Build a socket address, using the interface index to scope link-local IPv6.
pub(crate) fn endpoint(ip: IpAddr, port: u16, index: u32) -> SocketAddr {
    match ip {
        IpAddr::V6(a) if a.is_unicast_link_local() => {
            SocketAddr::V6(SocketAddrV6::new(a, port, 0, index))
        }
        _ => SocketAddr::new(ip, port),
    }
}
