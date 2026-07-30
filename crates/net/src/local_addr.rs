//! Local addresses suitable for direct peer connections.
//!
//! A route-probing UDP socket alone is not sufficient here: transparent proxy
//! TUNs commonly route public probes through an RFC 2544 benchmarking address
//! such as `198.18.0.1`. That address only exists inside the local proxy and is
//! not reachable by another kbshare peer.

use if_addrs::{get_if_addrs, IfOperStatus};
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

#[derive(Debug)]
struct Candidate {
    ip: Ipv4Addr,
    interface: String,
    point_to_point: bool,
}

/// Return usable IPv4 addresses in connection preference order.
///
/// The kernel-selected source address is preferred when it is a real,
/// publishable interface address. Other active interface addresses are kept as
/// fallbacks for multi-homed hosts. Loopback, link-local, documentation,
/// multicast/reserved, and RFC 2544 benchmarking addresses are never
/// advertised.
pub fn local_ipv4_addrs() -> io::Result<Vec<Ipv4Addr>> {
    let preferred = route_selected_ipv4().filter(|ip| is_publishable_ipv4(*ip));
    let mut candidates = get_if_addrs()?
        .into_iter()
        .filter(|interface| {
            !matches!(
                interface.oper_status,
                IfOperStatus::Down | IfOperStatus::NotPresent | IfOperStatus::LowerLayerDown
            )
        })
        .filter_map(|interface| match interface.ip() {
            IpAddr::V4(ip) if is_publishable_ipv4(ip) => {
                let point_to_point = interface.is_p2p();
                Some(Candidate {
                    ip,
                    interface: interface.name,
                    point_to_point,
                })
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    candidates.sort_by_key(|candidate| {
        let preference = if Some(candidate.ip) == preferred {
            0
        } else if !candidate.point_to_point {
            1
        } else {
            2
        };
        (
            preference,
            candidate.interface.clone(),
            u32::from(candidate.ip),
        )
    });
    candidates.dedup_by_key(|candidate| candidate.ip);
    Ok(candidates
        .into_iter()
        .map(|candidate| candidate.ip)
        .collect())
}

fn route_selected_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn is_publishable_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_link_local() {
        return false;
    }

    // RFC 2544 benchmarking range. Transparent proxy TUNs frequently use this
    // block, but it must never be treated as a peer-reachable LAN address.
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }

    // TEST-NET documentation ranges.
    if (a, b, c) == (192, 0, 2) || (a, b, c) == (198, 51, 100) || (a, b, c) == (203, 0, 113) {
        return false;
    }

    // Multicast, future/reserved space, and the limited broadcast address.
    a < 224
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_benchmark_addresses_are_not_published() {
        assert!(!is_publishable_ipv4(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(!is_publishable_ipv4(Ipv4Addr::new(198, 19, 255, 254)));
    }

    #[test]
    fn lan_and_overlay_addresses_are_publishable() {
        assert!(is_publishable_ipv4(Ipv4Addr::new(10, 245, 39, 200)));
        assert!(is_publishable_ipv4(Ipv4Addr::new(192, 168, 1, 20)));
        assert!(is_publishable_ipv4(Ipv4Addr::new(100, 64, 1, 2)));
    }

    #[test]
    fn non_peer_addresses_are_not_published() {
        assert!(!is_publishable_ipv4(Ipv4Addr::LOCALHOST));
        assert!(!is_publishable_ipv4(Ipv4Addr::new(169, 254, 1, 2)));
        assert!(!is_publishable_ipv4(Ipv4Addr::new(192, 0, 2, 4)));
        assert!(!is_publishable_ipv4(Ipv4Addr::new(239, 1, 2, 3)));
    }
}
