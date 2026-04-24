use anyhow::{bail, Result};
use ipnet::IpNet;
use std::net::IpAddr;

/// Allocate per-address-family IPs for a new peer from `tunnel_cidrs`.
///
/// For each CIDR in `tunnel_cidrs`, allocates the lowest available host
/// address not already used by `existing_peers`, skipping slot 1 (server).
/// Returns one `/32` per IPv4 CIDR and one `/128` per IPv6 CIDR.
///
/// `existing_peers` may contain host addresses (`/32`, `/128`) or subnets
/// (`/30`, `/126`, etc.). Any candidate host that falls within an existing
/// peer's CIDR is considered occupied and skipped.
pub fn allocate(tunnel_cidrs: &[IpNet], existing_peers: &[IpNet]) -> Result<Vec<IpNet>> {
    let mut result = Vec::new();
    for cidr in tunnel_cidrs {
        result.push(allocate_peer_ip(cidr, existing_peers)?);
    }
    Ok(result)
}

/// Allocate the next free host address within `tunnel_cidr` that does not
/// overlap with any entry in `existing_peers`.
///
/// The server always occupies the first host address (.1 / ::1).
/// Peers receive addresses from the second host (.2 / ::2) onwards.
pub fn allocate_peer_ip(tunnel_cidr: &IpNet, existing_peers: &[IpNet]) -> Result<IpNet> {
    // The server address is the first address in the network (network_addr + 1).
    let server_addr = {
        let mut h = tunnel_cidr.hosts();
        // For IPv4 hosts() skips the network address; for IPv6 it includes it.
        // In both cases the FIRST host yielded is address we want to call the server (.1 / ::1).
        // But for IPv6, hosts() starts at ::0 (the network address itself), so we need
        // to advance past the network address to get ::1.
        match tunnel_cidr.network() {
            IpAddr::V6(_) => {
                h.next(); // skip ::0 (network)
                h.next() // this is ::1 (server)
            }
            IpAddr::V4(_) => {
                h.next() // .0 is excluded, first is .1 (server)
            }
        }
    };
    let server_addr = server_addr.ok_or_else(|| anyhow::anyhow!("tunnel too small"))?;

    for host in tunnel_cidr.hosts() {
        // Skip the network address for IPv6 (::0).
        if host == tunnel_cidr.network() {
            continue;
        }
        // Skip the server address.
        if host == server_addr {
            continue;
        }
        // Skip if this host falls within any existing peer's allocated range.
        // This correctly handles both /32 host peers and wider subnet peers (/30, /29, etc.).
        if existing_peers.iter().any(|p| p.contains(&host)) {
            continue;
        }
        let prefix_len = match host {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        return Ok(IpNet::new(host, prefix_len)?);
    }
    bail!("tunnel address space exhausted");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_slot_2() {
        let cidr: IpNet = "10.100.0.0/24".parse().unwrap();
        let peer_ip = allocate_peer_ip(&cidr, &[]).unwrap();
        assert_eq!(peer_ip.to_string(), "10.100.0.2/32");
    }

    #[test]
    fn skips_used_addresses() {
        let cidr: IpNet = "10.100.0.0/24".parse().unwrap();
        let existing = vec!["10.100.0.2/32".parse().unwrap()];
        let peer_ip = allocate_peer_ip(&cidr, &existing).unwrap();
        assert_eq!(peer_ip.to_string(), "10.100.0.3/32");
    }

    #[test]
    fn allocate_dual_stack() {
        let cidrs: Vec<IpNet> = vec![
            "10.100.0.0/24".parse().unwrap(),
            "fd00::/64".parse().unwrap(),
        ];
        let allocated = allocate(&cidrs, &[]).unwrap();
        assert_eq!(allocated.len(), 2);
        assert_eq!(allocated[0].to_string(), "10.100.0.2/32");
        assert_eq!(allocated[1].to_string(), "fd00::2/128");
    }

    #[test]
    fn allocate_exhausted() {
        let cidr: IpNet = "10.100.0.0/30".parse().unwrap();
        // /30 has 2 hosts: .1 (server) and .2. After .2 is used, exhausted.
        let existing = vec!["10.100.0.2/32".parse::<IpNet>().unwrap()];
        assert!(allocate_peer_ip(&cidr, &existing).is_err());
    }

    #[test]
    fn respects_subnet_peers() {
        let cidr: IpNet = "10.100.0.0/24".parse().unwrap();
        // Peer owns /30 at .8 — covers .8, .9, .10, .11 (hosts within the /30)
        let existing: Vec<IpNet> = vec!["10.100.0.8/30".parse().unwrap()];
        let peer_ip = allocate_peer_ip(&cidr, &existing).unwrap();
        // .2 through .7 are free; .2 should be the first allocation
        assert_eq!(peer_ip.to_string(), "10.100.0.2/32");
    }

    #[test]
    fn respects_subnet_peers_skips_interior() {
        let cidr: IpNet = "10.100.0.0/24".parse().unwrap();
        // Peer owns /30 at .8, plus .2 as a host — next free should be .3
        let existing: Vec<IpNet> = vec![
            "10.100.0.2/32".parse().unwrap(),
            "10.100.0.8/30".parse().unwrap(),
        ];
        let peer_ip = allocate_peer_ip(&cidr, &existing).unwrap();
        assert_eq!(peer_ip.to_string(), "10.100.0.3/32");
    }

    #[test]
    fn respects_subnet_peers_ipv6() {
        let cidr: IpNet = "fd00::/64".parse().unwrap();
        // Peer owns a /126 at ::8 — covers ::8, ::9, ::a, ::b
        let existing: Vec<IpNet> = vec!["fd00::8/126".parse().unwrap()];
        let peer_ip = allocate_peer_ip(&cidr, &existing).unwrap();
        // ::2 through ::7 are free; ::2 is first
        assert_eq!(peer_ip.to_string(), "fd00::2/128");
    }
}
