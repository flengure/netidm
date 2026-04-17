use ipnet::IpNet;
use std::net::SocketAddr;
use uuid::Uuid;

/// Runtime snapshot of a configured WireGuard tunnel.
#[derive(Debug, Clone)]
pub struct WgTunnelConfig {
    pub uuid: Uuid,
    pub name: String,
    pub interface: String,
    pub private_key: String,
    pub public_key: String,
    pub endpoint: String,
    pub listen_port: u16,
    pub address: Vec<IpNet>,
    pub dns: Vec<String>,
    pub mtu: Option<u32>,
    pub pre_up: Vec<String>,
    pub post_up: Vec<String>,
    pub pre_down: Vec<String>,
    pub post_down: Vec<String>,
}

/// Runtime snapshot of a configured WireGuard peer.
#[derive(Debug, Clone)]
pub struct WgPeerConfig {
    pub name: String,
    pub pubkey: String,
    pub allowed_ips: Vec<IpNet>,
    pub preshared_key: Option<String>,
    pub persistent_keepalive: Option<u32>,
    pub endpoint: Option<SocketAddr>,
}
