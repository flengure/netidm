use crate::types::{WgPeerConfig, WgTunnelConfig};
use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::info;
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

use super::WgBackend;

pub struct BoringtunBackend;

#[async_trait]
impl WgBackend for BoringtunBackend {
    async fn bring_up(&self, tunnel: &WgTunnelConfig, peers: &[WgPeerConfig]) -> Result<()> {
        info!(interface = %tunnel.interface, "bringing up boringtun userspace WireGuard interface");

        let ifname: InterfaceName = tunnel
            .interface
            .parse()
            .context("invalid interface name")?;

        let private_key = Key::from_base64(&tunnel.private_key).context("invalid private key")?;

        let mut update = DeviceUpdate::new()
            .set_private_key(private_key)
            .set_listen_port(tunnel.listen_port);

        for peer in peers {
            update = update.add_peer(build_peer(peer)?);
        }

        update
            .apply(&ifname, Backend::Userspace)
            .context("wireguard-control userspace apply failed")?;

        Ok(())
    }

    async fn tear_down(&self, tunnel: &WgTunnelConfig) -> Result<()> {
        info!(interface = %tunnel.interface, "tearing down boringtun WireGuard interface");
        let ifname: InterfaceName = tunnel
            .interface
            .parse()
            .context("invalid interface name")?;
        let device =
            Device::get(&ifname, Backend::Userspace).context("failed to get userspace device")?;
        device
            .delete()
            .context("failed to delete userspace device")?;
        Ok(())
    }

    async fn add_peer(&self, tunnel: &WgTunnelConfig, peer: &WgPeerConfig) -> Result<()> {
        let ifname: InterfaceName = tunnel
            .interface
            .parse()
            .context("invalid interface name")?;
        DeviceUpdate::new()
            .add_peer(build_peer(peer)?)
            .apply(&ifname, Backend::Userspace)
            .context("add_peer userspace failed")?;
        Ok(())
    }

    async fn remove_peer(&self, tunnel: &WgTunnelConfig, pubkey: &str) -> Result<()> {
        let ifname: InterfaceName = tunnel
            .interface
            .parse()
            .context("invalid interface name")?;
        let key = Key::from_base64(pubkey).context("invalid pubkey")?;
        DeviceUpdate::new()
            .remove_peer_by_key(&key)
            .apply(&ifname, Backend::Userspace)
            .context("remove_peer userspace failed")?;
        Ok(())
    }

    async fn peer_handshakes(&self, tunnel: &WgTunnelConfig) -> Result<Vec<(String, u64)>> {
        let ifname: InterfaceName = tunnel
            .interface
            .parse()
            .context("invalid interface name")?;
        let device = Device::get(&ifname, Backend::Userspace).context("device get failed")?;
        let pairs = device
            .peers
            .into_iter()
            .filter_map(|p| {
                let ts = p
                    .stats
                    .last_handshake_time?
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()?
                    .as_secs();
                Some((p.config.public_key.to_base64(), ts))
            })
            .collect();
        Ok(pairs)
    }
}

fn build_peer(peer: &WgPeerConfig) -> Result<PeerConfigBuilder> {
    let pubkey = Key::from_base64(&peer.pubkey).context("invalid peer pubkey")?;
    let mut builder = PeerConfigBuilder::new(&pubkey);
    for net in &peer.allowed_ips {
        builder = builder.add_allowed_ip(net.network(), net.prefix_len());
    }
    if let Some(psk) = &peer.preshared_key {
        let psk_key = Key::from_base64(psk).context("invalid preshared key")?;
        builder = builder.set_preshared_key(psk_key);
    }
    if let Some(ka) = peer.persistent_keepalive {
        builder = builder.set_persistent_keepalive_interval(ka as u16);
    }
    if let Some(ep) = peer.endpoint {
        builder = builder.set_endpoint(ep);
    }
    Ok(builder)
}
