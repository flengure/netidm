use crate::types::{WgPeerConfig, WgTunnelConfig};
use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::{debug, info};
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

use super::WgBackend;

pub struct KernelBackend;

#[async_trait]
impl WgBackend for KernelBackend {
    async fn bring_up(&self, tunnel: &WgTunnelConfig, peers: &[WgPeerConfig]) -> Result<()> {
        info!(interface = %tunnel.interface, "bringing up kernel WireGuard interface");

        let ifname: InterfaceName = tunnel.interface.parse().context("invalid interface name")?;

        let private_key = Key::from_base64(&tunnel.private_key).context("invalid private key")?;

        let mut update = DeviceUpdate::new()
            .set_private_key(private_key)
            .set_listen_port(tunnel.listen_port);

        for peer in peers {
            update = update.add_peer(build_peer(peer)?);
        }

        update
            .apply(&ifname, Backend::Kernel)
            .context("wireguard-control apply failed")?;

        configure_link(tunnel).await?;

        debug!(interface = %tunnel.interface, "kernel interface up");
        Ok(())
    }

    async fn tear_down(&self, tunnel: &WgTunnelConfig) -> Result<()> {
        info!(interface = %tunnel.interface, "tearing down kernel WireGuard interface");
        let ifname: InterfaceName = tunnel.interface.parse().context("invalid interface name")?;
        let device = Device::get(&ifname, Backend::Kernel).context("failed to get device")?;
        device.delete().context("failed to delete interface")?;
        Ok(())
    }

    async fn add_peer(&self, tunnel: &WgTunnelConfig, peer: &WgPeerConfig) -> Result<()> {
        let ifname: InterfaceName = tunnel.interface.parse().context("invalid interface name")?;
        DeviceUpdate::new()
            .add_peer(build_peer(peer)?)
            .apply(&ifname, Backend::Kernel)
            .context("add_peer failed")?;
        Ok(())
    }

    async fn remove_peer(&self, tunnel: &WgTunnelConfig, pubkey: &str) -> Result<()> {
        let ifname: InterfaceName = tunnel.interface.parse().context("invalid interface name")?;
        let key = Key::from_base64(pubkey).context("invalid pubkey")?;
        DeviceUpdate::new()
            .remove_peer_by_key(&key)
            .apply(&ifname, Backend::Kernel)
            .context("remove_peer failed")?;
        Ok(())
    }

    async fn peer_handshakes(&self, tunnel: &WgTunnelConfig) -> Result<Vec<(String, u64)>> {
        let ifname: InterfaceName = tunnel.interface.parse().context("invalid interface name")?;
        let device = Device::get(&ifname, Backend::Kernel).context("device get failed")?;
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

async fn configure_link(tunnel: &WgTunnelConfig) -> Result<()> {
    use futures_util::stream::StreamExt;
    use rtnetlink::{new_connection, LinkUnspec};

    let (conn, handle, _messages) = new_connection().context("rtnetlink connection failed")?;
    tokio::spawn(conn);

    // Look up the link index.
    let mut stream = handle
        .link()
        .get()
        .match_name(tunnel.interface.clone())
        .execute();

    let link = stream
        .next()
        .await
        .with_context(|| format!("interface {} not found", tunnel.interface))?
        .with_context(|| format!("rtnetlink error looking up {}", tunnel.interface))?;
    let index = link.header.index;

    // Assign each address.
    for net in &tunnel.address {
        handle
            .address()
            .add(index, net.addr(), net.prefix_len())
            .execute()
            .await
            .context("failed to add address")?;
    }

    // Set MTU if specified, then bring link up.
    let mut msg_builder = LinkUnspec::new_with_index(index).up();
    if let Some(mtu) = tunnel.mtu {
        msg_builder = msg_builder.mtu(mtu);
    }
    handle
        .link()
        .set(msg_builder.build())
        .execute()
        .await
        .context("failed to configure link")?;

    Ok(())
}
