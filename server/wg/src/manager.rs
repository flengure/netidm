use crate::backend::{BackendKind, WgBackend};
use crate::types::{WgPeerConfig, WgTunnelConfig};
use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::info;
use wireguard_control::Key;

/// High-level manager that drives a single WireGuard tunnel via a chosen backend.
pub struct WgManager {
    backend: Arc<dyn WgBackend>,
    kind: BackendKind,
}

impl WgManager {
    pub fn new(backend: Arc<dyn WgBackend>, kind: BackendKind) -> Self {
        info!(?kind, "WireGuard backend selected");
        Self { backend, kind }
    }

    pub fn backend_kind(&self) -> BackendKind {
        self.kind
    }

    pub async fn bring_up(&self, tunnel: &WgTunnelConfig, peers: &[WgPeerConfig]) -> Result<()> {
        crate::hooks::run_hooks(&tunnel.pre_up, "PreUp").await?;
        self.backend.bring_up(tunnel, peers).await?;
        crate::hooks::run_hooks(&tunnel.post_up, "PostUp").await?;
        Ok(())
    }

    pub async fn tear_down(&self, tunnel: &WgTunnelConfig) -> Result<()> {
        crate::hooks::run_hooks(&tunnel.pre_down, "PreDown").await?;
        self.backend.tear_down(tunnel).await?;
        crate::hooks::run_hooks(&tunnel.post_down, "PostDown").await?;
        Ok(())
    }

    pub async fn add_peer(&self, tunnel: &WgTunnelConfig, peer: &WgPeerConfig) -> Result<()> {
        self.backend.add_peer(tunnel, peer).await
    }

    pub async fn remove_peer(&self, tunnel: &WgTunnelConfig, pubkey: &str) -> Result<()> {
        self.backend.remove_peer(tunnel, pubkey).await
    }

    /// Return (pubkey, last_handshake_unix_secs) for each live peer.
    pub async fn peer_handshakes(&self, tunnel: &WgTunnelConfig) -> Result<Vec<(String, u64)>> {
        self.backend.peer_handshakes(tunnel).await
    }

    /// Derive the WireGuard public key from a base64-encoded private key string.
    pub fn derive_public_key(private_key_b64: &str) -> Result<String> {
        let private = Key::from_base64(private_key_b64).context("invalid private key")?;
        Ok(private.get_public().to_base64())
    }
}
