pub mod boringtun;
pub mod kernel;

use crate::types::{WgPeerConfig, WgTunnelConfig};
use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;

/// Abstraction over kernel and userspace WireGuard backends.
#[async_trait]
pub trait WgBackend: Send + Sync {
    /// Create and configure the interface, assign addresses, bring link up, add routes.
    async fn bring_up(&self, tunnel: &WgTunnelConfig, peers: &[WgPeerConfig]) -> Result<()>;

    /// Remove routes, tear down the interface.
    async fn tear_down(&self, tunnel: &WgTunnelConfig) -> Result<()>;

    /// Add a single peer to a live interface.
    async fn add_peer(&self, tunnel: &WgTunnelConfig, peer: &WgPeerConfig) -> Result<()>;

    /// Remove a single peer from a live interface by pubkey.
    async fn remove_peer(&self, tunnel: &WgTunnelConfig, pubkey: &str) -> Result<()>;

    /// Return the last handshake time (Unix seconds) for each peer pubkey.
    async fn peer_handshakes(
        &self,
        tunnel: &WgTunnelConfig,
    ) -> Result<Vec<(String, u64)>>;
}

/// Probe `/sys/module/wireguard` to decide which backend to use.
pub fn detect_backend() -> BackendKind {
    if Path::new("/sys/module/wireguard").exists() {
        BackendKind::Kernel
    } else {
        BackendKind::Boringtun
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Kernel,
    Boringtun,
}
