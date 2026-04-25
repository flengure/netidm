//! WireGuard management API request/response types.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ---- Tunnel admin ----

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WgTunnelCreate {
    pub name: String,
    pub interface: String,
    pub private_key: String,
    pub endpoint: String,
    pub listen_port: u16,
    pub address: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WgTunnelPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_up: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_up: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_down: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_down: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WgTunnelResponse {
    pub name: String,
    pub interface: String,
    pub public_key: String,
    pub endpoint: String,
    pub listen_port: u16,
    pub address: Vec<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    pub peer_count: u32,
    pub backend: String,
}

// ---- Peer admin ----

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WgPeerResponse {
    pub name: String,
    pub pubkey: String,
    pub allowed_ips: Vec<String>,
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u32>,
}

// ---- Token admin ----

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WgTokenCreate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uses: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WgTokenCreatedResponse {
    pub token_name: String,
    pub secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WgTokenInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uses_left: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}

// ---- Client self-registration ----

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WgConnectRequest {
    pub token: String,
    pub pubkey: String,
    /// Optional PSK supplied by the client. If omitted on first registration,
    /// the server generates one. Ignored on re-sync (existing peer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    /// Optional device label (hostname) used to name the peer entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WgConnectResponse {
    /// wg-quick config block with `PrivateKey = <client-private-key>` as a
    /// placeholder — the calling script substitutes the real private key.
    pub config: String,
    pub address: Vec<String>,
    pub server_pubkey: String,
    pub endpoint: String,
    /// The PSK to embed in the config. Present on first registration (server-
    /// generated or client-supplied) and on re-sync (the stored value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psk: Option<String>,
    /// `"new"` when a peer was created, `"existing"` when returning stored config.
    pub status: String,
}
