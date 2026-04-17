//! Schema entries for DL16: WireGuard tunnel and peer objects.

use crate::constants::uuids::*;
use crate::prelude::*;

// ---- Tunnel attributes ----

pub static SCHEMA_ATTR_WG_INTERFACE_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_INTERFACE,
        name: Attribute::WgInterface,
        description: "OS interface name for this WireGuard tunnel (e.g. wg0).".to_string(),
        syntax: SyntaxType::Utf8StringIname,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_LISTEN_PORT_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_LISTEN_PORT,
        name: Attribute::WgListenPort,
        description: "WireGuard ListenPort for the server tunnel.".to_string(),
        syntax: SyntaxType::Uint32,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_ADDRESS_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_ADDRESS,
        name: Attribute::WgAddress,
        description: "CIDR addresses assigned to the tunnel interface (multi-value).".to_string(),
        syntax: SyntaxType::Utf8String,
        multivalue: true,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_DNS_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_DNS,
        name: Attribute::WgDns,
        description: "DNS servers pushed to clients (multi-value).".to_string(),
        syntax: SyntaxType::Utf8String,
        multivalue: true,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_MTU_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_MTU,
        name: Attribute::WgMtu,
        description: "Optional MTU override for the tunnel interface.".to_string(),
        syntax: SyntaxType::Uint32,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_TABLE_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_TABLE,
        name: Attribute::WgTable,
        description: "Routing table setting: auto, off, or a table id.".to_string(),
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_PRE_UP_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_PRE_UP,
        name: Attribute::WgPreUp,
        description: "PreUp hook commands (constrained, multi-value).".to_string(),
        syntax: SyntaxType::Utf8String,
        multivalue: true,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_POST_UP_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_POST_UP,
        name: Attribute::WgPostUp,
        description: "PostUp hook commands (constrained, multi-value).".to_string(),
        syntax: SyntaxType::Utf8String,
        multivalue: true,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_PRE_DOWN_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_PRE_DOWN,
        name: Attribute::WgPreDown,
        description: "PreDown hook commands (constrained, multi-value).".to_string(),
        syntax: SyntaxType::Utf8String,
        multivalue: true,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_POST_DOWN_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_POST_DOWN,
        name: Attribute::WgPostDown,
        description: "PostDown hook commands (constrained, multi-value).".to_string(),
        syntax: SyntaxType::Utf8String,
        multivalue: true,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_SAVE_CONFIG_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_SAVE_CONFIG,
        name: Attribute::WgSaveConfig,
        description: "Whether wg-quick saves runtime state back to the config file.".to_string(),
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_PUBLIC_KEY_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_PUBLIC_KEY,
        name: Attribute::WgPublicKey,
        description: "Server WireGuard public key (sent to clients as [Peer] PublicKey).".to_string(),
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_ENDPOINT_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_ENDPOINT,
        name: Attribute::WgEndpoint,
        description: "Public host:port of this tunnel (sent to clients as [Peer] Endpoint).".to_string(),
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

// ---- Peer attributes ----

pub static SCHEMA_ATTR_WG_PUBKEY_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_PUBKEY,
        name: Attribute::WgPubkey,
        description: "Peer WireGuard public key (user-registered).".to_string(),
        syntax: SyntaxType::Utf8String,
        unique: true,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_ALLOWED_IPS_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_ALLOWED_IPS,
        name: Attribute::WgAllowedIps,
        description: "Server-assigned AllowedIPs for this peer (multi-value CIDR).".to_string(),
        syntax: SyntaxType::Utf8String,
        multivalue: true,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_PRESHARED_KEY_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_PRESHARED_KEY,
        name: Attribute::WgPresharedKey,
        description: "Optional per-peer preshared key stored in netidm, readable by the daemon via ACP.".to_string(),
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_PERSISTENT_KEEPALIVE_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_PERSISTENT_KEEPALIVE,
        name: Attribute::WgPersistentKeepalive,
        description: "PersistentKeepalive interval in seconds.".to_string(),
        syntax: SyntaxType::Uint32,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_TUNNEL_REF_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_TUNNEL_REF,
        name: Attribute::WgTunnelRef,
        description: "Reference to the wg_tunnel entry this peer belongs to.".to_string(),
        syntax: SyntaxType::ReferenceUuid,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_USER_REF_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_USER_REF,
        name: Attribute::WgUserRef,
        description: "Reference to the person/account entry that owns this peer.".to_string(),
        syntax: SyntaxType::ReferenceUuid,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_PRIVATE_KEY_DL16: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_PRIVATE_KEY,
        name: Attribute::WgPrivateKey,
        description: "WireGuard tunnel private key, readable only by the daemon via ACP. Public key is derived from this whenever it changes.".to_string(),
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

// ---- Classes ----

pub static SCHEMA_CLASS_WG_TUNNEL_DL16: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_WG_TUNNEL,
    name: EntryClass::WgTunnel.into(),
    description: "A WireGuard tunnel (server Interface section).".to_string(),
    systemmust: vec![
        Attribute::Name,
        Attribute::WgInterface,
        Attribute::WgPrivateKey,
        Attribute::WgEndpoint,
        Attribute::WgListenPort,
        Attribute::WgAddress,
    ],
    systemmay: vec![
        Attribute::WgPublicKey,  // cached; daemon derives and writes this on private key change
        Attribute::WgDns,
        Attribute::WgMtu,
        Attribute::WgTable,
        Attribute::WgPreUp,
        Attribute::WgPostUp,
        Attribute::WgPreDown,
        Attribute::WgPostDown,
        Attribute::WgSaveConfig,
    ],
    ..Default::default()
});

pub static SCHEMA_CLASS_WG_PEER_DL16: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_WG_PEER,
    name: EntryClass::WgPeer.into(),
    description: "A WireGuard peer (server Peer section + client config derivation).".to_string(),
    systemmust: vec![
        Attribute::Name,
        Attribute::WgPubkey,
        Attribute::WgAllowedIps,
        Attribute::WgTunnelRef,
        Attribute::WgUserRef,
    ],
    systemmay: vec![
        Attribute::WgPresharedKey,
        Attribute::WgPersistentKeepalive,
    ],
    ..Default::default()
});
