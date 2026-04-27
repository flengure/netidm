//! Schema entries for DL17: WireGuard token and peer-monitoring attributes.

use crate::constants::uuids::*;
use crate::prelude::*;

// ---- Token attributes ----

pub static SCHEMA_ATTR_WG_LAST_SEEN_DL17: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_LAST_SEEN,
        name: Attribute::WgLastSeen,
        description: "Timestamp of the peer's most recent WireGuard handshake.".to_string(),
        syntax: SyntaxType::DateTime,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_TOKEN_SECRET_DL17: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_TOKEN_SECRET,
        name: Attribute::WgTokenSecret,
        description: "SHA-256 hash of the one-time registration token secret.".to_string(),
        syntax: SyntaxType::Sha256,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_TOKEN_USES_LEFT_DL17: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_TOKEN_USES_LEFT,
        name: Attribute::WgTokenUsesLeft,
        description: "Remaining uses for this registration token (absent = unlimited).".to_string(),
        syntax: SyntaxType::Uint32,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_TOKEN_EXPIRY_DL17: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_TOKEN_EXPIRY,
        name: Attribute::WgTokenExpiry,
        description: "Expiry datetime for this registration token (absent = no expiry)."
            .to_string(),
        syntax: SyntaxType::DateTime,
        ..Default::default()
    });

pub static SCHEMA_ATTR_WG_TOKEN_PRINCIPAL_REF_DL17: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_WG_TOKEN_PRINCIPAL_REF,
        name: Attribute::WgTokenPrincipalRef,
        description: "Optional reference to the person/account this token is restricted to."
            .to_string(),
        syntax: SyntaxType::ReferenceUuid,
        ..Default::default()
    });

// ---- Classes ----

pub static SCHEMA_CLASS_WG_PEER_DL17: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
        Attribute::WgLastSeen,
    ],
    ..Default::default()
});

pub static SCHEMA_CLASS_WG_TOKEN_DL17: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_WG_TOKEN,
    name: EntryClass::WgToken.into(),
    description: "A one-time (or limited-use) WireGuard peer registration token.".to_string(),
    systemmust: vec![
        Attribute::Name,
        Attribute::WgTunnelRef,
        Attribute::WgUserRef,
        Attribute::WgTokenSecret,
    ],
    systemmay: vec![
        Attribute::WgTokenUsesLeft,
        Attribute::WgTokenExpiry,
        Attribute::WgTokenPrincipalRef,
    ],
    ..Default::default()
});
