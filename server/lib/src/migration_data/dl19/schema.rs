//! Schema entries for DL19: skip-auth route rules for the forward auth gate.

// Re-export schema items used by test code via `latest::schema`.
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{UUID_SCHEMA_ATTR_SKIP_AUTH_ROUTE, UUID_SCHEMA_CLASS_SYSTEM_CONFIG};
use crate::prelude::*;

pub static SCHEMA_ATTR_SKIP_AUTH_ROUTE_DL19: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SKIP_AUTH_ROUTE,
        name: Attribute::SkipAuthRoute,
        description: "A skip-auth rule for the forward auth gate (`/oauth2/auth`). \
            Each value is a string of the form `METHOD=^/regex$` or `^/regex$` (any method)."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

pub static SCHEMA_CLASS_SYSTEM_CONFIG_DL19: LazyLock<SchemaClass> =
    LazyLock::new(|| SchemaClass {
        uuid: UUID_SCHEMA_CLASS_SYSTEM_CONFIG,
        name: EntryClass::SystemConfig.into(),
        description: "The class representing a system (topologies) configuration options"
            .to_string(),
        systemmay: vec![
            Attribute::Description,
            Attribute::BadlistPassword,
            Attribute::AuthSessionExpiry,
            Attribute::PrivilegeExpiry,
            Attribute::DeniedName,
            Attribute::SkipAuthRoute,
        ],
        ..Default::default()
    });
