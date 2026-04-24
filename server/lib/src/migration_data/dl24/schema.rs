//! Schema entries for DL24: OAuth2 per-connector `link_by` selector.
//!
//! Adds the `oauth2_link_by` attribute to `EntryClass::Connector`. The value is a
//! UTF-8 string; valid values are `"email"`, `"username"`, `"id"`. Semantic validation
//! lives in Rust (see `LinkBy::from_str`). When absent, behaviour defaults to `"email"`
//! which preserves the pre-DL24 linking semantics (`find_and_link_account_by_email`).

// Re-export schema items needed by tests that reference `migration_data::latest::schema`.
#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{UUID_SCHEMA_ATTR_OAUTH2_LINK_BY, UUID_SCHEMA_CLASS_CONNECTOR};
use crate::prelude::*;

/// Per-connector account-linking key selector.
pub static SCHEMA_ATTR_OAUTH2_LINK_BY_DL24: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_LINK_BY,
        name: Attribute::OAuth2LinkBy,
        description: "Per-connector account-linking key selector: one of \"email\", \"username\", \
             \"id\". When absent, linking defaults to matching by email."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// OAuth2 client class updated for DL24: adds `OAuth2LinkBy` to `systemmay`.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL24: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_CONNECTOR,
    name: EntryClass::Connector.into(),
    description: "The class representing a configured OAuth2 Confidential Client acting as \
                      an authentication source."
        .to_string(),
    systemmust: vec![
        Attribute::Name,
        Attribute::ConnectorId,
        Attribute::ConnectorSecret,
        Attribute::OAuth2AuthorisationEndpoint,
        Attribute::OAuth2TokenEndpoint,
        Attribute::OAuth2RequestScopes,
    ],
    systemmay: vec![
        Attribute::DisplayName,
        Attribute::OAuth2UserinfoEndpoint,
        Attribute::OAuth2JitProvisioning,
        Attribute::OAuth2ClaimMapName,
        Attribute::OAuth2ClaimMapDisplayname,
        Attribute::OAuth2ClaimMapEmail,
        Attribute::OAuth2EmailLinkAccounts,
        Attribute::ConnectorLogoUri,
        Attribute::OAuth2Issuer,
        Attribute::OAuth2JwksUri,
        Attribute::OAuth2LinkBy,
    ],
    ..Default::default()
});
