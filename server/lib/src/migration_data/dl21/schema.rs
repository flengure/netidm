//! Schema entries for DL21: generic OIDC upstream connector (issuer + JWKS URI attributes).

// Re-export schema items needed by tests that reference `migration_data::latest::schema`.
#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_OAUTH2_ISSUER, UUID_SCHEMA_ATTR_OAUTH2_JWKS_URI,
    UUID_SCHEMA_CLASS_CONNECTOR,
};
use crate::prelude::*;

/// Schema attribute for the OIDC issuer URL stored on an OAuth2 client provider entry.
pub static SCHEMA_ATTR_OAUTH2_ISSUER_DL21: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_ISSUER,
        name: Attribute::OAuth2Issuer,
        description: "OIDC issuer URL used to discover this provider's endpoints via \
            `.well-known/openid-configuration`."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

/// Schema attribute for the JWKS URI used to verify id_token signatures from an OIDC provider.
pub static SCHEMA_ATTR_OAUTH2_JWKS_URI_DL21: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_JWKS_URI,
        name: Attribute::OAuth2JwksUri,
        description:
            "JWKS endpoint URL for cryptographic verification of id_tokens from this OIDC provider."
                .to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

/// OAuth2 client class updated for DL21: adds `OAuth2Issuer` and `OAuth2JwksUri` to `systemmay`.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL21: LazyLock<SchemaClass> = LazyLock::new(|| {
    SchemaClass {
    uuid: UUID_SCHEMA_CLASS_CONNECTOR,
    name: EntryClass::Connector.into(),
    description:
        "The class representing a configured OAuth2 Confidential Client acting as an authentication source."
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
    ],
    ..Default::default()
}
});
