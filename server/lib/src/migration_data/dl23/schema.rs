//! Schema Entries
use crate::prelude::*;

#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

/// DL23: Add DisplayName to systemmay on OAuth2ResourceServer so existing
/// databases pick it up. The oauth2::reload() path requires DisplayName to be
/// set and schema must permit it before migration assertions can write it.
pub static SCHEMA_CLASS_OAUTH2_RS_DL23: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS,
    name: EntryClass::OAuth2ResourceServer.into(),
    description: "The class epresenting a configured OAuth2 Client".to_string(),

    systemmay: vec![
        Attribute::DisplayName,
        Attribute::Description,
        Attribute::OAuth2RsScopeMap,
        Attribute::OAuth2RsSupScopeMap,
        Attribute::OAuth2JwtLegacyCryptoEnable,
        Attribute::OAuth2PreferShortUsername,
        Attribute::Image,
        Attribute::OAuth2RsClaimMap,
        Attribute::OAuth2Session,
        Attribute::OAuth2RsOrigin,
        Attribute::OAuth2StrictRedirectUri,
        Attribute::OAuth2DeviceFlowEnable,
        Attribute::OAuth2ConsentPromptEnable,
        // Deprecated
        Attribute::Rs256PrivateKeyDer,
        Attribute::OAuth2RsTokenKey,
        Attribute::Es256PrivateKeyDer,
    ],
    systemmust: vec![Attribute::OAuth2RsOriginLanding, Attribute::Name],
    ..Default::default()
});
