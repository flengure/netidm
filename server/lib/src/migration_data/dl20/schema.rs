//! Schema entries for DL20: OAuth2 client logo URI for SSO button branding.

// Re-export schema items needed by tests that reference `migration_data::latest::schema`.
#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LOGO_URI, UUID_SCHEMA_CLASS_OAUTH2_CLIENT};
use crate::prelude::*;

pub static SCHEMA_ATTR_OAUTH2_CLIENT_LOGO_URI_DL20: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LOGO_URI,
        name: Attribute::OAuth2ClientLogoUri,
        description: "Optional logo image URL for the OAuth2 client provider, shown on the SSO login button."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL20: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_CLIENT,
    name: EntryClass::OAuth2Client.into(),
    description:
        "The class representing a configured OAuth2 Confidential Client acting as an authentication source."
            .to_string(),
    systemmust: vec![
        Attribute::Name,
        Attribute::OAuth2ClientId,
        Attribute::OAuth2ClientSecret,
        Attribute::OAuth2AuthorisationEndpoint,
        Attribute::OAuth2TokenEndpoint,
        Attribute::OAuth2RequestScopes,
    ],
    systemmay: vec![
        Attribute::OAuth2UserinfoEndpoint,
        Attribute::OAuth2JitProvisioning,
        Attribute::OAuth2ClaimMapName,
        Attribute::OAuth2ClaimMapDisplayname,
        Attribute::OAuth2ClaimMapEmail,
        Attribute::OAuth2EmailLinkAccounts,
        Attribute::OAuth2ClientLogoUri,
    ],
    ..Default::default()
});
