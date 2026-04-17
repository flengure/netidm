//! Schema entries for DL18: OAuth2 email-based account linking.

// Re-export schema items used by test code via `latest::schema`.
#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_OAUTH2_DOMAIN_EMAIL_LINK_ACCOUNTS,
    UUID_SCHEMA_ATTR_OAUTH2_EMAIL_LINK_ACCOUNTS, UUID_SCHEMA_CLASS_DOMAIN_INFO,
    UUID_SCHEMA_CLASS_OAUTH2_CLIENT,
};
use crate::prelude::*;

pub static SCHEMA_ATTR_OAUTH2_EMAIL_LINK_ACCOUNTS_DL18: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_EMAIL_LINK_ACCOUNTS,
        name: Attribute::OAuth2EmailLinkAccounts,
        description:
            "When set, overrides the global domain email-link-accounts setting for this provider."
                .to_string(),
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

pub static SCHEMA_ATTR_OAUTH2_DOMAIN_EMAIL_LINK_ACCOUNTS_DL18: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_DOMAIN_EMAIL_LINK_ACCOUNTS,
        name: Attribute::OAuth2DomainEmailLinkAccounts,
        description: "Global default for OAuth2 email-based account linking across all providers."
            .to_string(),
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL18: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
    ],
    ..Default::default()
});

pub static SCHEMA_CLASS_DOMAIN_INFO_DL18: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_DOMAIN_INFO,
    name: EntryClass::DomainInfo.into(),
    description: "Local domain information and configuration".to_string(),
    systemmay: vec![
        Attribute::DomainSsid,
        Attribute::DomainLdapBasedn,
        Attribute::LdapMaxQueryableAttrs,
        Attribute::LdapAllowUnixPwBind,
        Attribute::Image,
        Attribute::PatchLevel,
        Attribute::DomainDevelopmentTaint,
        Attribute::DomainAllowEasterEggs,
        Attribute::DomainDisplayName,
        Attribute::OAuth2DomainEmailLinkAccounts,
    ],
    systemmust: vec![
        Attribute::Name,
        Attribute::DomainUuid,
        Attribute::DomainName,
        Attribute::Version,
    ],
    ..Default::default()
});
