//! Schema entries for DL25: upstream-to-netidm group mapping plumbing.
//!
//! Adds three multi-value `Utf8String` attributes:
//!   * `OAuth2GroupMapping` on `EntryClass::Connector` — per-connector list of
//!     `<upstream-name>:<netidm-group-uuid>` values. Split on the *last* `:` when
//!     parsing so upstream names may contain colons.
//!   * `SamlGroupMapping` on `EntryClass::SamlClient` — same format, same semantics.
//!   * `OAuth2UpstreamSyncedGroup` on `EntryClass::Person` — per-user marker set
//!     of `<provider-uuid>:<netidm-group-uuid>` values. The reconciliation
//!     baseline: distinguishes connector-applied memberships (subject to removal
//!     on subsequent reconciliation) from locally-granted memberships (never
//!     removed by reconciliation).
//!
//! This DL introduces pure plumbing — no connector populates upstream group
//! names here. Each subsequent per-connector PR populates `claims.groups` for
//! its own provider.

#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_OAUTH2_GROUP_MAPPING, UUID_SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP,
    UUID_SCHEMA_ATTR_SAML_GROUP_MAPPING, UUID_SCHEMA_CLASS_CONNECTOR, UUID_SCHEMA_CLASS_PERSON,
    UUID_SCHEMA_CLASS_SAML_CLIENT,
};
use crate::prelude::*;

/// Per-connector mapping from upstream group names to netidm group UUIDs
/// (OAuth2 upstream). Multi-value. Each value is `<upstream-name>:<group-uuid>`
/// split on the last `:`.
pub static SCHEMA_ATTR_OAUTH2_GROUP_MAPPING_DL25: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_GROUP_MAPPING,
        name: Attribute::OAuth2GroupMapping,
        description: "Per-connector mapping of an upstream group name to a netidm group UUID, \
                      stored as '<upstream-name>:<group-uuid>' and split on the last ':'. \
                      Upstream names may contain ':'; UUIDs cannot."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Per-connector mapping from upstream group names to netidm group UUIDs
/// (SAML upstream). Identical format to `OAuth2GroupMapping`.
pub static SCHEMA_ATTR_SAML_GROUP_MAPPING_DL25: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_GROUP_MAPPING,
        name: Attribute::SamlGroupMapping,
        description: "Per-connector mapping of an upstream SAML group name to a netidm group \
                      UUID, stored as '<upstream-name>:<group-uuid>' and split on the last ':'."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Per-person record of netidm-group memberships applied by upstream
/// connectors. Each value is `<provider-uuid>:<group-uuid>` split on the last
/// `:`. Reconciliation uses this set as its baseline: memberships with a
/// marker entry are subject to upstream-driven removal; memberships without a
/// marker are locally granted and are never removed by reconciliation.
pub static SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP_DL25: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP,
        name: Attribute::OAuth2UpstreamSyncedGroup,
        description: "Per-person marker of netidm-group memberships applied by an upstream \
                      connector, stored as '<provider-uuid>:<group-uuid>' and split on the \
                      last ':'. Written only by the reconciliation helper; its presence \
                      distinguishes connector-applied memberships from locally-granted ones."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// OAuth2 client class updated for DL25: adds `OAuth2GroupMapping` to `systemmay`.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL25: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
        Attribute::OAuth2GroupMapping,
    ],
    ..Default::default()
});

/// SAML client class updated for DL25: adds `SamlGroupMapping` to `systemmay`.
pub static SCHEMA_CLASS_SAML_CLIENT_DL25: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SAML_CLIENT,
    name: EntryClass::SamlClient.into(),
    description: "A SAML 2.0 Identity Provider configuration used for SP-initiated SSO."
        .to_string(),
    systemmust: vec![
        Attribute::Name,
        Attribute::DisplayName,
        Attribute::SamlIdpSsoUrl,
        Attribute::SamlIdpCertificate,
        Attribute::SamlEntityId,
        Attribute::SamlAcsUrl,
    ],
    systemmay: vec![
        Attribute::SamlNameIdFormat,
        Attribute::SamlAttrMapEmail,
        Attribute::SamlAttrMapDisplayname,
        Attribute::SamlAttrMapGroups,
        Attribute::SamlJitProvisioning,
        Attribute::SamlGroupMapping,
    ],
    ..Default::default()
});

/// Person class updated for DL25: adds `OAuth2UpstreamSyncedGroup` to `systemmay`.
pub static SCHEMA_CLASS_PERSON_DL25: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_PERSON,
    name: EntryClass::Person.into(),
    description: "Object representation of a person".to_string(),

    sync_allowed: true,
    systemmay: vec![
        Attribute::PrimaryCredential,
        Attribute::PassKeys,
        Attribute::AttestedPasskeys,
        Attribute::CredentialUpdateIntentToken,
        Attribute::SshPublicKey,
        Attribute::RadiusSecret,
        Attribute::OAuth2ConsentScopeMap,
        Attribute::UserAuthTokenSession,
        Attribute::OAuth2Session,
        Attribute::Mail,
        Attribute::LegalName,
        Attribute::ApplicationPassword,
        Attribute::PasswordChangedTime,
        Attribute::OAuth2UpstreamSyncedGroup,
    ],
    systemmust: vec![Attribute::Name],
    systemexcludes: vec![
        EntryClass::ServiceAccount.into(),
        EntryClass::Application.into(),
    ],
    ..Default::default()
});
