//! Schema entries for DL30: Google upstream connector (PR-CONNECTOR-GOOGLE).
//!
//! Adds four Google-specific config attributes on `EntryClass::Connector`.
//! All are optional with documented defaults so pre-DL30 `Connector` entries
//! decode unchanged.

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_CONNECTOR_GOOGLE_ADMIN_EMAIL, UUID_SCHEMA_ATTR_CONNECTOR_GOOGLE_FETCH_GROUPS,
    UUID_SCHEMA_ATTR_CONNECTOR_GOOGLE_HOSTED_DOMAIN,
    UUID_SCHEMA_ATTR_CONNECTOR_GOOGLE_SERVICE_ACCOUNT_JSON, UUID_SCHEMA_CLASS_CONNECTOR,
};
use crate::prelude::*;

/// Google Workspace hosted domain (`hd` claim) restriction.
/// When set, only users whose `hd` claim exactly matches this value are allowed
/// to proceed. Absent = no restriction (all Google accounts accepted).
pub static SCHEMA_ATTR_CONNECTOR_GOOGLE_HOSTED_DOMAIN_DL30: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GOOGLE_HOSTED_DOMAIN,
        name: Attribute::ConnectorGoogleHostedDomain,
        description: "Restrict login to users whose Google Workspace hd claim matches this \
                      domain. Absent = no restriction. Mirrors dex hostedDomains."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// Google service account JSON key for Admin SDK Directory API access.
/// Must be the full JSON object as exported from the Google Cloud Console.
/// Required when `connector_google_fetch_groups` is true.
pub static SCHEMA_ATTR_CONNECTOR_GOOGLE_SERVICE_ACCOUNT_JSON_DL30: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GOOGLE_SERVICE_ACCOUNT_JSON,
        name: Attribute::ConnectorGoogleServiceAccountJson,
        description: "Google service account JSON key for Admin SDK Directory API group fetching. \
                      Required when connector_google_fetch_groups is true."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Google Workspace admin email to impersonate when calling the Directory API
/// via domain-wide delegation. Must be a super-admin or delegated-admin account.
pub static SCHEMA_ATTR_CONNECTOR_GOOGLE_ADMIN_EMAIL_DL30: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GOOGLE_ADMIN_EMAIL,
        name: Attribute::ConnectorGoogleAdminEmail,
        description: "Google Workspace admin email to impersonate via domain-wide delegation \
                      when calling the Directory API. Required with fetch_groups."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// When true, fetch group memberships from the Admin SDK Directory API and
/// feed them to the group-mapping reconciler. Requires `service_account_json`
/// and `admin_email` to be set. Default: false.
pub static SCHEMA_ATTR_CONNECTOR_GOOGLE_FETCH_GROUPS_DL30: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GOOGLE_FETCH_GROUPS,
        name: Attribute::ConnectorGoogleFetchGroups,
        description: "When true, fetch group memberships from the Admin SDK Directory API. \
                      Requires service_account_json and admin_email. Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// OAuth2 client class updated for DL30: adds the four Google-specific config
/// attributes to `systemmay`. Carries forward all DL29 `systemmay` entries.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL30: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
        // DL28 additions — PR-CONNECTOR-GITHUB
        Attribute::ConnectorProviderKind,
        Attribute::ConnectorGithubHost,
        Attribute::ConnectorGithubOrgFilter,
        Attribute::ConnectorGithubAllowedTeams,
        Attribute::ConnectorGithubTeamNameField,
        Attribute::ConnectorGithubLoadAllGroups,
        Attribute::ConnectorGithubPreferredEmailDomain,
        Attribute::ConnectorGithubAllowJitProvisioning,
        // DL29 additions — PR-CONNECTOR-GENERIC-OIDC
        Attribute::ConnectorOidcEnableGroups,
        Attribute::ConnectorOidcGroupsKey,
        Attribute::ConnectorOidcSkipEmailVerified,
        Attribute::ConnectorOidcAllowedGroups,
        Attribute::ConnectorOidcGetUserInfo,
        Attribute::ConnectorOidcUserIdKey,
        Attribute::ConnectorOidcUserNameKey,
        Attribute::ConnectorOidcOverrideClaimMapping,
        Attribute::ConnectorOidcGroupsPrefix,
        Attribute::ConnectorOidcGroupsSuffix,
        // DL30 additions — PR-CONNECTOR-GOOGLE
        Attribute::ConnectorGoogleHostedDomain,
        Attribute::ConnectorGoogleServiceAccountJson,
        Attribute::ConnectorGoogleAdminEmail,
        Attribute::ConnectorGoogleFetchGroups,
    ],
    ..Default::default()
});
