//! Schema entries for DL31: Microsoft Azure AD upstream connector (PR-CONNECTOR-MICROSOFT).
//!
//! Adds thirteen Microsoft-specific config attributes on `EntryClass::Connector`.
//! All are optional with documented defaults so pre-DL31 `Connector` entries
//! decode unchanged.

use crate::constants::{
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_ALLOW_JIT_PROVISIONING,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_API_URL,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_DOMAIN_HINT,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_EMAIL_TO_LOWERCASE,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_GRAPH_URL,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_GROUPS,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_GROUP_NAME_FORMAT,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_ONLY_SECURITY_GROUPS,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_PREFERRED_USERNAME_FIELD,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_PROMPT_TYPE,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_SCOPES,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_TENANT,
    UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_USE_GROUPS_AS_WHITELIST,
    UUID_SCHEMA_CLASS_CONNECTOR,
};
use crate::prelude::*;

/// Azure AD / Entra ID tenant identifier. Use a specific tenant UUID/name to
/// restrict to a single organisation, or "common" / "consumers" / "organizations"
/// for multi-tenant. Default when absent: "common". Groups are only fetched for
/// org (non-common) tenants — mirrors dex tenant field.
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_TENANT_DL31: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_TENANT,
        name: Attribute::ConnectorMicrosoftTenant,
        description: "Azure AD tenant: specific UUID/name for org tenants, or \
                      \"common\" / \"consumers\" / \"organizations\" for multi-tenant. \
                      Default: \"common\". Groups only supported for org tenants."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// Restrict `getMemberGroups` to security groups only. When true, passes
/// `securityEnabledOnly: true` to the Microsoft Graph API. Default: false.
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_ONLY_SECURITY_GROUPS_DL31: LazyLock<
    SchemaAttribute,
> = LazyLock::new(|| SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_ONLY_SECURITY_GROUPS,
    name: Attribute::ConnectorMicrosoftOnlySecurityGroups,
    description: "When true, only security groups are returned from getMemberGroups \
                      (securityEnabledOnly: true). Default: false."
        .to_string(),
    multivalue: false,
    syntax: SyntaxType::Boolean,
    ..Default::default()
});

/// Required-group allowlist. When set, users must be a member of at least one
/// of these groups (after resolution) to be permitted. Also used as a whitelist
/// when `use_groups_as_whitelist` is true. Mirrors dex groups field.
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_GROUPS_DL31: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_GROUPS,
        name: Attribute::ConnectorMicrosoftGroups,
        description: "Required-group allowlist: users must belong to at least one of these \
                      groups. When use_groups_as_whitelist is true, only matching groups \
                      are emitted in the token. Mirrors dex groups."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Format of group identifiers returned by the connector: \"id\" (Azure object ID)
/// or \"name\" (displayName resolved via directoryObjects/getByIds). Default: \"name\".
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_GROUP_NAME_FORMAT_DL31: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_GROUP_NAME_FORMAT,
        name: Attribute::ConnectorMicrosoftGroupNameFormat,
        description: "Group identifier format: \"id\" (Azure object ID) or \
                      \"name\" (displayName via directoryObjects/getByIds). Default: \"name\"."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// When true and `groups` is also set, emit only the intersection of the user's
/// groups and the configured allowlist in the downstream token. When false (default),
/// all groups are emitted and the allowlist is used only as an access gate.
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_USE_GROUPS_AS_WHITELIST_DL31: LazyLock<
    SchemaAttribute,
> = LazyLock::new(|| SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_USE_GROUPS_AS_WHITELIST,
    name: Attribute::ConnectorMicrosoftUseGroupsAsWhitelist,
    description: "When true, only groups from the allowlist are emitted in the token. \
                      When false (default), all groups are emitted and the allowlist is an \
                      access gate only."
        .to_string(),
    multivalue: false,
    syntax: SyntaxType::Boolean,
    ..Default::default()
});

/// When true, lowercase the user's `userPrincipalName` before storing it as the
/// email claim. Matches dex emailToLowercase. Default: false.
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_EMAIL_TO_LOWERCASE_DL31: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_EMAIL_TO_LOWERCASE,
        name: Attribute::ConnectorMicrosoftEmailToLowercase,
        description: "When true, lowercase userPrincipalName before using it as the email claim. \
                      Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// Override the Microsoft login API base URL. Default: https://login.microsoftonline.com.
/// Set for Azure sovereign clouds (e.g. https://login.microsoftonline.us).
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_API_URL_DL31: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_API_URL,
        name: Attribute::ConnectorMicrosoftApiUrl,
        description: "Override the Microsoft login API base URL. \
                      Default: https://login.microsoftonline.com. \
                      Use for Azure sovereign clouds."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

/// Override the Microsoft Graph API base URL. Default: https://graph.microsoft.com.
/// Set for Azure sovereign clouds (e.g. https://graph.microsoft.us).
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_GRAPH_URL_DL31: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_GRAPH_URL,
        name: Attribute::ConnectorMicrosoftGraphUrl,
        description: "Override the Microsoft Graph API base URL. \
                      Default: https://graph.microsoft.com. \
                      Use for Azure sovereign clouds."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

/// Value for the `prompt` query parameter in the authorization URL. Valid values
/// per Microsoft docs: \"login\", \"none\", \"consent\", \"select_account\".
/// Absent = no prompt parameter added.
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_PROMPT_TYPE_DL31: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_PROMPT_TYPE,
        name: Attribute::ConnectorMicrosoftPromptType,
        description: "Value for the prompt= query parameter in the authorization URL \
                      (e.g. \"consent\", \"login\"). Absent = no prompt parameter."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// Value for the `domain_hint` query parameter in the authorization URL.
/// Absent = no domain_hint parameter added.
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_DOMAIN_HINT_DL31: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_DOMAIN_HINT,
        name: Attribute::ConnectorMicrosoftDomainHint,
        description: "Value for the domain_hint= query parameter in the authorization URL. \
                      Absent = no domain_hint parameter."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// Custom OAuth2 scopes to request. When absent, defaults to `user.read`.
/// `directory.read.all` is automatically added when group fetching is needed;
/// `offline_access` is added when refresh tokens are requested.
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_SCOPES_DL31: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_SCOPES,
        name: Attribute::ConnectorMicrosoftScopes,
        description: "Custom OAuth2 scopes to request. Default: user.read. \
                      directory.read.all and offline_access are added automatically when needed."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Which Microsoft Graph user field to use as the preferred_username claim.
/// Valid values: \"name\" (displayName), \"email\" (userPrincipalName),
/// \"mailNickname\", \"onPremisesSamAccountName\". Absent = preferred_username left empty.
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_PREFERRED_USERNAME_FIELD_DL31: LazyLock<
    SchemaAttribute,
> = LazyLock::new(|| SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_PREFERRED_USERNAME_FIELD,
    name: Attribute::ConnectorMicrosoftPreferredUsernameField,
    description: "Which Graph user field maps to preferred_username: \
                      \"name\", \"email\", \"mailNickname\", or \"onPremisesSamAccountName\". \
                      Absent = preferred_username left empty."
        .to_string(),
    multivalue: false,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
});

/// When true, first-time users (no existing Person matching the link key) are
/// automatically provisioned as a new Person entry on login. Default: false.
pub static SCHEMA_ATTR_CONNECTOR_MICROSOFT_ALLOW_JIT_PROVISIONING_DL31: LazyLock<
    SchemaAttribute,
> = LazyLock::new(|| SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CONNECTOR_MICROSOFT_ALLOW_JIT_PROVISIONING,
    name: Attribute::ConnectorMicrosoftAllowJitProvisioning,
    description: "When true, first-time users are automatically provisioned as a new \
                      Person entry on login. Default: false."
        .to_string(),
    multivalue: false,
    syntax: SyntaxType::Boolean,
    ..Default::default()
});

/// OAuth2 client class updated for DL31: adds the thirteen Microsoft-specific config
/// attributes to `systemmay`. Carries forward all DL30 `systemmay` entries.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL31: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
        // DL31 additions — PR-CONNECTOR-MICROSOFT
        Attribute::ConnectorMicrosoftTenant,
        Attribute::ConnectorMicrosoftOnlySecurityGroups,
        Attribute::ConnectorMicrosoftGroups,
        Attribute::ConnectorMicrosoftGroupNameFormat,
        Attribute::ConnectorMicrosoftUseGroupsAsWhitelist,
        Attribute::ConnectorMicrosoftEmailToLowercase,
        Attribute::ConnectorMicrosoftApiUrl,
        Attribute::ConnectorMicrosoftGraphUrl,
        Attribute::ConnectorMicrosoftPromptType,
        Attribute::ConnectorMicrosoftDomainHint,
        Attribute::ConnectorMicrosoftScopes,
        Attribute::ConnectorMicrosoftPreferredUsernameField,
        Attribute::ConnectorMicrosoftAllowJitProvisioning,
    ],
    ..Default::default()
});
