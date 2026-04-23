//! Schema entries for DL29: generic-OIDC upstream connector (PR-CONNECTOR-GENERIC-OIDC).
//!
//! Adds ten OIDC-specific config attributes on `EntryClass::OAuth2Client`.
//! All are optional with documented defaults so pre-DL29 `OAuth2Client` entries
//! decode unchanged. The discriminator `OAuth2ClientProviderKind` was already
//! added in DL28 and is not repeated here.

#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_ALLOWED_GROUPS,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_ENABLE_GROUPS,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GET_USER_INFO,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_KEY,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_PREFIX,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_SUFFIX,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_OVERRIDE_CLAIM_MAPPING,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_SKIP_EMAIL_VERIFIED,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_USER_ID_KEY,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_USER_NAME_KEY, UUID_SCHEMA_CLASS_OAUTH2_CLIENT,
};
use crate::prelude::*;

/// When true, groups are extracted from the configured claim key and fed to
/// the group-mapping reconciler. Disabled by default (mirrors dex's
/// `insecureEnableGroups = false` default — issue #1065).
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_ENABLE_GROUPS_DL29: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_ENABLE_GROUPS,
        name: Attribute::OAuth2ClientOidcEnableGroups,
        description: "When true, extract groups from the OIDC token/userinfo and feed them to \
                      the group-mapping reconciler. Disabled by default. Mirrors dex \
                      insecureEnableGroups."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// The claim key to look up for upstream group names. Defaults to `"groups"`.
/// Mirrors dex's `claimMapping.groupsKey`.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_KEY_DL29: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_KEY,
        name: Attribute::OAuth2ClientOidcGroupsKey,
        description: "Claim key used to extract upstream group names from the OIDC token or \
                      userinfo response. Defaults to 'groups'. Mirrors dex claimMapping.groupsKey."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// When true, treat a missing `email_verified` claim as verified. Useful for
/// providers that omit the claim but are known to only issue verified addresses.
/// Mirrors dex's `insecureSkipEmailVerified`.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_SKIP_EMAIL_VERIFIED_DL29: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_SKIP_EMAIL_VERIFIED,
        name: Attribute::OAuth2ClientOidcSkipEmailVerified,
        description: "When true, a missing email_verified claim is treated as true. Defaults to \
                      false. Mirrors dex insecureSkipEmailVerified."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// Allowlist of upstream group names that gate login. When non-empty, a login
/// succeeds only if the user's upstream groups intersect this list. Absence =
/// gate off. Mirrors dex's `allowedGroups`.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_ALLOWED_GROUPS_DL29: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_ALLOWED_GROUPS,
        name: Attribute::OAuth2ClientOidcAllowedGroups,
        description: "Allowlist of upstream group names. Non-empty = login only when user's \
                      upstream groups intersect this list. Mirrors dex allowedGroups."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// When true, always call the userinfo endpoint after token exchange, even
/// when an id_token is present. Userinfo claims override id_token claims on
/// conflict. Mirrors dex's `getUserInfo`.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GET_USER_INFO_DL29: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GET_USER_INFO,
        name: Attribute::OAuth2ClientOidcGetUserInfo,
        description: "When true, always call the userinfo endpoint and merge its claims over \
                      the id_token claims. Mirrors dex getUserInfo."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// Override the claim key used to derive the stable subject identifier.
/// Absent = use the standard `sub` claim. Mirrors dex's `userIDKey`.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_USER_ID_KEY_DL29: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_USER_ID_KEY,
        name: Attribute::OAuth2ClientOidcUserIdKey,
        description: "Override the claim key used as the stable user ID. Absent = use 'sub'. \
                      Mirrors dex userIDKey."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Override the claim key used to derive the display name / username hint.
/// Absent = use the standard `name` claim. Mirrors dex's `userNameKey`.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_USER_NAME_KEY_DL29: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_USER_NAME_KEY,
        name: Attribute::OAuth2ClientOidcUserNameKey,
        description: "Override the claim key used as the display name. Absent = use 'name'. \
                      Mirrors dex userNameKey."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// When true, custom claim keys always take precedence over the standard OIDC
/// claim names even when both are present. Mirrors dex's `overrideClaimMapping`.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_OVERRIDE_CLAIM_MAPPING_DL29: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_OVERRIDE_CLAIM_MAPPING,
        name: Attribute::OAuth2ClientOidcOverrideClaimMapping,
        description: "When true, custom claim keys override standard OIDC claim names even when \
                      the standard name is present. Mirrors dex overrideClaimMapping."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// String prefix prepended to every extracted upstream group name before the
/// group-mapping reconciler sees it. Absent = no prefix. Mirrors dex's
/// `claimMutations.modifyGroupNames.prefix`.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_PREFIX_DL29: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_PREFIX,
        name: Attribute::OAuth2ClientOidcGroupsPrefix,
        description: "Prefix prepended to every upstream group name. Absent = no prefix. \
                      Mirrors dex claimMutations.modifyGroupNames.prefix."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// String suffix appended to every extracted upstream group name before the
/// group-mapping reconciler sees it. Absent = no suffix. Mirrors dex's
/// `claimMutations.modifyGroupNames.suffix`.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_SUFFIX_DL29: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_SUFFIX,
        name: Attribute::OAuth2ClientOidcGroupsSuffix,
        description: "Suffix appended to every upstream group name. Absent = no suffix. \
                      Mirrors dex claimMutations.modifyGroupNames.suffix."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// OAuth2 client class updated for DL29: adds the ten OIDC-specific config
/// attributes to `systemmay`. Carries forward the DL28 `systemmay` set.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL29: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_CLIENT,
    name: EntryClass::OAuth2Client.into(),
    description: "The class representing a configured OAuth2 Confidential Client acting as \
                      an authentication source."
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
        Attribute::DisplayName,
        Attribute::OAuth2UserinfoEndpoint,
        Attribute::OAuth2JitProvisioning,
        Attribute::OAuth2ClaimMapName,
        Attribute::OAuth2ClaimMapDisplayname,
        Attribute::OAuth2ClaimMapEmail,
        Attribute::OAuth2EmailLinkAccounts,
        Attribute::OAuth2ClientLogoUri,
        Attribute::OAuth2Issuer,
        Attribute::OAuth2JwksUri,
        Attribute::OAuth2LinkBy,
        Attribute::OAuth2GroupMapping,
        // DL28 additions — PR-CONNECTOR-GITHUB
        Attribute::OAuth2ClientProviderKind,
        Attribute::OAuth2ClientGithubHost,
        Attribute::OAuth2ClientGithubOrgFilter,
        Attribute::OAuth2ClientGithubAllowedTeams,
        Attribute::OAuth2ClientGithubTeamNameField,
        Attribute::OAuth2ClientGithubLoadAllGroups,
        Attribute::OAuth2ClientGithubPreferredEmailDomain,
        Attribute::OAuth2ClientGithubAllowJitProvisioning,
        // DL29 additions — PR-CONNECTOR-GENERIC-OIDC
        Attribute::OAuth2ClientOidcEnableGroups,
        Attribute::OAuth2ClientOidcGroupsKey,
        Attribute::OAuth2ClientOidcSkipEmailVerified,
        Attribute::OAuth2ClientOidcAllowedGroups,
        Attribute::OAuth2ClientOidcGetUserInfo,
        Attribute::OAuth2ClientOidcUserIdKey,
        Attribute::OAuth2ClientOidcUserNameKey,
        Attribute::OAuth2ClientOidcOverrideClaimMapping,
        Attribute::OAuth2ClientOidcGroupsPrefix,
        Attribute::OAuth2ClientOidcGroupsSuffix,
    ],
    ..Default::default()
});
