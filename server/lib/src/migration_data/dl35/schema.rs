//! Schema entries for DL35: GitLab connector dex-parity additions (PR-CONNECTOR-GITLAB).
//!
//! Adds five optional config attributes on `EntryClass::OAuth2Client`:
//! `OAuth2ClientGitlabBaseUrl`, `OAuth2ClientGitlabGroups`,
//! `OAuth2ClientGitlabUseLoginAsId`, `OAuth2ClientGitlabGetGroupsPermission`,
//! and `OAuth2ClientGitlabRootCa`.

#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_BASE_URL,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_GET_GROUPS_PERMISSION,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_GROUPS, UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_ROOT_CA,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_USE_LOGIN_AS_ID, UUID_SCHEMA_CLASS_OAUTH2_CLIENT,
};
use crate::prelude::*;

/// Base URL for the GitLab instance. Defaults to `https://gitlab.com` when absent.
/// Set to the root of a self-hosted GitLab for enterprise deployments.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_BASE_URL_DL35: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_BASE_URL,
        name: Attribute::OAuth2ClientGitlabBaseUrl,
        description: "Base URL of the GitLab instance (default: https://gitlab.com). \
                      Set for self-hosted GitLab deployments."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Allowlist of GitLab group paths. When non-empty, only users who are members of
/// at least one listed group are permitted to authenticate. Multi-value — each
/// value is one permitted group path (e.g. `myorg/myteam`).
pub static SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_GROUPS_DL35: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_GROUPS,
        name: Attribute::OAuth2ClientGitlabGroups,
        description: "Allowlist of GitLab group paths. Users not in any listed group are \
                      rejected. When absent, all authenticated users are permitted."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// When true, use the user's GitLab login (username) as the subject identifier
/// instead of the numeric user ID. Mirrors dex's `useLoginAsID` option.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_USE_LOGIN_AS_ID_DL35: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_USE_LOGIN_AS_ID,
        name: Attribute::OAuth2ClientGitlabUseLoginAsId,
        description: "When true, use the GitLab username as the subject ID instead of the \
                      numeric user ID. Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// When true, group membership level (owner/maintainer/developer) is appended to
/// each group name as a suffix (e.g. `myorg:owner`). Mirrors dex's
/// `getGroupsPermission` option.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_GET_GROUPS_PERMISSION_DL35: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_GET_GROUPS_PERMISSION,
        name: Attribute::OAuth2ClientGitlabGetGroupsPermission,
        description: "When true, append the user's role suffix (:owner/:maintainer/:developer) \
                      to each group name. Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// PEM-encoded root CA certificate used when connecting to a self-hosted GitLab
/// instance with a private/self-signed CA.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_ROOT_CA_DL35: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_ROOT_CA,
        name: Attribute::OAuth2ClientGitlabRootCa,
        description: "PEM-encoded root CA certificate for self-hosted GitLab TLS verification."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// OAuth2Client class updated for DL35: adds the five GitLab connector config
/// attributes to `systemmay`. Carries forward all DL34 `systemmay` entries.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL35: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
        // DL30 additions — PR-CONNECTOR-GOOGLE
        Attribute::OAuth2ClientGoogleHostedDomain,
        Attribute::OAuth2ClientGoogleServiceAccountJson,
        Attribute::OAuth2ClientGoogleAdminEmail,
        Attribute::OAuth2ClientGoogleFetchGroups,
        // DL31 additions — PR-CONNECTOR-MICROSOFT
        Attribute::OAuth2ClientMicrosoftTenant,
        Attribute::OAuth2ClientMicrosoftOnlySecurityGroups,
        Attribute::OAuth2ClientMicrosoftGroups,
        Attribute::OAuth2ClientMicrosoftGroupNameFormat,
        Attribute::OAuth2ClientMicrosoftUseGroupsAsWhitelist,
        Attribute::OAuth2ClientMicrosoftEmailToLowercase,
        Attribute::OAuth2ClientMicrosoftApiUrl,
        Attribute::OAuth2ClientMicrosoftGraphUrl,
        Attribute::OAuth2ClientMicrosoftPromptType,
        Attribute::OAuth2ClientMicrosoftDomainHint,
        Attribute::OAuth2ClientMicrosoftScopes,
        Attribute::OAuth2ClientMicrosoftPreferredUsernameField,
        Attribute::OAuth2ClientMicrosoftAllowJitProvisioning,
        // DL32 additions — PR-CONNECTOR-LDAP
        Attribute::OAuth2ClientLdapHost,
        Attribute::OAuth2ClientLdapInsecureNoSsl,
        Attribute::OAuth2ClientLdapInsecureSkipVerify,
        Attribute::OAuth2ClientLdapStartTls,
        Attribute::OAuth2ClientLdapRootCaData,
        Attribute::OAuth2ClientLdapClientCert,
        Attribute::OAuth2ClientLdapClientKey,
        Attribute::OAuth2ClientLdapBindDn,
        Attribute::OAuth2ClientLdapBindPw,
        Attribute::OAuth2ClientLdapUsernamePrompt,
        Attribute::OAuth2ClientLdapUserSearchBaseDn,
        Attribute::OAuth2ClientLdapUserSearchFilter,
        Attribute::OAuth2ClientLdapUserSearchUsername,
        Attribute::OAuth2ClientLdapUserSearchScope,
        Attribute::OAuth2ClientLdapUserSearchIdAttr,
        Attribute::OAuth2ClientLdapUserSearchEmailAttr,
        Attribute::OAuth2ClientLdapUserSearchNameAttr,
        Attribute::OAuth2ClientLdapUserSearchPreferredUsernameAttr,
        Attribute::OAuth2ClientLdapUserSearchEmailSuffix,
        Attribute::OAuth2ClientLdapGroupSearchBaseDn,
        Attribute::OAuth2ClientLdapGroupSearchFilter,
        Attribute::OAuth2ClientLdapGroupSearchScope,
        Attribute::OAuth2ClientLdapGroupSearchUserMatchers,
        Attribute::OAuth2ClientLdapGroupSearchNameAttr,
        // DL34 additions — PR-CONNECTOR-OPENSHIFT
        Attribute::OAuth2ClientOpenshiftIssuer,
        Attribute::OAuth2ClientOpenshiftGroups,
        Attribute::OAuth2ClientOpenshiftInsecureCa,
        Attribute::OAuth2ClientOpenshiftRootCa,
        // DL35 additions — PR-CONNECTOR-GITLAB
        Attribute::OAuth2ClientGitlabBaseUrl,
        Attribute::OAuth2ClientGitlabGroups,
        Attribute::OAuth2ClientGitlabUseLoginAsId,
        Attribute::OAuth2ClientGitlabGetGroupsPermission,
        Attribute::OAuth2ClientGitlabRootCa,
    ],
    ..Default::default()
});
