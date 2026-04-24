//! Schema entries for DL35: GitLab connector dex-parity additions (PR-CONNECTOR-GITLAB).
//!
//! Adds five optional config attributes on `EntryClass::Connector`:
//! `ConnectorGitlabBaseUrl`, `ConnectorGitlabGroups`,
//! `ConnectorGitlabUseLoginAsId`, `ConnectorGitlabGetGroupsPermission`,
//! and `ConnectorGitlabRootCa`.

use crate::constants::{
    UUID_SCHEMA_ATTR_CONNECTOR_GITLAB_BASE_URL,
    UUID_SCHEMA_ATTR_CONNECTOR_GITLAB_GET_GROUPS_PERMISSION,
    UUID_SCHEMA_ATTR_CONNECTOR_GITLAB_GROUPS, UUID_SCHEMA_ATTR_CONNECTOR_GITLAB_ROOT_CA,
    UUID_SCHEMA_ATTR_CONNECTOR_GITLAB_USE_LOGIN_AS_ID, UUID_SCHEMA_CLASS_CONNECTOR,
};
use crate::prelude::*;

/// Base URL for the GitLab instance. Defaults to `https://gitlab.com` when absent.
/// Set to the root of a self-hosted GitLab for enterprise deployments.
pub static SCHEMA_ATTR_CONNECTOR_GITLAB_BASE_URL_DL35: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITLAB_BASE_URL,
        name: Attribute::ConnectorGitlabBaseUrl,
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
pub static SCHEMA_ATTR_CONNECTOR_GITLAB_GROUPS_DL35: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITLAB_GROUPS,
        name: Attribute::ConnectorGitlabGroups,
        description: "Allowlist of GitLab group paths. Users not in any listed group are \
                      rejected. When absent, all authenticated users are permitted."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// When true, use the user's GitLab login (username) as the subject identifier
/// instead of the numeric user ID. Mirrors dex's `useLoginAsID` option.
pub static SCHEMA_ATTR_CONNECTOR_GITLAB_USE_LOGIN_AS_ID_DL35: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITLAB_USE_LOGIN_AS_ID,
        name: Attribute::ConnectorGitlabUseLoginAsId,
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
pub static SCHEMA_ATTR_CONNECTOR_GITLAB_GET_GROUPS_PERMISSION_DL35: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITLAB_GET_GROUPS_PERMISSION,
        name: Attribute::ConnectorGitlabGetGroupsPermission,
        description: "When true, append the user's role suffix (:owner/:maintainer/:developer) \
                      to each group name. Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// PEM-encoded root CA certificate used when connecting to a self-hosted GitLab
/// instance with a private/self-signed CA.
pub static SCHEMA_ATTR_CONNECTOR_GITLAB_ROOT_CA_DL35: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITLAB_ROOT_CA,
        name: Attribute::ConnectorGitlabRootCa,
        description: "PEM-encoded root CA certificate for self-hosted GitLab TLS verification."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Connector class updated for DL35: adds the five GitLab connector config
/// attributes to `systemmay`. Carries forward all DL34 `systemmay` entries.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL35: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
        // DL32 additions — PR-CONNECTOR-LDAP
        Attribute::ConnectorLdapHost,
        Attribute::ConnectorLdapInsecureNoSsl,
        Attribute::ConnectorLdapInsecureSkipVerify,
        Attribute::ConnectorLdapStartTls,
        Attribute::ConnectorLdapRootCaData,
        Attribute::ConnectorLdapClientCert,
        Attribute::ConnectorLdapClientKey,
        Attribute::ConnectorLdapBindDn,
        Attribute::ConnectorLdapBindPw,
        Attribute::ConnectorLdapUsernamePrompt,
        Attribute::ConnectorLdapUserSearchBaseDn,
        Attribute::ConnectorLdapUserSearchFilter,
        Attribute::ConnectorLdapUserSearchUsername,
        Attribute::ConnectorLdapUserSearchScope,
        Attribute::ConnectorLdapUserSearchIdAttr,
        Attribute::ConnectorLdapUserSearchEmailAttr,
        Attribute::ConnectorLdapUserSearchNameAttr,
        Attribute::ConnectorLdapUserSearchPreferredUsernameAttr,
        Attribute::ConnectorLdapUserSearchEmailSuffix,
        Attribute::ConnectorLdapGroupSearchBaseDn,
        Attribute::ConnectorLdapGroupSearchFilter,
        Attribute::ConnectorLdapGroupSearchScope,
        Attribute::ConnectorLdapGroupSearchUserMatchers,
        Attribute::ConnectorLdapGroupSearchNameAttr,
        // DL34 additions — PR-CONNECTOR-OPENSHIFT
        Attribute::ConnectorOpenshiftIssuer,
        Attribute::ConnectorOpenshiftGroups,
        Attribute::ConnectorOpenshiftInsecureCa,
        Attribute::ConnectorOpenshiftRootCa,
        // DL35 additions — PR-CONNECTOR-GITLAB
        Attribute::ConnectorGitlabBaseUrl,
        Attribute::ConnectorGitlabGroups,
        Attribute::ConnectorGitlabUseLoginAsId,
        Attribute::ConnectorGitlabGetGroupsPermission,
        Attribute::ConnectorGitlabRootCa,
    ],
    ..Default::default()
});
