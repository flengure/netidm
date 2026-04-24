//! Schema entries for DL36: Bitbucket Cloud connector dex-parity additions (PR-CONNECTOR-BITBUCKET).
//!
//! Adds three optional config attributes on `EntryClass::Connector`:
//! `ConnectorBitbucketTeams`, `ConnectorBitbucketGetWorkspacePermissions`,
//! and `ConnectorBitbucketIncludeTeamGroups`.

#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_CONNECTOR_BITBUCKET_GET_WORKSPACE_PERMISSIONS,
    UUID_SCHEMA_ATTR_CONNECTOR_BITBUCKET_INCLUDE_TEAM_GROUPS,
    UUID_SCHEMA_ATTR_CONNECTOR_BITBUCKET_TEAMS, UUID_SCHEMA_CLASS_CONNECTOR,
};
use crate::prelude::*;

/// Workspace/team allowlist for Bitbucket Cloud. Each value is a workspace slug.
/// Empty = allow any authenticated Bitbucket user. Non-empty = access denied unless
/// the user belongs to at least one listed workspace.
pub static SCHEMA_ATTR_CONNECTOR_BITBUCKET_TEAMS_DL36: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_BITBUCKET_TEAMS,
        name: Attribute::ConnectorBitbucketTeams,
        description: "Workspace slugs the Bitbucket user must belong to (access gate). \
                      Empty = allow any authenticated user."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// When enabled, appends `{workspace}:{permission}` entries to the groups claim
/// (e.g. `my-org:owner`, `my-org:member`), mirroring dex's getWorkspacePermissions.
pub static SCHEMA_ATTR_CONNECTOR_BITBUCKET_GET_WORKSPACE_PERMISSIONS_DL36: LazyLock<
    SchemaAttribute,
> = LazyLock::new(|| SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CONNECTOR_BITBUCKET_GET_WORKSPACE_PERMISSIONS,
    name: Attribute::ConnectorBitbucketGetWorkspacePermissions,
    description: "Append workspace:permission suffix entries to the groups claim.".to_string(),
    multivalue: false,
    syntax: SyntaxType::Boolean,
    ..Default::default()
});

/// Deprecated. The Bitbucket 1.0 API this relied on has been removed by Atlassian.
/// If set, a warning is logged at startup and the value is otherwise ignored.
pub static SCHEMA_ATTR_CONNECTOR_BITBUCKET_INCLUDE_TEAM_GROUPS_DL36: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_BITBUCKET_INCLUDE_TEAM_GROUPS,
        name: Attribute::ConnectorBitbucketIncludeTeamGroups,
        description: "Deprecated. The Bitbucket 1.0 API this relied on has been removed. \
                      Setting this logs a warning at startup."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL36: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_CONNECTOR,
    name: EntryClass::Connector.into(),
    description: "OAuth2 upstream client connector (DL36).".to_string(),
    systemmust: vec![
        Attribute::Class,
        Attribute::Uuid,
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
        // DL36 additions — PR-CONNECTOR-BITBUCKET
        Attribute::ConnectorBitbucketTeams,
        Attribute::ConnectorBitbucketGetWorkspacePermissions,
        Attribute::ConnectorBitbucketIncludeTeamGroups,
    ],
    ..Default::default()
});
