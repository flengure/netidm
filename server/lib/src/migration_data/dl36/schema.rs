//! Schema entries for DL36: Bitbucket Cloud connector dex-parity additions (PR-CONNECTOR-BITBUCKET).
//!
//! Adds three optional config attributes on `EntryClass::OAuth2Client`:
//! `OAuth2ClientBitbucketTeams`, `OAuth2ClientBitbucketGetWorkspacePermissions`,
//! and `OAuth2ClientBitbucketIncludeTeamGroups`.

#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_BITBUCKET_GET_WORKSPACE_PERMISSIONS,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_BITBUCKET_INCLUDE_TEAM_GROUPS,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_BITBUCKET_TEAMS, UUID_SCHEMA_CLASS_OAUTH2_CLIENT,
};
use crate::prelude::*;

/// Workspace/team allowlist for Bitbucket Cloud. Each value is a workspace slug.
/// Empty = allow any authenticated Bitbucket user. Non-empty = access denied unless
/// the user belongs to at least one listed workspace.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_BITBUCKET_TEAMS_DL36: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_BITBUCKET_TEAMS,
        name: Attribute::OAuth2ClientBitbucketTeams,
        description: "Workspace slugs the Bitbucket user must belong to (access gate). \
                      Empty = allow any authenticated user."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// When enabled, appends `{workspace}:{permission}` entries to the groups claim
/// (e.g. `my-org:owner`, `my-org:member`), mirroring dex's getWorkspacePermissions.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_BITBUCKET_GET_WORKSPACE_PERMISSIONS_DL36: LazyLock<
    SchemaAttribute,
> = LazyLock::new(|| SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_BITBUCKET_GET_WORKSPACE_PERMISSIONS,
    name: Attribute::OAuth2ClientBitbucketGetWorkspacePermissions,
    description: "Append workspace:permission suffix entries to the groups claim.".to_string(),
    multivalue: false,
    syntax: SyntaxType::Boolean,
    ..Default::default()
});

/// Deprecated. The Bitbucket 1.0 API this relied on has been removed by Atlassian.
/// If set, a warning is logged at startup and the value is otherwise ignored.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_BITBUCKET_INCLUDE_TEAM_GROUPS_DL36: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_BITBUCKET_INCLUDE_TEAM_GROUPS,
        name: Attribute::OAuth2ClientBitbucketIncludeTeamGroups,
        description: "Deprecated. The Bitbucket 1.0 API this relied on has been removed. \
                      Setting this logs a warning at startup."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL36: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_CLIENT,
    name: EntryClass::OAuth2Client.into(),
    description: "OAuth2 upstream client connector (DL36).".to_string(),
    systemmust: vec![
        Attribute::Class,
        Attribute::Uuid,
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
        // DL36 additions — PR-CONNECTOR-BITBUCKET
        Attribute::OAuth2ClientBitbucketTeams,
        Attribute::OAuth2ClientBitbucketGetWorkspacePermissions,
        Attribute::OAuth2ClientBitbucketIncludeTeamGroups,
    ],
    ..Default::default()
});
