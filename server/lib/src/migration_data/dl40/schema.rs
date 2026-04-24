//! Schema entries for DL40: Atlassian Crowd connector attrs.
//!
//! Four optional attrs on `EntryClass::Connector`:
//! (`ConnectorCrowdBaseUrl`, `ConnectorCrowdClientName`,
//! `ConnectorCrowdClientSecret`, `ConnectorCrowdGroups`).

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_CONNECTOR_CROWD_BASE_URL, UUID_SCHEMA_ATTR_CONNECTOR_CROWD_CLIENT_NAME,
    UUID_SCHEMA_ATTR_CONNECTOR_CROWD_CLIENT_SECRET, UUID_SCHEMA_ATTR_CONNECTOR_CROWD_GROUPS,
    UUID_SCHEMA_CLASS_CONNECTOR,
};
use crate::prelude::*;

// ─── crowd attrs ─────────────────────────────────────────────────────────────

pub static SCHEMA_ATTR_CONNECTOR_CROWD_BASE_URL_DL40: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_CROWD_BASE_URL,
        name: Attribute::ConnectorCrowdBaseUrl,
        description: "Atlassian Crowd REST base URL (e.g. https://crowd.example.com). Required."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_CROWD_CLIENT_NAME_DL40: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_CROWD_CLIENT_NAME,
        name: Attribute::ConnectorCrowdClientName,
        description: "Crowd application name used for HTTP Basic auth. Required.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_CROWD_CLIENT_SECRET_DL40: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_CROWD_CLIENT_SECRET,
        name: Attribute::ConnectorCrowdClientSecret,
        description: "Crowd application password used for HTTP Basic auth. Required.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_CROWD_GROUPS_DL40: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_CROWD_GROUPS,
        name: Attribute::ConnectorCrowdGroups,
        description: "Required Crowd group names (access gate). \
                      Empty = allow any authenticated Crowd user."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

// ─── updated Connector class ─────────────────────────────────────────────────

pub static SCHEMA_CLASS_CONNECTOR_DL40: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_CONNECTOR,
    name: EntryClass::Connector.into(),
    description: "OAuth2 upstream client connector (DL40).".to_string(),
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
        // DL28 — GitHub
        Attribute::ConnectorProviderKind,
        Attribute::ConnectorGithubHost,
        Attribute::ConnectorGithubOrgFilter,
        Attribute::ConnectorGithubAllowedTeams,
        Attribute::ConnectorGithubTeamNameField,
        Attribute::ConnectorGithubLoadAllGroups,
        Attribute::ConnectorGithubPreferredEmailDomain,
        Attribute::ConnectorGithubAllowJitProvisioning,
        // DL29 — generic OIDC
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
        // DL30 — Google
        Attribute::ConnectorGoogleHostedDomain,
        Attribute::ConnectorGoogleServiceAccountJson,
        Attribute::ConnectorGoogleAdminEmail,
        Attribute::ConnectorGoogleFetchGroups,
        // DL31 — Microsoft
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
        // DL32 — LDAP
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
        // DL34 — OpenShift
        Attribute::ConnectorOpenshiftIssuer,
        Attribute::ConnectorOpenshiftGroups,
        Attribute::ConnectorOpenshiftInsecureCa,
        Attribute::ConnectorOpenshiftRootCa,
        // DL35 — GitLab
        Attribute::ConnectorGitlabBaseUrl,
        Attribute::ConnectorGitlabGroups,
        Attribute::ConnectorGitlabUseLoginAsId,
        Attribute::ConnectorGitlabGetGroupsPermission,
        Attribute::ConnectorGitlabRootCa,
        // DL36 — Bitbucket Cloud
        Attribute::ConnectorBitbucketTeams,
        Attribute::ConnectorBitbucketGetWorkspacePermissions,
        Attribute::ConnectorBitbucketIncludeTeamGroups,
        // DL37 — GitHub use_login_as_id
        Attribute::ConnectorGithubUseLoginAsId,
        // DL38 — authproxy
        Attribute::ConnectorAuthproxyUserHeader,
        Attribute::ConnectorAuthproxyEmailHeader,
        Attribute::ConnectorAuthproxyGroupsHeader,
        // DL38 — gitea
        Attribute::ConnectorGiteaBaseUrl,
        Attribute::ConnectorGiteaGroups,
        Attribute::ConnectorGiteaInsecureCa,
        Attribute::ConnectorGiteaRootCa,
        Attribute::ConnectorGiteaLoadAllGroups,
        Attribute::ConnectorGiteaUseLoginAsId,
        // DL39 — keystone
        Attribute::ConnectorKeystoneHost,
        Attribute::ConnectorKeystoneDomain,
        Attribute::ConnectorKeystoneGroups,
        Attribute::ConnectorKeystoneInsecureCa,
        // DL40 — atlassian crowd
        Attribute::ConnectorCrowdBaseUrl,
        Attribute::ConnectorCrowdClientName,
        Attribute::ConnectorCrowdClientSecret,
        Attribute::ConnectorCrowdGroups,
    ],
    ..Default::default()
});
