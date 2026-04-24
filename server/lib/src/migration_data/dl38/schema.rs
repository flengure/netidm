//! Schema entries for DL38: authproxy + gitea connector attrs.
//!
//! Authproxy: three optional header-name attrs on `EntryClass::Connector`
//! (`ConnectorAuthproxyUserHeader`, `ConnectorAuthproxyEmailHeader`,
//! `ConnectorAuthproxyGroupsHeader`).
//!
//! Gitea: six optional attrs on `EntryClass::Connector`
//! (`ConnectorGiteaBaseUrl`, `ConnectorGiteaGroups`,
//! `ConnectorGiteaInsecureCa`, `ConnectorGiteaRootCa`,
//! `ConnectorGiteaLoadAllGroups`, `ConnectorGiteaUseLoginAsId`).

#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_CONNECTOR_AUTHPROXY_EMAIL_HEADER,
    UUID_SCHEMA_ATTR_CONNECTOR_AUTHPROXY_GROUPS_HEADER,
    UUID_SCHEMA_ATTR_CONNECTOR_AUTHPROXY_USER_HEADER, UUID_SCHEMA_ATTR_CONNECTOR_GITEA_BASE_URL,
    UUID_SCHEMA_ATTR_CONNECTOR_GITEA_GROUPS, UUID_SCHEMA_ATTR_CONNECTOR_GITEA_INSECURE_CA,
    UUID_SCHEMA_ATTR_CONNECTOR_GITEA_LOAD_ALL_GROUPS, UUID_SCHEMA_ATTR_CONNECTOR_GITEA_ROOT_CA,
    UUID_SCHEMA_ATTR_CONNECTOR_GITEA_USE_LOGIN_AS_ID, UUID_SCHEMA_CLASS_CONNECTOR,
};
use crate::prelude::*;

// ─── authproxy attrs ─────────────────────────────────────────────────────────

pub static SCHEMA_ATTR_CONNECTOR_AUTHPROXY_USER_HEADER_DL38: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_AUTHPROXY_USER_HEADER,
        name: Attribute::ConnectorAuthproxyUserHeader,
        description: "Name of the HTTP request header carrying the authenticated username \
                      (e.g. X-Remote-User). Required for authproxy connectors."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_AUTHPROXY_EMAIL_HEADER_DL38: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_AUTHPROXY_EMAIL_HEADER,
        name: Attribute::ConnectorAuthproxyEmailHeader,
        description:
            "Name of the HTTP request header carrying the user's email address (optional)."
                .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_AUTHPROXY_GROUPS_HEADER_DL38: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_AUTHPROXY_GROUPS_HEADER,
        name: Attribute::ConnectorAuthproxyGroupsHeader,
        description: "Name of the HTTP request header carrying a comma-separated list of \
                      group names (optional)."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

// ─── gitea attrs ─────────────────────────────────────────────────────────────

pub static SCHEMA_ATTR_CONNECTOR_GITEA_BASE_URL_DL38: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITEA_BASE_URL,
        name: Attribute::ConnectorGiteaBaseUrl,
        description: "Base URL of the Gitea instance (e.g. https://gitea.example.com). Required."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_GITEA_GROUPS_DL38: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITEA_GROUPS,
        name: Attribute::ConnectorGiteaGroups,
        description: "Gitea organization names the user must belong to (access gate). \
                      Empty = allow any authenticated Gitea user."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_GITEA_INSECURE_CA_DL38: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITEA_INSECURE_CA,
        name: Attribute::ConnectorGiteaInsecureCa,
        description: "Skip TLS certificate verification for Gitea API calls. \
                      Use only in development environments."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_GITEA_ROOT_CA_DL38: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITEA_ROOT_CA,
        name: Attribute::ConnectorGiteaRootCa,
        description: "PEM-encoded root CA certificate to trust for Gitea TLS connections."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_GITEA_LOAD_ALL_GROUPS_DL38: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITEA_LOAD_ALL_GROUPS,
        name: Attribute::ConnectorGiteaLoadAllGroups,
        description:
            "When true, load all Gitea organizations the user belongs to as group claims, \
                      not only those listed in connector_gitea_groups."
                .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_GITEA_USE_LOGIN_AS_ID_DL38: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITEA_USE_LOGIN_AS_ID,
        name: Attribute::ConnectorGiteaUseLoginAsId,
        description: "Use the Gitea login name as the identity subject instead of the \
                      numeric user ID."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

// ─── updated Connector class ─────────────────────────────────────────────────

pub static SCHEMA_CLASS_CONNECTOR_DL38: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_CONNECTOR,
    name: EntryClass::Connector.into(),
    description: "OAuth2 upstream client connector (DL38).".to_string(),
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
    ],
    ..Default::default()
});
