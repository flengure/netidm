//! Schema entries for DL39: OpenStack Keystone connector attrs.
//!
//! Four optional attrs on `EntryClass::Connector`:
//! (`ConnectorKeystoneHost`, `ConnectorKeystoneDomain`,
//! `ConnectorKeystoneGroups`, `ConnectorKeystoneInsecureCa`).

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_CONNECTOR_KEYSTONE_DOMAIN, UUID_SCHEMA_ATTR_CONNECTOR_KEYSTONE_GROUPS,
    UUID_SCHEMA_ATTR_CONNECTOR_KEYSTONE_HOST, UUID_SCHEMA_ATTR_CONNECTOR_KEYSTONE_INSECURE_CA,
    UUID_SCHEMA_CLASS_CONNECTOR,
};
use crate::prelude::*;

// ─── keystone attrs ───────────────────────────────────────────────────────────

pub static SCHEMA_ATTR_CONNECTOR_KEYSTONE_HOST_DL39: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_KEYSTONE_HOST,
        name: Attribute::ConnectorKeystoneHost,
        description: "Keystone v3 identity endpoint URL \
                      (e.g. https://keystone.example.com:5000). Required."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_KEYSTONE_DOMAIN_DL39: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_KEYSTONE_DOMAIN,
        name: Attribute::ConnectorKeystoneDomain,
        description: "Keystone domain for user lookup. Defaults to \"Default\" when absent."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_KEYSTONE_GROUPS_DL39: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_KEYSTONE_GROUPS,
        name: Attribute::ConnectorKeystoneGroups,
        description: "Required Keystone role names. Empty = allow any authenticated user."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

pub static SCHEMA_ATTR_CONNECTOR_KEYSTONE_INSECURE_CA_DL39: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_KEYSTONE_INSECURE_CA,
        name: Attribute::ConnectorKeystoneInsecureCa,
        description: "Skip TLS certificate verification for Keystone API calls. \
                      Use only in development environments."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

// ─── updated Connector class ─────────────────────────────────────────────────

pub static SCHEMA_CLASS_CONNECTOR_DL39: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_CONNECTOR,
    name: EntryClass::Connector.into(),
    description: "OAuth2 upstream client connector (DL39).".to_string(),
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
    ],
    ..Default::default()
});
