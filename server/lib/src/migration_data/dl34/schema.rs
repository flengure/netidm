//! Schema entries for DL34: OpenShift connector dex-parity additions (PR-CONNECTOR-OPENSHIFT).
//!
//! Adds four optional config attributes on `EntryClass::Connector`:
//! `ConnectorOpenshiftIssuer`, `ConnectorOpenshiftGroups`,
//! `ConnectorOpenshiftInsecureCa`, and `ConnectorOpenshiftRootCa`.

use crate::constants::{
    UUID_SCHEMA_ATTR_CONNECTOR_OPENSHIFT_GROUPS,
    UUID_SCHEMA_ATTR_CONNECTOR_OPENSHIFT_INSECURE_CA,
    UUID_SCHEMA_ATTR_CONNECTOR_OPENSHIFT_ISSUER,
    UUID_SCHEMA_ATTR_CONNECTOR_OPENSHIFT_ROOT_CA, UUID_SCHEMA_CLASS_CONNECTOR,
};
use crate::prelude::*;

/// Issuer URL for the OpenShift cluster. Discovery of auth/token endpoints is
/// performed at connector initialisation by fetching
/// `{issuer}/.well-known/oauth-authorization-server`.
pub static SCHEMA_ATTR_CONNECTOR_OPENSHIFT_ISSUER_DL34: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_OPENSHIFT_ISSUER,
        name: Attribute::ConnectorOpenshiftIssuer,
        description: "OpenShift cluster issuer URL. Used for endpoint discovery and the \
                      users/~ API base."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Allowlist of OpenShift group names. When non-empty, only users belonging to
/// at least one listed group are permitted to authenticate. Multi-value — each
/// value is one permitted group name.
pub static SCHEMA_ATTR_CONNECTOR_OPENSHIFT_GROUPS_DL34: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_OPENSHIFT_GROUPS,
        name: Attribute::ConnectorOpenshiftGroups,
        description: "Allowlist of OpenShift group names. Users not in any listed group are \
                      rejected. When absent, all authenticated users are permitted."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// When true, TLS certificate verification is skipped for all OpenShift API
/// calls. Dangerous — use only in dev/test against trusted clusters.
pub static SCHEMA_ATTR_CONNECTOR_OPENSHIFT_INSECURE_CA_DL34: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_OPENSHIFT_INSECURE_CA,
        name: Attribute::ConnectorOpenshiftInsecureCa,
        description: "When true, skip TLS certificate verification for OpenShift API calls. \
                      Dangerous — use only in dev/test. Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// PEM-encoded root CA certificate used when connecting to the OpenShift cluster.
/// Takes precedence over system trust roots. Use when the cluster presents a
/// private/self-signed CA.
pub static SCHEMA_ATTR_CONNECTOR_OPENSHIFT_ROOT_CA_DL34: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_OPENSHIFT_ROOT_CA,
        name: Attribute::ConnectorOpenshiftRootCa,
        description: "PEM-encoded root CA certificate for OpenShift cluster TLS verification. \
                      Use when the cluster presents a private/self-signed CA."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Connector class updated for DL34: adds the four OpenShift connector config
/// attributes to `systemmay`. Carries forward all DL32 `systemmay` entries.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL34: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
    ],
    ..Default::default()
});
