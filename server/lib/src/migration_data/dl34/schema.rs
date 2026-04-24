//! Schema entries for DL34: OpenShift connector dex-parity additions (PR-CONNECTOR-OPENSHIFT).
//!
//! Adds four optional config attributes on `EntryClass::OAuth2Client`:
//! `OAuth2ClientOpenshiftIssuer`, `OAuth2ClientOpenshiftGroups`,
//! `OAuth2ClientOpenshiftInsecureCa`, and `OAuth2ClientOpenshiftRootCa`.

#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_GROUPS,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_INSECURE_CA,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_ISSUER,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_ROOT_CA, UUID_SCHEMA_CLASS_OAUTH2_CLIENT,
};
use crate::prelude::*;

/// Issuer URL for the OpenShift cluster. Discovery of auth/token endpoints is
/// performed at connector initialisation by fetching
/// `{issuer}/.well-known/oauth-authorization-server`.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_ISSUER_DL34: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_ISSUER,
        name: Attribute::OAuth2ClientOpenshiftIssuer,
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
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_GROUPS_DL34: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_GROUPS,
        name: Attribute::OAuth2ClientOpenshiftGroups,
        description: "Allowlist of OpenShift group names. Users not in any listed group are \
                      rejected. When absent, all authenticated users are permitted."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// When true, TLS certificate verification is skipped for all OpenShift API
/// calls. Dangerous — use only in dev/test against trusted clusters.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_INSECURE_CA_DL34: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_INSECURE_CA,
        name: Attribute::OAuth2ClientOpenshiftInsecureCa,
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
pub static SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_ROOT_CA_DL34: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_ROOT_CA,
        name: Attribute::OAuth2ClientOpenshiftRootCa,
        description: "PEM-encoded root CA certificate for OpenShift cluster TLS verification. \
                      Use when the cluster presents a private/self-signed CA."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// OAuth2Client class updated for DL34: adds the four OpenShift connector config
/// attributes to `systemmay`. Carries forward all DL32 `systemmay` entries.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL34: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
    ],
    ..Default::default()
});
