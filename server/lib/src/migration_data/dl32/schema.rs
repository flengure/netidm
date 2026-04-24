//! Schema entries for DL32: inbound LDAP federation connector (PR-CONNECTOR-LDAP).
//!
//! Adds twenty-four LDAP-specific config attributes on `EntryClass::Connector`.
//! All are optional with documented defaults so pre-DL32 `Connector` entries
//! decode unchanged.

use crate::constants::{
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_BIND_DN, UUID_SCHEMA_ATTR_CONNECTOR_LDAP_BIND_PW,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_CLIENT_CERT,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_CLIENT_KEY,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_BASE_DN,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_FILTER,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_NAME_ATTR,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_SCOPE,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_USER_MATCHERS,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_HOST, UUID_SCHEMA_ATTR_CONNECTOR_LDAP_INSECURE_NO_SSL,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_INSECURE_SKIP_VERIFY,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_ROOT_CA_DATA,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_START_TLS,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USERNAME_PROMPT,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_BASE_DN,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_ATTR,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_SUFFIX,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_FILTER,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_ID_ATTR,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_NAME_ATTR,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_PREFERRED_USERNAME_ATTR,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_SCOPE,
    UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_USERNAME, UUID_SCHEMA_CLASS_CONNECTOR,
};
use crate::prelude::*;

/// LDAP server host and port. Required for the connector to function.
/// Use `ldaps://host:636` for LDAPS or `ldap://host:389` for plain.
/// When no port is given, defaults to 636 (LDAPS) or 389 (plain).
pub static SCHEMA_ATTR_CONNECTOR_LDAP_HOST_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_HOST,
        name: Attribute::ConnectorLdapHost,
        description: "LDAP server host and optional port (e.g. ldap.example.com:636). \
                      Defaults to port 636 for LDAPS or 389 for plain."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// When true, connect without TLS (port 389). Required if not using LDAPS or StartTLS.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_INSECURE_NO_SSL_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_INSECURE_NO_SSL,
        name: Attribute::ConnectorLdapInsecureNoSsl,
        description: "When true, connect without TLS (port 389). Default: false.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// When true, skip TLS certificate verification. Dangerous — use only in dev/test.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_INSECURE_SKIP_VERIFY_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_INSECURE_SKIP_VERIFY,
        name: Attribute::ConnectorLdapInsecureSkipVerify,
        description: "When true, skip TLS certificate verification. \
                      Dangerous — use only in dev/test. Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// Connect to port 389 then upgrade via StartTLS. Mutually exclusive with LDAPS.
/// Note: StartTLS is recorded but currently requires ldaps:// URL in practice.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_START_TLS_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_START_TLS,
        name: Attribute::ConnectorLdapStartTls,
        description: "Connect to port 389 then upgrade to TLS via StartTLS. \
                      Mutually exclusive with LDAPS. Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// Base64-encoded PEM data containing root CA certificate(s) for LDAP TLS verification.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_ROOT_CA_DATA_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_ROOT_CA_DATA,
        name: Attribute::ConnectorLdapRootCaData,
        description: "Base64-encoded PEM root CA certificate(s) for LDAP TLS verification."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// PEM-encoded client certificate for mutual TLS authentication to the LDAP server.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_CLIENT_CERT_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_CLIENT_CERT,
        name: Attribute::ConnectorLdapClientCert,
        description: "PEM-encoded client certificate for mutual TLS to the LDAP server."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// PEM-encoded client private key for mutual TLS authentication to the LDAP server.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_CLIENT_KEY_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_CLIENT_KEY,
        name: Attribute::ConnectorLdapClientKey,
        description: "PEM-encoded client private key for mutual TLS to the LDAP server."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Service account bind DN used to search the LDAP directory. When absent, anonymous bind is used.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_BIND_DN_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_BIND_DN,
        name: Attribute::ConnectorLdapBindDn,
        description: "Service account bind DN for directory searches. \
                      When absent, anonymous bind is used."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Service account bind password. Required when bind_dn is set.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_BIND_PW_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_BIND_PW,
        name: Attribute::ConnectorLdapBindPw,
        description: "Service account bind password. Required when bind_dn is set.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Override the label shown above the username field on the LDAP login form.
/// Default: "Username".
pub static SCHEMA_ATTR_CONNECTOR_LDAP_USERNAME_PROMPT_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USERNAME_PROMPT,
        name: Attribute::ConnectorLdapUsernamePrompt,
        description: "Override label for the username field on the LDAP login form. \
                      Default: \"Username\"."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Base DN for user searches. Required for the connector to function.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_BASE_DN_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_BASE_DN,
        name: Attribute::ConnectorLdapUserSearchBaseDn,
        description: "Base DN for user searches (e.g. cn=users,dc=example,dc=com). Required."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Optional LDAP filter applied to user searches (e.g. `(objectClass=person)`).
pub static SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_FILTER_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_FILTER,
        name: Attribute::ConnectorLdapUserSearchFilter,
        description: "Optional LDAP filter for user searches (e.g. \"(objectClass=person)\")."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// LDAP attribute(s) matched against the typed username during login. Multi-value:
/// each value is one attribute name. Required — at least one must be set.
/// Example: `uid` or both `uid` and `mail` for flexible lookup.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_USERNAME_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_USERNAME,
        name: Attribute::ConnectorLdapUserSearchUsername,
        description: "LDAP attribute(s) matched against the typed username. \
                      Multi-value — each value is one attribute name (e.g. \"uid\", \"mail\"). \
                      Required."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// User search scope. Valid values: \"sub\" (whole subtree, default) or \"one\" (single level).
pub static SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_SCOPE_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_SCOPE,
        name: Attribute::ConnectorLdapUserSearchScope,
        description: "User search scope: \"sub\" (whole subtree, default) or \
                      \"one\" (single level)."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// LDAP attribute used as the stable user ID claim (`sub`). Default: `uid`.
/// Use the literal string `DN` to use the entry's distinguished name.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_ID_ATTR_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_ID_ATTR,
        name: Attribute::ConnectorLdapUserSearchIdAttr,
        description: "LDAP attribute for the stable user ID claim. Default: \"uid\". \
                      Use \"DN\" to use the entry's distinguished name."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// LDAP attribute used for the email claim. Default: `mail`.
/// Ignored when `user_search_email_suffix` is set.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_ATTR_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_ATTR,
        name: Attribute::ConnectorLdapUserSearchEmailAttr,
        description: "LDAP attribute for the email claim. Default: \"mail\". \
                      Ignored when email_suffix is set."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// LDAP attribute used for the display name claim.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_NAME_ATTR_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_NAME_ATTR,
        name: Attribute::ConnectorLdapUserSearchNameAttr,
        description: "LDAP attribute for the display name claim (e.g. \"displayName\")."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// LDAP attribute used for the preferred_username claim.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_PREFERRED_USERNAME_ATTR_DL32: LazyLock<
    SchemaAttribute,
> = LazyLock::new(|| SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_PREFERRED_USERNAME_ATTR,
    name: Attribute::ConnectorLdapUserSearchPreferredUsernameAttr,
    description: "LDAP attribute for the preferred_username claim.".to_string(),
    multivalue: false,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
});

/// Suffix appended to the ID attribute value to construct the email claim.
/// When set, `email_attr` is ignored. E.g. `example.com` → `uid_value@example.com`.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_SUFFIX_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_SUFFIX,
        name: Attribute::ConnectorLdapUserSearchEmailSuffix,
        description: "Suffix appended to id_attr value to construct the email claim. \
                      E.g. \"example.com\" → \"uid_value@example.com\". \
                      When set, email_attr is ignored."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Base DN for group searches. When absent, group membership is not fetched.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_BASE_DN_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_BASE_DN,
        name: Attribute::ConnectorLdapGroupSearchBaseDn,
        description: "Base DN for group searches. When absent, group membership is not fetched."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Optional LDAP filter for group searches.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_FILTER_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_FILTER,
        name: Attribute::ConnectorLdapGroupSearchFilter,
        description: "Optional LDAP filter for group searches \
                      (e.g. \"(|(objectClass=posixGroup)(objectClass=groupOfNames))\")."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Group search scope. Valid values: \"sub\" (default) or \"one\".
pub static SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_SCOPE_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_SCOPE,
        name: Attribute::ConnectorLdapGroupSearchScope,
        description: "Group search scope: \"sub\" (default) or \"one\".".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// User-to-group attribute matchers. Multi-value; each value encodes one matcher as
/// `userAttr:groupAttr` or `userAttr:groupAttr:recursionGroupAttr`.
/// Example: `DN:member` (by DN) or `uid:memberUid` (by uid) or `DN:member:member` (recursive).
pub static SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_USER_MATCHERS_DL32: LazyLock<
    SchemaAttribute,
> = LazyLock::new(|| SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_USER_MATCHERS,
    name: Attribute::ConnectorLdapGroupSearchUserMatchers,
    description: "User-to-group attribute matchers. Multi-value; each value is \
                  \"userAttr:groupAttr\" or \"userAttr:groupAttr:recursionGroupAttr\". \
                  E.g. \"DN:member\" or \"uid:memberUid\" or \"DN:member:member\" (recursive)."
        .to_string(),
    multivalue: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
});

/// LDAP attribute on group entries that holds the group name. Required when group_search_base_dn is set.
pub static SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_NAME_ATTR_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_LDAP_GROUP_SEARCH_NAME_ATTR,
        name: Attribute::ConnectorLdapGroupSearchNameAttr,
        description: "LDAP attribute on group entries that holds the group name (e.g. \"cn\"). \
                      Required when group_search_base_dn is set."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// OAuth2 client class updated for DL32: adds the twenty-four LDAP-specific config
/// attributes to `systemmay`. Carries forward all DL31 `systemmay` entries.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL32: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
    ],
    ..Default::default()
});
