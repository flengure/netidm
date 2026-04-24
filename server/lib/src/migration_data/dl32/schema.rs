//! Schema entries for DL32: inbound LDAP federation connector (PR-CONNECTOR-LDAP).
//!
//! Adds twenty-four LDAP-specific config attributes on `EntryClass::OAuth2Client`.
//! All are optional with documented defaults so pre-DL32 `OAuth2Client` entries
//! decode unchanged.

use crate::constants::{
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_BIND_DN, UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_BIND_PW,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_CLIENT_CERT,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_CLIENT_KEY,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_BASE_DN,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_FILTER,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_NAME_ATTR,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_SCOPE,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_USER_MATCHERS,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_HOST, UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_INSECURE_NO_SSL,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_INSECURE_SKIP_VERIFY,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_ROOT_CA_DATA,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_START_TLS,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USERNAME_PROMPT,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_BASE_DN,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_EMAIL_ATTR,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_EMAIL_SUFFIX,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_FILTER,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_ID_ATTR,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_NAME_ATTR,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_PREFERRED_USERNAME_ATTR,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_SCOPE,
    UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_USERNAME, UUID_SCHEMA_CLASS_OAUTH2_CLIENT,
};
use crate::prelude::*;

/// LDAP server host and port. Required for the connector to function.
/// Use `ldaps://host:636` for LDAPS or `ldap://host:389` for plain.
/// When no port is given, defaults to 636 (LDAPS) or 389 (plain).
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_HOST_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_HOST,
        name: Attribute::OAuth2ClientLdapHost,
        description: "LDAP server host and optional port (e.g. ldap.example.com:636). \
                      Defaults to port 636 for LDAPS or 389 for plain."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// When true, connect without TLS (port 389). Required if not using LDAPS or StartTLS.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_INSECURE_NO_SSL_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_INSECURE_NO_SSL,
        name: Attribute::OAuth2ClientLdapInsecureNoSsl,
        description: "When true, connect without TLS (port 389). Default: false.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// When true, skip TLS certificate verification. Dangerous — use only in dev/test.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_INSECURE_SKIP_VERIFY_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_INSECURE_SKIP_VERIFY,
        name: Attribute::OAuth2ClientLdapInsecureSkipVerify,
        description: "When true, skip TLS certificate verification. \
                      Dangerous — use only in dev/test. Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// Connect to port 389 then upgrade via StartTLS. Mutually exclusive with LDAPS.
/// Note: StartTLS is recorded but currently requires ldaps:// URL in practice.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_START_TLS_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_START_TLS,
        name: Attribute::OAuth2ClientLdapStartTls,
        description: "Connect to port 389 then upgrade to TLS via StartTLS. \
                      Mutually exclusive with LDAPS. Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// Base64-encoded PEM data containing root CA certificate(s) for LDAP TLS verification.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_ROOT_CA_DATA_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_ROOT_CA_DATA,
        name: Attribute::OAuth2ClientLdapRootCaData,
        description: "Base64-encoded PEM root CA certificate(s) for LDAP TLS verification."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// PEM-encoded client certificate for mutual TLS authentication to the LDAP server.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_CLIENT_CERT_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_CLIENT_CERT,
        name: Attribute::OAuth2ClientLdapClientCert,
        description: "PEM-encoded client certificate for mutual TLS to the LDAP server."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// PEM-encoded client private key for mutual TLS authentication to the LDAP server.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_CLIENT_KEY_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_CLIENT_KEY,
        name: Attribute::OAuth2ClientLdapClientKey,
        description: "PEM-encoded client private key for mutual TLS to the LDAP server."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Service account bind DN used to search the LDAP directory. When absent, anonymous bind is used.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_BIND_DN_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_BIND_DN,
        name: Attribute::OAuth2ClientLdapBindDn,
        description: "Service account bind DN for directory searches. \
                      When absent, anonymous bind is used."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Service account bind password. Required when bind_dn is set.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_BIND_PW_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_BIND_PW,
        name: Attribute::OAuth2ClientLdapBindPw,
        description: "Service account bind password. Required when bind_dn is set.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Override the label shown above the username field on the LDAP login form.
/// Default: "Username".
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USERNAME_PROMPT_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USERNAME_PROMPT,
        name: Attribute::OAuth2ClientLdapUsernamePrompt,
        description: "Override label for the username field on the LDAP login form. \
                      Default: \"Username\"."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Base DN for user searches. Required for the connector to function.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_BASE_DN_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_BASE_DN,
        name: Attribute::OAuth2ClientLdapUserSearchBaseDn,
        description: "Base DN for user searches (e.g. cn=users,dc=example,dc=com). Required."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Optional LDAP filter applied to user searches (e.g. `(objectClass=person)`).
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_FILTER_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_FILTER,
        name: Attribute::OAuth2ClientLdapUserSearchFilter,
        description: "Optional LDAP filter for user searches (e.g. \"(objectClass=person)\")."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// LDAP attribute(s) matched against the typed username during login. Multi-value:
/// each value is one attribute name. Required — at least one must be set.
/// Example: `uid` or both `uid` and `mail` for flexible lookup.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_USERNAME_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_USERNAME,
        name: Attribute::OAuth2ClientLdapUserSearchUsername,
        description: "LDAP attribute(s) matched against the typed username. \
                      Multi-value — each value is one attribute name (e.g. \"uid\", \"mail\"). \
                      Required."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// User search scope. Valid values: \"sub\" (whole subtree, default) or \"one\" (single level).
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_SCOPE_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_SCOPE,
        name: Attribute::OAuth2ClientLdapUserSearchScope,
        description: "User search scope: \"sub\" (whole subtree, default) or \
                      \"one\" (single level)."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// LDAP attribute used as the stable user ID claim (`sub`). Default: `uid`.
/// Use the literal string `DN` to use the entry's distinguished name.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_ID_ATTR_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_ID_ATTR,
        name: Attribute::OAuth2ClientLdapUserSearchIdAttr,
        description: "LDAP attribute for the stable user ID claim. Default: \"uid\". \
                      Use \"DN\" to use the entry's distinguished name."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// LDAP attribute used for the email claim. Default: `mail`.
/// Ignored when `user_search_email_suffix` is set.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_EMAIL_ATTR_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_EMAIL_ATTR,
        name: Attribute::OAuth2ClientLdapUserSearchEmailAttr,
        description: "LDAP attribute for the email claim. Default: \"mail\". \
                      Ignored when email_suffix is set."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// LDAP attribute used for the display name claim.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_NAME_ATTR_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_NAME_ATTR,
        name: Attribute::OAuth2ClientLdapUserSearchNameAttr,
        description: "LDAP attribute for the display name claim (e.g. \"displayName\")."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// LDAP attribute used for the preferred_username claim.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_PREFERRED_USERNAME_ATTR_DL32: LazyLock<
    SchemaAttribute,
> = LazyLock::new(|| SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_PREFERRED_USERNAME_ATTR,
    name: Attribute::OAuth2ClientLdapUserSearchPreferredUsernameAttr,
    description: "LDAP attribute for the preferred_username claim.".to_string(),
    multivalue: false,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
});

/// Suffix appended to the ID attribute value to construct the email claim.
/// When set, `email_attr` is ignored. E.g. `example.com` → `uid_value@example.com`.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_EMAIL_SUFFIX_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_EMAIL_SUFFIX,
        name: Attribute::OAuth2ClientLdapUserSearchEmailSuffix,
        description: "Suffix appended to id_attr value to construct the email claim. \
                      E.g. \"example.com\" → \"uid_value@example.com\". \
                      When set, email_attr is ignored."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Base DN for group searches. When absent, group membership is not fetched.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_BASE_DN_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_BASE_DN,
        name: Attribute::OAuth2ClientLdapGroupSearchBaseDn,
        description: "Base DN for group searches. When absent, group membership is not fetched."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Optional LDAP filter for group searches.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_FILTER_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_FILTER,
        name: Attribute::OAuth2ClientLdapGroupSearchFilter,
        description: "Optional LDAP filter for group searches \
                      (e.g. \"(|(objectClass=posixGroup)(objectClass=groupOfNames))\")."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Group search scope. Valid values: \"sub\" (default) or \"one\".
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_SCOPE_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_SCOPE,
        name: Attribute::OAuth2ClientLdapGroupSearchScope,
        description: "Group search scope: \"sub\" (default) or \"one\".".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// User-to-group attribute matchers. Multi-value; each value encodes one matcher as
/// `userAttr:groupAttr` or `userAttr:groupAttr:recursionGroupAttr`.
/// Example: `DN:member` (by DN) or `uid:memberUid` (by uid) or `DN:member:member` (recursive).
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_USER_MATCHERS_DL32: LazyLock<
    SchemaAttribute,
> = LazyLock::new(|| SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_USER_MATCHERS,
    name: Attribute::OAuth2ClientLdapGroupSearchUserMatchers,
    description: "User-to-group attribute matchers. Multi-value; each value is \
                  \"userAttr:groupAttr\" or \"userAttr:groupAttr:recursionGroupAttr\". \
                  E.g. \"DN:member\" or \"uid:memberUid\" or \"DN:member:member\" (recursive)."
        .to_string(),
    multivalue: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
});

/// LDAP attribute on group entries that holds the group name. Required when group_search_base_dn is set.
pub static SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_NAME_ATTR_DL32: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_NAME_ATTR,
        name: Attribute::OAuth2ClientLdapGroupSearchNameAttr,
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
    ],
    ..Default::default()
});
