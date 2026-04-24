//! Schema entries for DL37.
//!
//! Adds:
//! 1. `ConnectorGithubUseLoginAsId` — boolean attr on `EntryClass::Connector` systemmay.
//!    Already present in proto since the GitHub connector parity rewrite; registered here.
//! 2. `ProviderIdentity` entry class with 11 attrs — per-user per-connector identity record.
//!    Stores upstream claims and OAuth2 consent grants for each (user, connector) pair.
//! 3. `Oauth2RsTrustedPeers` and `Oauth2RsAllowedConnectors` on `OAuth2ResourceServer` —
//!    cross-client SSO trust and connector-restriction attrs.

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_USE_LOGIN_AS_ID,
    UUID_SCHEMA_ATTR_OAUTH2_RS_ALLOWED_CONNECTORS, UUID_SCHEMA_ATTR_OAUTH2_RS_TRUSTED_PEERS,
    UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_BLOCKED_UNTIL,
    UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_EMAIL,
    UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_EMAIL_VERIFIED,
    UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_GROUPS,
    UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_USERNAME,
    UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_USER_ID,
    UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CONNECTOR_ID, UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CONSENTS,
    UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CREATED_AT, UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_LAST_LOGIN,
    UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_USER_UUID, UUID_SCHEMA_CLASS_CONNECTOR,
    UUID_SCHEMA_CLASS_OAUTH2_RS, UUID_SCHEMA_CLASS_PROVIDER_IDENTITY,
};
use crate::prelude::*;

// ─── ConnectorGithubUseLoginAsId ─────────────────────────────────────────────

/// When true, use the GitHub login handle as the connector-local user ID
/// instead of the numeric GitHub account ID. Mirrors dex's `useLoginAsID`.
pub static SCHEMA_ATTR_CONNECTOR_GITHUB_USE_LOGIN_AS_ID_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_USE_LOGIN_AS_ID,
        name: Attribute::ConnectorGithubUseLoginAsId,
        description: "Use the GitHub login handle as the connector-local user ID instead of \
                      the numeric account ID."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

// ─── ProviderIdentity attrs ───────────────────────────────────────────────────

/// FK reference to the netidm `Person` entry UUID this identity belongs to.
pub static SCHEMA_ATTR_PROVIDER_IDENTITY_USER_UUID_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_USER_UUID,
        name: Attribute::ProviderIdentityUserUuid,
        description: "UUID of the netidm Person entry this provider identity belongs to."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// The connector ID (e.g. `"github"`, `"ldap-corp"`) that produced this identity.
pub static SCHEMA_ATTR_PROVIDER_IDENTITY_CONNECTOR_ID_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CONNECTOR_ID,
        name: Attribute::ProviderIdentityConnectorId,
        description: "Connector ID that produced this identity record.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// Upstream user ID as returned by the connector (e.g. GitHub numeric ID or LDAP DN).
pub static SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_USER_ID_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_USER_ID,
        name: Attribute::ProviderIdentityClaimsUserId,
        description: "Upstream user ID from the connector claims.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Upstream username as returned by the connector.
pub static SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_USERNAME_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_USERNAME,
        name: Attribute::ProviderIdentityClaimsUsername,
        description: "Upstream username from the connector claims.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Upstream email address as returned by the connector.
pub static SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_EMAIL_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_EMAIL,
        name: Attribute::ProviderIdentityClaimsEmail,
        description: "Upstream email address from the connector claims.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// Whether the upstream email address was verified by the connector.
pub static SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_EMAIL_VERIFIED_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_EMAIL_VERIFIED,
        name: Attribute::ProviderIdentityClaimsEmailVerified,
        description: "Whether the upstream email address has been verified.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// Group membership claims returned by the connector (multi-value).
pub static SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_GROUPS_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_GROUPS,
        name: Attribute::ProviderIdentityClaimsGroups,
        description: "Upstream group membership claims from the connector.".to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// OAuth2 consent records in the form `clientId:scope` (multi-value).
pub static SCHEMA_ATTR_PROVIDER_IDENTITY_CONSENTS_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CONSENTS,
        name: Attribute::ProviderIdentityConsents,
        description: "OAuth2 consent grants recorded as 'clientId:scope' pairs.".to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// ISO-8601 timestamp when this identity record was first created.
pub static SCHEMA_ATTR_PROVIDER_IDENTITY_CREATED_AT_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_CREATED_AT,
        name: Attribute::ProviderIdentityCreatedAt,
        description: "ISO-8601 timestamp of first login via this connector.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// ISO-8601 timestamp of the last successful login via this connector.
pub static SCHEMA_ATTR_PROVIDER_IDENTITY_LAST_LOGIN_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_LAST_LOGIN,
        name: Attribute::ProviderIdentityLastLogin,
        description: "ISO-8601 timestamp of the last successful login via this connector."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Optional ISO-8601 timestamp after which this identity is unblocked. Absent = not blocked.
pub static SCHEMA_ATTR_PROVIDER_IDENTITY_BLOCKED_UNTIL_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_PROVIDER_IDENTITY_BLOCKED_UNTIL,
        name: Attribute::ProviderIdentityBlockedUntil,
        description: "ISO-8601 timestamp until which this identity is blocked from logging in. \
                      Absent means the identity is not blocked."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

// ─── OAuth2ResourceServer cross-client attrs ─────────────────────────────────

/// List of client IDs whose session grants this RS inherits.
/// When client A lists client B here, a token minted for B can be exchanged for
/// a token for A without re-prompting the user for consent.
pub static SCHEMA_ATTR_OAUTH2_RS_TRUSTED_PEERS_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_TRUSTED_PEERS,
        name: Attribute::Oauth2RsTrustedPeers,
        description: "Client IDs whose OAuth2 grants this resource server inherits. \
                      Enables cross-client token exchange without re-consent."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Connector IDs permitted to authenticate users for this RS.
/// Empty = all connectors allowed. Non-empty = only the listed connector IDs may auth.
pub static SCHEMA_ATTR_OAUTH2_RS_ALLOWED_CONNECTORS_DL37: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_ALLOWED_CONNECTORS,
        name: Attribute::Oauth2RsAllowedConnectors,
        description: "Connector IDs allowed to authenticate users for this resource server. \
                      Empty = allow all connectors."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

// ─── Updated Connector class ─────────────────────────────────────────────────

/// DL37 refresh of the `Connector` entry class. Forks DL36 and adds
/// `ConnectorGithubUseLoginAsId` to `systemmay`.
pub static SCHEMA_CLASS_CONNECTOR_DL37: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_CONNECTOR,
    name: EntryClass::Connector.into(),
    description: "OAuth2 upstream client connector (DL37).".to_string(),
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
        // DL29 — Generic OIDC
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
    ],
    ..Default::default()
});

// ─── Updated OAuth2ResourceServer class ──────────────────────────────────────

/// DL37 refresh of the `OAuth2ResourceServer` entry class. Forks DL26 and adds
/// `Oauth2RsTrustedPeers` and `Oauth2RsAllowedConnectors` to `systemmay`.
pub static SCHEMA_CLASS_OAUTH2_RS_DL37: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS,
    name: EntryClass::OAuth2ResourceServer.into(),
    description: "The class representing a configured OAuth2 Client".to_string(),
    systemmay: vec![
        Attribute::DisplayName,
        Attribute::Description,
        Attribute::OAuth2RsScopeMap,
        Attribute::OAuth2RsSupScopeMap,
        Attribute::OAuth2JwtLegacyCryptoEnable,
        Attribute::OAuth2PreferShortUsername,
        Attribute::Image,
        Attribute::OAuth2RsClaimMap,
        Attribute::OAuth2Session,
        Attribute::OAuth2RsOrigin,
        Attribute::OAuth2StrictRedirectUri,
        Attribute::OAuth2DeviceFlowEnable,
        Attribute::OAuth2ConsentPromptEnable,
        // Deprecated
        Attribute::Rs256PrivateKeyDer,
        Attribute::OAuth2RsTokenKey,
        Attribute::Es256PrivateKeyDer,
        // DL26 — RP-Initiated Logout 1.0 + Back-Channel Logout 1.0
        Attribute::OAuth2RsPostLogoutRedirectUri,
        Attribute::OAuth2RsBackchannelLogoutUri,
        // DL37 — cross-client trust + connector restriction
        Attribute::Oauth2RsTrustedPeers,
        Attribute::Oauth2RsAllowedConnectors,
    ],
    systemmust: vec![Attribute::OAuth2RsOriginLanding, Attribute::Name],
    ..Default::default()
});

// ─── ProviderIdentity class ───────────────────────────────────────────────────

/// Per-user per-connector identity record. One entry per (user, connector) pair.
/// Populated on first federated login; updated on each subsequent login via the
/// same connector.
pub static SCHEMA_CLASS_PROVIDER_IDENTITY_DL37: LazyLock<SchemaClass> =
    LazyLock::new(|| SchemaClass {
        uuid: UUID_SCHEMA_CLASS_PROVIDER_IDENTITY,
        name: EntryClass::ProviderIdentity.into(),
        description: "Per-user per-connector identity record.".to_string(),
        systemmust: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::ProviderIdentityUserUuid,
            Attribute::ProviderIdentityConnectorId,
        ],
        systemmay: vec![
            Attribute::ProviderIdentityClaimsUserId,
            Attribute::ProviderIdentityClaimsUsername,
            Attribute::ProviderIdentityClaimsEmail,
            Attribute::ProviderIdentityClaimsEmailVerified,
            Attribute::ProviderIdentityClaimsGroups,
            Attribute::ProviderIdentityConsents,
            Attribute::ProviderIdentityCreatedAt,
            Attribute::ProviderIdentityLastLogin,
            Attribute::ProviderIdentityBlockedUntil,
        ],
        ..Default::default()
    });
