use crate::constants::*;
use crate::internal::OperationError;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;
use strum::AsRefStr;
use utoipa::ToSchema;

pub use smartstring::alias::String as AttrString;

#[derive(
    Serialize,
    Deserialize,
    Clone,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    ToSchema,
    AsRefStr,
)]
#[cfg_attr(test, derive(enum_iterator::Sequence))]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "lowercase", from = "String", into = "AttrString")]
pub enum Attribute {
    Account,
    AccountExpire,
    AccountValidFrom,
    AccountSoftlockExpire,
    AcpCreateAttr,
    AcpCreateClass,
    AcpEnable,
    AcpModifyClass,
    AcpModifyPresentClass,
    AcpModifyRemoveClass,
    #[strum(serialize = "acp_modify_presentattr")]
    AcpModifyPresentAttr,
    #[strum(serialize = "acp_modify_removedattr")]
    AcpModifyRemovedAttr,
    AcpReceiver,
    AcpReceiverGroup,
    AcpSearchAttr,
    #[strum(serialize = "acp_targetscope")]
    AcpTargetScope,
    ApiTokenSession,
    ApplicationPassword,
    ApplicationUrl,
    AttestedPasskeys,
    #[default]
    Attr,
    #[strum(serialize = "attributename")]
    AttributeName,
    #[strum(serialize = "attributetype")]
    AttributeType,
    #[strum(serialize = "authsession_expiry")]
    AuthSessionExpiry,
    AuthPasswordMinimumLength,
    BadlistPassword,
    Certificate,
    CascadeDeleted,
    Claim,
    Class,
    #[strum(serialize = "classname")]
    ClassName,
    Cn,
    CookiePrivateKey,
    CreatedAtCid,
    CredentialUpdateIntentToken,
    CredentialTypeMinimum,
    DeniedName,
    DeleteAfter,
    Description,
    #[strum(serialize = "directmemberof")]
    DirectMemberOf,
    #[strum(serialize = "displayname")]
    DisplayName,
    Dn,
    Domain,
    DomainAllowEasterEggs,
    DomainDevelopmentTaint,
    DomainDisplayName,
    DomainLdapBasedn,
    DomainName,
    DomainSsid,
    DomainTokenKey,
    DomainUuid,
    #[strum(serialize = "dyngroup")]
    DynGroup,
    #[strum(serialize = "dyngroup_filter")]
    DynGroupFilter,
    #[strum(serialize = "dynmember")]
    DynMember,
    Enabled,
    Email,
    #[strum(serialize = "emailalternative")]
    EmailAlternative,
    #[strum(serialize = "emailprimary")]
    EmailPrimary,
    #[strum(serialize = "entrydn")]
    EntryDn,
    EntryManagedBy,
    #[strum(serialize = "entryuuid")]
    EntryUuid,
    Es256PrivateKeyDer,
    Excludes,
    FernetPrivateKeyStr,
    Gecos,
    #[strum(serialize = "gidnumber")]
    GidNumber,
    GrantUiHint,
    Group,
    HmacNameHistory,
    #[strum(serialize = "homedirectory")]
    HomeDirectory,
    #[strum(serialize = "id_verification_eckey")]
    IdVerificationEcKey,
    Image,
    Index,
    Indexed,
    InMemoriam,
    #[strum(serialize = "ipanthash")]
    IpaNtHash,
    #[strum(serialize = "ipasshpubkey")]
    IpaSshPubKey,
    JwsEs256PrivateKey,
    KeyActionRotate,
    KeyActionRevoke,
    KeyActionImportJwsEs256,
    KeyActionImportJwsRs256,
    KeyInternalData,
    KeyProvider,
    LastModifiedCid,
    LdapAllowUnixPwBind,
    /// An LDAP Compatible emailAddress
    #[strum(serialize = "emailaddress")]
    LdapEmailAddress,
    /// An LDAP Compatible sshkeys virtual attribute
    #[strum(serialize = "keys")]
    LdapKeys,
    LdapMaxQueryableAttrs,
    #[strum(serialize = "legalname")]
    LegalName,
    LimitSearchMaxResults,
    LimitSearchMaxFilterTest,
    LinkedGroup,
    #[strum(serialize = "loginshell")]
    LoginShell,
    Mail,
    MailDestination,
    May,
    Member,
    MemberCreateOnce,
    #[strum(serialize = "memberof")]
    MemberOf,
    MessageTemplate,
    #[strum(serialize = "multivalue")]
    MultiValue,
    Must,
    Name,
    NameHistory,
    #[strum(serialize = "no-index")]
    NoIndex,
    #[strum(serialize = "nsuniqueid")]
    NsUniqueId,
    #[strum(serialize = "nsaccountlock")]
    NsAccountLock,
    #[strum(serialize = "oauth2_allow_insecure_client_disable_pkce")]
    OAuth2AllowInsecureClientDisablePkce,
    #[strum(serialize = "oauth2_allow_localhost_redirect")]
    OAuth2AllowLocalhostRedirect,
    #[strum(serialize = "oauth2_authorisation_endpoint")]
    OAuth2AuthorisationEndpoint,
    #[strum(serialize = "connector_id")]
    ConnectorId,
    #[strum(serialize = "connector_logo_uri")]
    ConnectorLogoUri,
    #[strum(serialize = "connector_secret")]
    ConnectorSecret,
    #[strum(serialize = "oauth2_consent_scope_map")]
    OAuth2ConsentScopeMap,
    #[strum(serialize = "oauth2_device_flow_enable")]
    OAuth2DeviceFlowEnable,
    #[strum(serialize = "oauth2_jwt_legacy_crypto_enable")]
    OAuth2JwtLegacyCryptoEnable,
    #[strum(serialize = "oauth2_prefer_short_username")]
    OAuth2PreferShortUsername,
    #[strum(serialize = "oauth2_request_scopes")]
    OAuth2RequestScopes,
    #[strum(serialize = "oauth2_rs_basic_secret")]
    OAuth2RsBasicSecret,
    #[strum(serialize = "oauth2_rs_claim_map")]
    OAuth2RsClaimMap,
    #[strum(serialize = "oauth2_rs_implicit_scopes")]
    OAuth2RsImplicitScopes,
    #[strum(serialize = "oauth2_rs_name")]
    OAuth2RsName,
    #[strum(serialize = "oauth2_rs_origin")]
    OAuth2RsOrigin,
    #[strum(serialize = "oauth2_rs_origin_landing")]
    OAuth2RsOriginLanding,
    #[strum(serialize = "oauth2_rs_scope_map")]
    OAuth2RsScopeMap,
    #[strum(serialize = "oauth2_rs_sup_scope_map")]
    OAuth2RsSupScopeMap,
    #[strum(serialize = "oauth2_rs_token_key")]
    OAuth2RsTokenKey,
    #[strum(serialize = "oauth2_session")]
    OAuth2Session,
    #[strum(serialize = "oauth2_strict_redirect_uri")]
    OAuth2StrictRedirectUri,
    #[strum(serialize = "oauth2_token_endpoint")]
    OAuth2TokenEndpoint,
    #[strum(serialize = "oauth2_account_credential_uuid")]
    OAuth2AccountCredentialUuid,
    #[strum(serialize = "oauth2_account_provider")]
    OAuth2AccountProvider,
    #[strum(serialize = "oauth2_account_unique_user_id")]
    OAuth2AccountUniqueUserId,
    #[strum(serialize = "oauth2_consent_prompt_enable")]
    OAuth2ConsentPromptEnable,
    #[strum(serialize = "oauth2_userinfo_endpoint")]
    OAuth2UserinfoEndpoint,
    #[strum(serialize = "oauth2_jit_provisioning")]
    OAuth2JitProvisioning,
    #[strum(serialize = "oauth2_claim_map_name")]
    OAuth2ClaimMapName,
    #[strum(serialize = "oauth2_claim_map_displayname")]
    OAuth2ClaimMapDisplayname,
    #[strum(serialize = "oauth2_claim_map_email")]
    OAuth2ClaimMapEmail,
    #[strum(serialize = "oauth2_email_link_accounts")]
    OAuth2EmailLinkAccounts,
    #[strum(serialize = "oauth2_domain_email_link_accounts")]
    OAuth2DomainEmailLinkAccounts,
    #[strum(serialize = "oauth2_issuer")]
    OAuth2Issuer,
    #[strum(serialize = "oauth2_jwks_uri")]
    OAuth2JwksUri,
    #[strum(serialize = "oauth2_link_by")]
    OAuth2LinkBy,
    #[strum(serialize = "oauth2_group_mapping")]
    OAuth2GroupMapping,
    SamlGroupMapping,
    #[strum(serialize = "oauth2_upstream_synced_group")]
    OAuth2UpstreamSyncedGroup,
    #[strum(serialize = "oauth2_rs_post_logout_redirect_uri")]
    OAuth2RsPostLogoutRedirectUri,
    #[strum(serialize = "oauth2_rs_backchannel_logout_uri")]
    OAuth2RsBackchannelLogoutUri,
    SamlSingleLogoutServiceUrl,
    LogoutDeliveryEndpoint,
    LogoutDeliveryToken,
    LogoutDeliveryStatus,
    LogoutDeliveryAttempts,
    LogoutDeliveryNextAttempt,
    LogoutDeliveryCreated,
    LogoutDeliveryRp,
    SamlSessionUser,
    SamlSessionSp,
    SamlSessionIndex,
    SamlSessionUatUuid,
    SamlSessionCreated,
    // PR-CONNECTOR-GITHUB (DL28) — per-connector config attributes on
    // `EntryClass::Connector`. All optional with documented defaults.
    // See `specs/012-github-connector/data-model.md`.
    #[strum(serialize = "connector_provider_kind")]
    ConnectorProviderKind,
    #[strum(serialize = "connector_github_host")]
    ConnectorGithubHost,
    #[strum(serialize = "connector_github_org_filter")]
    ConnectorGithubOrgFilter,
    #[strum(serialize = "connector_github_allowed_teams")]
    ConnectorGithubAllowedTeams,
    #[strum(serialize = "connector_github_team_name_field")]
    ConnectorGithubTeamNameField,
    #[strum(serialize = "connector_github_load_all_groups")]
    ConnectorGithubLoadAllGroups,
    #[strum(serialize = "connector_github_preferred_email_domain")]
    ConnectorGithubPreferredEmailDomain,
    #[strum(serialize = "connector_github_allow_jit_provisioning")]
    ConnectorGithubAllowJitProvisioning,
    #[strum(serialize = "connector_github_use_login_as_id")]
    ConnectorGithubUseLoginAsId,
    // DL29 — Generic OIDC upstream connector config attributes.
    // All optional on `EntryClass::Connector`; absent = default shown in spec.
    #[strum(serialize = "connector_oidc_enable_groups")]
    ConnectorOidcEnableGroups,
    #[strum(serialize = "connector_oidc_groups_key")]
    ConnectorOidcGroupsKey,
    #[strum(serialize = "connector_oidc_skip_email_verified")]
    ConnectorOidcSkipEmailVerified,
    #[strum(serialize = "connector_oidc_allowed_groups")]
    ConnectorOidcAllowedGroups,
    #[strum(serialize = "connector_oidc_get_user_info")]
    ConnectorOidcGetUserInfo,
    #[strum(serialize = "connector_oidc_user_id_key")]
    ConnectorOidcUserIdKey,
    #[strum(serialize = "connector_oidc_user_name_key")]
    ConnectorOidcUserNameKey,
    #[strum(serialize = "connector_oidc_override_claim_mapping")]
    ConnectorOidcOverrideClaimMapping,
    #[strum(serialize = "connector_oidc_groups_prefix")]
    ConnectorOidcGroupsPrefix,
    #[strum(serialize = "connector_oidc_groups_suffix")]
    ConnectorOidcGroupsSuffix,
    // DL30 — Google upstream connector config attributes.
    // All optional on `EntryClass::Connector`.
    #[strum(serialize = "connector_google_hosted_domain")]
    ConnectorGoogleHostedDomain,
    #[strum(serialize = "connector_google_service_account_json")]
    ConnectorGoogleServiceAccountJson,
    #[strum(serialize = "connector_google_admin_email")]
    ConnectorGoogleAdminEmail,
    #[strum(serialize = "connector_google_fetch_groups")]
    ConnectorGoogleFetchGroups,
    // DL31 — Microsoft Azure AD upstream connector config attributes.
    // All optional on `EntryClass::Connector`.
    #[strum(serialize = "connector_microsoft_tenant")]
    ConnectorMicrosoftTenant,
    #[strum(serialize = "connector_microsoft_only_security_groups")]
    ConnectorMicrosoftOnlySecurityGroups,
    #[strum(serialize = "connector_microsoft_groups")]
    ConnectorMicrosoftGroups,
    #[strum(serialize = "connector_microsoft_group_name_format")]
    ConnectorMicrosoftGroupNameFormat,
    #[strum(serialize = "connector_microsoft_use_groups_as_whitelist")]
    ConnectorMicrosoftUseGroupsAsWhitelist,
    #[strum(serialize = "connector_microsoft_email_to_lowercase")]
    ConnectorMicrosoftEmailToLowercase,
    #[strum(serialize = "connector_microsoft_api_url")]
    ConnectorMicrosoftApiUrl,
    #[strum(serialize = "connector_microsoft_graph_url")]
    ConnectorMicrosoftGraphUrl,
    #[strum(serialize = "connector_microsoft_prompt_type")]
    ConnectorMicrosoftPromptType,
    #[strum(serialize = "connector_microsoft_domain_hint")]
    ConnectorMicrosoftDomainHint,
    #[strum(serialize = "connector_microsoft_scopes")]
    ConnectorMicrosoftScopes,
    #[strum(serialize = "connector_microsoft_preferred_username_field")]
    ConnectorMicrosoftPreferredUsernameField,
    #[strum(serialize = "connector_microsoft_allow_jit_provisioning")]
    ConnectorMicrosoftAllowJitProvisioning,
    // DL32 — Inbound LDAP federation connector config attributes.
    // All optional on `EntryClass::Connector`.
    // Connection / TLS
    #[strum(serialize = "connector_ldap_host")]
    ConnectorLdapHost,
    #[strum(serialize = "connector_ldap_insecure_no_ssl")]
    ConnectorLdapInsecureNoSsl,
    #[strum(serialize = "connector_ldap_insecure_skip_verify")]
    ConnectorLdapInsecureSkipVerify,
    #[strum(serialize = "connector_ldap_start_tls")]
    ConnectorLdapStartTls,
    #[strum(serialize = "connector_ldap_root_ca_data")]
    ConnectorLdapRootCaData,
    #[strum(serialize = "connector_ldap_client_cert")]
    ConnectorLdapClientCert,
    #[strum(serialize = "connector_ldap_client_key")]
    ConnectorLdapClientKey,
    #[strum(serialize = "connector_ldap_bind_dn")]
    ConnectorLdapBindDn,
    #[strum(serialize = "connector_ldap_bind_pw")]
    ConnectorLdapBindPw,
    #[strum(serialize = "connector_ldap_username_prompt")]
    ConnectorLdapUsernamePrompt,
    // UserSearch
    #[strum(serialize = "connector_ldap_user_search_base_dn")]
    ConnectorLdapUserSearchBaseDn,
    #[strum(serialize = "connector_ldap_user_search_filter")]
    ConnectorLdapUserSearchFilter,
    #[strum(serialize = "connector_ldap_user_search_username")]
    ConnectorLdapUserSearchUsername,
    #[strum(serialize = "connector_ldap_user_search_scope")]
    ConnectorLdapUserSearchScope,
    #[strum(serialize = "connector_ldap_user_search_id_attr")]
    ConnectorLdapUserSearchIdAttr,
    #[strum(serialize = "connector_ldap_user_search_email_attr")]
    ConnectorLdapUserSearchEmailAttr,
    #[strum(serialize = "connector_ldap_user_search_name_attr")]
    ConnectorLdapUserSearchNameAttr,
    #[strum(serialize = "connector_ldap_user_search_preferred_username_attr")]
    ConnectorLdapUserSearchPreferredUsernameAttr,
    #[strum(serialize = "connector_ldap_user_search_email_suffix")]
    ConnectorLdapUserSearchEmailSuffix,
    // GroupSearch
    #[strum(serialize = "connector_ldap_group_search_base_dn")]
    ConnectorLdapGroupSearchBaseDn,
    #[strum(serialize = "connector_ldap_group_search_filter")]
    ConnectorLdapGroupSearchFilter,
    #[strum(serialize = "connector_ldap_group_search_scope")]
    ConnectorLdapGroupSearchScope,
    #[strum(serialize = "connector_ldap_group_search_user_matchers")]
    ConnectorLdapGroupSearchUserMatchers,
    #[strum(serialize = "connector_ldap_group_search_name_attr")]
    ConnectorLdapGroupSearchNameAttr,
    #[strum(serialize = "connector_openshift_issuer")]
    ConnectorOpenshiftIssuer,
    #[strum(serialize = "connector_openshift_groups")]
    ConnectorOpenshiftGroups,
    #[strum(serialize = "connector_openshift_insecure_ca")]
    ConnectorOpenshiftInsecureCa,
    #[strum(serialize = "connector_openshift_root_ca")]
    ConnectorOpenshiftRootCa,
    #[strum(serialize = "connector_gitlab_base_url")]
    ConnectorGitlabBaseUrl,
    #[strum(serialize = "connector_gitlab_groups")]
    ConnectorGitlabGroups,
    #[strum(serialize = "connector_gitlab_use_login_as_id")]
    ConnectorGitlabUseLoginAsId,
    #[strum(serialize = "connector_gitlab_get_groups_permission")]
    ConnectorGitlabGetGroupsPermission,
    #[strum(serialize = "connector_gitlab_root_ca")]
    ConnectorGitlabRootCa,
    #[strum(serialize = "connector_bitbucket_teams")]
    ConnectorBitbucketTeams,
    #[strum(serialize = "connector_bitbucket_get_workspace_permissions")]
    ConnectorBitbucketGetWorkspacePermissions,
    #[strum(serialize = "connector_bitbucket_include_team_groups")]
    ConnectorBitbucketIncludeTeamGroups,
    // DL37 — ProviderIdentity class attributes (per-user per-connector identity record)
    #[strum(serialize = "provider_identity_user_uuid")]
    ProviderIdentityUserUuid,
    #[strum(serialize = "provider_identity_connector_id")]
    ProviderIdentityConnectorId,
    #[strum(serialize = "provider_identity_claims_user_id")]
    ProviderIdentityClaimsUserId,
    #[strum(serialize = "provider_identity_claims_username")]
    ProviderIdentityClaimsUsername,
    #[strum(serialize = "provider_identity_claims_email")]
    ProviderIdentityClaimsEmail,
    #[strum(serialize = "provider_identity_claims_email_verified")]
    ProviderIdentityClaimsEmailVerified,
    #[strum(serialize = "provider_identity_claims_groups")]
    ProviderIdentityClaimsGroups,
    #[strum(serialize = "provider_identity_consents")]
    ProviderIdentityConsents,
    #[strum(serialize = "provider_identity_created_at")]
    ProviderIdentityCreatedAt,
    #[strum(serialize = "provider_identity_last_login")]
    ProviderIdentityLastLogin,
    #[strum(serialize = "provider_identity_blocked_until")]
    ProviderIdentityBlockedUntil,
    // DL37 — OAuth2ResourceServer cross-client trust/connector-restriction attrs
    #[strum(serialize = "oauth2_rs_trusted_peers")]
    Oauth2RsTrustedPeers,
    #[strum(serialize = "oauth2_rs_allowed_connectors")]
    Oauth2RsAllowedConnectors,
    // DL38 — authproxy connector attrs (header-based identity trust)
    #[strum(serialize = "connector_authproxy_user_header")]
    ConnectorAuthproxyUserHeader,
    #[strum(serialize = "connector_authproxy_email_header")]
    ConnectorAuthproxyEmailHeader,
    #[strum(serialize = "connector_authproxy_groups_header")]
    ConnectorAuthproxyGroupsHeader,
    // DL38 — gitea connector attrs
    #[strum(serialize = "connector_gitea_base_url")]
    ConnectorGiteaBaseUrl,
    #[strum(serialize = "connector_gitea_groups")]
    ConnectorGiteaGroups,
    #[strum(serialize = "connector_gitea_insecure_ca")]
    ConnectorGiteaInsecureCa,
    #[strum(serialize = "connector_gitea_root_ca")]
    ConnectorGiteaRootCa,
    #[strum(serialize = "connector_gitea_load_all_groups")]
    ConnectorGiteaLoadAllGroups,
    #[strum(serialize = "connector_gitea_use_login_as_id")]
    ConnectorGiteaUseLoginAsId,
    // DL39 — keystone connector attrs
    #[strum(serialize = "connector_keystone_host")]
    ConnectorKeystoneHost,
    #[strum(serialize = "connector_keystone_domain")]
    ConnectorKeystoneDomain,
    #[strum(serialize = "connector_keystone_groups")]
    ConnectorKeystoneGroups,
    #[strum(serialize = "connector_keystone_insecure_ca")]
    ConnectorKeystoneInsecureCa,
    // DL40 — atlassian crowd connector attrs
    #[strum(serialize = "connector_crowd_base_url")]
    ConnectorCrowdBaseUrl,
    #[strum(serialize = "connector_crowd_client_name")]
    ConnectorCrowdClientName,
    #[strum(serialize = "connector_crowd_client_secret")]
    ConnectorCrowdClientSecret,
    #[strum(serialize = "connector_crowd_groups")]
    ConnectorCrowdGroups,
    #[strum(serialize = "objectclass")]
    ObjectClass,
    #[strum(serialize = "other-no-index")]
    OtherNoIndex,
    #[strum(serialize = "passkeys")]
    PassKeys,
    PasswordImport,
    #[strum(serialize = "pwd_changed_time")]
    PasswordChangedTime,
    PatchLevel,
    Phantom,
    PrimaryCredential,
    PrivateCookieKey,
    PrivilegeExpiry,
    RadiusSecret,
    #[strum(serialize = "recycled_directmemberof")]
    RecycledDirectMemberOf,
    Refers,
    Replicated,
    Rs256PrivateKeyDer,
    S256,
    /// A set of scim schemas. This is similar to a netidm class.
    #[serde(rename = "schemas")]
    #[strum(serialize = "schemas")]
    ScimSchemas,
    Scope,
    SendAfter,
    SentAt,
    SkipAuthRoute,
    SourceUuid,
    Spn,
    /// An LDAP-compatible sshpublickey
    #[strum(serialize = "sshpublickey")]
    LdapSshPublicKey,
    /// The Netidm-local ssh_publickey
    #[strum(serialize = "ssh_publickey")]
    SshPublicKey,
    #[strum(serialize = "sudohost")]
    SudoHost,
    Supplements,
    #[strum(serialize = "systemsupplements")]
    SystemSupplements,
    SyncAllowed,
    SyncClass,
    SyncCookie,
    SyncCredentialPortal,
    SyncExternalId,
    SyncParentUuid,
    SyncTokenSession,
    SyncYieldAuthority,
    Syntax,
    #[strum(serialize = "systemexcludes")]
    SystemExcludes,
    #[strum(serialize = "systemmay")]
    SystemMay,
    #[strum(serialize = "systemmust")]
    SystemMust,
    Term,
    TotpImport,
    Uid,
    #[strum(serialize = "uidnumber")]
    UidNumber,
    Unique,
    UnixPassword,
    UnixPasswordImport,
    UserAuthTokenSession,
    #[strum(serialize = "userid")]
    UserId,
    #[strum(serialize = "userpassword")]
    UserPassword,
    Uuid,
    Version,
    WebauthnAttestationCaList,
    AllowPrimaryCredFallback,
    // DL16 — WireGuard tunnel attributes
    WgInterface,
    WgListenPort,
    WgAddress,
    WgDns,
    WgMtu,
    WgTable,
    WgPreUp,
    WgPostUp,
    WgPreDown,
    WgPostDown,
    WgSaveConfig,
    WgPublicKey,
    WgEndpoint,
    // DL16 — WireGuard peer attributes
    WgPubkey,
    WgAllowedIps,
    WgPresharedKey,
    WgPersistentKeepalive,
    WgTunnelRef,
    WgUserRef,
    WgPrivateKey,
    // DL17 — WireGuard token and peer monitoring
    WgLastSeen,
    WgTokenSecret,
    WgTokenUsesLeft,
    WgTokenExpiry,
    WgTokenPrincipalRef,
    /// Virtual attribute used in preload TOML files to inline WG peer specs
    /// on person assertions. Stripped by scim_assert() before schema validation.
    #[strum(serialize = "wg")]
    WgInlinePeer,

    // DL22 — SAML 2.0 client attributes
    SamlIdpSsoUrl,
    SamlIdpCertificate,
    SamlEntityId,
    SamlAcsUrl,
    SamlNameIdFormat,
    SamlAttrMapEmail,
    SamlAttrMapDisplayname,
    SamlAttrMapGroups,
    SamlJitProvisioning,
    // DL33 — SAML connector dex-parity additions (PR-CONNECTOR-SAML)
    SamlSsoIssuer,
    SamlInsecureSkipSigValidation,
    SamlGroupsDelim,
    SamlAllowedGroups,
    SamlFilterGroups,

    #[cfg(any(debug_assertions, test, feature = "test"))]
    #[strum(serialize = "non-exist")]
    NonExist,
    #[cfg(any(debug_assertions, test, feature = "test"))]
    #[strum(serialize = "testattr")]
    TestAttr,
    #[cfg(test)]
    #[strum(serialize = "testattr_a")]
    TestAttrA,
    #[cfg(test)]
    #[strum(serialize = "testattr_b")]
    TestAttrB,
    #[cfg(test)]
    #[strum(serialize = "testattr_c")]
    TestAttrC,
    #[cfg(test)]
    #[strum(serialize = "testattr_d")]
    TestAttrD,
    #[cfg(any(debug_assertions, test, feature = "test"))]
    #[strum(serialize = "testattrnumber")]
    TestNumber,
    #[cfg(any(debug_assertions, test, feature = "test"))]
    Extra,
    #[cfg(any(debug_assertions, test, feature = "test"))]
    #[strum(serialize = "notallowed")]
    TestNotAllowed,

    #[cfg(not(test))]
    #[schema(value_type = String)]
    #[strum(serialize = "")]
    Custom(AttrString),
}

impl AsRef<Attribute> for Attribute {
    fn as_ref(&self) -> &Attribute {
        self
    }
}

impl TryFrom<&AttrString> for Attribute {
    type Error = OperationError;

    fn try_from(value: &AttrString) -> Result<Self, Self::Error> {
        Ok(Attribute::inner_from_str(value.as_str()))
    }
}

impl From<&str> for Attribute {
    fn from(value: &str) -> Self {
        Self::inner_from_str(value)
    }
}

impl From<String> for Attribute {
    fn from(value: String) -> Self {
        Self::inner_from_str(value.as_str())
    }
}

impl FromStr for Attribute {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::inner_from_str(value))
    }
}

impl<'a> From<&'a Attribute> for &'a str {
    fn from(val: &'a Attribute) -> Self {
        val.as_str()
    }
}

impl From<Attribute> for AttrString {
    fn from(val: Attribute) -> Self {
        AttrString::from(val.as_str())
    }
}

impl Attribute {
    pub fn as_str(&self) -> &str {
        #[cfg(not(test))]
        if let Attribute::Custom(s) = self {
            return s.as_str();
        }
        <Self as AsRef<str>>::as_ref(self)
    }

    // We allow this because the standard lib from_str is fallible, and we want an infallible version.
    #[allow(clippy::should_implement_trait)]
    fn inner_from_str(value: &str) -> Self {
        // Could this be something like heapless to save allocations? Also gives a way
        // to limit length of str?
        match value.to_lowercase().as_str() {
            ATTR_ACCOUNT => Attribute::Account,
            ATTR_ACCOUNT_EXPIRE => Attribute::AccountExpire,
            ATTR_ACCOUNT_VALID_FROM => Attribute::AccountValidFrom,
            ATTR_ACCOUNT_SOFTLOCK_EXPIRE => Attribute::AccountSoftlockExpire,
            ATTR_ACP_CREATE_ATTR => Attribute::AcpCreateAttr,
            ATTR_ACP_CREATE_CLASS => Attribute::AcpCreateClass,
            ATTR_ACP_ENABLE => Attribute::AcpEnable,
            ATTR_ACP_MODIFY_CLASS => Attribute::AcpModifyClass,
            ATTR_ACP_MODIFY_PRESENT_CLASS => Attribute::AcpModifyPresentClass,
            ATTR_ACP_MODIFY_REMOVE_CLASS => Attribute::AcpModifyRemoveClass,
            ATTR_ACP_MODIFY_PRESENTATTR => Attribute::AcpModifyPresentAttr,
            ATTR_ACP_MODIFY_REMOVEDATTR => Attribute::AcpModifyRemovedAttr,
            ATTR_ACP_RECEIVER => Attribute::AcpReceiver,
            ATTR_ACP_RECEIVER_GROUP => Attribute::AcpReceiverGroup,
            ATTR_ACP_SEARCH_ATTR => Attribute::AcpSearchAttr,
            ATTR_ACP_TARGET_SCOPE => Attribute::AcpTargetScope,
            ATTR_ALLOW_PRIMARY_CRED_FALLBACK => Attribute::AllowPrimaryCredFallback,
            ATTR_API_TOKEN_SESSION => Attribute::ApiTokenSession,
            ATTR_APPLICATION_PASSWORD => Attribute::ApplicationPassword,
            ATTR_APPLICATION_URL => Attribute::ApplicationUrl,
            ATTR_ATTESTED_PASSKEYS => Attribute::AttestedPasskeys,
            ATTR_ATTR => Attribute::Attr,
            ATTR_ATTRIBUTENAME => Attribute::AttributeName,
            ATTR_ATTRIBUTETYPE => Attribute::AttributeType,
            ATTR_AUTH_SESSION_EXPIRY => Attribute::AuthSessionExpiry,
            ATTR_AUTH_PASSWORD_MINIMUM_LENGTH => Attribute::AuthPasswordMinimumLength,
            ATTR_BADLIST_PASSWORD => Attribute::BadlistPassword,
            ATTR_CERTIFICATE => Attribute::Certificate,
            ATTR_CASCADE_DELETED => Attribute::CascadeDeleted,
            ATTR_CLAIM => Attribute::Claim,
            ATTR_CLASS => Attribute::Class,
            ATTR_CLASSNAME => Attribute::ClassName,
            ATTR_CN => Attribute::Cn,
            ATTR_COOKIE_PRIVATE_KEY => Attribute::CookiePrivateKey,
            ATTR_CREATED_AT_CID => Attribute::CreatedAtCid,
            ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN => Attribute::CredentialUpdateIntentToken,
            ATTR_CREDENTIAL_TYPE_MINIMUM => Attribute::CredentialTypeMinimum,
            ATTR_DENIED_NAME => Attribute::DeniedName,
            ATTR_DELETE_AFTER => Attribute::DeleteAfter,
            ATTR_DESCRIPTION => Attribute::Description,
            ATTR_DIRECTMEMBEROF => Attribute::DirectMemberOf,
            ATTR_DISPLAYNAME => Attribute::DisplayName,
            ATTR_DN => Attribute::Dn,
            ATTR_DOMAIN => Attribute::Domain,
            ATTR_DOMAIN_ALLOW_EASTER_EGGS => Attribute::DomainAllowEasterEggs,
            ATTR_DOMAIN_DISPLAY_NAME => Attribute::DomainDisplayName,
            ATTR_DOMAIN_DEVELOPMENT_TAINT => Attribute::DomainDevelopmentTaint,
            ATTR_DOMAIN_LDAP_BASEDN => Attribute::DomainLdapBasedn,
            ATTR_DOMAIN_NAME => Attribute::DomainName,
            ATTR_DOMAIN_SSID => Attribute::DomainSsid,
            ATTR_DOMAIN_TOKEN_KEY => Attribute::DomainTokenKey,
            ATTR_DOMAIN_UUID => Attribute::DomainUuid,
            ATTR_DYNGROUP => Attribute::DynGroup,
            ATTR_DYNGROUP_FILTER => Attribute::DynGroupFilter,
            ATTR_DYNMEMBER => Attribute::DynMember,
            ATTR_ENABLED => Attribute::Enabled,
            ATTR_EMAIL => Attribute::Email,
            ATTR_EMAIL_ALTERNATIVE => Attribute::EmailAlternative,
            ATTR_EMAIL_PRIMARY => Attribute::EmailPrimary,
            ATTR_ENTRYDN => Attribute::EntryDn,
            ATTR_ENTRY_MANAGED_BY => Attribute::EntryManagedBy,
            ATTR_ENTRYUUID => Attribute::EntryUuid,
            ATTR_ES256_PRIVATE_KEY_DER => Attribute::Es256PrivateKeyDer,
            ATTR_EXCLUDES => Attribute::Excludes,
            ATTR_FERNET_PRIVATE_KEY_STR => Attribute::FernetPrivateKeyStr,
            ATTR_GECOS => Attribute::Gecos,
            ATTR_GIDNUMBER => Attribute::GidNumber,
            ATTR_GRANT_UI_HINT => Attribute::GrantUiHint,
            ATTR_GROUP => Attribute::Group,
            ATTR_HMAC_NAME_HISTORY => Attribute::HmacNameHistory,
            ATTR_HOME_DIRECTORY => Attribute::HomeDirectory,
            ATTR_ID_VERIFICATION_ECKEY => Attribute::IdVerificationEcKey,
            ATTR_IMAGE => Attribute::Image,
            ATTR_INDEX => Attribute::Index,
            ATTR_INDEXED => Attribute::Indexed,
            ATTR_IN_MEMORIAM => Attribute::InMemoriam,
            ATTR_IPANTHASH => Attribute::IpaNtHash,
            ATTR_IPASSHPUBKEY => Attribute::IpaSshPubKey,
            ATTR_JWS_ES256_PRIVATE_KEY => Attribute::JwsEs256PrivateKey,
            ATTR_KEY_ACTION_ROTATE => Attribute::KeyActionRotate,
            ATTR_KEY_ACTION_REVOKE => Attribute::KeyActionRevoke,
            ATTR_KEY_ACTION_IMPORT_JWS_ES256 => Attribute::KeyActionImportJwsEs256,
            ATTR_KEY_ACTION_IMPORT_JWS_RS256 => Attribute::KeyActionImportJwsRs256,
            ATTR_KEY_INTERNAL_DATA => Attribute::KeyInternalData,
            ATTR_KEY_PROVIDER => Attribute::KeyProvider,
            ATTR_LAST_MODIFIED_CID => Attribute::LastModifiedCid,
            ATTR_LDAP_ALLOW_UNIX_PW_BIND => Attribute::LdapAllowUnixPwBind,
            ATTR_LDAP_EMAIL_ADDRESS => Attribute::LdapEmailAddress,
            ATTR_LDAP_KEYS => Attribute::LdapKeys,
            ATTR_LDAP_MAX_QUERYABLE_ATTRS => Attribute::LdapMaxQueryableAttrs,
            ATTR_SSH_PUBLICKEY => Attribute::SshPublicKey,
            ATTR_LEGALNAME => Attribute::LegalName,
            ATTR_LINKEDGROUP => Attribute::LinkedGroup,
            ATTR_LOGINSHELL => Attribute::LoginShell,
            ATTR_LIMIT_SEARCH_MAX_RESULTS => Attribute::LimitSearchMaxResults,
            ATTR_LIMIT_SEARCH_MAX_FILTER_TEST => Attribute::LimitSearchMaxFilterTest,
            ATTR_MAIL => Attribute::Mail,
            ATTR_MAIL_DESTINATION => Attribute::MailDestination,
            ATTR_MAY => Attribute::May,
            ATTR_MEMBER => Attribute::Member,
            ATTR_MEMBER_CREATE_ONCE => Attribute::MemberCreateOnce,
            ATTR_MEMBEROF => Attribute::MemberOf,
            ATTR_MESSAGE_TEMPLATE => Attribute::MessageTemplate,
            ATTR_MULTIVALUE => Attribute::MultiValue,
            ATTR_MUST => Attribute::Must,
            ATTR_NAME => Attribute::Name,
            ATTR_NAME_HISTORY => Attribute::NameHistory,
            ATTR_NO_INDEX => Attribute::NoIndex,
            ATTR_NSUNIQUEID => Attribute::NsUniqueId,
            ATTR_NSACCOUNTLOCK => Attribute::NsAccountLock,
            ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE => {
                Attribute::OAuth2AllowInsecureClientDisablePkce
            }
            ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT => Attribute::OAuth2AllowLocalhostRedirect,
            ATTR_OAUTH2_AUTHORISATION_ENDPOINT => Attribute::OAuth2AuthorisationEndpoint,
            ATTR_CONNECTOR_ID => Attribute::ConnectorId,
            ATTR_CONNECTOR_LOGO_URI => Attribute::ConnectorLogoUri,
            ATTR_CONNECTOR_SECRET => Attribute::ConnectorSecret,
            ATTR_OAUTH2_CONSENT_SCOPE_MAP => Attribute::OAuth2ConsentScopeMap,
            ATTR_OAUTH2_DEVICE_FLOW_ENABLE => Attribute::OAuth2DeviceFlowEnable,
            ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE => Attribute::OAuth2JwtLegacyCryptoEnable,
            ATTR_OAUTH2_PREFER_SHORT_USERNAME => Attribute::OAuth2PreferShortUsername,
            ATTR_OAUTH2_REQUEST_SCOPES => Attribute::OAuth2RequestScopes,
            ATTR_OAUTH2_RS_BASIC_SECRET => Attribute::OAuth2RsBasicSecret,
            ATTR_OAUTH2_RS_CLAIM_MAP => Attribute::OAuth2RsClaimMap,
            ATTR_OAUTH2_RS_IMPLICIT_SCOPES => Attribute::OAuth2RsImplicitScopes,
            ATTR_OAUTH2_RS_NAME => Attribute::OAuth2RsName,
            ATTR_OAUTH2_RS_ORIGIN => Attribute::OAuth2RsOrigin,
            ATTR_OAUTH2_RS_ORIGIN_LANDING => Attribute::OAuth2RsOriginLanding,
            ATTR_OAUTH2_RS_SCOPE_MAP => Attribute::OAuth2RsScopeMap,
            ATTR_OAUTH2_RS_SUP_SCOPE_MAP => Attribute::OAuth2RsSupScopeMap,
            ATTR_OAUTH2_RS_TOKEN_KEY => Attribute::OAuth2RsTokenKey,
            ATTR_OAUTH2_SESSION => Attribute::OAuth2Session,
            ATTR_OAUTH2_STRICT_REDIRECT_URI => Attribute::OAuth2StrictRedirectUri,
            ATTR_OAUTH2_TOKEN_ENDPOINT => Attribute::OAuth2TokenEndpoint,
            ATTR_OAUTH2_ACCOUNT_CREDENTIAL_UUID => Attribute::OAuth2AccountCredentialUuid,
            ATTR_OAUTH2_ACCOUNT_PROVIDER => Attribute::OAuth2AccountProvider,
            ATTR_OAUTH2_ACCOUNT_UNIQUE_USER_ID => Attribute::OAuth2AccountUniqueUserId,
            ATTR_OAUTH2_CONSENT_PROMPT_ENABLE => Attribute::OAuth2ConsentPromptEnable,
            ATTR_OAUTH2_USERINFO_ENDPOINT => Attribute::OAuth2UserinfoEndpoint,
            ATTR_OAUTH2_JIT_PROVISIONING => Attribute::OAuth2JitProvisioning,
            ATTR_OAUTH2_CLAIM_MAP_NAME => Attribute::OAuth2ClaimMapName,
            ATTR_OAUTH2_CLAIM_MAP_DISPLAYNAME => Attribute::OAuth2ClaimMapDisplayname,
            ATTR_OAUTH2_CLAIM_MAP_EMAIL => Attribute::OAuth2ClaimMapEmail,
            ATTR_OAUTH2_EMAIL_LINK_ACCOUNTS => Attribute::OAuth2EmailLinkAccounts,
            ATTR_OAUTH2_DOMAIN_EMAIL_LINK_ACCOUNTS => Attribute::OAuth2DomainEmailLinkAccounts,
            ATTR_OAUTH2_ISSUER => Attribute::OAuth2Issuer,
            ATTR_OAUTH2_JWKS_URI => Attribute::OAuth2JwksUri,
            ATTR_OAUTH2_LINK_BY => Attribute::OAuth2LinkBy,
            ATTR_OAUTH2_GROUP_MAPPING => Attribute::OAuth2GroupMapping,
            ATTR_SAML_GROUP_MAPPING => Attribute::SamlGroupMapping,
            ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP => Attribute::OAuth2UpstreamSyncedGroup,
            ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI => Attribute::OAuth2RsPostLogoutRedirectUri,
            ATTR_OAUTH2_RS_BACKCHANNEL_LOGOUT_URI => Attribute::OAuth2RsBackchannelLogoutUri,
            ATTR_SAML_SINGLE_LOGOUT_SERVICE_URL => Attribute::SamlSingleLogoutServiceUrl,
            ATTR_LOGOUT_DELIVERY_ENDPOINT => Attribute::LogoutDeliveryEndpoint,
            ATTR_LOGOUT_DELIVERY_TOKEN => Attribute::LogoutDeliveryToken,
            ATTR_LOGOUT_DELIVERY_STATUS => Attribute::LogoutDeliveryStatus,
            ATTR_LOGOUT_DELIVERY_ATTEMPTS => Attribute::LogoutDeliveryAttempts,
            ATTR_LOGOUT_DELIVERY_NEXT_ATTEMPT => Attribute::LogoutDeliveryNextAttempt,
            ATTR_LOGOUT_DELIVERY_CREATED => Attribute::LogoutDeliveryCreated,
            ATTR_LOGOUT_DELIVERY_RP => Attribute::LogoutDeliveryRp,
            ATTR_SAML_SESSION_USER => Attribute::SamlSessionUser,
            ATTR_SAML_SESSION_SP => Attribute::SamlSessionSp,
            ATTR_SAML_SESSION_INDEX => Attribute::SamlSessionIndex,
            ATTR_SAML_SESSION_UAT_UUID => Attribute::SamlSessionUatUuid,
            ATTR_SAML_SESSION_CREATED => Attribute::SamlSessionCreated,
            ATTR_CONNECTOR_PROVIDER_KIND => Attribute::ConnectorProviderKind,
            ATTR_CONNECTOR_GITHUB_HOST => Attribute::ConnectorGithubHost,
            ATTR_CONNECTOR_GITHUB_ORG_FILTER => Attribute::ConnectorGithubOrgFilter,
            ATTR_CONNECTOR_GITHUB_ALLOWED_TEAMS => Attribute::ConnectorGithubAllowedTeams,
            ATTR_CONNECTOR_GITHUB_TEAM_NAME_FIELD => Attribute::ConnectorGithubTeamNameField,
            ATTR_CONNECTOR_GITHUB_LOAD_ALL_GROUPS => Attribute::ConnectorGithubLoadAllGroups,
            ATTR_CONNECTOR_GITHUB_PREFERRED_EMAIL_DOMAIN => {
                Attribute::ConnectorGithubPreferredEmailDomain
            }
            ATTR_CONNECTOR_GITHUB_ALLOW_JIT_PROVISIONING => {
                Attribute::ConnectorGithubAllowJitProvisioning
            }
            ATTR_CONNECTOR_GITHUB_USE_LOGIN_AS_ID => Attribute::ConnectorGithubUseLoginAsId,
            ATTR_CONNECTOR_OIDC_ENABLE_GROUPS => Attribute::ConnectorOidcEnableGroups,
            ATTR_CONNECTOR_OIDC_GROUPS_KEY => Attribute::ConnectorOidcGroupsKey,
            ATTR_CONNECTOR_OIDC_SKIP_EMAIL_VERIFIED => Attribute::ConnectorOidcSkipEmailVerified,
            ATTR_CONNECTOR_OIDC_ALLOWED_GROUPS => Attribute::ConnectorOidcAllowedGroups,
            ATTR_CONNECTOR_OIDC_GET_USER_INFO => Attribute::ConnectorOidcGetUserInfo,
            ATTR_CONNECTOR_OIDC_USER_ID_KEY => Attribute::ConnectorOidcUserIdKey,
            ATTR_CONNECTOR_OIDC_USER_NAME_KEY => Attribute::ConnectorOidcUserNameKey,
            ATTR_CONNECTOR_OIDC_OVERRIDE_CLAIM_MAPPING => {
                Attribute::ConnectorOidcOverrideClaimMapping
            }
            ATTR_CONNECTOR_OIDC_GROUPS_PREFIX => Attribute::ConnectorOidcGroupsPrefix,
            ATTR_CONNECTOR_OIDC_GROUPS_SUFFIX => Attribute::ConnectorOidcGroupsSuffix,
            ATTR_CONNECTOR_GOOGLE_HOSTED_DOMAIN => Attribute::ConnectorGoogleHostedDomain,
            ATTR_CONNECTOR_GOOGLE_SERVICE_ACCOUNT_JSON => {
                Attribute::ConnectorGoogleServiceAccountJson
            }
            ATTR_CONNECTOR_GOOGLE_ADMIN_EMAIL => Attribute::ConnectorGoogleAdminEmail,
            ATTR_CONNECTOR_GOOGLE_FETCH_GROUPS => Attribute::ConnectorGoogleFetchGroups,
            ATTR_CONNECTOR_MICROSOFT_TENANT => Attribute::ConnectorMicrosoftTenant,
            ATTR_CONNECTOR_MICROSOFT_ONLY_SECURITY_GROUPS => {
                Attribute::ConnectorMicrosoftOnlySecurityGroups
            }
            ATTR_CONNECTOR_MICROSOFT_GROUPS => Attribute::ConnectorMicrosoftGroups,
            ATTR_CONNECTOR_MICROSOFT_GROUP_NAME_FORMAT => {
                Attribute::ConnectorMicrosoftGroupNameFormat
            }
            ATTR_CONNECTOR_MICROSOFT_USE_GROUPS_AS_WHITELIST => {
                Attribute::ConnectorMicrosoftUseGroupsAsWhitelist
            }
            ATTR_CONNECTOR_MICROSOFT_EMAIL_TO_LOWERCASE => {
                Attribute::ConnectorMicrosoftEmailToLowercase
            }
            ATTR_CONNECTOR_MICROSOFT_API_URL => Attribute::ConnectorMicrosoftApiUrl,
            ATTR_CONNECTOR_MICROSOFT_GRAPH_URL => Attribute::ConnectorMicrosoftGraphUrl,
            ATTR_CONNECTOR_MICROSOFT_PROMPT_TYPE => Attribute::ConnectorMicrosoftPromptType,
            ATTR_CONNECTOR_MICROSOFT_DOMAIN_HINT => Attribute::ConnectorMicrosoftDomainHint,
            ATTR_CONNECTOR_MICROSOFT_SCOPES => Attribute::ConnectorMicrosoftScopes,
            ATTR_CONNECTOR_MICROSOFT_PREFERRED_USERNAME_FIELD => {
                Attribute::ConnectorMicrosoftPreferredUsernameField
            }
            ATTR_CONNECTOR_MICROSOFT_ALLOW_JIT_PROVISIONING => {
                Attribute::ConnectorMicrosoftAllowJitProvisioning
            }
            ATTR_CONNECTOR_LDAP_HOST => Attribute::ConnectorLdapHost,
            ATTR_CONNECTOR_LDAP_INSECURE_NO_SSL => Attribute::ConnectorLdapInsecureNoSsl,
            ATTR_CONNECTOR_LDAP_INSECURE_SKIP_VERIFY => Attribute::ConnectorLdapInsecureSkipVerify,
            ATTR_CONNECTOR_LDAP_START_TLS => Attribute::ConnectorLdapStartTls,
            ATTR_CONNECTOR_LDAP_ROOT_CA_DATA => Attribute::ConnectorLdapRootCaData,
            ATTR_CONNECTOR_LDAP_CLIENT_CERT => Attribute::ConnectorLdapClientCert,
            ATTR_CONNECTOR_LDAP_CLIENT_KEY => Attribute::ConnectorLdapClientKey,
            ATTR_CONNECTOR_LDAP_BIND_DN => Attribute::ConnectorLdapBindDn,
            ATTR_CONNECTOR_LDAP_BIND_PW => Attribute::ConnectorLdapBindPw,
            ATTR_CONNECTOR_LDAP_USERNAME_PROMPT => Attribute::ConnectorLdapUsernamePrompt,
            ATTR_CONNECTOR_LDAP_USER_SEARCH_BASE_DN => Attribute::ConnectorLdapUserSearchBaseDn,
            ATTR_CONNECTOR_LDAP_USER_SEARCH_FILTER => Attribute::ConnectorLdapUserSearchFilter,
            ATTR_CONNECTOR_LDAP_USER_SEARCH_USERNAME => Attribute::ConnectorLdapUserSearchUsername,
            ATTR_CONNECTOR_LDAP_USER_SEARCH_SCOPE => Attribute::ConnectorLdapUserSearchScope,
            ATTR_CONNECTOR_LDAP_USER_SEARCH_ID_ATTR => Attribute::ConnectorLdapUserSearchIdAttr,
            ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_ATTR => {
                Attribute::ConnectorLdapUserSearchEmailAttr
            }
            ATTR_CONNECTOR_LDAP_USER_SEARCH_NAME_ATTR => Attribute::ConnectorLdapUserSearchNameAttr,
            ATTR_CONNECTOR_LDAP_USER_SEARCH_PREFERRED_USERNAME_ATTR => {
                Attribute::ConnectorLdapUserSearchPreferredUsernameAttr
            }
            ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_SUFFIX => {
                Attribute::ConnectorLdapUserSearchEmailSuffix
            }
            ATTR_CONNECTOR_LDAP_GROUP_SEARCH_BASE_DN => Attribute::ConnectorLdapGroupSearchBaseDn,
            ATTR_CONNECTOR_LDAP_GROUP_SEARCH_FILTER => Attribute::ConnectorLdapGroupSearchFilter,
            ATTR_CONNECTOR_LDAP_GROUP_SEARCH_SCOPE => Attribute::ConnectorLdapGroupSearchScope,
            ATTR_CONNECTOR_LDAP_GROUP_SEARCH_USER_MATCHERS => {
                Attribute::ConnectorLdapGroupSearchUserMatchers
            }
            ATTR_CONNECTOR_LDAP_GROUP_SEARCH_NAME_ATTR => {
                Attribute::ConnectorLdapGroupSearchNameAttr
            }
            ATTR_OBJECTCLASS => Attribute::ObjectClass,
            ATTR_OTHER_NO_INDEX => Attribute::OtherNoIndex,
            ATTR_PASSKEYS => Attribute::PassKeys,
            ATTR_PASSWORD_IMPORT => Attribute::PasswordImport,
            ATTR_PATCH_LEVEL => Attribute::PatchLevel,
            ATTR_PHANTOM => Attribute::Phantom,
            ATTR_PRIMARY_CREDENTIAL => Attribute::PrimaryCredential,
            ATTR_PRIVATE_COOKIE_KEY => Attribute::PrivateCookieKey,
            ATTR_PRIVILEGE_EXPIRY => Attribute::PrivilegeExpiry,
            ATTR_PWD_CHANGED_TIME => Attribute::PasswordChangedTime,
            ATTR_RADIUS_SECRET => Attribute::RadiusSecret,
            ATTR_RECYCLEDDIRECTMEMBEROF => Attribute::RecycledDirectMemberOf,
            ATTR_REFERS => Attribute::Refers,
            ATTR_REPLICATED => Attribute::Replicated,
            ATTR_RS256_PRIVATE_KEY_DER => Attribute::Rs256PrivateKeyDer,
            ATTR_S256 => Attribute::S256,
            ATTR_SCIM_SCHEMAS => Attribute::ScimSchemas,
            ATTR_SEND_AFTER => Attribute::SendAfter,
            ATTR_SENT_AT => Attribute::SentAt,
            ATTR_SCOPE => Attribute::Scope,
            ATTR_SKIP_AUTH_ROUTE => Attribute::SkipAuthRoute,
            ATTR_SOURCE_UUID => Attribute::SourceUuid,
            ATTR_SPN => Attribute::Spn,
            ATTR_LDAP_SSHPUBLICKEY => Attribute::LdapSshPublicKey,
            ATTR_SUDOHOST => Attribute::SudoHost,
            ATTR_SUPPLEMENTS => Attribute::Supplements,
            ATTR_SYNC_ALLOWED => Attribute::SyncAllowed,
            ATTR_SYNC_CLASS => Attribute::SyncClass,
            ATTR_SYNC_COOKIE => Attribute::SyncCookie,
            ATTR_SYNC_CREDENTIAL_PORTAL => Attribute::SyncCredentialPortal,
            ATTR_SYNC_EXTERNAL_ID => Attribute::SyncExternalId,
            ATTR_SYNC_PARENT_UUID => Attribute::SyncParentUuid,
            ATTR_SYNC_TOKEN_SESSION => Attribute::SyncTokenSession,
            ATTR_SYNC_YIELD_AUTHORITY => Attribute::SyncYieldAuthority,
            ATTR_SYNTAX => Attribute::Syntax,
            ATTR_SYSTEMEXCLUDES => Attribute::SystemExcludes,
            ATTR_SYSTEMMAY => Attribute::SystemMay,
            ATTR_SYSTEMMUST => Attribute::SystemMust,
            ATTR_SYSTEMSUPPLEMENTS => Attribute::SystemSupplements,
            ATTR_TERM => Attribute::Term,
            ATTR_TOTP_IMPORT => Attribute::TotpImport,
            ATTR_UID => Attribute::Uid,
            ATTR_UIDNUMBER => Attribute::UidNumber,
            ATTR_UNIQUE => Attribute::Unique,
            ATTR_UNIX_PASSWORD => Attribute::UnixPassword,
            ATTR_UNIX_PASSWORD_IMPORT => Attribute::UnixPasswordImport,
            ATTR_USER_AUTH_TOKEN_SESSION => Attribute::UserAuthTokenSession,
            ATTR_USERID => Attribute::UserId,
            ATTR_USERPASSWORD => Attribute::UserPassword,
            ATTR_UUID => Attribute::Uuid,
            ATTR_VERSION => Attribute::Version,
            ATTR_WEBAUTHN_ATTESTATION_CA_LIST => Attribute::WebauthnAttestationCaList,
            ATTR_WG_INTERFACE => Attribute::WgInterface,
            ATTR_WG_LISTEN_PORT => Attribute::WgListenPort,
            ATTR_WG_ADDRESS => Attribute::WgAddress,
            ATTR_WG_DNS => Attribute::WgDns,
            ATTR_WG_MTU => Attribute::WgMtu,
            ATTR_WG_TABLE => Attribute::WgTable,
            ATTR_WG_PRE_UP => Attribute::WgPreUp,
            ATTR_WG_POST_UP => Attribute::WgPostUp,
            ATTR_WG_PRE_DOWN => Attribute::WgPreDown,
            ATTR_WG_POST_DOWN => Attribute::WgPostDown,
            ATTR_WG_SAVE_CONFIG => Attribute::WgSaveConfig,
            ATTR_WG_PUBLIC_KEY => Attribute::WgPublicKey,
            ATTR_WG_ENDPOINT => Attribute::WgEndpoint,
            ATTR_WG_PUBKEY => Attribute::WgPubkey,
            ATTR_WG_ALLOWED_IPS => Attribute::WgAllowedIps,
            ATTR_WG_PRESHARED_KEY => Attribute::WgPresharedKey,
            ATTR_WG_PERSISTENT_KEEPALIVE => Attribute::WgPersistentKeepalive,
            ATTR_WG_TUNNEL_REF => Attribute::WgTunnelRef,
            ATTR_WG_USER_REF => Attribute::WgUserRef,
            ATTR_WG_PRIVATE_KEY => Attribute::WgPrivateKey,
            ATTR_WG_LAST_SEEN => Attribute::WgLastSeen,
            ATTR_WG_TOKEN_SECRET => Attribute::WgTokenSecret,
            ATTR_WG_TOKEN_USES_LEFT => Attribute::WgTokenUsesLeft,
            ATTR_WG_TOKEN_EXPIRY => Attribute::WgTokenExpiry,
            ATTR_WG_TOKEN_PRINCIPAL_REF => Attribute::WgTokenPrincipalRef,
            "wg" => Attribute::WgInlinePeer,
            "saml_idp_sso_url" => Attribute::SamlIdpSsoUrl,
            "saml_idp_certificate" => Attribute::SamlIdpCertificate,
            "saml_entity_id" => Attribute::SamlEntityId,
            "saml_acs_url" => Attribute::SamlAcsUrl,
            "saml_name_id_format" => Attribute::SamlNameIdFormat,
            "saml_attr_map_email" => Attribute::SamlAttrMapEmail,
            "saml_attr_map_displayname" => Attribute::SamlAttrMapDisplayname,
            "saml_attr_map_groups" => Attribute::SamlAttrMapGroups,
            "saml_jit_provisioning" => Attribute::SamlJitProvisioning,
            ATTR_CONNECTOR_OPENSHIFT_ISSUER => Attribute::ConnectorOpenshiftIssuer,
            ATTR_CONNECTOR_OPENSHIFT_GROUPS => Attribute::ConnectorOpenshiftGroups,
            ATTR_CONNECTOR_OPENSHIFT_INSECURE_CA => Attribute::ConnectorOpenshiftInsecureCa,
            ATTR_CONNECTOR_OPENSHIFT_ROOT_CA => Attribute::ConnectorOpenshiftRootCa,
            ATTR_CONNECTOR_GITLAB_BASE_URL => Attribute::ConnectorGitlabBaseUrl,
            ATTR_CONNECTOR_GITLAB_GROUPS => Attribute::ConnectorGitlabGroups,
            ATTR_CONNECTOR_GITLAB_USE_LOGIN_AS_ID => Attribute::ConnectorGitlabUseLoginAsId,
            ATTR_CONNECTOR_GITLAB_GET_GROUPS_PERMISSION => {
                Attribute::ConnectorGitlabGetGroupsPermission
            }
            ATTR_CONNECTOR_GITLAB_ROOT_CA => Attribute::ConnectorGitlabRootCa,
            ATTR_CONNECTOR_BITBUCKET_TEAMS => Attribute::ConnectorBitbucketTeams,
            ATTR_CONNECTOR_BITBUCKET_GET_WORKSPACE_PERMISSIONS => {
                Attribute::ConnectorBitbucketGetWorkspacePermissions
            }
            ATTR_CONNECTOR_BITBUCKET_INCLUDE_TEAM_GROUPS => {
                Attribute::ConnectorBitbucketIncludeTeamGroups
            }
            ATTR_PROVIDER_IDENTITY_USER_UUID => Attribute::ProviderIdentityUserUuid,
            ATTR_PROVIDER_IDENTITY_CONNECTOR_ID => Attribute::ProviderIdentityConnectorId,
            ATTR_PROVIDER_IDENTITY_CLAIMS_USER_ID => Attribute::ProviderIdentityClaimsUserId,
            ATTR_PROVIDER_IDENTITY_CLAIMS_USERNAME => Attribute::ProviderIdentityClaimsUsername,
            ATTR_PROVIDER_IDENTITY_CLAIMS_EMAIL => Attribute::ProviderIdentityClaimsEmail,
            ATTR_PROVIDER_IDENTITY_CLAIMS_EMAIL_VERIFIED => {
                Attribute::ProviderIdentityClaimsEmailVerified
            }
            ATTR_PROVIDER_IDENTITY_CLAIMS_GROUPS => Attribute::ProviderIdentityClaimsGroups,
            ATTR_PROVIDER_IDENTITY_CONSENTS => Attribute::ProviderIdentityConsents,
            ATTR_PROVIDER_IDENTITY_CREATED_AT => Attribute::ProviderIdentityCreatedAt,
            ATTR_PROVIDER_IDENTITY_LAST_LOGIN => Attribute::ProviderIdentityLastLogin,
            ATTR_PROVIDER_IDENTITY_BLOCKED_UNTIL => Attribute::ProviderIdentityBlockedUntil,
            ATTR_OAUTH2_RS_TRUSTED_PEERS => Attribute::Oauth2RsTrustedPeers,
            ATTR_OAUTH2_RS_ALLOWED_CONNECTORS => Attribute::Oauth2RsAllowedConnectors,
            ATTR_CONNECTOR_AUTHPROXY_USER_HEADER => Attribute::ConnectorAuthproxyUserHeader,
            ATTR_CONNECTOR_AUTHPROXY_EMAIL_HEADER => Attribute::ConnectorAuthproxyEmailHeader,
            ATTR_CONNECTOR_AUTHPROXY_GROUPS_HEADER => Attribute::ConnectorAuthproxyGroupsHeader,
            ATTR_CONNECTOR_GITEA_BASE_URL => Attribute::ConnectorGiteaBaseUrl,
            ATTR_CONNECTOR_GITEA_GROUPS => Attribute::ConnectorGiteaGroups,
            ATTR_CONNECTOR_GITEA_INSECURE_CA => Attribute::ConnectorGiteaInsecureCa,
            ATTR_CONNECTOR_GITEA_ROOT_CA => Attribute::ConnectorGiteaRootCa,
            ATTR_CONNECTOR_GITEA_LOAD_ALL_GROUPS => Attribute::ConnectorGiteaLoadAllGroups,
            ATTR_CONNECTOR_GITEA_USE_LOGIN_AS_ID => Attribute::ConnectorGiteaUseLoginAsId,
            ATTR_CONNECTOR_KEYSTONE_HOST => Attribute::ConnectorKeystoneHost,
            ATTR_CONNECTOR_KEYSTONE_DOMAIN => Attribute::ConnectorKeystoneDomain,
            ATTR_CONNECTOR_KEYSTONE_GROUPS => Attribute::ConnectorKeystoneGroups,
            ATTR_CONNECTOR_KEYSTONE_INSECURE_CA => Attribute::ConnectorKeystoneInsecureCa,
            ATTR_CONNECTOR_CROWD_BASE_URL => Attribute::ConnectorCrowdBaseUrl,
            ATTR_CONNECTOR_CROWD_CLIENT_NAME => Attribute::ConnectorCrowdClientName,
            ATTR_CONNECTOR_CROWD_CLIENT_SECRET => Attribute::ConnectorCrowdClientSecret,
            ATTR_CONNECTOR_CROWD_GROUPS => Attribute::ConnectorCrowdGroups,
            ATTR_SAML_SSO_ISSUER => Attribute::SamlSsoIssuer,
            ATTR_SAML_INSECURE_SKIP_SIG_VALIDATION => Attribute::SamlInsecureSkipSigValidation,
            ATTR_SAML_GROUPS_DELIM => Attribute::SamlGroupsDelim,
            ATTR_SAML_ALLOWED_GROUPS => Attribute::SamlAllowedGroups,
            ATTR_SAML_FILTER_GROUPS => Attribute::SamlFilterGroups,

            #[cfg(any(debug_assertions, test, feature = "test"))]
            TEST_ATTR_NON_EXIST => Attribute::NonExist,
            #[cfg(any(debug_assertions, test, feature = "test"))]
            TEST_ATTR_TEST_ATTR => Attribute::TestAttr,

            #[cfg(test)]
            TEST_ATTR_TEST_ATTR_A => Attribute::TestAttrA,
            #[cfg(test)]
            TEST_ATTR_TEST_ATTR_B => Attribute::TestAttrB,
            #[cfg(test)]
            TEST_ATTR_TEST_ATTR_C => Attribute::TestAttrC,
            #[cfg(test)]
            TEST_ATTR_TEST_ATTR_D => Attribute::TestAttrD,

            #[cfg(any(debug_assertions, test, feature = "test"))]
            TEST_ATTR_EXTRA => Attribute::Extra,
            #[cfg(any(debug_assertions, test, feature = "test"))]
            TEST_ATTR_NUMBER => Attribute::TestNumber,
            #[cfg(any(debug_assertions, test, feature = "test"))]
            TEST_ATTR_NOTALLOWED => Attribute::TestNotAllowed,

            #[cfg(not(test))]
            _ => Attribute::Custom(AttrString::from(value)),
            // Allowed only in tests
            #[allow(clippy::unreachable)]
            #[cfg(test)]
            _ => {
                unreachable!(
                    "Check that you've implemented the Attribute conversion for {:?}",
                    value
                );
            }
        }
    }
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<Attribute> for String {
    fn from(attr: Attribute) -> String {
        attr.to_string()
    }
}

/// Sub attributes are a component of SCIM, allowing tagged sub properties of a complex
/// attribute to be accessed.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, ToSchema)]
#[serde(rename_all = "lowercase", try_from = "&str", into = "AttrString")]
pub enum SubAttribute {
    /// Denotes a primary value.
    Primary,
    /// The type of value
    Type,
    /// The data associated to a value
    Value,

    #[cfg(not(test))]
    #[schema(value_type = String)]
    Custom(AttrString),
}

impl fmt::Display for SubAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<SubAttribute> for AttrString {
    fn from(val: SubAttribute) -> Self {
        AttrString::from(val.as_str())
    }
}

impl From<&str> for SubAttribute {
    fn from(value: &str) -> Self {
        Self::inner_from_str(value)
    }
}

impl std::str::FromStr for SubAttribute {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::inner_from_str(value))
    }
}

impl SubAttribute {
    pub fn as_str(&self) -> &str {
        match self {
            SubAttribute::Primary => SUB_ATTR_PRIMARY,
            SubAttribute::Type => SUB_ATTR_TYPE,
            SubAttribute::Value => SUB_ATTR_VALUE,
            #[cfg(not(test))]
            SubAttribute::Custom(s) => s,
        }
    }

    // We allow this because the standard lib from_str is fallible, and we want an infallible version.
    #[allow(clippy::should_implement_trait)]
    fn inner_from_str(value: &str) -> Self {
        // Could this be something like heapless to save allocations? Also gives a way
        // to limit length of str?
        match value.to_lowercase().as_str() {
            SUB_ATTR_PRIMARY => SubAttribute::Primary,
            SUB_ATTR_TYPE => SubAttribute::Type,
            SUB_ATTR_VALUE => SubAttribute::Value,

            #[cfg(not(test))]
            _ => SubAttribute::Custom(AttrString::from(value)),

            // Allowed only in tests
            #[allow(clippy::unreachable)]
            #[cfg(test)]
            _ => {
                unreachable!(
                    "Check that you've implemented the SubAttribute conversion for {:?}",
                    value
                );
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::Attribute;

    #[test]
    fn test_valueattribute_from_str() {
        assert_eq!(Attribute::Uuid, Attribute::from("UUID".to_owned()));
        assert_eq!(Attribute::Uuid, Attribute::from("UuiD".to_owned()));
        assert_eq!(Attribute::Uuid, Attribute::from("uuid".to_owned()));
    }

    #[test]
    fn test_valueattribute_as_str() {
        assert_eq!(Attribute::Class.as_str(), "class");
        assert_eq!(Attribute::Class.to_string(), "class".to_string());
    }

    #[test]
    // this ensures we cover both ends of the conversion to/from string-types
    fn test_valueattribute_round_trip() {
        use enum_iterator::all;
        let the_list = all::<Attribute>().collect::<Vec<_>>();
        for attr in the_list {
            let attr2 = Attribute::from(attr.as_str().to_owned());
            assert!(
                attr == attr2,
                "Round-trip failed for {attr} <=> {attr2} check you've implemented a from and to string"
            );
        }
    }
}
