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
    #[strum(serialize = "oauth2_client_id")]
    OAuth2ClientId,
    #[strum(serialize = "oauth2_client_logo_uri")]
    OAuth2ClientLogoUri,
    #[strum(serialize = "oauth2_client_secret")]
    OAuth2ClientSecret,
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
    // `EntryClass::OAuth2Client`. All optional with documented defaults.
    // See `specs/012-github-connector/data-model.md`.
    #[strum(serialize = "oauth2_client_provider_kind")]
    OAuth2ClientProviderKind,
    #[strum(serialize = "oauth2_client_github_host")]
    OAuth2ClientGithubHost,
    #[strum(serialize = "oauth2_client_github_org_filter")]
    OAuth2ClientGithubOrgFilter,
    #[strum(serialize = "oauth2_client_github_allowed_teams")]
    OAuth2ClientGithubAllowedTeams,
    #[strum(serialize = "oauth2_client_github_team_name_field")]
    OAuth2ClientGithubTeamNameField,
    #[strum(serialize = "oauth2_client_github_load_all_groups")]
    OAuth2ClientGithubLoadAllGroups,
    #[strum(serialize = "oauth2_client_github_preferred_email_domain")]
    OAuth2ClientGithubPreferredEmailDomain,
    #[strum(serialize = "oauth2_client_github_allow_jit_provisioning")]
    OAuth2ClientGithubAllowJitProvisioning,
    // DL29 — Generic OIDC upstream connector config attributes.
    // All optional on `EntryClass::OAuth2Client`; absent = default shown in spec.
    #[strum(serialize = "oauth2_client_oidc_enable_groups")]
    OAuth2ClientOidcEnableGroups,
    #[strum(serialize = "oauth2_client_oidc_groups_key")]
    OAuth2ClientOidcGroupsKey,
    #[strum(serialize = "oauth2_client_oidc_skip_email_verified")]
    OAuth2ClientOidcSkipEmailVerified,
    #[strum(serialize = "oauth2_client_oidc_allowed_groups")]
    OAuth2ClientOidcAllowedGroups,
    #[strum(serialize = "oauth2_client_oidc_get_user_info")]
    OAuth2ClientOidcGetUserInfo,
    #[strum(serialize = "oauth2_client_oidc_user_id_key")]
    OAuth2ClientOidcUserIdKey,
    #[strum(serialize = "oauth2_client_oidc_user_name_key")]
    OAuth2ClientOidcUserNameKey,
    #[strum(serialize = "oauth2_client_oidc_override_claim_mapping")]
    OAuth2ClientOidcOverrideClaimMapping,
    #[strum(serialize = "oauth2_client_oidc_groups_prefix")]
    OAuth2ClientOidcGroupsPrefix,
    #[strum(serialize = "oauth2_client_oidc_groups_suffix")]
    OAuth2ClientOidcGroupsSuffix,
    // DL30 — Google upstream connector config attributes.
    // All optional on `EntryClass::OAuth2Client`.
    #[strum(serialize = "oauth2_client_google_hosted_domain")]
    OAuth2ClientGoogleHostedDomain,
    #[strum(serialize = "oauth2_client_google_service_account_json")]
    OAuth2ClientGoogleServiceAccountJson,
    #[strum(serialize = "oauth2_client_google_admin_email")]
    OAuth2ClientGoogleAdminEmail,
    #[strum(serialize = "oauth2_client_google_fetch_groups")]
    OAuth2ClientGoogleFetchGroups,
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
            ATTR_OAUTH2_CLIENT_ID => Attribute::OAuth2ClientId,
            ATTR_OAUTH2_CLIENT_LOGO_URI => Attribute::OAuth2ClientLogoUri,
            ATTR_OAUTH2_CLIENT_SECRET => Attribute::OAuth2ClientSecret,
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
            ATTR_OAUTH2_CLIENT_PROVIDER_KIND => Attribute::OAuth2ClientProviderKind,
            ATTR_OAUTH2_CLIENT_GITHUB_HOST => Attribute::OAuth2ClientGithubHost,
            ATTR_OAUTH2_CLIENT_GITHUB_ORG_FILTER => Attribute::OAuth2ClientGithubOrgFilter,
            ATTR_OAUTH2_CLIENT_GITHUB_ALLOWED_TEAMS => Attribute::OAuth2ClientGithubAllowedTeams,
            ATTR_OAUTH2_CLIENT_GITHUB_TEAM_NAME_FIELD => Attribute::OAuth2ClientGithubTeamNameField,
            ATTR_OAUTH2_CLIENT_GITHUB_LOAD_ALL_GROUPS => Attribute::OAuth2ClientGithubLoadAllGroups,
            ATTR_OAUTH2_CLIENT_GITHUB_PREFERRED_EMAIL_DOMAIN => {
                Attribute::OAuth2ClientGithubPreferredEmailDomain
            }
            ATTR_OAUTH2_CLIENT_GITHUB_ALLOW_JIT_PROVISIONING => {
                Attribute::OAuth2ClientGithubAllowJitProvisioning
            }
            ATTR_OAUTH2_CLIENT_OIDC_ENABLE_GROUPS => Attribute::OAuth2ClientOidcEnableGroups,
            ATTR_OAUTH2_CLIENT_OIDC_GROUPS_KEY => Attribute::OAuth2ClientOidcGroupsKey,
            ATTR_OAUTH2_CLIENT_OIDC_SKIP_EMAIL_VERIFIED => {
                Attribute::OAuth2ClientOidcSkipEmailVerified
            }
            ATTR_OAUTH2_CLIENT_OIDC_ALLOWED_GROUPS => Attribute::OAuth2ClientOidcAllowedGroups,
            ATTR_OAUTH2_CLIENT_OIDC_GET_USER_INFO => Attribute::OAuth2ClientOidcGetUserInfo,
            ATTR_OAUTH2_CLIENT_OIDC_USER_ID_KEY => Attribute::OAuth2ClientOidcUserIdKey,
            ATTR_OAUTH2_CLIENT_OIDC_USER_NAME_KEY => Attribute::OAuth2ClientOidcUserNameKey,
            ATTR_OAUTH2_CLIENT_OIDC_OVERRIDE_CLAIM_MAPPING => {
                Attribute::OAuth2ClientOidcOverrideClaimMapping
            }
            ATTR_OAUTH2_CLIENT_OIDC_GROUPS_PREFIX => Attribute::OAuth2ClientOidcGroupsPrefix,
            ATTR_OAUTH2_CLIENT_OIDC_GROUPS_SUFFIX => Attribute::OAuth2ClientOidcGroupsSuffix,
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
            "saml_idp_sso_url" => Attribute::SamlIdpSsoUrl,
            "saml_idp_certificate" => Attribute::SamlIdpCertificate,
            "saml_entity_id" => Attribute::SamlEntityId,
            "saml_acs_url" => Attribute::SamlAcsUrl,
            "saml_name_id_format" => Attribute::SamlNameIdFormat,
            "saml_attr_map_email" => Attribute::SamlAttrMapEmail,
            "saml_attr_map_displayname" => Attribute::SamlAttrMapDisplayname,
            "saml_attr_map_groups" => Attribute::SamlAttrMapGroups,
            "saml_jit_provisioning" => Attribute::SamlJitProvisioning,

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
