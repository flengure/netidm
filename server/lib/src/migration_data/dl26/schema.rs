//! Schema entries for DL26: RP-Initiated Logout plumbing.
//!
//! Adds three URL attributes on existing client classes (OAuth2 post-logout
//! redirect allowlist, OAuth2 back-channel logout endpoint, SAML SP SLO URL),
//! plus two new entry classes:
//!
//!   * [`EntryClass::LogoutDelivery`] — one entry per pending / succeeded /
//!     permanently-failed back-channel logout token delivery. Holds the target
//!     endpoint (frozen at enqueue time), the signed logout token, attempt
//!     bookkeeping, and the terminal status. Administrators list pending /
//!     succeeded / failed records via CLI; the server is the sole writer.
//!   * [`EntryClass::SamlSession`] — one entry per SAML authentication at a
//!     service provider, tying the (user, SP, `<SessionIndex>`, UAT) tuple
//!     together so inbound `<LogoutRequest>` correlation can find the netidm
//!     session to terminate.

#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_ATTEMPTS, UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_CREATED,
    UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_ENDPOINT, UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_NEXT_ATTEMPT,
    UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_RP, UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_STATUS,
    UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_TOKEN, UUID_SCHEMA_ATTR_OAUTH2_RS_BACKCHANNEL_LOGOUT_URI,
    UUID_SCHEMA_ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI, UUID_SCHEMA_ATTR_SAML_SESSION_CREATED,
    UUID_SCHEMA_ATTR_SAML_SESSION_INDEX, UUID_SCHEMA_ATTR_SAML_SESSION_SP,
    UUID_SCHEMA_ATTR_SAML_SESSION_UAT_UUID, UUID_SCHEMA_ATTR_SAML_SESSION_USER,
    UUID_SCHEMA_ATTR_SAML_SINGLE_LOGOUT_SERVICE_URL, UUID_SCHEMA_CLASS_LOGOUT_DELIVERY,
    UUID_SCHEMA_CLASS_OAUTH2_CLIENT, UUID_SCHEMA_CLASS_PERSON, UUID_SCHEMA_CLASS_SAML_CLIENT,
    UUID_SCHEMA_CLASS_SAML_SESSION,
};
use crate::prelude::*;

/// Allowlist of URIs an OAuth2 relying party may name as its
/// `post_logout_redirect_uri` on an OIDC end-session request. Exact-match
/// semantics — any URI presented in the request must equal one entry to be
/// honoured. Multi-value URL.
pub static SCHEMA_ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI,
        name: Attribute::OAuth2RsPostLogoutRedirectUri,
        description: "Allowlist of post-logout redirect URIs the relying party may name in \
                      an OIDC end_session_endpoint request. Exact match only."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

/// OAuth2 relying party's back-channel logout endpoint. Netidm POSTs a signed
/// logout token here when a session bound to this RP terminates. Single-value
/// URL — absence means the RP does not want back-channel logout notifications.
pub static SCHEMA_ATTR_OAUTH2_RS_BACKCHANNEL_LOGOUT_URI_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_BACKCHANNEL_LOGOUT_URI,
        name: Attribute::OAuth2RsBackchannelLogoutUri,
        description: "URL netidm POSTs a signed OIDC Back-Channel Logout token to when a \
                      session bound to this relying party terminates."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

/// SAML service provider's Single Logout Service URL. Absence means SLO is not
/// configured for this SP; inbound `<LogoutRequest>` signed by a recognised
/// key is still honoured because SLO is a profile of the SP-to-IdP
/// relationship. Single-value URL.
pub static SCHEMA_ATTR_SAML_SINGLE_LOGOUT_SERVICE_URL_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_SINGLE_LOGOUT_SERVICE_URL,
        name: Attribute::SamlSingleLogoutServiceUrl,
        description: "The SAML service provider's Single Logout Service endpoint URL, \
                      advertised back to the SP in the IdP metadata."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

/// Target URL for one back-channel logout delivery. Frozen at enqueue time so
/// subsequent re-config of the relying party's back-channel URI does not
/// affect deliveries already in flight.
pub static SCHEMA_ATTR_LOGOUT_DELIVERY_ENDPOINT_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_ENDPOINT,
        name: Attribute::LogoutDeliveryEndpoint,
        description: "Target URL for one back-channel logout delivery, frozen at enqueue time."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

/// Signed OIDC Back-Channel Logout token (JWS compact form) to POST.
pub static SCHEMA_ATTR_LOGOUT_DELIVERY_TOKEN_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_TOKEN,
        name: Attribute::LogoutDeliveryToken,
        description: "The signed OIDC Back-Channel Logout token (JWS compact form) \
                      that netidm will POST to the delivery endpoint."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Terminal state of one back-channel delivery: `pending` | `succeeded` |
/// `failed`. Schema-level validation is by-convention via `FromStr`; the
/// server never writes other values.
pub static SCHEMA_ATTR_LOGOUT_DELIVERY_STATUS_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_STATUS,
        name: Attribute::LogoutDeliveryStatus,
        description: "Status of one back-channel logout delivery: pending, succeeded, or failed."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// How many delivery attempts have been made so far (0 at enqueue).
pub static SCHEMA_ATTR_LOGOUT_DELIVERY_ATTEMPTS_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_ATTEMPTS,
        name: Attribute::LogoutDeliveryAttempts,
        description: "Number of delivery attempts made so far (0 at enqueue).".to_string(),
        multivalue: false,
        syntax: SyntaxType::Uint32,
        ..Default::default()
    });

/// When the worker should next attempt this delivery.
pub static SCHEMA_ATTR_LOGOUT_DELIVERY_NEXT_ATTEMPT_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_NEXT_ATTEMPT,
        name: Attribute::LogoutDeliveryNextAttempt,
        description: "Timestamp at which the delivery worker should next attempt this record."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::DateTime,
        ..Default::default()
    });

/// Enqueue time. Immutable.
pub static SCHEMA_ATTR_LOGOUT_DELIVERY_CREATED_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_CREATED,
        name: Attribute::LogoutDeliveryCreated,
        description: "Timestamp at which this delivery record was enqueued.".to_string(),
        multivalue: false,
        syntax: SyntaxType::DateTime,
        ..Default::default()
    });

/// Reference to the relying party that minted the tokens this delivery
/// pertains to. For admin filtering and debug; source of truth is the JWT
/// `aud` claim embedded in [`Attribute::LogoutDeliveryToken`].
pub static SCHEMA_ATTR_LOGOUT_DELIVERY_RP_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_RP,
        name: Attribute::LogoutDeliveryRp,
        description: "UUID of the relying party this delivery pertains to; admin-visible."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::ReferenceUuid,
        ..Default::default()
    });

/// The user whose session produced this SAML assertion.
pub static SCHEMA_ATTR_SAML_SESSION_USER_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_SESSION_USER,
        name: Attribute::SamlSessionUser,
        description: "UUID of the user whose authentication produced this SAML session."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::ReferenceUuid,
        ..Default::default()
    });

/// The SAML service provider this session was created for.
pub static SCHEMA_ATTR_SAML_SESSION_SP_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_SESSION_SP,
        name: Attribute::SamlSessionSp,
        description: "UUID of the SAML service provider this session was created for.".to_string(),
        multivalue: false,
        syntax: SyntaxType::ReferenceUuid,
        ..Default::default()
    });

/// The `<SessionIndex>` value emitted on the matching `<AuthnStatement>`.
/// Opaque to the SP; netidm uses a UUID-v4 string.
pub static SCHEMA_ATTR_SAML_SESSION_INDEX_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_SESSION_INDEX,
        name: Attribute::SamlSessionIndex,
        description: "The <SessionIndex> value emitted on the SAML AuthnStatement for this \
                      session. Opaque to the SP; netidm uses a UUID-v4 string."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// Reference to the netidm UAT that backs this SAML session.
pub static SCHEMA_ATTR_SAML_SESSION_UAT_UUID_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_SESSION_UAT_UUID,
        name: Attribute::SamlSessionUatUuid,
        description: "UUID of the netidm UAT that backs this SAML session; logout \
                      correlation runs `terminate_session` on this UAT."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Uuid,
        ..Default::default()
    });

/// Emission time of the SAML assertion that created this session.
pub static SCHEMA_ATTR_SAML_SESSION_CREATED_DL26: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_SESSION_CREATED,
        name: Attribute::SamlSessionCreated,
        description: "Timestamp at which this SAML session was issued.".to_string(),
        multivalue: false,
        syntax: SyntaxType::DateTime,
        ..Default::default()
    });

/// OAuth2 client class updated for DL26: adds the two new URL attributes to
/// `systemmay` (post-logout redirect allowlist and back-channel logout URI).
/// Every systemmay entry carried forward from DL25.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL26: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
        Attribute::OAuth2RsPostLogoutRedirectUri,
        Attribute::OAuth2RsBackchannelLogoutUri,
    ],
    ..Default::default()
});

/// SAML client class updated for DL26: adds `SamlSingleLogoutServiceUrl` to
/// `systemmay`. Every systemmay entry carried forward from DL25.
pub static SCHEMA_CLASS_SAML_CLIENT_DL26: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SAML_CLIENT,
    name: EntryClass::SamlClient.into(),
    description: "A SAML 2.0 Identity Provider configuration used for SP-initiated SSO."
        .to_string(),
    systemmust: vec![
        Attribute::Name,
        Attribute::DisplayName,
        Attribute::SamlIdpSsoUrl,
        Attribute::SamlIdpCertificate,
        Attribute::SamlEntityId,
        Attribute::SamlAcsUrl,
    ],
    systemmay: vec![
        Attribute::SamlNameIdFormat,
        Attribute::SamlAttrMapEmail,
        Attribute::SamlAttrMapDisplayname,
        Attribute::SamlAttrMapGroups,
        Attribute::SamlJitProvisioning,
        Attribute::SamlGroupMapping,
        Attribute::SamlSingleLogoutServiceUrl,
    ],
    ..Default::default()
});

/// Person class carried forward from DL25. Included so the DL26 `phase_2`
/// batch presents the full set of updated classes; no DL26 changes to Person.
pub static SCHEMA_CLASS_PERSON_DL26: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_PERSON,
    name: EntryClass::Person.into(),
    description: "Object representation of a person".to_string(),

    sync_allowed: true,
    systemmay: vec![
        Attribute::PrimaryCredential,
        Attribute::PassKeys,
        Attribute::AttestedPasskeys,
        Attribute::CredentialUpdateIntentToken,
        Attribute::SshPublicKey,
        Attribute::RadiusSecret,
        Attribute::OAuth2ConsentScopeMap,
        Attribute::UserAuthTokenSession,
        Attribute::OAuth2Session,
        Attribute::Mail,
        Attribute::LegalName,
        Attribute::ApplicationPassword,
        Attribute::PasswordChangedTime,
        Attribute::OAuth2UpstreamSyncedGroup,
    ],
    systemmust: vec![Attribute::Name],
    systemexcludes: vec![
        EntryClass::ServiceAccount.into(),
        EntryClass::Application.into(),
    ],
    ..Default::default()
});

/// Persistent back-channel logout delivery queue entry. One per pending /
/// succeeded / permanently-failed delivery attempt.
pub static SCHEMA_CLASS_LOGOUT_DELIVERY_DL26: LazyLock<SchemaClass> =
    LazyLock::new(|| SchemaClass {
        uuid: UUID_SCHEMA_CLASS_LOGOUT_DELIVERY,
        name: EntryClass::LogoutDelivery.into(),
        description: "A single back-channel logout delivery record: target endpoint, signed \
                      logout token payload, attempt bookkeeping, and terminal status."
            .to_string(),
        systemmust: vec![
            Attribute::LogoutDeliveryEndpoint,
            Attribute::LogoutDeliveryToken,
            Attribute::LogoutDeliveryStatus,
            Attribute::LogoutDeliveryAttempts,
            Attribute::LogoutDeliveryNextAttempt,
            Attribute::LogoutDeliveryCreated,
            Attribute::LogoutDeliveryRp,
        ],
        systemmay: vec![],
        ..Default::default()
    });

/// Per-SP SAML session index entry. One per (user, SP, SessionIndex) tuple;
/// consulted when an inbound `<LogoutRequest>` arrives.
pub static SCHEMA_CLASS_SAML_SESSION_DL26: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SAML_SESSION,
    name: EntryClass::SamlSession.into(),
    description: "A per-SP SAML session index entry. Populated at SAML auth time; consulted \
                      on inbound <LogoutRequest> to correlate the request to a netidm session."
        .to_string(),
    systemmust: vec![
        Attribute::SamlSessionUser,
        Attribute::SamlSessionIndex,
        Attribute::SamlSessionUatUuid,
        Attribute::SamlSessionCreated,
    ],
    systemmay: vec![Attribute::SamlSessionSp],
    ..Default::default()
});
