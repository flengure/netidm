//! Access control profiles updated for DL26.
//!
//! * `idm_acp_oauth2_manage` (the downstream-RS admin ACP, UUID
//!   `UUID_IDM_ACP_OAUTH2_MANAGE_V1`) gains the two new URL attributes
//!   (`OAuth2RsPostLogoutRedirectUri`, `OAuth2RsBackchannelLogoutUri`)
//!   in its search / modify / create allowlists so admins can manage
//!   them via CLI. These attrs live on `EntryClass::OAuth2ResourceServer`
//!   — the downstream relying-party class — because netidm consults them
//!   when issuing OIDC logout responses FOR those RPs. (The upstream
//!   `OAuth2Client` class is unrelated — it's netidm-as-SP federation.)
//! * `idm_acp_saml_client_admin` gains `SamlSingleLogoutServiceUrl`
//!   symmetrically (the SAML client class is used per spec §US4).
//! * A new `idm_acp_logout_delivery_read` ACP gives system admins
//!   read-only visibility into the persistent back-channel logout
//!   delivery queue. Nobody has write access — the delivery worker is
//!   the sole writer.

use crate::constants::{
    UUID_IDM_ACP_LOGOUT_DELIVERY_READ, UUID_IDM_ACP_OAUTH2_MANAGE_V1,
    UUID_IDM_ACP_SAML_CLIENT_ADMIN, UUID_IDM_OAUTH2_ADMINS, UUID_IDM_SAML_CLIENT_ADMINS,
    UUID_SYSTEM_ADMINS,
};
use crate::prelude::*;

pub(crate) use crate::migration_data::dl21::access::{
    BuiltinAcp, BuiltinAcpReceiver, BuiltinAcpTarget,
};

static FILTER_RECYCLED_OR_TOMBSTONE_DL26: LazyLock<ProtoFilter> = LazyLock::new(|| {
    ProtoFilter::Or(vec![
        match_class_filter!(EntryClass::Recycled),
        match_class_filter!(EntryClass::Tombstone),
    ])
});

static FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL26: LazyLock<ProtoFilter> =
    LazyLock::new(|| ProtoFilter::AndNot(Box::new(FILTER_RECYCLED_OR_TOMBSTONE_DL26.clone())));

/// ACP for downstream OAuth2 Resource Server administration — DL26
/// adds the two RP-Initiated Logout URL attrs
/// (`OAuth2RsPostLogoutRedirectUri`, `OAuth2RsBackchannelLogoutUri`)
/// to the search/modify/create allowlists. Forked from DL14's
/// `IDM_ACP_OAUTH2_MANAGE`; unchanged except for the two additions.
pub(crate) static IDM_ACP_OAUTH2_MANAGE_DL26: LazyLock<BuiltinAcp> = LazyLock::new(|| BuiltinAcp {
    classes: vec![
        EntryClass::Object,
        EntryClass::AccessControlProfile,
        EntryClass::AccessControlCreate,
        EntryClass::AccessControlDelete,
        EntryClass::AccessControlModify,
        EntryClass::AccessControlSearch,
    ],
    name: "idm_acp_oauth2_manage",
    uuid: UUID_IDM_ACP_OAUTH2_MANAGE_V1,
    description: "Builtin IDM Control for managing OAuth2 resource server integrations.",
    receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_OAUTH2_ADMINS]),
    target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
        match_class_filter!(EntryClass::OAuth2ResourceServer),
        FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL26.clone(),
    ])),
    search_attrs: vec![
        Attribute::Class,
        Attribute::Description,
        Attribute::DisplayName,
        Attribute::Name,
        Attribute::Uuid,
        Attribute::Spn,
        Attribute::OAuth2Session,
        Attribute::OAuth2RsOrigin,
        Attribute::OAuth2RsOriginLanding,
        Attribute::OAuth2RsScopeMap,
        Attribute::OAuth2RsSupScopeMap,
        Attribute::OAuth2RsBasicSecret,
        Attribute::OAuth2AllowInsecureClientDisablePkce,
        Attribute::OAuth2JwtLegacyCryptoEnable,
        Attribute::OAuth2PreferShortUsername,
        Attribute::OAuth2AllowLocalhostRedirect,
        Attribute::OAuth2RsClaimMap,
        Attribute::Image,
        Attribute::OAuth2StrictRedirectUri,
        Attribute::OAuth2DeviceFlowEnable,
        Attribute::KeyInternalData,
        // DL26 additions
        Attribute::OAuth2RsPostLogoutRedirectUri,
        Attribute::OAuth2RsBackchannelLogoutUri,
    ],
    modify_removed_attrs: vec![
        Attribute::Description,
        Attribute::DisplayName,
        Attribute::Name,
        Attribute::OAuth2Session,
        Attribute::OAuth2RsOrigin,
        Attribute::OAuth2RsOriginLanding,
        Attribute::OAuth2RsScopeMap,
        Attribute::OAuth2RsSupScopeMap,
        Attribute::OAuth2RsBasicSecret,
        Attribute::OAuth2AllowInsecureClientDisablePkce,
        Attribute::OAuth2JwtLegacyCryptoEnable,
        Attribute::OAuth2PreferShortUsername,
        Attribute::OAuth2AllowLocalhostRedirect,
        Attribute::OAuth2RsClaimMap,
        Attribute::Image,
        Attribute::OAuth2StrictRedirectUri,
        Attribute::OAuth2DeviceFlowEnable,
        Attribute::KeyActionRevoke,
        Attribute::KeyActionRotate,
        // DL26 additions
        Attribute::OAuth2RsPostLogoutRedirectUri,
        Attribute::OAuth2RsBackchannelLogoutUri,
    ],
    modify_present_attrs: vec![
        Attribute::Description,
        Attribute::DisplayName,
        Attribute::Name,
        Attribute::OAuth2RsOrigin,
        Attribute::OAuth2RsOriginLanding,
        Attribute::OAuth2RsSupScopeMap,
        Attribute::OAuth2RsScopeMap,
        Attribute::OAuth2AllowInsecureClientDisablePkce,
        Attribute::OAuth2JwtLegacyCryptoEnable,
        Attribute::OAuth2PreferShortUsername,
        Attribute::OAuth2AllowLocalhostRedirect,
        Attribute::OAuth2RsClaimMap,
        Attribute::Image,
        Attribute::OAuth2StrictRedirectUri,
        Attribute::OAuth2DeviceFlowEnable,
        Attribute::KeyActionRevoke,
        Attribute::KeyActionRotate,
        // DL26 additions
        Attribute::OAuth2RsPostLogoutRedirectUri,
        Attribute::OAuth2RsBackchannelLogoutUri,
    ],
    create_attrs: vec![
        Attribute::Class,
        Attribute::Description,
        Attribute::Name,
        Attribute::DisplayName,
        Attribute::OAuth2RsName,
        Attribute::OAuth2RsOrigin,
        Attribute::OAuth2RsOriginLanding,
        Attribute::OAuth2RsSupScopeMap,
        Attribute::OAuth2RsScopeMap,
        Attribute::OAuth2AllowInsecureClientDisablePkce,
        Attribute::OAuth2JwtLegacyCryptoEnable,
        Attribute::OAuth2PreferShortUsername,
        Attribute::OAuth2AllowLocalhostRedirect,
        Attribute::OAuth2RsClaimMap,
        Attribute::Image,
        Attribute::OAuth2StrictRedirectUri,
        Attribute::OAuth2DeviceFlowEnable,
        // DL26 additions
        Attribute::OAuth2RsPostLogoutRedirectUri,
        Attribute::OAuth2RsBackchannelLogoutUri,
    ],
    create_classes: vec![
        EntryClass::Object,
        EntryClass::Account,
        EntryClass::OAuth2ResourceServer,
        EntryClass::OAuth2ResourceServerBasic,
        EntryClass::OAuth2ResourceServerPublic,
    ],
    ..Default::default()
});

/// ACP for SAML upstream client administration — DL26 adds
/// `SamlSingleLogoutServiceUrl`.
pub(crate) static IDM_ACP_SAML_CLIENT_ADMIN_DL26: LazyLock<BuiltinAcp> =
    LazyLock::new(|| BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
            EntryClass::AccessControlDelete,
        ],
        name: "idm_acp_saml_client_admin",
        uuid: UUID_IDM_ACP_SAML_CLIENT_ADMIN,
        description:
            "Builtin IDM Control for granting SAML identity provider administration rights.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_SAML_CLIENT_ADMINS, UUID_SYSTEM_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::SamlClient),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL26.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::Spn,
            Attribute::SamlIdpSsoUrl,
            Attribute::SamlIdpCertificate,
            Attribute::SamlEntityId,
            Attribute::SamlAcsUrl,
            Attribute::SamlNameIdFormat,
            Attribute::SamlAttrMapEmail,
            Attribute::SamlAttrMapDisplayname,
            Attribute::SamlAttrMapGroups,
            Attribute::SamlJitProvisioning,
            Attribute::SamlGroupMapping,
            Attribute::SamlSingleLogoutServiceUrl,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::SamlIdpSsoUrl,
            Attribute::SamlIdpCertificate,
            Attribute::SamlEntityId,
            Attribute::SamlAcsUrl,
            Attribute::SamlNameIdFormat,
            Attribute::SamlAttrMapEmail,
            Attribute::SamlAttrMapDisplayname,
            Attribute::SamlAttrMapGroups,
            Attribute::SamlJitProvisioning,
            Attribute::SamlGroupMapping,
            Attribute::SamlSingleLogoutServiceUrl,
        ],
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::SamlIdpSsoUrl,
            Attribute::SamlIdpCertificate,
            Attribute::SamlEntityId,
            Attribute::SamlAcsUrl,
            Attribute::SamlNameIdFormat,
            Attribute::SamlAttrMapEmail,
            Attribute::SamlAttrMapDisplayname,
            Attribute::SamlAttrMapGroups,
            Attribute::SamlJitProvisioning,
            Attribute::SamlGroupMapping,
            Attribute::SamlSingleLogoutServiceUrl,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::SamlIdpSsoUrl,
            Attribute::SamlIdpCertificate,
            Attribute::SamlEntityId,
            Attribute::SamlAcsUrl,
            Attribute::SamlNameIdFormat,
            Attribute::SamlAttrMapEmail,
            Attribute::SamlAttrMapDisplayname,
            Attribute::SamlAttrMapGroups,
            Attribute::SamlJitProvisioning,
            Attribute::SamlGroupMapping,
            Attribute::SamlSingleLogoutServiceUrl,
        ],
        create_classes: vec![EntryClass::Object, EntryClass::SamlClient],
        ..Default::default()
    });

/// DL26: admin read-only ACP for the persistent back-channel logout delivery
/// queue. System administrators can `search` `LogoutDelivery` entries; there
/// is no modify / create / delete path — the delivery worker is the sole
/// writer to these entries via server-internal ops.
pub(crate) static IDM_ACP_LOGOUT_DELIVERY_READ_DL26: LazyLock<BuiltinAcp> = LazyLock::new(|| {
    BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_logout_delivery_read",
        uuid: UUID_IDM_ACP_LOGOUT_DELIVERY_READ,
        description:
            "Builtin IDM Control granting system admins read-only visibility into the persistent back-channel logout delivery queue.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_SYSTEM_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::LogoutDelivery),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL26.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::LogoutDeliveryEndpoint,
            Attribute::LogoutDeliveryStatus,
            Attribute::LogoutDeliveryAttempts,
            Attribute::LogoutDeliveryNextAttempt,
            Attribute::LogoutDeliveryCreated,
            Attribute::LogoutDeliveryRp,
        ],
        ..Default::default()
    }
});
