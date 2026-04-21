//! Access control profiles updated for DL26.
//!
//! * `idm_acp_oauth2_client_admin` gains the two new URL attributes
//!   (`OAuth2RsPostLogoutRedirectUri`, `OAuth2RsBackchannelLogoutUri`) in
//!   its search / modify / create allowlists so admins can manage them via
//!   CLI.
//! * `idm_acp_saml_client_admin` gains `SamlSingleLogoutServiceUrl`
//!   symmetrically.
//! * A new `idm_acp_logout_delivery_read` ACP gives system admins read-only
//!   visibility into the persistent back-channel logout delivery queue.
//!   Nobody has write access — the delivery worker is the sole writer.

use crate::constants::{
    UUID_IDM_ACP_LOGOUT_DELIVERY_READ, UUID_IDM_ACP_OAUTH2_CLIENT_ADMIN,
    UUID_IDM_ACP_SAML_CLIENT_ADMIN, UUID_IDM_OAUTH2_CLIENT_ADMINS, UUID_IDM_SAML_CLIENT_ADMINS,
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

/// ACP for OAuth2 upstream client administration — DL26 adds the two
/// RP-Initiated Logout URL attrs.
pub(crate) static IDM_ACP_OAUTH2_CLIENT_ADMIN_DL26: LazyLock<BuiltinAcp> =
    LazyLock::new(|| BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_oauth2_client_admin",
        uuid: UUID_IDM_ACP_OAUTH2_CLIENT_ADMIN,
        description:
            "Builtin IDM Control for granting oauth2 trust provider administration rights.",
        receiver: BuiltinAcpReceiver::Group(vec![
            UUID_IDM_OAUTH2_CLIENT_ADMINS,
            UUID_SYSTEM_ADMINS,
        ]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::OAuth2Client),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL26.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::Spn,
            Attribute::OAuth2ClientId,
            Attribute::OAuth2ClientSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::OAuth2ClientLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            Attribute::OAuth2RsPostLogoutRedirectUri,
            Attribute::OAuth2RsBackchannelLogoutUri,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::OAuth2ClientId,
            Attribute::OAuth2ClientSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::OAuth2ClientLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            Attribute::OAuth2RsPostLogoutRedirectUri,
            Attribute::OAuth2RsBackchannelLogoutUri,
        ],
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::OAuth2ClientId,
            Attribute::OAuth2ClientSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::OAuth2ClientLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            Attribute::OAuth2RsPostLogoutRedirectUri,
            Attribute::OAuth2RsBackchannelLogoutUri,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::OAuth2ClientId,
            Attribute::OAuth2ClientSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::OAuth2ClientLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            Attribute::OAuth2RsPostLogoutRedirectUri,
            Attribute::OAuth2RsBackchannelLogoutUri,
        ],
        create_classes: vec![EntryClass::Object, EntryClass::OAuth2Client],
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
