//! Access control profiles updated for DL25.
//!
//! Adds the new DL25 attributes to the modify / create attribute allowlists
//! on the OAuth2 upstream and SAML upstream admin ACPs:
//!   * `OAuth2GroupMapping`, `OAuth2LinkBy` on `idm_acp_oauth2_client_admin`
//!     (`OAuth2LinkBy` was added to the schema in DL24 but the ACP was never
//!     updated, leaving `set-link-by` silently AccessDenied; fixing it here
//!     alongside the new `OAuth2GroupMapping` keeps both attributes
//!     administrable end-to-end.)
//!   * `SamlGroupMapping` on `idm_acp_saml_client_admin`.

use crate::constants::{
    UUID_IDM_ACP_OAUTH2_CLIENT_ADMIN, UUID_IDM_ACP_SAML_CLIENT_ADMIN,
    UUID_IDM_OAUTH2_CLIENT_ADMINS, UUID_IDM_SAML_CLIENT_ADMINS, UUID_SYSTEM_ADMINS,
};
use crate::prelude::*;

pub(crate) use crate::migration_data::dl21::access::{
    BuiltinAcp, BuiltinAcpReceiver, BuiltinAcpTarget,
};

static FILTER_RECYCLED_OR_TOMBSTONE_DL25: LazyLock<ProtoFilter> = LazyLock::new(|| {
    ProtoFilter::Or(vec![
        match_class_filter!(EntryClass::Recycled),
        match_class_filter!(EntryClass::Tombstone),
    ])
});

static FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL25: LazyLock<ProtoFilter> =
    LazyLock::new(|| ProtoFilter::AndNot(Box::new(FILTER_RECYCLED_OR_TOMBSTONE_DL25.clone())));

/// ACP for OAuth2 upstream client administration — DL25 adds `OAuth2LinkBy`
/// (omitted in DL24's schema-only change) and the new `OAuth2GroupMapping`.
pub(crate) static IDM_ACP_OAUTH2_CLIENT_ADMIN_DL25: LazyLock<BuiltinAcp> =
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
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL25.clone(),
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
        ],
        create_classes: vec![EntryClass::Object, EntryClass::OAuth2Client],
        ..Default::default()
    });

/// ACP for SAML upstream client administration — DL25 adds `SamlGroupMapping`.
pub(crate) static IDM_ACP_SAML_CLIENT_ADMIN_DL25: LazyLock<BuiltinAcp> =
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
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL25.clone(),
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
        ],
        create_classes: vec![EntryClass::Object, EntryClass::SamlClient],
        ..Default::default()
    });
