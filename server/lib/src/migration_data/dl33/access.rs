//! Access control profiles updated for DL33.
//!
//! `idm_acp_saml_client_admin` gains the five new DL33 SAML dex-parity
//! attributes in its search / modify / create allowlists.
//!
//! Forked from `IDM_ACP_SAML_CLIENT_ADMIN_DL26`; unchanged except for
//! the new attribute additions.

use crate::constants::{
    UUID_IDM_ACP_SAML_CLIENT_ADMIN, UUID_IDM_SAML_CLIENT_ADMINS, UUID_SYSTEM_ADMINS,
};
use crate::prelude::*;

pub(crate) use crate::migration_data::dl21::access::{
    BuiltinAcp, BuiltinAcpReceiver, BuiltinAcpTarget,
};

static FILTER_RECYCLED_OR_TOMBSTONE_DL33: LazyLock<ProtoFilter> = LazyLock::new(|| {
    ProtoFilter::Or(vec![
        match_class_filter!(EntryClass::Recycled),
        match_class_filter!(EntryClass::Tombstone),
    ])
});

static FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL33: LazyLock<ProtoFilter> =
    LazyLock::new(|| ProtoFilter::AndNot(Box::new(FILTER_RECYCLED_OR_TOMBSTONE_DL33.clone())));

/// DL33 refresh of `idm_acp_saml_client_admin`. Forks DL26 and adds the
/// five SAML dex-parity config attributes introduced by PR-CONNECTOR-SAML.
pub(crate) static IDM_ACP_SAML_CLIENT_ADMIN_DL33: LazyLock<BuiltinAcp> =
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
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL33.clone(),
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
            // DL33 additions — PR-CONNECTOR-SAML
            Attribute::SamlSsoIssuer,
            Attribute::SamlInsecureSkipSigValidation,
            Attribute::SamlGroupsDelim,
            Attribute::SamlAllowedGroups,
            Attribute::SamlFilterGroups,
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
            // DL33 additions — PR-CONNECTOR-SAML
            Attribute::SamlSsoIssuer,
            Attribute::SamlInsecureSkipSigValidation,
            Attribute::SamlGroupsDelim,
            Attribute::SamlAllowedGroups,
            Attribute::SamlFilterGroups,
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
            // DL33 additions — PR-CONNECTOR-SAML
            Attribute::SamlSsoIssuer,
            Attribute::SamlInsecureSkipSigValidation,
            Attribute::SamlGroupsDelim,
            Attribute::SamlAllowedGroups,
            Attribute::SamlFilterGroups,
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
            // DL33 additions — PR-CONNECTOR-SAML
            Attribute::SamlSsoIssuer,
            Attribute::SamlInsecureSkipSigValidation,
            Attribute::SamlGroupsDelim,
            Attribute::SamlAllowedGroups,
            Attribute::SamlFilterGroups,
        ],
        create_classes: vec![EntryClass::Object, EntryClass::SamlClient],
        ..Default::default()
    });
