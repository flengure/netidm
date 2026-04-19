//! Access control profiles and builtin group for DL22: SAML 2.0 upstream connector.

use crate::constants::{
    UUID_IDM_ACP_SAML_CLIENT_ADMIN, UUID_IDM_SAML_CLIENT_ADMINS, UUID_SYSTEM_ADMINS,
};
use crate::prelude::*;

pub(crate) use crate::migration_data::dl13::groups::BuiltinGroup;
pub(crate) use crate::migration_data::dl21::access::{
    BuiltinAcp, BuiltinAcpReceiver, BuiltinAcpTarget,
};

static FILTER_RECYCLED_OR_TOMBSTONE_DL22: LazyLock<ProtoFilter> = LazyLock::new(|| {
    ProtoFilter::Or(vec![
        match_class_filter!(EntryClass::Recycled),
        match_class_filter!(EntryClass::Tombstone),
    ])
});

static FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL22: LazyLock<ProtoFilter> =
    LazyLock::new(|| ProtoFilter::AndNot(Box::new(FILTER_RECYCLED_OR_TOMBSTONE_DL22.clone())));

/// Builtin group for SAML client administration.
pub(crate) static IDM_GROUP_SAML_CLIENT_ADMINS_DL22: LazyLock<BuiltinGroup> =
    LazyLock::new(|| BuiltinGroup {
        name: "idm_saml_client_admins",
        description: "Builtin SAML Identity Provider Administration Group.",
        uuid: UUID_IDM_SAML_CLIENT_ADMINS,
        entry_managed_by: Some(UUID_SYSTEM_ADMINS),
        members: vec![UUID_SYSTEM_ADMINS],
        ..Default::default()
    });

/// ACP granting SAML client administration rights.
pub(crate) static IDM_ACP_SAML_CLIENT_ADMIN_DL22: LazyLock<BuiltinAcp> =
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
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL22.clone(),
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
        ],
        create_classes: vec![EntryClass::Object, EntryClass::SamlClient],
        ..Default::default()
    });
