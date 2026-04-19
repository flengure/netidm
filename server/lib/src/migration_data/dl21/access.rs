//! Updated access control profiles for DL21.
//!
//! Extends `idm_acp_oauth2_client_admin` with the new DL21 attributes
//! (`OAuth2Issuer`, `OAuth2JwksUri`) and fills gaps left by earlier DLs
//! (`DisplayName`, `OAuth2UserinfoEndpoint`, `OAuth2ClientLogoUri`).

use crate::constants::{
    UUID_IDM_ACP_OAUTH2_CLIENT_ADMIN, UUID_IDM_OAUTH2_CLIENT_ADMINS, UUID_SYSTEM_ADMINS,
};
use crate::prelude::*;

static FILTER_RECYCLED_OR_TOMBSTONE_DL21: LazyLock<ProtoFilter> = LazyLock::new(|| {
    ProtoFilter::Or(vec![
        match_class_filter!(EntryClass::Recycled),
        match_class_filter!(EntryClass::Tombstone),
    ])
});

static FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL21: LazyLock<ProtoFilter> =
    LazyLock::new(|| ProtoFilter::AndNot(Box::new(FILTER_RECYCLED_OR_TOMBSTONE_DL21.clone())));

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub(crate) enum BuiltinAcpReceiver {
    #[default]
    None,
    Group(Vec<Uuid>),
    EntryManager,
}

#[derive(Clone, Debug, Default)]
pub(crate) enum BuiltinAcpTarget {
    #[default]
    None,
    Filter(ProtoFilter),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BuiltinAcp {
    pub(crate) classes: Vec<EntryClass>,
    pub(crate) name: &'static str,
    pub(crate) uuid: Uuid,
    pub(crate) description: &'static str,
    pub(crate) receiver: BuiltinAcpReceiver,
    pub(crate) target: BuiltinAcpTarget,
    pub(crate) search_attrs: Vec<Attribute>,
    pub(crate) modify_present_attrs: Vec<Attribute>,
    pub(crate) modify_removed_attrs: Vec<Attribute>,
    pub(crate) modify_classes: Vec<EntryClass>,
    pub(crate) modify_present_classes: Vec<EntryClass>,
    pub(crate) modify_remove_classes: Vec<EntryClass>,
    pub(crate) create_classes: Vec<EntryClass>,
    pub(crate) create_attrs: Vec<Attribute>,
}

impl From<BuiltinAcp> for EntryInitNew {
    #[allow(clippy::panic)]
    fn from(value: BuiltinAcp) -> Self {
        let mut entry = EntryInitNew::default();

        if value.name.is_empty() {
            panic!("Builtin ACP has no name! {value:?}");
        }
        if value.classes.is_empty() {
            panic!("Builtin ACP has no classes! {value:?}");
        }

        value.classes.iter().for_each(|class| {
            entry.add_ava(Attribute::Class, class.to_value());
        });

        entry.set_ava(Attribute::Name, [Value::new_iname(value.name)]);

        if value.uuid >= DYNAMIC_RANGE_MINIMUM_UUID {
            panic!("Builtin ACP has invalid UUID! {value:?}");
        }

        entry.set_ava(Attribute::Uuid, [Value::Uuid(value.uuid)]);
        entry.set_ava(
            Attribute::Description,
            [Value::new_utf8s(value.description)],
        );

        match &value.receiver {
            #[allow(clippy::panic)]
            BuiltinAcpReceiver::None => {
                panic!("Builtin ACP has no receiver! {:?}", &value);
            }
            BuiltinAcpReceiver::Group(list) => {
                entry.add_ava(
                    Attribute::Class,
                    EntryClass::AccessControlReceiverGroup.to_value(),
                );
                for group in list {
                    entry.set_ava(Attribute::AcpReceiverGroup, [Value::Refer(*group)]);
                }
            }
            BuiltinAcpReceiver::EntryManager => {
                entry.add_ava(
                    Attribute::Class,
                    EntryClass::AccessControlReceiverEntryManager.to_value(),
                );
            }
        };

        match &value.target {
            #[allow(clippy::panic)]
            BuiltinAcpTarget::None => {
                panic!("Builtin ACP has no target! {:?}", &value);
            }
            BuiltinAcpTarget::Filter(proto_filter) => {
                entry.add_ava(
                    Attribute::Class,
                    EntryClass::AccessControlTargetScope.to_value(),
                );
                entry.set_ava(
                    Attribute::AcpTargetScope,
                    [Value::JsonFilt(proto_filter.clone())],
                );
            }
        }

        entry.set_ava(
            Attribute::AcpSearchAttr,
            value
                .search_attrs
                .into_iter()
                .map(Value::from)
                .collect::<Vec<Value>>(),
        );
        value.modify_present_attrs.into_iter().for_each(|attr| {
            entry.add_ava(Attribute::AcpModifyPresentAttr, Value::from(attr));
        });
        value.modify_removed_attrs.into_iter().for_each(|attr| {
            entry.add_ava(Attribute::AcpModifyRemovedAttr, Value::from(attr));
        });
        value.modify_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpModifyClass, Value::from(class));
        });
        value.modify_present_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpModifyPresentClass, Value::from(class));
        });
        value.modify_remove_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpModifyRemoveClass, Value::from(class));
        });
        value.create_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpCreateClass, Value::from(class));
        });
        value.create_attrs.into_iter().for_each(|attr| {
            entry.add_ava(Attribute::AcpCreateAttr, Value::from(attr));
        });
        entry
    }
}

pub(crate) static IDM_ACP_OAUTH2_CLIENT_ADMIN_DL21: LazyLock<BuiltinAcp> =
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
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL21.clone(),
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
        ],
        create_classes: vec![EntryClass::Object, EntryClass::OAuth2Client],
        ..Default::default()
    });
