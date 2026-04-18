//! Access control profiles for DL19: dedicated ACP for skip-auth route management.

use crate::constants::{
    STR_UUID_SYSTEM_CONFIG, UUID_DOMAIN_ADMINS,
    UUID_IDM_ACP_SYSTEM_CONFIG_SKIP_AUTH_ROUTE_MANAGE_DL19,
};
use crate::prelude::*;

static FILTER_RECYCLED_OR_TOMBSTONE_DL19: LazyLock<ProtoFilter> = LazyLock::new(|| {
    ProtoFilter::Or(vec![
        match_class_filter!(EntryClass::Recycled),
        match_class_filter!(EntryClass::Tombstone),
    ])
});

static FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL19: LazyLock<ProtoFilter> =
    LazyLock::new(|| ProtoFilter::AndNot(Box::new(FILTER_RECYCLED_OR_TOMBSTONE_DL19.clone())));

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub enum BuiltinAcpReceiver {
    #[default]
    None,
    Group(Vec<Uuid>),
    EntryManager,
}

#[derive(Clone, Debug, Default)]
pub enum BuiltinAcpTarget {
    #[default]
    None,
    Filter(ProtoFilter),
}

#[derive(Clone, Debug, Default)]
pub struct BuiltinAcp {
    classes: Vec<EntryClass>,
    pub name: &'static str,
    uuid: Uuid,
    description: &'static str,
    receiver: BuiltinAcpReceiver,
    target: BuiltinAcpTarget,
    search_attrs: Vec<Attribute>,
    modify_present_attrs: Vec<Attribute>,
    modify_removed_attrs: Vec<Attribute>,
    modify_classes: Vec<EntryClass>,
    modify_present_classes: Vec<EntryClass>,
    modify_remove_classes: Vec<EntryClass>,
    create_classes: Vec<EntryClass>,
    create_attrs: Vec<Attribute>,
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

pub static IDM_ACP_SYSTEM_CONFIG_SKIP_AUTH_ROUTE_MANAGE_DL19: LazyLock<BuiltinAcp> =
    LazyLock::new(|| BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_system_config_skip_auth_route_manage",
        uuid: UUID_IDM_ACP_SYSTEM_CONFIG_SKIP_AUTH_ROUTE_MANAGE_DL19,
        description: "Builtin IDM Control for managing skip-auth route rules in the forward auth gate",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_DOMAIN_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Eq(
                Attribute::Uuid.to_string(),
                STR_UUID_SYSTEM_CONFIG.to_string(),
            ),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL19.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::SkipAuthRoute,
        ],
        modify_removed_attrs: vec![Attribute::SkipAuthRoute],
        modify_present_attrs: vec![Attribute::SkipAuthRoute],
        ..Default::default()
    });
