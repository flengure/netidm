pub(crate) mod schema;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl15::phase_1_schema_attrs();
    attrs.extend([
        SCHEMA_ATTR_WG_INTERFACE_DL16.clone().into(),
        SCHEMA_ATTR_WG_LISTEN_PORT_DL16.clone().into(),
        SCHEMA_ATTR_WG_ADDRESS_DL16.clone().into(),
        SCHEMA_ATTR_WG_DNS_DL16.clone().into(),
        SCHEMA_ATTR_WG_MTU_DL16.clone().into(),
        SCHEMA_ATTR_WG_TABLE_DL16.clone().into(),
        SCHEMA_ATTR_WG_PRE_UP_DL16.clone().into(),
        SCHEMA_ATTR_WG_POST_UP_DL16.clone().into(),
        SCHEMA_ATTR_WG_PRE_DOWN_DL16.clone().into(),
        SCHEMA_ATTR_WG_POST_DOWN_DL16.clone().into(),
        SCHEMA_ATTR_WG_SAVE_CONFIG_DL16.clone().into(),
        SCHEMA_ATTR_WG_PUBLIC_KEY_DL16.clone().into(),
        SCHEMA_ATTR_WG_ENDPOINT_DL16.clone().into(),
        SCHEMA_ATTR_WG_PUBKEY_DL16.clone().into(),
        SCHEMA_ATTR_WG_ALLOWED_IPS_DL16.clone().into(),
        SCHEMA_ATTR_WG_PRESHARED_KEY_DL16.clone().into(),
        SCHEMA_ATTR_WG_PERSISTENT_KEEPALIVE_DL16.clone().into(),
        SCHEMA_ATTR_WG_TUNNEL_REF_DL16.clone().into(),
        SCHEMA_ATTR_WG_USER_REF_DL16.clone().into(),
        SCHEMA_ATTR_WG_PRIVATE_KEY_DL16.clone().into(),
    ]);
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl15::phase_2_schema_classes();
    classes.extend([
        SCHEMA_CLASS_WG_TUNNEL_DL16.clone().into(),
        SCHEMA_CLASS_WG_PEER_DL16.clone().into(),
    ]);
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl15::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl15::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl15::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl15::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    super::dl15::phase_7_builtin_access_control_profiles()
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl15::phase_8_delete_uuids()
}
