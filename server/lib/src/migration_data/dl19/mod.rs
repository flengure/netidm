pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use super::dl14::accounts;

use self::access::*;
use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl18::phase_1_schema_attrs();
    attrs.push(SCHEMA_ATTR_SKIP_AUTH_ROUTE_DL19.clone().into());
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl18::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_SYSTEM_CONFIG_DL19.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl18::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl18::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl18::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl18::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl18::phase_7_builtin_access_control_profiles();
    acps.push(
        IDM_ACP_SYSTEM_CONFIG_SKIP_AUTH_ROUTE_MANAGE_DL19
            .clone()
            .into(),
    );
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl18::phase_8_delete_uuids()
}
