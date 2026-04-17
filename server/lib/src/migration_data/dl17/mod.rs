pub(crate) mod schema;

// Re-export accounts from the last DL that introduced new accounts.
#[cfg(test)]
pub(crate) use super::dl14::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl16::phase_1_schema_attrs();
    attrs.extend([
        SCHEMA_ATTR_WG_LAST_SEEN_DL17.clone().into(),
        SCHEMA_ATTR_WG_TOKEN_SECRET_DL17.clone().into(),
        SCHEMA_ATTR_WG_TOKEN_USES_LEFT_DL17.clone().into(),
        SCHEMA_ATTR_WG_TOKEN_EXPIRY_DL17.clone().into(),
        SCHEMA_ATTR_WG_TOKEN_PRINCIPAL_REF_DL17.clone().into(),
    ]);
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl16::phase_2_schema_classes();
    classes.extend([SCHEMA_CLASS_WG_TOKEN_DL17.clone().into()]);
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl16::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl16::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, kanidm_proto::internal::OperationError> {
    super::dl16::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, kanidm_proto::internal::OperationError> {
    super::dl16::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    super::dl16::phase_7_builtin_access_control_profiles()
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl16::phase_8_delete_uuids()
}
