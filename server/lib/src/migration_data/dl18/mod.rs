pub(crate) mod schema;

#[cfg(test)]
pub(crate) use super::dl14::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl17::phase_1_schema_attrs();
    attrs.extend([
        SCHEMA_ATTR_OAUTH2_EMAIL_LINK_ACCOUNTS_DL18.clone().into(),
        SCHEMA_ATTR_OAUTH2_DOMAIN_EMAIL_LINK_ACCOUNTS_DL18
            .clone()
            .into(),
    ]);
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl17::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_OAUTH2_CLIENT_DL18.clone().into());
    classes.push(SCHEMA_CLASS_DOMAIN_INFO_DL18.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl17::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl17::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl17::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl17::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    super::dl17::phase_7_builtin_access_control_profiles()
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl17::phase_8_delete_uuids()
}
