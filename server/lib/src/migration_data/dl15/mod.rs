pub(crate) mod schema;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl14::phase_1_schema_attrs();
    attrs.extend([
        SCHEMA_ATTR_OAUTH2_USERINFO_ENDPOINT_DL15.clone().into(),
        SCHEMA_ATTR_OAUTH2_JIT_PROVISIONING_DL15.clone().into(),
        SCHEMA_ATTR_OAUTH2_CLAIM_MAP_NAME_DL15.clone().into(),
        SCHEMA_ATTR_OAUTH2_CLAIM_MAP_DISPLAYNAME_DL15.clone().into(),
        SCHEMA_ATTR_OAUTH2_CLAIM_MAP_EMAIL_DL15.clone().into(),
    ]);
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl14::phase_2_schema_classes();
    // Replace OAuth2Client with the DL15 version that has the new systemmay attributes.
    classes.push(SCHEMA_CLASS_OAUTH2_CLIENT_DL15.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl14::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl14::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl14::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl14::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    super::dl14::phase_7_builtin_access_control_profiles()
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl14::phase_8_delete_uuids()
}
