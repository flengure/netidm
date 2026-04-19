pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
pub(crate) use super::dl14::accounts;

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use self::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl21::phase_1_schema_attrs();
    attrs.push(SCHEMA_ATTR_SAML_IDP_SSO_URL_DL22.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_IDP_CERTIFICATE_DL22.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_ENTITY_ID_DL22.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_ACS_URL_DL22.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_NAME_ID_FORMAT_DL22.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_ATTR_MAP_EMAIL_DL22.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_ATTR_MAP_DISPLAYNAME_DL22.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_ATTR_MAP_GROUPS_DL22.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_JIT_PROVISIONING_DL22.clone().into());
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl21::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_SAML_CLIENT_DL22.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl21::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl21::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl21::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    let mut entries = super::dl21::phase_6_builtin_non_admin_entries()?;
    entries.push(
        access::IDM_GROUP_SAML_CLIENT_ADMINS_DL22
            .clone()
            .try_into()?,
    );
    Ok(entries)
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl21::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_SAML_CLIENT_ADMIN_DL22.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl21::phase_8_delete_uuids()
}
