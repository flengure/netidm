//! DL39 migration phases.
//!
//! DL39 introduces OpenStack Keystone connector support:
//!   * Four Keystone config attrs on `EntryClass::Connector`
//!     (`ConnectorKeystoneHost`, `ConnectorKeystoneDomain`,
//!     `ConnectorKeystoneGroups`, `ConnectorKeystoneInsecureCa`)
//!   * Updated `idm_acp_oauth2_client_admin` covering the new attrs

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use super::dl25::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl38::phase_1_schema_attrs();
    attrs.push(SCHEMA_ATTR_CONNECTOR_KEYSTONE_HOST_DL39.clone().into());
    attrs.push(SCHEMA_ATTR_CONNECTOR_KEYSTONE_DOMAIN_DL39.clone().into());
    attrs.push(SCHEMA_ATTR_CONNECTOR_KEYSTONE_GROUPS_DL39.clone().into());
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_KEYSTONE_INSECURE_CA_DL39
            .clone()
            .into(),
    );
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl38::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_CONNECTOR_DL39.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl38::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl38::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl38::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl38::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl38::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL39.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl38::phase_8_delete_uuids()
}
