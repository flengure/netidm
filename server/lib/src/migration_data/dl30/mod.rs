//! DL30 migration phases.
//!
//! DL30 introduces the Google upstream connector (PR-CONNECTOR-GOOGLE):
//!   * Four Google-specific config attributes on `EntryClass::Connector`
//!     (hosted_domain, service_account_json, admin_email, fetch_groups).
//!   * An extended `idm_acp_connector_admin` covering the new attrs.
//!
//! No new entry class. No new ACP class. All new attributes are optional.
//! Every other phase delegates to DL29.

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use super::dl25::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl29::phase_1_schema_attrs();
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_GOOGLE_HOSTED_DOMAIN_DL30
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_GOOGLE_SERVICE_ACCOUNT_JSON_DL30
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_GOOGLE_ADMIN_EMAIL_DL30
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_GOOGLE_FETCH_GROUPS_DL30
            .clone()
            .into(),
    );
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl29::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_OAUTH2_CLIENT_DL30.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl29::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl29::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl29::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl29::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl29::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL30.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl29::phase_8_delete_uuids()
}
