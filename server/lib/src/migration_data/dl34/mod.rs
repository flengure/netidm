//! DL34 migration phases.
//!
//! DL34 introduces OpenShift connector dex-parity additions (PR-CONNECTOR-OPENSHIFT):
//!   * Four new optional config attributes on `EntryClass::OAuth2Client`:
//!     `OAuth2ClientOpenshiftIssuer`, `OAuth2ClientOpenshiftGroups`,
//!     `OAuth2ClientOpenshiftInsecureCa`, and `OAuth2ClientOpenshiftRootCa`.
//!   * An extended `idm_acp_oauth2_client_admin` covering the new attrs.
//!
//! No new entry class. No data migration — schema-only. Every other phase
//! delegates to DL33.

pub(crate) mod access;
pub(crate) mod schema;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl33::phase_1_schema_attrs();
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_ISSUER_DL34
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_GROUPS_DL34
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_INSECURE_CA_DL34
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OPENSHIFT_ROOT_CA_DL34
            .clone()
            .into(),
    );
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl33::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_OAUTH2_CLIENT_DL34.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl33::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl33::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl33::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl33::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl33::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL34.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl33::phase_8_delete_uuids()
}
