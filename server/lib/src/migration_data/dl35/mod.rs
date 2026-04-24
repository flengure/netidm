//! DL35 migration phases.
//!
//! DL35 introduces GitLab connector dex-parity additions (PR-CONNECTOR-GITLAB):
//!   * Five new optional config attributes on `EntryClass::OAuth2Client`:
//!     `OAuth2ClientGitlabBaseUrl`, `OAuth2ClientGitlabGroups`,
//!     `OAuth2ClientGitlabUseLoginAsId`, `OAuth2ClientGitlabGetGroupsPermission`,
//!     and `OAuth2ClientGitlabRootCa`.
//!   * An extended `idm_acp_oauth2_client_admin` covering the new attrs.
//!
//! No new entry class. No data migration — schema-only. Every other phase
//! delegates to DL34.

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
pub(crate) use super::dl25::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl34::phase_1_schema_attrs();
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_BASE_URL_DL35
            .clone()
            .into(),
    );
    attrs.push(SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_GROUPS_DL35.clone().into());
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_USE_LOGIN_AS_ID_DL35
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_GET_GROUPS_PERMISSION_DL35
            .clone()
            .into(),
    );
    attrs.push(SCHEMA_ATTR_OAUTH2_CLIENT_GITLAB_ROOT_CA_DL35.clone().into());
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl34::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_OAUTH2_CLIENT_DL35.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl34::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl34::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl34::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl34::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl34::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL35.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl34::phase_8_delete_uuids()
}
