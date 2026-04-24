//! DL36 migration phases.
//!
//! DL36 introduces Bitbucket Cloud connector dex-parity additions (PR-CONNECTOR-BITBUCKET):
//!   * Three new optional config attributes on `EntryClass::Connector`:
//!     `ConnectorBitbucketTeams`, `ConnectorBitbucketGetWorkspacePermissions`,
//!     and `ConnectorBitbucketIncludeTeamGroups`.
//!   * An extended `idm_acp_connector_admin` covering the new attrs.
//!
//! No new entry class. No data migration — schema-only. Every other phase
//! delegates to DL35.

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use super::dl25::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl35::phase_1_schema_attrs();
    attrs.push(SCHEMA_ATTR_CONNECTOR_BITBUCKET_TEAMS_DL36.clone().into());
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_BITBUCKET_GET_WORKSPACE_PERMISSIONS_DL36
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_BITBUCKET_INCLUDE_TEAM_GROUPS_DL36
            .clone()
            .into(),
    );
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl35::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_OAUTH2_CLIENT_DL36.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl35::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl35::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl35::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl35::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl35::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL36.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl35::phase_8_delete_uuids()
}
