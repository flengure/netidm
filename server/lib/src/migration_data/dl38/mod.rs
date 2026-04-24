//! DL38 migration phases.
//!
//! DL38 introduces authproxy and gitea connector support:
//!   * Three authproxy header attrs on `EntryClass::Connector`
//!     (`ConnectorAuthproxyUserHeader`, `ConnectorAuthproxyEmailHeader`,
//!     `ConnectorAuthproxyGroupsHeader`)
//!   * Six gitea config attrs on `EntryClass::Connector`
//!     (`ConnectorGiteaBaseUrl`, `ConnectorGiteaGroups`, `ConnectorGiteaInsecureCa`,
//!     `ConnectorGiteaRootCa`, `ConnectorGiteaLoadAllGroups`, `ConnectorGiteaUseLoginAsId`)
//!   * Updated `idm_acp_oauth2_client_admin` covering the new attrs

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use super::dl25::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl37::phase_1_schema_attrs();
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_AUTHPROXY_USER_HEADER_DL38
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_AUTHPROXY_EMAIL_HEADER_DL38
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_AUTHPROXY_GROUPS_HEADER_DL38
            .clone()
            .into(),
    );
    attrs.push(SCHEMA_ATTR_CONNECTOR_GITEA_BASE_URL_DL38.clone().into());
    attrs.push(SCHEMA_ATTR_CONNECTOR_GITEA_GROUPS_DL38.clone().into());
    attrs.push(SCHEMA_ATTR_CONNECTOR_GITEA_INSECURE_CA_DL38.clone().into());
    attrs.push(SCHEMA_ATTR_CONNECTOR_GITEA_ROOT_CA_DL38.clone().into());
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_GITEA_LOAD_ALL_GROUPS_DL38
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_GITEA_USE_LOGIN_AS_ID_DL38
            .clone()
            .into(),
    );
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl37::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_CONNECTOR_DL38.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl37::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl37::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl37::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl37::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl37::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL38.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl37::phase_8_delete_uuids()
}
