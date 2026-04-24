//! DL32 migration phases.
//!
//! DL32 introduces the inbound LDAP federation connector (PR-CONNECTOR-LDAP):
//!   * Twenty-four LDAP-specific config attributes on `EntryClass::OAuth2Client`
//!     (connection/TLS settings, user search config, and group search config).
//!   * An extended `idm_acp_oauth2_client_admin` covering the new attrs.
//!
//! No new entry class. No new ACP class. All new attributes are optional.
//! Every other phase delegates to DL31.

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
pub(crate) use super::dl25::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl31::phase_1_schema_attrs();
    attrs.push(SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_HOST_DL32.clone().into());
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_INSECURE_NO_SSL_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_INSECURE_SKIP_VERIFY_DL32
            .clone()
            .into(),
    );
    attrs.push(SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_START_TLS_DL32.clone().into());
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_ROOT_CA_DATA_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_CLIENT_CERT_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_CLIENT_KEY_DL32
            .clone()
            .into(),
    );
    attrs.push(SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_BIND_DN_DL32.clone().into());
    attrs.push(SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_BIND_PW_DL32.clone().into());
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USERNAME_PROMPT_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_BASE_DN_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_FILTER_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_USERNAME_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_SCOPE_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_ID_ATTR_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_EMAIL_ATTR_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_NAME_ATTR_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_PREFERRED_USERNAME_ATTR_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_USER_SEARCH_EMAIL_SUFFIX_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_BASE_DN_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_FILTER_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_SCOPE_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_USER_MATCHERS_DL32
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_LDAP_GROUP_SEARCH_NAME_ATTR_DL32
            .clone()
            .into(),
    );
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl31::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_OAUTH2_CLIENT_DL32.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl31::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl31::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl31::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl31::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl31::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL32.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl31::phase_8_delete_uuids()
}
