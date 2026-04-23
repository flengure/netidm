//! DL31 migration phases.
//!
//! DL31 introduces the Microsoft Azure AD upstream connector (PR-CONNECTOR-MICROSOFT):
//!   * Thirteen Microsoft-specific config attributes on `EntryClass::OAuth2Client`
//!     (tenant, group settings, sovereign-cloud URL overrides, prompt/hint params,
//!     custom scopes, preferred-username field, JIT provisioning toggle).
//!   * An extended `idm_acp_oauth2_client_admin` covering the new attrs.
//!
//! No new entry class. No new ACP class. All new attributes are optional.
//! Every other phase delegates to DL30.

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
pub(crate) use super::dl25::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl30::phase_1_schema_attrs();
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_TENANT_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_ONLY_SECURITY_GROUPS_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_GROUPS_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_GROUP_NAME_FORMAT_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_USE_GROUPS_AS_WHITELIST_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_EMAIL_TO_LOWERCASE_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_API_URL_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_GRAPH_URL_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_PROMPT_TYPE_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_DOMAIN_HINT_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_SCOPES_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_PREFERRED_USERNAME_FIELD_DL31
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_MICROSOFT_ALLOW_JIT_PROVISIONING_DL31
            .clone()
            .into(),
    );
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl30::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_OAUTH2_CLIENT_DL31.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl30::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl30::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl30::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl30::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl30::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL31.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl30::phase_8_delete_uuids()
}
