//! DL29 migration phases.
//!
//! DL29 introduces the generic-OIDC upstream connector (PR-CONNECTOR-GENERIC-OIDC):
//!   * Ten OIDC-specific config attributes on `EntryClass::OAuth2Client`
//!     (enable_groups, groups_key, skip_email_verified, allowed_groups,
//!     get_user_info, user_id_key, user_name_key, override_claim_mapping,
//!     groups_prefix, groups_suffix).
//!   * An extended `idm_acp_oauth2_client_admin` covering the new attrs.
//!
//! No new entry class. No new ACP class. All new attributes are optional.
//! Every other phase delegates to DL28.

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use super::dl25::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl28::phase_1_schema_attrs();
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_ENABLE_GROUPS_DL29
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_KEY_DL29
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_SKIP_EMAIL_VERIFIED_DL29
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_ALLOWED_GROUPS_DL29
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GET_USER_INFO_DL29
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_USER_ID_KEY_DL29
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_USER_NAME_KEY_DL29
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_OVERRIDE_CLAIM_MAPPING_DL29
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_PREFIX_DL29
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_OIDC_GROUPS_SUFFIX_DL29
            .clone()
            .into(),
    );
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl28::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_OAUTH2_CLIENT_DL29.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl28::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl28::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl28::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl28::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl28::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL29.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl28::phase_8_delete_uuids()
}
