//! DL26 migration phases.
//!
//! DL26 introduces RP-Initiated Logout across OIDC and SAML:
//!   * Three new URL attributes on existing client classes
//!     (`OAuth2RsPostLogoutRedirectUri`, `OAuth2RsBackchannelLogoutUri`,
//!     `SamlSingleLogoutServiceUrl`).
//!   * Two new entry classes (`LogoutDelivery` for the persistent back-channel
//!     delivery queue, `SamlSession` for the per-SP SAML session index).
//!   * Updated `idm_acp_oauth2_client_admin` and `idm_acp_saml_client_admin`
//!     ACPs to include the new URL attributes; a new
//!     `idm_acp_logout_delivery_read` for admin visibility into the queue.
//!   * Twelve new schema attributes (the three URL attrs plus seven on
//!     `LogoutDelivery` and five on `SamlSession`).
//!
//! Every non-schema / non-access phase delegates to DL25.

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
pub(crate) use super::dl25::accounts;

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use self::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl25::phase_1_schema_attrs();
    attrs.push(
        SCHEMA_ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI_DL26
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_RS_BACKCHANNEL_LOGOUT_URI_DL26
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_SAML_SINGLE_LOGOUT_SERVICE_URL_DL26
            .clone()
            .into(),
    );
    attrs.push(SCHEMA_ATTR_LOGOUT_DELIVERY_ENDPOINT_DL26.clone().into());
    attrs.push(SCHEMA_ATTR_LOGOUT_DELIVERY_TOKEN_DL26.clone().into());
    attrs.push(SCHEMA_ATTR_LOGOUT_DELIVERY_STATUS_DL26.clone().into());
    attrs.push(SCHEMA_ATTR_LOGOUT_DELIVERY_ATTEMPTS_DL26.clone().into());
    attrs.push(SCHEMA_ATTR_LOGOUT_DELIVERY_NEXT_ATTEMPT_DL26.clone().into());
    attrs.push(SCHEMA_ATTR_LOGOUT_DELIVERY_CREATED_DL26.clone().into());
    attrs.push(SCHEMA_ATTR_LOGOUT_DELIVERY_RP_DL26.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_SESSION_USER_DL26.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_SESSION_SP_DL26.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_SESSION_INDEX_DL26.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_SESSION_UAT_UUID_DL26.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_SESSION_CREATED_DL26.clone().into());
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl25::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_OAUTH2_RS_DL26.clone().into());
    classes.push(SCHEMA_CLASS_SAML_CLIENT_DL26.clone().into());
    classes.push(SCHEMA_CLASS_PERSON_DL26.clone().into());
    classes.push(SCHEMA_CLASS_LOGOUT_DELIVERY_DL26.clone().into());
    classes.push(SCHEMA_CLASS_SAML_SESSION_DL26.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl25::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl25::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl25::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl25::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl25::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_MANAGE_DL26.clone().into());
    acps.push(access::IDM_ACP_SAML_CLIENT_ADMIN_DL26.clone().into());
    acps.push(access::IDM_ACP_LOGOUT_DELIVERY_READ_DL26.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl25::phase_8_delete_uuids()
}
