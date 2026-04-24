//! DL33 migration phases.
//!
//! DL33 introduces SAML connector dex-parity additions (PR-CONNECTOR-SAML):
//!   * Five new optional config attributes on `EntryClass::SamlClient`:
//!     `SamlSsoIssuer`, `SamlInsecureSkipSigValidation`, `SamlGroupsDelim`,
//!     `SamlAllowedGroups`, and `SamlFilterGroups`.
//!   * An extended `idm_acp_saml_client_admin` covering the new attrs.
//!
//! No new entry class. No data migration — schema-only. Every other phase
//! delegates to DL32.

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
pub(crate) use super::dl25::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl32::phase_1_schema_attrs();
    attrs.push(SCHEMA_ATTR_SAML_SSO_ISSUER_DL33.clone().into());
    attrs.push(
        SCHEMA_ATTR_SAML_INSECURE_SKIP_SIG_VALIDATION_DL33
            .clone()
            .into(),
    );
    attrs.push(SCHEMA_ATTR_SAML_GROUPS_DELIM_DL33.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_ALLOWED_GROUPS_DL33.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_FILTER_GROUPS_DL33.clone().into());
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl32::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_SAML_CLIENT_DL33.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl32::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl32::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl32::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl32::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl32::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_SAML_CLIENT_ADMIN_DL33.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl32::phase_8_delete_uuids()
}
