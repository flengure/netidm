//! DL25 migration phases.
//!
//! DL25 extends three schema attributes (all `Utf8String`, multi-value) and
//! updates three classes' `systemmay` lists (`OAuth2Client`, `SamlClient`,
//! `Person`). It also updates the OAuth2 / SAML client admin ACPs to allow
//! writing the new attributes (and `OAuth2LinkBy`, which was added in DL24
//! but whose ACP entry was missed at the time). Every non-schema /
//! non-access phase delegates to DL24.

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
pub(crate) use super::dl24::accounts;

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use self::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl24::phase_1_schema_attrs();
    attrs.push(SCHEMA_ATTR_OAUTH2_GROUP_MAPPING_DL25.clone().into());
    attrs.push(SCHEMA_ATTR_SAML_GROUP_MAPPING_DL25.clone().into());
    attrs.push(SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP_DL25.clone().into());
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl24::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_OAUTH2_CLIENT_DL25.clone().into());
    classes.push(SCHEMA_CLASS_SAML_CLIENT_DL25.clone().into());
    classes.push(SCHEMA_CLASS_PERSON_DL25.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl24::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl24::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl24::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl24::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl24::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL25.clone().into());
    acps.push(access::IDM_ACP_SAML_CLIENT_ADMIN_DL25.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl24::phase_8_delete_uuids()
}
