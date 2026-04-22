//! DL28 migration phases.
//!
//! DL28 introduces the GitHub upstream connector (PR-CONNECTOR-GITHUB):
//!   * One discriminator attribute (`OAuth2ClientProviderKind`) selecting
//!     which concrete connector implementation handles a given
//!     `OAuth2Client` entry. Value `"github"` in this PR; absence
//!     defaults to `"generic-oidc"` at the dispatch site.
//!   * Seven GitHub-specific config attributes on `EntryClass::OAuth2Client`
//!     (host, org filter, allowed-teams access gate, team-name field,
//!     load-all-groups flag, preferred-email-domain, allow-JIT flag).
//!   * An extended `idm_acp_oauth2_client_admin` covering the new attrs.
//!
//! No new entry class. No new ACP class. Every other phase delegates to
//! DL26 (DL27 was a no-op for migration purposes — see DL27 notes in
//! `server/lib/src/constants/mod.rs`).

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
pub(crate) use super::dl25::accounts;

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use self::schema::SCHEMA_ATTR_OAUTH2_CLIENT_PROVIDER_KIND_DL28;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl26::phase_1_schema_attrs();
    attrs.push(SCHEMA_ATTR_OAUTH2_CLIENT_PROVIDER_KIND_DL28.clone().into());
    attrs.push(SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_HOST_DL28.clone().into());
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_ORG_FILTER_DL28
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_ALLOWED_TEAMS_DL28
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_TEAM_NAME_FIELD_DL28
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_LOAD_ALL_GROUPS_DL28
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_PREFERRED_EMAIL_DOMAIN_DL28
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_ALLOW_JIT_PROVISIONING_DL28
            .clone()
            .into(),
    );
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    // DL28 adds no NEW classes, but extends the existing `OAuth2Client`
    // class to include the eight DL28 attrs in its `systemmay` set so
    // entries can actually carry them through schema validation.
    let mut classes = super::dl26::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_OAUTH2_CLIENT_DL28.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl26::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl26::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl26::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl26::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl26::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL28.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl26::phase_8_delete_uuids()
}
