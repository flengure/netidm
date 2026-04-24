//! DL37 migration phases.
//!
//! DL37 introduces:
//! * `ConnectorGithubUseLoginAsId` — registers the boolean schema attr already
//!   present in proto since the GitHub connector parity rewrite.
//! * `ProviderIdentity` entry class — per-user per-connector identity record
//!   (upstream provider's view of the user: claims + consent grants).
//!   Attrs: `provider_identity_user_uuid`, `provider_identity_connector_id`,
//!   `provider_identity_claims_*`, `provider_identity_consents`,
//!   `provider_identity_created_at`, `provider_identity_last_login`,
//!   `provider_identity_blocked_until`.
//! * `Oauth2RsTrustedPeers` and `Oauth2RsAllowedConnectors` on
//!   `OAuth2ResourceServer` — cross-client SSO trust and connector restriction.
//! * Updated ACPs: connector admin, OAuth2 manage, new provider identity manage.

pub(crate) mod access;
pub(crate) mod schema;

#[cfg(test)]
pub(crate) use super::dl25::accounts;

use self::schema::*;
use crate::prelude::*;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    let mut attrs = super::dl36::phase_1_schema_attrs();
    attrs.push(
        SCHEMA_ATTR_CONNECTOR_GITHUB_USE_LOGIN_AS_ID_DL37
            .clone()
            .into(),
    );
    attrs.push(SCHEMA_ATTR_PROVIDER_IDENTITY_USER_UUID_DL37.clone().into());
    attrs.push(
        SCHEMA_ATTR_PROVIDER_IDENTITY_CONNECTOR_ID_DL37
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_USER_ID_DL37
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_USERNAME_DL37
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_EMAIL_DL37
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_EMAIL_VERIFIED_DL37
            .clone()
            .into(),
    );
    attrs.push(
        SCHEMA_ATTR_PROVIDER_IDENTITY_CLAIMS_GROUPS_DL37
            .clone()
            .into(),
    );
    attrs.push(SCHEMA_ATTR_PROVIDER_IDENTITY_CONSENTS_DL37.clone().into());
    attrs.push(SCHEMA_ATTR_PROVIDER_IDENTITY_CREATED_AT_DL37.clone().into());
    attrs.push(SCHEMA_ATTR_PROVIDER_IDENTITY_LAST_LOGIN_DL37.clone().into());
    attrs.push(
        SCHEMA_ATTR_PROVIDER_IDENTITY_BLOCKED_UNTIL_DL37
            .clone()
            .into(),
    );
    attrs.push(SCHEMA_ATTR_OAUTH2_RS_TRUSTED_PEERS_DL37.clone().into());
    attrs.push(SCHEMA_ATTR_OAUTH2_RS_ALLOWED_CONNECTORS_DL37.clone().into());
    attrs
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    let mut classes = super::dl36::phase_2_schema_classes();
    classes.push(SCHEMA_CLASS_CONNECTOR_DL37.clone().into());
    classes.push(SCHEMA_CLASS_OAUTH2_RS_DL37.clone().into());
    classes.push(SCHEMA_CLASS_PROVIDER_IDENTITY_DL37.clone().into());
    classes
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    super::dl36::phase_3_key_provider()
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    super::dl36::phase_4_system_entries()
}

pub fn phase_5_builtin_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl36::phase_5_builtin_admin_entries()
}

pub fn phase_6_builtin_non_admin_entries(
) -> Result<Vec<EntryInitNew>, netidm_proto::internal::OperationError> {
    super::dl36::phase_6_builtin_non_admin_entries()
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    let mut acps = super::dl36::phase_7_builtin_access_control_profiles();
    acps.push(access::IDM_ACP_OAUTH2_CLIENT_ADMIN_DL37.clone().into());
    acps.push(access::IDM_ACP_OAUTH2_MANAGE_DL37.clone().into());
    acps.push(access::IDM_ACP_PROVIDER_IDENTITY_MANAGE_DL37.clone().into());
    acps
}

pub fn phase_8_delete_uuids() -> Vec<uuid::Uuid> {
    super::dl36::phase_8_delete_uuids()
}
