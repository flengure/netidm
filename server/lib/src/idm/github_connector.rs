//! GitHub upstream connector (PR-CONNECTOR-GITHUB, DL28).
//!
//! This module is the concrete implementation of the `RefreshableConnector`
//! trait for GitHub / GitHub Enterprise. Providers whose `OAuth2Client`
//! entry carries `oauth2_client_provider_kind = "github"` are dispatched
//! here at callback time, bypassing the generic OIDC code-exchange /
//! userinfo / JWKS path that pre-DL28 providers still use.
//!
//! ## Status
//!
//! This is the **T009 stub**: it only exposes the rendered "not yet
//! implemented" message used by the authsession short-circuit in
//! `handler_oauth2_client::validate_authorisation_response`. The full
//! implementation — code exchange, user/emails/orgs/teams fetch, the
//! four-step linking chain, session-state blob, `RefreshableConnector`
//! impl — lands in T011–T017, T023–T034 per
//! `specs/012-github-connector/tasks.md`.
//!
//! ## Dispatch contract (FR-016)
//!
//! Absence of `oauth2_client_provider_kind` on an `OAuth2Client` entry, or
//! an unrecognised value, both resolve to `ProviderKind::GenericOidc` in
//! `idm::oauth2_client::reload_oauth2_client_providers` — so pre-DL28
//! providers decode byte-identically to DL27 and never reach this module.

/// User-visible message rendered in place of the OAuth2 auth flow when a
/// provider is configured with `provider_kind = "github"` under the T009
/// stub. Replaced in T013 by the real callback dispatch. Kept short so it
/// fits inside the existing `CredState::Denied(&'static str)` arm without
/// a string-lifetime shim.
pub const GITHUB_CONNECTOR_STUB_MSG: &str =
    "GitHub upstream connector is not yet available on this build";
