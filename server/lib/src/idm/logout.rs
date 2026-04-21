//! Central session-termination routine and OIDC Back-Channel logout-token
//! minting.
//!
//! Every end-of-session path in netidm — OIDC `end_session_endpoint`, SAML
//! `<LogoutRequest>`, session expiry, administrator revoke, and the US5 "log
//! out everywhere" surface — is intended to call [`terminate_session`]. This
//! routine ends the netidm session, revokes the refresh tokens issued against
//! it, and enqueues back-channel-logout deliveries for every relying party
//! that has a [`netidm_proto::attribute::Attribute::OAuth2RsBackchannelLogoutUri`].
//!
//! Module scaffolding only in DL26 Foundational phase; the real `terminate_session`
//! and `logout_token_for_rp` implementations land with US1 (Phase 3) of
//! PR-RP-LOGOUT (specs/009-rp-logout/).
