//! Central session-termination routine and OIDC RP-Initiated Logout
//! orchestration.
//!
//! This module carries the outcome types and orchestration for OIDC
//! RP-Initiated Logout 1.0. The actual protocol-level work
//! (`id_token_hint` verification, session termination, post-logout redirect
//! allowlist evaluation) lives on [`crate::idm::server::IdmServerProxyWriteTransaction`]
//! alongside the other OAuth2 logic — see
//! [`crate::idm::server::IdmServerProxyWriteTransaction::handle_oauth2_rp_initiated_logout`].
//!
//! The generic `terminate_session` (used by every end-of-session path —
//! OIDC, SAML SLO, session expiry, admin revoke, and the US5 "log out
//! everywhere" surface) and the back-channel `LogoutTokenClaims`
//! minting will land here in subsequent PR-RP-LOGOUT commits (US3 +
//! US4 + US5). See `specs/009-rp-logout/plan.md` Layer 3.

use url::Url;

/// Outcome of an OIDC RP-Initiated Logout 1.0 request.
///
/// The handler decides between a post-logout redirect back to the relying
/// party (honoured only if the caller-supplied URI exactly matches an entry
/// in the client's registered allowlist) and rendering netidm's own
/// confirmation page. Both outcomes MUST carry `Cache-Control: no-store`
/// at the HTTP layer.
#[derive(Debug, Clone)]
pub enum OidcLogoutOutcome {
    /// Redirect the user-agent to a post-logout URI. The `state` parameter
    /// from the original request (if any) is echoed back verbatim — the
    /// caller at the HTTP layer is responsible for URL-encoding and
    /// appending it to the returned URL.
    Redirect {
        /// Destination URI, guaranteed to be one of the client's registered
        /// `OAuth2RsPostLogoutRedirectUri` values.
        url: Url,
        /// Opaque state to echo back.
        state: Option<String>,
    },
    /// Render a netidm-owned confirmation page. Used when the request has
    /// no valid `id_token_hint`, when `post_logout_redirect_uri` is absent
    /// or not on the allowlist, or any time the redirect path cannot be
    /// taken safely.
    Confirmation,
}
