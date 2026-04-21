//! Central session-termination routine and OIDC RP-Initiated Logout
//! orchestration.
//!
//! Every end-of-session path in netidm — OIDC `end_session_endpoint`, SAML
//! `<LogoutRequest>`, session expiry, administrator revoke, and the US5
//! "log out everywhere" surface — funnels through [`terminate_session`].
//! Current surface: UAT session destruction. Subsequent PR-RP-LOGOUT
//! commits extend the routine with refresh-token revocation tie-in (US3),
//! back-channel `LogoutDelivery` enqueue (US3), and `SamlSession`
//! cleanup (US4) — the call sites stay the same, they just pick up the
//! additional behaviour automatically.

use url::Url;
use uuid::Uuid;

use crate::idm::account::DestroySessionTokenEvent;
use crate::idm::server::IdmServerProxyWriteTransaction;
use crate::prelude::Identity;
use netidm_proto::internal::OperationError;

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

/// Terminate a single netidm session.
///
/// This is the central convergence routine every end-of-session path calls:
///
///   * OIDC RP-Initiated Logout 1.0 (`end_session_endpoint`) — called from
///     [`IdmServerProxyWriteTransaction::handle_oauth2_rp_initiated_logout`].
///   * SAML Single Logout — called from the SLO handler once US4 lands.
///   * US5 self-service / admin "log out everywhere" — called once per
///     UAT the target user holds.
///   * Netidm-internal session expiry and administrator revoke paths as
///     they migrate to the single routine.
///
/// Current behaviour: destroy the named UAT session via
/// [`IdmServerProxyWriteTransaction::account_destroy_session_token`] and
/// swallow [`OperationError::NoMatchingEntries`] as success (so OIDC logout
/// remains idempotent from the relying party's perspective). Subsequent
/// PR-RP-LOGOUT commits layer in:
///
///   * Refresh-token revocation for RP-issued tokens bound to this session
///     (US3).
///   * Enqueue of `LogoutDelivery` entries to every relying party with a
///     registered `OAuth2RsBackchannelLogoutUri` whose tokens were minted
///     against this session (US3).
///   * Deletion of `SamlSession` entries linked to the UAT (US4).
///
/// A project-wide grep for this function's definition MUST return exactly
/// one match — the single convergence point for session termination.
///
/// # Errors
///
/// Returns any [`OperationError`] variant propagated from the underlying
/// `account_destroy_session_token` call except `NoMatchingEntries`, which
/// is swallowed as success. The caller is responsible for committing the
/// enclosing write transaction.
pub fn terminate_session(
    idms: &mut IdmServerProxyWriteTransaction<'_>,
    user_uuid: Uuid,
    session_uuid: Uuid,
) -> Result<(), OperationError> {
    let dte = DestroySessionTokenEvent {
        ident: Identity::from_internal(),
        target: user_uuid,
        token_id: session_uuid,
    };
    match idms.account_destroy_session_token(&dte) {
        Ok(()) => {
            tracing::info!(
                target_uuid = %user_uuid,
                session_uuid = %session_uuid,
                "netidm session terminated"
            );
            Ok(())
        }
        Err(OperationError::NoMatchingEntries) => {
            tracing::trace!(
                target_uuid = %user_uuid,
                session_uuid = %session_uuid,
                "session already terminated — treated as idempotent success"
            );
            Ok(())
        }
        Err(err) => {
            tracing::error!(
                ?err,
                target_uuid = %user_uuid,
                session_uuid = %session_uuid,
                "failed to terminate netidm session"
            );
            Err(err)
        }
    }
}
