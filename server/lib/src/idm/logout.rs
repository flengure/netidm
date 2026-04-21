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
use crate::server::QueryServerTransaction;
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
    // Enumerate the relying parties that minted OAuth2 tokens against
    // the ending session BEFORE we destroy the session — once the UAT
    // is gone, the plugin layer will start reaping the linked
    // OAuth2Sessions and our lookup would come up empty.
    let rp_uuids = collect_rps_for_session(idms, user_uuid, session_uuid)?;

    // Destroy the netidm session (UAT). Idempotent on
    // NoMatchingEntries — matches the OIDC expectation that logout is
    // repeatable without surfacing an error.
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
                rps_notified = rp_uuids.len(),
                "netidm session terminated"
            );
        }
        Err(OperationError::NoMatchingEntries) => {
            tracing::trace!(
                target_uuid = %user_uuid,
                session_uuid = %session_uuid,
                "session already terminated — treated as idempotent success"
            );
            return Ok(());
        }
        Err(err) => {
            tracing::error!(
                ?err,
                target_uuid = %user_uuid,
                session_uuid = %session_uuid,
                "failed to terminate netidm session"
            );
            return Err(err);
        }
    }

    // Enqueue OIDC Back-Channel Logout deliveries for every RP with a
    // registered `OAuth2RsBackchannelLogoutUri` that minted tokens
    // against this session. Individual enqueue failures are logged but
    // do not unwind the termination — a missed back-channel
    // notification is preferable to a re-logged-in session.
    let ct = crate::prelude::duration_from_epoch_now();
    for rp_uuid in rp_uuids {
        match idms.enqueue_backchannel_logout_for_rp(rp_uuid, user_uuid, session_uuid, ct) {
            Ok(Some(delivery_uuid)) => {
                tracing::info!(
                    %rp_uuid,
                    %delivery_uuid,
                    target_uuid = %user_uuid,
                    session_uuid = %session_uuid,
                    "enqueued back-channel logout delivery"
                );
            }
            Ok(None) => {
                // RP opted out (no backchannel_logout_uri) — nothing to do.
            }
            Err(err) => {
                tracing::error!(
                    ?err,
                    %rp_uuid,
                    target_uuid = %user_uuid,
                    session_uuid = %session_uuid,
                    "failed to enqueue back-channel logout delivery"
                );
            }
        }
    }

    Ok(())
}

/// Read the target user's `OAuth2Session` attribute and collect the
/// unique relying-party UUIDs that minted tokens against the given
/// parent UAT session. Used by [`terminate_session`] to decide which
/// relying parties deserve a back-channel logout notification.
///
/// Non-revoked sessions only — a revoked session's RP was already told
/// (either by the original revoke path or because the session had been
/// terminated before).
fn collect_rps_for_session(
    idms: &mut IdmServerProxyWriteTransaction<'_>,
    user_uuid: Uuid,
    session_uuid: Uuid,
) -> Result<hashbrown::HashSet<Uuid>, OperationError> {
    use crate::value::SessionState;

    let entry = match idms.qs_write.internal_search_uuid(user_uuid) {
        Ok(e) => e,
        Err(OperationError::NoMatchingEntries) => {
            return Ok(hashbrown::HashSet::new());
        }
        Err(err) => return Err(err),
    };
    let Some(map) = entry.get_ava_as_oauth2session_map(netidm_proto::attribute::Attribute::OAuth2Session)
    else {
        return Ok(hashbrown::HashSet::new());
    };
    let mut rp_uuids: hashbrown::HashSet<Uuid> = hashbrown::HashSet::new();
    for session in map.values() {
        if session.parent == Some(session_uuid)
            && !matches!(session.state, SessionState::RevokedAt(_))
        {
            rp_uuids.insert(session.rs_uuid);
        }
    }
    Ok(rp_uuids)
}
