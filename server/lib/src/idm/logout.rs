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
    let (rp_uuids, oauth2_session_ids) =
        collect_rps_and_oauth2_sessions_for_session(idms, user_uuid, session_uuid)?;

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

    // Revoke every OAuth2 session (refresh-token holder) bound to the
    // ending UAT per spec §FR-002: "revoke the refresh tokens held by
    // the identified app for that user that were issued against the
    // ended session". The plugin layer WOULD reap orphaned
    // OAuth2Sessions after `AUTH_TOKEN_GRACE_WINDOW` — but that grace
    // is for transient session churn, not intentional logout. Logout
    // MUST invalidate refresh tokens immediately.
    if !oauth2_session_ids.is_empty() {
        use crate::prelude::{f_eq, Filter, Modify, ModifyList, PartialValue};
        let mut modify_list = Vec::with_capacity(oauth2_session_ids.len());
        for o2_session_id in &oauth2_session_ids {
            modify_list.push(Modify::Removed(
                netidm_proto::attribute::Attribute::OAuth2Session,
                PartialValue::Refer(*o2_session_id),
            ));
        }
        let ml = ModifyList::new_list(modify_list);
        let filter = Filter::new(f_eq(
            netidm_proto::attribute::Attribute::Uuid,
            PartialValue::Uuid(user_uuid),
        ));
        if let Err(err) = idms.qs_write.internal_modify(&filter, &ml) {
            // Log + continue — a failed OAuth2 session revoke is
            // preferable to leaving the UAT alive. Plugin layer will
            // eventually reap the orphans.
            tracing::error!(
                ?err,
                target_uuid = %user_uuid,
                session_uuid = %session_uuid,
                oauth2_sessions = oauth2_session_ids.len(),
                "failed to explicitly revoke OAuth2 sessions; relying on plugin cleanup"
            );
        } else {
            tracing::info!(
                target_uuid = %user_uuid,
                session_uuid = %session_uuid,
                oauth2_sessions_revoked = oauth2_session_ids.len(),
                "revoked OAuth2 sessions bound to terminated UAT"
            );
        }
    }

    // Enqueue OIDC Back-Channel Logout deliveries for every RP with a
    // registered `OAuth2RsBackchannelLogoutUri` that minted tokens
    // against this session. Individual enqueue failures are logged but
    // do not unwind the termination — a missed back-channel
    // notification is preferable to a re-logged-in session.
    let ct = crate::prelude::duration_from_epoch_now();
    let mut enqueued_any = false;
    for rp_uuid in rp_uuids {
        match idms.enqueue_backchannel_logout_for_rp(rp_uuid, user_uuid, session_uuid, ct) {
            Ok(Some(delivery_uuid)) => {
                enqueued_any = true;
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

    // Wake the delivery worker so it attempts these records immediately
    // rather than waiting for its next poll tick. Signal is edge-like —
    // one `notify_one` per batch is sufficient since the worker drains
    // all due records in one pass. Safe to call even if no records
    // were enqueued; a spurious wake just causes an empty iteration.
    if enqueued_any {
        idms.logout_delivery_notify.notify_one();
    }

    Ok(())
}

/// Read the target user's `OAuth2Session` attribute and collect (a)
/// the unique relying-party UUIDs that minted tokens against the
/// given parent UAT session, and (b) the individual OAuth2Session IDs
/// themselves, so `terminate_session` can both notify and revoke.
///
/// Non-revoked sessions only — a revoked session's RP was already told
/// (either by the original revoke path or because the session had been
/// terminated before).
fn collect_rps_and_oauth2_sessions_for_session(
    idms: &mut IdmServerProxyWriteTransaction<'_>,
    user_uuid: Uuid,
    session_uuid: Uuid,
) -> Result<(hashbrown::HashSet<Uuid>, Vec<Uuid>), OperationError> {
    use crate::value::SessionState;

    let entry = match idms.qs_write.internal_search_uuid(user_uuid) {
        Ok(e) => e,
        Err(OperationError::NoMatchingEntries) => {
            return Ok((hashbrown::HashSet::new(), Vec::new()));
        }
        Err(err) => return Err(err),
    };
    let Some(map) =
        entry.get_ava_as_oauth2session_map(netidm_proto::attribute::Attribute::OAuth2Session)
    else {
        return Ok((hashbrown::HashSet::new(), Vec::new()));
    };
    let mut rp_uuids: hashbrown::HashSet<Uuid> = hashbrown::HashSet::new();
    let mut oauth2_session_ids: Vec<Uuid> = Vec::new();
    for (o2_session_id, session) in map.iter() {
        if session.parent == Some(session_uuid)
            && !matches!(session.state, SessionState::RevokedAt(_))
        {
            rp_uuids.insert(session.rs_uuid);
            oauth2_session_ids.push(*o2_session_id);
        }
    }
    Ok((rp_uuids, oauth2_session_ids))
}

#[cfg(test)]
mod tests {
    //! Pure-library shape tests for the back-channel logout token.
    //! The full wire path is exercised end-to-end in the testkit
    //! integration suite (`test_logout_backchannel_delivery_end_to_end`).
    //! What these tests protect is the claim STRUCTURE — the
    //! specific fields, the literal `events` map shape, and the
    //! `typ: "logout+jwt"` header — so a refactor that accidentally
    //! drops or renames a field is caught without needing a full
    //! test server to boot.

    use compact_jwt::jws::JwsBuilder;
    use compact_jwt::{
        compact::JwsCompact, JwsEs256Signer, JwsEs256Verifier, JwsSigner, JwsVerifier,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::str::FromStr;
    use uuid::Uuid;

    /// Mirror of the claim struct defined in `idm/oauth2.rs` so
    /// this test is decoupled from the signing path but pinned to
    /// the same field set. Any rename or removal over in the
    /// real claim struct should prompt an update here too —
    /// which is the point.
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct LogoutTokenClaims {
        iss: String,
        aud: String,
        iat: i64,
        jti: String,
        sub: String,
        sid: String,
        events: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    }

    #[test]
    fn logout_token_claims_round_trip() {
        let mut events = BTreeMap::new();
        events.insert(
            "http://schemas.openid.net/event/backchannel-logout".to_string(),
            BTreeMap::new(),
        );
        let original = LogoutTokenClaims {
            iss: "https://idm.example.com/oauth2/openid/test_rp".to_string(),
            aud: "test_rp".to_string(),
            iat: 1_700_000_000,
            jti: Uuid::new_v4().to_string(),
            sub: Uuid::new_v4().to_string(),
            sid: Uuid::new_v4().to_string(),
            events,
        };

        let data = JwsBuilder::into_json(&original)
            .expect("serialise claims")
            .set_typ(Some("logout+jwt"))
            .build();

        let signer = JwsEs256Signer::generate_es256().expect("generate signer");
        let signed: JwsCompact = signer.sign(&data).expect("sign");

        let jws_str = signed.to_string();
        let parsed = JwsCompact::from_str(&jws_str).expect("parse JwsCompact");

        // Header — typ must carry through verbatim per OIDC
        // Back-Channel Logout 1.0 §2.4.
        assert_eq!(
            parsed.header().typ.as_deref(),
            Some("logout+jwt"),
            "typ header must be preserved as 'logout+jwt'"
        );

        // Verify + decode the payload with the matching public key.
        let jwk = signer.public_key_as_jwk().expect("extract jwk");
        let verifier = JwsEs256Verifier::try_from(&jwk).expect("build verifier");
        let verified = verifier.verify(&parsed).expect("verify");
        let round_tripped: LogoutTokenClaims =
            serde_json::from_slice(verified.payload()).expect("parse claims");

        assert_eq!(
            round_tripped, original,
            "every claim must round-trip, including the events map shape"
        );

        // Explicit re-assertion of the events shape — it's the
        // one claim whose structure is most likely to be silently
        // reshaped by a lazy refactor.
        let logout_event = round_tripped
            .events
            .get("http://schemas.openid.net/event/backchannel-logout")
            .expect("back-channel-logout event key present");
        assert!(
            logout_event.is_empty(),
            "back-channel-logout event value must be an empty object"
        );
    }
}
