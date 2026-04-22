//! Upstream connector abstraction for OAuth2 refresh-token claim re-fetch.
//!
//! When a downstream relying party exchanges a `grant_type=refresh_token`
//! against netidm's `/oauth2/token`, sessions that were federated through
//! an upstream identity provider must re-resolve their claims before the
//! new access token is minted. Without this, a user's upstream group
//! membership can become stale for the entire refresh-token lifetime
//! (Gap #5 in the netidm-vs-dex parity audit — see
//! `specs/010-refresh-claims/spec.md`).
//!
//! The core abstraction here is [`RefreshableConnector`]: a trait every
//! upstream connector implementation (OIDC, SAML, LDAP, GitHub, Google,
//! …) provides. Netidm stores an opaque connector-owned byte blob on
//! each connector-bound `Oauth2Session` and hands it back to the
//! connector on refresh, together with the previously-issued claims.
//! The connector returns fresh [`ExternalUserClaims`] (plus an optional
//! blob rotation) or a typed error — all of which the refresh call
//! site maps to `Oauth2Error::InvalidGrant` per FR-003.
//!
//! This PR (PR-REFRESH-CLAIMS) ships the trait, the registry plumbing,
//! and a test-only `TestMockConnector` so the refresh-path code can
//! be exercised end-to-end in the testkit. No concrete production
//! connector lands here — PR-CONNECTOR-GITHUB (#4) and the subsequent
//! per-connector PRs implement [`RefreshableConnector`] for their
//! upstream and register with [`ConnectorRegistry`] at boot.

use async_trait::async_trait;
use hashbrown::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::idm::authsession::handler_oauth2_client::ExternalUserClaims;

/// Hook invoked at `grant_type=refresh_token` time for sessions
/// federated through an upstream connector. Re-fetches the user's
/// claims (typically group membership, possibly email/display-name)
/// from the upstream authority that minted the session.
///
/// # Errors
///
/// Every [`ConnectorRefreshError`] variant maps to
/// [`crate::idm::oauth2::Oauth2Error::InvalidGrant`] at the call site
/// (FR-003, fail-closed). Implementations MUST NOT return success
/// with a stale claim set — if the upstream is unreachable or the
/// refresh material is revoked, return an error so the downstream RP
/// is forced to restart authentication.
///
/// # Examples
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use netidmd_lib::idm::oauth2_connector::{
///     RefreshableConnector, RefreshOutcome, ConnectorRefreshError,
/// };
/// use netidmd_lib::idm::authsession::handler_oauth2_client::ExternalUserClaims;
///
/// struct EchoConnector;
///
/// #[async_trait]
/// impl RefreshableConnector for EchoConnector {
///     async fn refresh(
///         &self,
///         _session_state: &[u8],
///         previous_claims: &ExternalUserClaims,
///     ) -> Result<RefreshOutcome, ConnectorRefreshError> {
///         Ok(RefreshOutcome {
///             claims: previous_claims.clone(),
///             new_session_state: None,
///         })
///     }
/// }
/// ```
#[async_trait]
pub trait RefreshableConnector: Send + Sync {
    /// Re-fetch the user's claims from the upstream that minted the
    /// session. See module-level docs for invariants the call site
    /// enforces.
    async fn refresh(
        &self,
        session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError>;

    /// Exchange an OAuth2 `code` for user claims by making the full
    /// upstream API call chain. Implemented by connectors that bypass
    /// the OIDC state machine (PR-CONNECTOR-GITHUB, T013). The default
    /// returns `ConnectorRefreshError::Other` so non-GitHub connectors
    /// are unaffected.
    async fn fetch_callback_claims(
        &self,
        _code: &str,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        Err(ConnectorRefreshError::Other(
            "fetch_callback_claims not implemented for this connector".to_string(),
        ))
    }
}

/// Successful outcome of [`RefreshableConnector::refresh`]. Carries
/// the refreshed claim set and optionally an updated opaque session-
/// state blob to persist on the rotated session.
#[derive(Debug, Clone)]
pub struct RefreshOutcome {
    /// Fresh claims from the upstream. `sub` MUST equal the session's
    /// originally-minted subject — any mismatch is caught at the
    /// refresh call site and mapped to
    /// [`ConnectorRefreshError::TokenRevoked`]. `groups` is
    /// authoritative for the new upstream-synced membership set (the
    /// reconciler at the call site does not merge with prior
    /// markers).
    pub claims: ExternalUserClaims,
    /// If `Some(_)`, the rotated session stores this byte blob as its
    /// new `upstream_refresh_state`. If `None`, the old blob is
    /// copied forward unchanged.
    pub new_session_state: Option<Vec<u8>>,
}

/// Failure modes the refresh call site recognises. Every variant is
/// mapped to `Oauth2Error::InvalidGrant` on the wire (per RFC 6749
/// §5.2); the variant itself is logged server-side with the
/// connector UUID and user UUID for operational triage.
#[derive(Debug, Clone)]
pub enum ConnectorRefreshError {
    /// Transport-level failure talking to the upstream (TCP refused,
    /// TLS handshake failure, DNS, timeout).
    Network(String),
    /// Upstream responded with a non-2xx HTTP status. The `u16` is
    /// the observed status code; typical causes are upstream
    /// rate-limit (429), upstream misconfiguration (500), or the
    /// upstream revoking our client (401).
    UpstreamRejected(u16),
    /// The upstream explicitly said the refresh material is invalid,
    /// OR the returned `sub` does not match the session's original
    /// `sub`. Either way netidm must treat the session as no longer
    /// authoritative.
    TokenRevoked,
    /// The connector referenced by the session is not registered in
    /// the [`ConnectorRegistry`]. Usually means an admin deleted the
    /// connector entry after the session was minted.
    ConnectorMissing(Uuid),
    /// The opaque session-state blob could not be deserialized by
    /// the connector — almost always a connector-internal bug.
    Serialization(String),
    /// Anything else the connector could not categorise. Keep for
    /// forward-compatibility with connector-internal error types.
    Other(String),
}

impl std::fmt::Display for ConnectorRefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectorRefreshError::Network(msg) => {
                write!(f, "upstream transport error: {msg}")
            }
            ConnectorRefreshError::UpstreamRejected(status) => {
                write!(f, "upstream responded with HTTP {status}")
            }
            ConnectorRefreshError::TokenRevoked => {
                write!(f, "upstream refresh token revoked")
            }
            ConnectorRefreshError::ConnectorMissing(uuid) => {
                write!(f, "connector {uuid} is not registered")
            }
            ConnectorRefreshError::Serialization(msg) => {
                write!(f, "session state could not be deserialized: {msg}")
            }
            ConnectorRefreshError::Other(msg) => {
                write!(f, "connector error: {msg}")
            }
        }
    }
}

impl std::error::Error for ConnectorRefreshError {}

/// Process-local lookup of concrete [`RefreshableConnector`]
/// implementations by the connector-entry UUID that declares their
/// upstream trust. Populated at `IdmServer::start` (or at test
/// setup) and then read-mostly for the lifetime of the process.
///
/// Uses interior mutability so the registry can be shared behind
/// an `Arc` on `IdmServer` while still accepting late registrations
/// from test fixtures. The lock is only taken during `register`
/// (rare — boot and test setup) and during `get` (cheap; the lock
/// is held only long enough to clone the `Arc`).
///
/// This PR (PR-REFRESH-CLAIMS) ships an empty registry — later
/// connector PRs (#4+) populate it with concrete implementations
/// via [`ConnectorRegistry::register`] during their boot hook.
pub struct ConnectorRegistry {
    by_uuid: std::sync::Mutex<HashMap<Uuid, Arc<dyn RefreshableConnector>>>,
}

impl ConnectorRegistry {
    /// Build an empty registry — the production default for PR-REFRESH-CLAIMS.
    /// Later connector PRs call [`Self::register`] to populate it.
    #[must_use]
    pub fn new_empty() -> Self {
        Self {
            by_uuid: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Register a concrete connector implementation against its
    /// configuration-entry UUID. Typically called at netidmd boot
    /// before the `IdmServer` starts serving requests; test fixtures
    /// may also call this at runtime to inject a mock.
    ///
    /// Overwrites any previous registration for `uuid` — not expected
    /// to happen in production because each connector entry has a
    /// unique UUID, but tests rely on this to replace one mock with
    /// another within a single process.
    ///
    /// Takes `&self` (not `&mut`) so it can be called through the
    /// `Arc<ConnectorRegistry>` held on `IdmServer`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex has been poisoned by a previous
    /// panicking access. Only occurs in tests that deliberately
    /// panic while holding the registry lock.
    pub fn register(&self, uuid: Uuid, connector: Arc<dyn RefreshableConnector>) {
        #[allow(clippy::unwrap_used)]
        self.by_uuid.lock().unwrap().insert(uuid, connector);
    }

    /// Look up the connector responsible for the given UUID. Returns
    /// `None` if no connector is registered for that UUID — the
    /// refresh call site maps that to
    /// [`ConnectorRefreshError::ConnectorMissing`] and then to
    /// `Oauth2Error::InvalidGrant`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex has been poisoned.
    #[must_use]
    pub fn get(&self, uuid: Uuid) -> Option<Arc<dyn RefreshableConnector>> {
        #[allow(clippy::unwrap_used)]
        self.by_uuid.lock().unwrap().get(&uuid).cloned()
    }

    /// True when no connectors are registered. Useful for tests and
    /// for startup logging.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex has been poisoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        #[allow(clippy::unwrap_used)]
        self.by_uuid.lock().unwrap().is_empty()
    }
}

impl Default for ConnectorRegistry {
    fn default() -> Self {
        Self::new_empty()
    }
}

/// Read the Person entry's `OAuth2UpstreamSyncedGroup` markers filtered to
/// a single connector. Used by the OAuth2 refresh-token handler to decide
/// whether the new upstream-asserted group set requires a reconciliation
/// write (FR-010 persist-on-change).
///
/// Returns the set of netidm group UUIDs currently marked as
/// upstream-synced for `(person_uuid, provider_uuid)`. Markers tagged to
/// other providers are ignored; malformed marker values are logged and
/// skipped (same semantics as
/// [`crate::idm::group_mapping::reconcile_upstream_memberships`]).
///
/// # Errors
///
/// Returns any [`crate::prelude::OperationError`] propagated from the
/// underlying `internal_search_uuid` call — typically
/// `NoMatchingEntries` if `person_uuid` does not resolve, which the
/// caller should treat as "no markers yet."
pub fn read_synced_markers(
    qs_write: &mut crate::server::QueryServerWriteTransaction,
    person_uuid: Uuid,
    provider_uuid: Uuid,
) -> Result<hashbrown::HashSet<Uuid>, crate::prelude::OperationError> {
    use crate::idm::group_mapping::parse_marker;
    use crate::server::QueryServerTransaction;
    use netidm_proto::attribute::Attribute;

    let entry = qs_write.internal_search_uuid(person_uuid)?;
    let mut out = hashbrown::HashSet::new();
    if let Some(vs) = entry.get_ava_set(Attribute::OAuth2UpstreamSyncedGroup) {
        if let Some(markers) = vs.as_utf8_iter() {
            for value in markers {
                if let Some((prov, grp)) = parse_marker(value) {
                    if prov == provider_uuid {
                        out.insert(grp);
                    }
                }
            }
        }
    }
    Ok(out)
}

// Ensure the debug derive doesn't need to format `dyn RefreshableConnector`
// (which isn't Debug) — provide a minimal Debug impl that just lists keys.
impl std::fmt::Debug for ConnectorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<Uuid> = match self.by_uuid.lock() {
            Ok(g) => g.keys().copied().collect(),
            Err(_) => Vec::new(),
        };
        f.debug_struct("ConnectorRegistry")
            .field("connectors", &keys)
            .finish()
    }
}

// ===========================================================================
// Test-only mock connector (FR-011).
// ===========================================================================

/// In-process mock connector for integration tests. Lets tests drive
/// the "upstream changed → refresh → claim mutated" loop (FR-011a)
/// and the "connector error → fail-closed" loop (FR-011b) without a
/// real upstream provider.
///
/// Gated behind either `#[cfg(test)]` (for in-crate unit tests) or
/// the `testkit` feature (for integration tests using
/// `netidmd_testkit`). Zero release-mode code.
#[cfg(any(test, feature = "testkit"))]
#[derive(Debug)]
pub struct TestMockConnector {
    groups: std::sync::Mutex<Vec<String>>,
    error_mode: std::sync::Mutex<Option<ConnectorRefreshError>>,
    sub: String,
    refresh_call_count: std::sync::atomic::AtomicUsize,
}

#[cfg(any(test, feature = "testkit"))]
impl TestMockConnector {
    /// Build a fresh mock. `sub` is the upstream subject this mock
    /// will return on success — tests should not mutate it because
    /// changing `sub` mid-session trips the refresh call site's
    /// subject-consistency check.
    #[must_use]
    pub fn new(sub: impl Into<String>) -> Self {
        Self {
            groups: std::sync::Mutex::new(Vec::new()),
            error_mode: std::sync::Mutex::new(None),
            sub: sub.into(),
            refresh_call_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Replace the group list the mock will return on the next
    /// successful `refresh`. Drives the US1/US3 mutation scenarios.
    pub fn set_groups(&self, groups: Vec<String>) {
        #[allow(clippy::unwrap_used)]
        let mut guard = self.groups.lock().unwrap();
        *guard = groups;
    }

    /// Stage an error to be returned on the next `refresh`. The
    /// error is consumed on the next call, so setting `Some(_)`
    /// drives a single failure then recovery.
    pub fn set_error(&self, err: Option<ConnectorRefreshError>) {
        #[allow(clippy::unwrap_used)]
        let mut guard = self.error_mode.lock().unwrap();
        *guard = err;
    }

    /// Number of times [`RefreshableConnector::refresh`] has been
    /// invoked on this mock. Used by tests to assert the dispatch
    /// path did or did not fire.
    #[must_use]
    pub fn refresh_call_count(&self) -> usize {
        self.refresh_call_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(any(test, feature = "testkit"))]
#[async_trait]
impl RefreshableConnector for TestMockConnector {
    async fn refresh(
        &self,
        _session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        self.refresh_call_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        #[allow(clippy::unwrap_used)]
        if let Some(err) = self.error_mode.lock().unwrap().take() {
            return Err(err);
        }
        #[allow(clippy::unwrap_used)]
        let groups = self.groups.lock().unwrap().clone();
        Ok(RefreshOutcome {
            claims: ExternalUserClaims {
                sub: self.sub.clone(),
                email: previous_claims.email.clone(),
                email_verified: previous_claims.email_verified,
                display_name: previous_claims.display_name.clone(),
                username_hint: previous_claims.username_hint.clone(),
                groups,
            },
            new_session_state: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(sub: &str) -> ExternalUserClaims {
        ExternalUserClaims {
            sub: sub.to_string(),
            email: None,
            email_verified: None,
            display_name: None,
            username_hint: None,
            groups: Vec::new(),
        }
    }

    #[test]
    fn registry_empty_by_default() {
        let r = ConnectorRegistry::new_empty();
        assert!(r.is_empty());
        assert!(r.get(Uuid::new_v4()).is_none());
    }

    #[test]
    fn registry_register_and_lookup() {
        let uuid = Uuid::new_v4();
        let r = ConnectorRegistry::new_empty();
        let mock: Arc<dyn RefreshableConnector> = Arc::new(TestMockConnector::new("alice"));
        r.register(uuid, mock);
        assert!(!r.is_empty());
        assert!(r.get(uuid).is_some());
        assert!(r.get(Uuid::new_v4()).is_none());
    }

    #[tokio::test]
    async fn mock_returns_configured_groups() {
        let mock = TestMockConnector::new("alice");
        mock.set_groups(vec!["platform".into(), "audit".into()]);
        let out = mock.refresh(&[], &claims("alice")).await.expect("ok");
        assert_eq!(out.claims.sub, "alice");
        assert_eq!(out.claims.groups, vec!["platform", "audit"]);
        assert!(out.new_session_state.is_none());
        assert_eq!(mock.refresh_call_count(), 1);
    }

    #[tokio::test]
    async fn mock_staged_error_returned_once() {
        let mock = TestMockConnector::new("alice");
        mock.set_error(Some(ConnectorRefreshError::TokenRevoked));
        // First call gets the error.
        let err = mock.refresh(&[], &claims("alice")).await.unwrap_err();
        assert!(matches!(err, ConnectorRefreshError::TokenRevoked));
        // Second call succeeds — the error was consumed.
        let ok = mock.refresh(&[], &claims("alice")).await;
        assert!(ok.is_ok());
        assert_eq!(mock.refresh_call_count(), 2);
    }

    #[tokio::test]
    async fn mock_preserves_previous_narrowable_claims() {
        let mock = TestMockConnector::new("alice");
        mock.set_groups(vec!["platform".into()]);
        let prev = ExternalUserClaims {
            sub: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: Some(true),
            display_name: Some("Alice".into()),
            username_hint: Some("alice".into()),
            groups: vec![],
        };
        let out = mock.refresh(&[], &prev).await.expect("ok");
        assert_eq!(out.claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(out.claims.email_verified, Some(true));
        assert_eq!(out.claims.display_name.as_deref(), Some("Alice"));
        assert_eq!(out.claims.username_hint.as_deref(), Some("alice"));
    }
}
