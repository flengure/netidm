# Contract: `RefreshableConnector` Trait (PR-REFRESH-CLAIMS)

This is the stable interface every upstream connector implementation must honour from DL27 onward. This PR defines the trait, ships a test-only mock, and wires the refresh path to call it. Later PRs (#4 PR-CONNECTOR-GITHUB, #5 PR-CONNECTOR-GENERIC-OIDC, #6+) provide concrete implementations — each of which must conform to the invariants stated here.

## Location

- Module: `server/lib/src/idm/oauth2/connector.rs` (new)
- Visibility: `pub trait`, `pub struct`, `pub enum` — these are cross-crate types the later connector PRs will depend on.
- Feature-gate: `TestMockConnector` lives in the same file under `#[cfg(any(test, feature = "testkit"))]`.

## Trait definition

```rust
use async_trait::async_trait;
use crate::idm::authsession::handler_oauth2_client::ExternalUserClaims;

/// Trust-provider-specific hook that re-fetches a user's claims at
/// OAuth2 refresh-token time. Implemented by every upstream connector
/// (OIDC, SAML, LDAP, GitHub, Google, …). Netidm core invokes this
/// during `grant_type=refresh_token` handling for sessions that were
/// minted through a provider-initiated login.
///
/// # Errors
///
/// Every [`ConnectorRefreshError`] variant maps to
/// [`Oauth2Error::InvalidGrant`] at the call site. The trait
/// implementer MUST NOT return success with a stale or cached claim
/// set — if the upstream is unreachable or the refresh token is
/// revoked, return an error.
///
/// # Examples
///
/// ```rust,ignore
/// # use async_trait::async_trait;
/// # use netidmd_lib::idm::oauth2::connector::{RefreshableConnector, RefreshOutcome, ConnectorRefreshError};
/// # use netidmd_lib::idm::authsession::handler_oauth2_client::ExternalUserClaims;
/// struct NoopConnector;
///
/// #[async_trait]
/// impl RefreshableConnector for NoopConnector {
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
    async fn refresh(
        &self,
        session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError>;
}

/// Successful outcome of [`RefreshableConnector::refresh`]. Carries the
/// refreshed claim set and optionally an updated opaque session-state
/// blob the connector wishes netidm to persist on the session.
#[derive(Debug, Clone)]
pub struct RefreshOutcome {
    /// Fresh claims from the upstream provider. `sub` MUST equal the
    /// session's original subject — any mismatch is treated as a
    /// security-class event ([`ConnectorRefreshError::TokenRevoked`]
    /// at the refresh call site).
    pub claims: ExternalUserClaims,
    /// If `Some(_)`, replaces the stored `upstream_refresh_state`
    /// on the session. If `None`, leaves the stored blob unchanged.
    pub new_session_state: Option<Vec<u8>>,
}

/// Failure modes the refresh call site recognises.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorRefreshError {
    #[error("upstream transport error: {0}")]
    Network(String),
    #[error("upstream responded with HTTP {0}")]
    UpstreamRejected(u16),
    #[error("upstream refresh token revoked")]
    TokenRevoked,
    #[error("connector {0} is not registered")]
    ConnectorMissing(uuid::Uuid),
    #[error("session state could not be deserialized: {0}")]
    Serialization(String),
    #[error("connector error: {0}")]
    Other(String),
}
```

## Invariants enforced at the call site (not by the trait itself)

The refresh call site in `IdmServerProxyWriteTransaction::check_oauth2_token_refresh` enforces invariants the trait cannot express. Connector authors MUST understand these:

1. **Subject consistency**: if `RefreshOutcome::claims.sub` differs from the `Oauth2Session`'s originally-minted subject, the call site rejects with `Oauth2Error::InvalidGrant` as if the connector had returned `ConnectorRefreshError::TokenRevoked`. This is a defence against a compromised connector returning someone else's identity.
2. **Authoritative groups**: `RefreshOutcome::claims.groups` is treated as the complete, authoritative new upstream group assertion. The call site does NOT merge it with prior upstream markers. If the connector wants a group to persist, the group name must appear in this field on this call.
3. **Opaque blob rotation**: if `RefreshOutcome::new_session_state = Some(new)`, the call site writes `new` to `Oauth2Session::upstream_refresh_state` on the new (rotated) session. If `None`, the call site copies the old blob forward unchanged.
4. **Connector-ref continuity**: the rotated session's `upstream_connector` field is always copied from the source session. Connectors CANNOT change which connector a session is bound to mid-life.
5. **Failure swallow**: every `Err(_)` from `refresh` becomes `Oauth2Error::InvalidGrant` to the RP. The specific variant is logged server-side at `error` level with the connector UUID and the user UUID; the RP sees only `invalid_grant` (per RFC 6749 §5.2 — no leak of upstream implementation details).

## `TestMockConnector` shape

```rust
#[cfg(any(test, feature = "testkit"))]
pub struct TestMockConnector {
    /// Current group set the mock will return on next `refresh` call.
    /// Mutable via `set_groups` so tests can drive upstream mutation.
    groups: Arc<Mutex<Vec<String>>>,
    /// If `Some(_)`, `refresh` returns this error instead of the groups.
    /// Lets tests drive the fail-closed path.
    error_mode: Arc<Mutex<Option<ConnectorRefreshError>>>,
    /// Subject identifier this mock will return on success. Must stay
    /// constant through a session's lifetime — tests should not mutate
    /// this to avoid spuriously tripping the subject-consistency check.
    sub: String,
}

#[cfg(any(test, feature = "testkit"))]
impl TestMockConnector {
    pub fn new(sub: impl Into<String>) -> Self { /* … */ }
    pub fn set_groups(&self, groups: Vec<String>) { /* … */ }
    pub fn set_error(&self, err: Option<ConnectorRefreshError>) { /* … */ }
}

#[cfg(any(test, feature = "testkit"))]
#[async_trait]
impl RefreshableConnector for TestMockConnector {
    async fn refresh(
        &self,
        _session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        if let Some(err) = self.error_mode.lock().unwrap().take() {
            return Err(err);
        }
        Ok(RefreshOutcome {
            claims: ExternalUserClaims {
                sub: self.sub.clone(),
                groups: self.groups.lock().unwrap().clone(),
                email: previous_claims.email.clone(),
                email_verified: previous_claims.email_verified,
                display_name: previous_claims.display_name.clone(),
                username_hint: previous_claims.username_hint.clone(),
            },
            new_session_state: None,
        })
    }
}
```

- `set_error` uses `take()` so the injected error is consumed on the next refresh — tests can stage a single failure then observe recovery.
- `set_groups` replaces the full set — tests drive both add and remove by calling it with the desired post-mutation list.
- `sub` is fixed at construction; tests that want to exercise the subject-consistency check (invariant 1 above) should use a separate mock instance or a dedicated helper.

## Re-export from testkit

```rust
// server/testkit/src/lib.rs
#[cfg(feature = "testkit")]
pub use netidmd_lib::idm::oauth2::connector::{
    ConnectorRefreshError, RefreshOutcome, RefreshableConnector, TestMockConnector,
};
```

Integration tests under `server/testkit/tests/testkit/` can then `use netidmd_testkit::TestMockConnector;` directly.

## Out of scope for this PR

- Concrete connector implementations (each is a separate PR #4+).
- Admin CLI / HTTP surface to inspect the registry, list connector-bound sessions, or force-revoke a connector's sessions.
- TTL / caching layer on top of the trait (R8 in research.md defers this).
- Per-connector configuration schema for refresh behaviour (e.g. preservation policy for claims the upstream does not re-assert).
