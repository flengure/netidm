# Research: OAuth2 Refresh-Token Claim Re-Fetch (PR-REFRESH-CLAIMS)

Phase 0 research resolves the technical-context unknowns flagged in `plan.md` before Phase 1 design begins. Each decision is recorded as Decision / Rationale / Alternatives considered.

## R1. Dex parity for connector refresh failure

**Decision**: Netidm diverges from dex and fails closed. An `Oauth2Error::InvalidGrant` is returned for any `ConnectorRefreshError` variant (network, upstream-rejected, token-revoked, connector-missing, serialization). No silent fallthrough to cached claims.

**Rationale**: Dex's `server/handlers.go` refresh grant calls the connector's `Refresh` method only if the connector implements the `storage.RefreshConnector` interface (optional in Go — connectors without a `Refresh` method silently skip re-fetch). For netidm, which is downstream of CI/CD and reverse-proxy auth paths, a silent skip-on-failure means an administrator who has *deliberately* revoked a user's upstream membership cannot rely on netidm to reflect that revocation until the user's RP re-does a full code-flow login — which may be weeks away. Fail-closed matches the PR-RP-LOGOUT precedent (back-channel-durability is a netidm-beyond-dex extension for the same "operational visibility and security" reason, flagged in the dex-parity memory).

**Alternatives considered**:
- **Follow dex exactly**: silent skip. Rejected — inconsistent with PR-RP-LOGOUT's posture and weakens the operational guarantee this feature exists to provide.
- **Fail-closed but with an admin-configurable override**: a per-connector "fail-open" flag for operators who want dex semantics. Rejected for this PR — adds an admin surface (FR-012 says "no new CLI verbs"). Can be added later if operational demand appears.

## R2. `RefreshableConnector` trait shape

**Decision**: The trait takes both the opaque per-session blob AND a reference to the previously-issued claims, so the connector can preserve non-upstream-asserted fields when the upstream refresh returns a narrower claim set.

```rust
#[async_trait::async_trait]
pub trait RefreshableConnector: Send + Sync {
    async fn refresh(
        &self,
        session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError>;
}

pub struct RefreshOutcome {
    pub claims: ExternalUserClaims,
    pub new_session_state: Option<Vec<u8>>,
}
```

**Rationale**: Dex's `Refresh(ctx, scopes, identity Identity) (Identity, error)` passes the previous `Identity` for exactly this reason: some upstream refresh paths (e.g. the OIDC token endpoint with `grant_type=refresh_token` and no `scope=openid`) return only a subset of the fields the original authorization flow returned. Letting the connector copy-forward `email`, `email_verified`, `username_hint` from `previous_claims` keeps the refreshed token coherent. The `RefreshOutcome::new_session_state` lets the connector rotate its opaque blob (common for OAuth2 upstream refresh-token rotation); `None` means "don't touch the blob."

**Alternatives considered**:
- **Blob-only input** (`refresh(&[u8]) -> Result<ExternalUserClaims, _>`): simpler, but forces every connector to re-derive preservation-worthy claims from inside the blob. Rejected — pushes serialization complexity into every connector.
- **Pass the full `Oauth2Session`**: too broad — connector does not need `rs_uuid`, `state`, `issued_at`, `parent` to do its job. Passing them couples the trait to internal types.
- **Return only claims, side-effect the blob via `&mut`**: would break the clean "return a value" contract. Explicit `RefreshOutcome` wins.

## R3. `reconcile_upstream_memberships` reuse

**Decision**: Reuse the existing helper from PR-GROUPS-PIPELINE unchanged. The diff-against-entry guard (FR-010 "persist-on-change") lives at the refresh call site, not inside the helper.

**Rationale**: The helper was designed for the login-time use case, which already writes the memberOf marker unconditionally (logins are infrequent relative to refreshes, so unconditional write is fine). For refreshes, skipping the write when nothing changed is a new concern. Burying the diff guard inside the helper would change its contract for all callers and introduce a subtle behavioural difference between "called at login" and "called at refresh." The cleaner design keeps the helper pure (computes + writes the desired state) and wraps it at the refresh site with a preflight read that decides whether to invoke it at all.

Call-site pattern:

```rust
// Preflight: read the current upstream-synced markers for this (person, provider) pair
let existing_synced: HashSet<Uuid> = read_synced_markers(qs_write, person_uuid, provider_uuid)?;
let desired_synced: HashSet<Uuid> = resolve_desired(mapping, &fresh_claims.groups);

if existing_synced != desired_synced {
    reconcile_upstream_memberships(qs_write, person_uuid, provider_uuid, mapping, &fresh_claims.groups)?;
    emit_change_span(user_uuid, provider_uuid, added, removed);  // FR-013
}
// else: no write, no span, no replication event
```

**Alternatives considered**:
- **Embed the diff guard in `reconcile_upstream_memberships`**: rejected per above (changes contract for all callers, couples rarely-changing helper to a concern specific to one caller).
- **A new `reconcile_upstream_memberships_if_changed` parallel helper**: rejected as an unnecessary second entry point — two helpers with near-identical bodies invite drift.

## R4. DL-gated `Oauth2Session` serialization

**Decision**: DL27 adds `upstream_connector: Option<Uuid>` and `upstream_refresh_state: Option<Vec<u8>>` to the `Oauth2Session` struct. Serialization in `valueset/oauth2session.rs` picks the encode/decode branch from the domain level: DL26-and-below decoders ignore the new fields on encode and set them to `None` on decode (round-trips existing records cleanly); DL27 decoders read both fields if present and default them to `None` if absent (round-trips DL26 records after migration).

**Rationale**: `Oauth2Session` is a value inside a value-set on the Person entry, not its own top-level attribute. DL27's migration does not create a new attribute or entry class; it changes the wire format of an existing attribute. This is the same pattern DL22 used when it added fields to `OAuth2RsClaimMap`. The DL gate is one branch in the decoder that reads `dl_version` from the store header before deserializing each `Oauth2Session` value.

**Alternatives considered**:
- **New attribute carrying the state in a separate sidecar value-set keyed by session UUID**: rejected — introduces cross-attribute consistency concerns (what if the sidecar survives the session deletion?) and duplicates the session's identity.
- **New top-level entry class `OAuth2SessionRefreshState`**: rejected as overkill for two optional fields; the existing in-session shape is the right place.

## R5. Connector registry at boot

**Decision**: `IdmServer` gains a `connector_registry: Arc<ConnectorRegistry>` field. `ConnectorRegistry` is a `HashMap<Uuid, Arc<dyn RefreshableConnector + Send + Sync>>` built once during `IdmServer::start` by scanning `OAuth2Client` entries whose `OAuth2ClientAuthorisationEndpoint` is non-empty (the existing upstream-trust marker from PR-LINKBY / PR-OIDC-CONNECTOR / PR-SAML-CONNECTOR). This PR registers no concrete impls — `ConnectorRegistry::new()` returns an empty registry, and the refresh path gracefully handles empty-registry lookups via `ConnectorRefreshError::ConnectorMissing → Oauth2Error::InvalidGrant`.

**Rationale**: Later connector PRs (#4+) each attach their concrete implementation to the registry at boot, via a discoverable hook on `IdmServer::start` (e.g. each connector crate exposes a `fn register_with(&ConnectorRegistry, &QueryServer)` called in registration order). This PR's scope is only the plumbing, so the registry ships empty and the integration-test mock uses a test-only injection path to register itself without a DB entry.

**Alternatives considered**:
- **Global static registry** (`OnceLock<ConnectorRegistry>`): rejected — makes per-test isolation hard and inhibits future multi-tenant deployments.
- **Per-session registry passed through function arguments**: rejected — the call stack from `check_oauth2_token_refresh` to the connector is deep; threading the registry through every layer is noisy. An `Arc` on `IdmServer` is the least invasive.

## R6. Connector-deletion edge case

**Decision**: If `Oauth2Session::upstream_connector = Some(uuid)` and `ConnectorRegistry::get(uuid) = None`, the refresh returns `ConnectorRefreshError::ConnectorMissing`, mapped at the call site to `Oauth2Error::InvalidGrant`. No fallback to "session without connector-ref" semantics, no retry, no grace period.

**Rationale**: The spec (edge-cases bullet 1 and US4 assumption 2) is explicit: once a session was minted through a connector, the connector's authority is required for every subsequent refresh. If an admin has deleted the connector, the sessions minted against it are no longer refreshable — the admin action is the semantic "revoke everything this connector vouched for." Retrying or falling back would undermine that admin action.

**Alternatives considered**:
- **Fall back to cached-claims path** (treat deleted-connector sessions as pre-DL27 sessions): rejected — silently weakens the admin's revocation action.
- **Revoke the session proactively** (mutate the session to `RevokedAt` in the same transaction): tempting but out of scope — the refresh path is read-mostly, and session state mutations belong to `terminate_session`. The session naturally ages out via the existing refresh-token expiry; no leak.

## R7. Test-mock location

**Decision**: `TestMockConnector` lives in `server/lib/src/idm/oauth2/connector.rs` gated by `#[cfg(any(test, feature = "testkit"))]`. `netidmd_testkit` adds a `pub use` re-export behind its existing `testkit` feature. Zero release-mode code.

**Rationale**: Putting the mock in the same file as the trait keeps it close to the contract it implements — changes to the trait immediately invalidate the mock. Re-exporting from `netidmd_testkit` makes it reachable from integration tests without making `netidmd_testkit` a build-time dependency of `netidmd_lib`.

**Alternatives considered**:
- **Mock in `server/testkit/src/`**: rejected — integration test would depend on the mock, but unit tests in `netidmd_lib` need it too; duplicating the type or threading it through another crate is worse.
- **Mock in a separate `netidmd_lib_testmocks` crate**: rejected as over-engineering for one connector mock.

## R8. Refresh-cache TTL policy

**Decision**: No cache in this PR. Every refresh that hits a connector-bound session performs an upstream call.

**Rationale**: Dex does not cache. The spec's cache-TTL discussion is an acknowledged planning-stage placeholder, not a user-visible guarantee. Caching introduces correctness risk (a user whose upstream groups changed in the cache window would still see stale claims — the exact bug this feature is fixing). The cost of one upstream call per refresh is bounded by the upstream's own latency; if that cost is unacceptable, the RP should increase its access-token lifetime rather than expect netidm to cache claims.

**Alternatives considered**:
- **Per-connector TTL with a safe default (e.g. 60 s)**: rejected for this PR — adds an admin surface (FR-012) and reintroduces the staleness window this feature exists to eliminate. Can be added as an opt-in per-connector config in a follow-up if operational demand surfaces.
- **TTL driven by upstream `expires_in`**: rejected — upstream `expires_in` is about the access token's lifetime, not about claim staleness. Coupling them would be semantically wrong.
