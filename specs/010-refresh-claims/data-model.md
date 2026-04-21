# Data Model: OAuth2 Refresh-Token Claim Re-Fetch (PR-REFRESH-CLAIMS)

Phase 1 design artifact. Describes the entities whose shape this PR changes or introduces, and the state transitions for the refresh path. Implementation-level definitions (Rust field types, attribute UUIDs, serde tags) appear in the corresponding `.rs` files at implementation time; this document is authoritative for the invariants those types must uphold.

## Entity: `Oauth2Session` (modified, DL27)

Existing value-shaped entity, stored as one entry inside the `OAuth2Session` value-set on a Person entry. DL27 extends it with two optional fields.

| Field | DL introduced | Cardinality | Type | Description |
|---|---|---|---|---|
| `parent` | pre-DL26 | single | `Option<Uuid>` | UAT UUID that parents this OAuth2 session (unchanged). |
| `state` | pre-DL26 | single | `SessionState` | `ExpiresAt(..)` / `RevokedAt(..)` (unchanged). |
| `issued_at` | pre-DL26 | single | `OffsetDateTime` | When this session was minted (unchanged). |
| `rs_uuid` | pre-DL26 | single | `Uuid` | Downstream RP / OAuth2ResourceServer this session was issued for (unchanged). |
| `upstream_connector` | **DL27 NEW** | single, optional | `Option<Uuid>` | UUID of the connector (`OAuth2Client` entry with an upstream trust) that federated this login. `None` for locally-authenticated sessions and for all sessions minted before DL27. |
| `upstream_refresh_state` | **DL27 NEW** | single, optional | `Option<Vec<u8>>` | Opaque connector-owned byte blob. Netidm core stores and returns verbatim; only the connector interprets the contents. `None` when `upstream_connector` is `None` or when the connector chose not to persist any state. |

**Invariants (enforced by value-set serialization + DL27 migration tests)**:
- If `upstream_refresh_state = Some(_)` then `upstream_connector = Some(_)`. The inverse is not required (a connector that needs no per-session state can set `upstream_connector = Some(_)` and `upstream_refresh_state = None` — the refresh path still dispatches through the connector, just with an empty blob).
- `upstream_connector`, once set on session mint, MUST NOT change over the session's lifetime. Refresh-token rotation preserves both new fields verbatim to the replacement session (FR-007).
- `upstream_refresh_state` MAY be updated by the connector on every refresh (via `RefreshOutcome::new_session_state`); the replacement session carries the new blob.
- DL26 decoders reading DL27-written records MUST drop the new fields silently (forward compatibility during rolling upgrade). DL27 decoders reading DL26-written records MUST default both fields to `None`.

**Lifecycle**: unchanged from DL26. Sessions transition `Active → ExpiresAt` at refresh-token expiry or `Active → RevokedAt` on termination (PR-RP-LOGOUT). The new fields are purely informational — they do not participate in lifecycle transitions.

**Size bound**: `upstream_refresh_state` is expected to be at most a few kilobytes per session — typical OIDC refresh tokens plus a small JSON wrapper. Hard cap: 64 KiB (enforced at serialization time, return `OperationError::InvalidAttribute` on overflow, since an oversized blob almost certainly indicates a connector bug). No compression, no external key store.

---

## Entity: `ConnectorRegistry` (new, in-memory only)

Process-local registry owned by `IdmServer`. Populated once at server start; immutable thereafter for the lifetime of the process.

| Field | Cardinality | Type | Description |
|---|---|---|---|
| `by_uuid` | multi | `HashMap<Uuid, Arc<dyn RefreshableConnector + Send + Sync>>` | Lookup of concrete connector impls by the `OAuth2Client` entry UUID that declares their upstream trust. |

**Invariants**:
- The registry is read-only at runtime. Adding or removing a connector requires a netidmd restart. This matches how the existing provider-initiated auth paths (PR-LINKBY / PR-OIDC-CONNECTOR / PR-SAML-CONNECTOR) treat connector config — they read it at boot and cache it.
- Registry lookups are `Option`-returning — a missing entry is not an error at the registry level (it becomes `ConnectorRefreshError::ConnectorMissing` at the refresh call site).

**Population**: `ConnectorRegistry::new_empty()` returns an empty registry (what this PR ships). Later connector PRs (#4+) contribute concrete impls via a `register(uuid, impl)` method called during boot, before `IdmServer` exits its setup phase. The exact registration hook is out of scope for this PR — the empty registry plus a test-only injection path is sufficient to exercise the refresh path.

**Persistence**: none. The registry is rebuilt on every boot from DB configuration. Concrete connector state (HTTP client, signing key, discovery cache, etc.) lives inside each impl, not on the registry.

---

## Entity: `RefreshOutcome` (new value type)

Return type of `RefreshableConnector::refresh`. Conveys both the refreshed claims and the optionally-updated session state blob.

| Field | Cardinality | Type | Description |
|---|---|---|---|
| `claims` | single | `ExternalUserClaims` | The fresh upstream claim set. `sub` MUST equal the session's original `sub` (enforced by the refresh call site; mismatch → `ConnectorRefreshError::TokenRevoked`). |
| `new_session_state` | single, optional | `Option<Vec<u8>>` | `Some(_)` → replace `Oauth2Session::upstream_refresh_state` with this value. `None` → leave the stored blob unchanged. |

**Invariants**:
- `claims.groups` is the *authoritative* new upstream group assertion. The reconciler treats it as "the set of upstream-synced group memberships the user should have after this refresh." No merging with the previously-stored upstream markers — if the upstream dropped a group, it's gone.
- `claims.email`, `claims.email_verified`, `claims.display_name`, `claims.username_hint` are narrow-able. A connector MAY return `None` for any of these even if the original login set them; the refresh path MUST NOT use these claims to mutate the Person entry (they flow into the outgoing token claims only, subject to each connector's policy).

---

## Entity: `ConnectorRefreshError` (new enum)

Error type returned by `RefreshableConnector::refresh`. Mapped to `Oauth2Error::InvalidGrant` at the call site, with the variant logged at `error` level for operational visibility.

| Variant | Meaning | Typical cause |
|---|---|---|
| `Network(String)` | Transport-level failure talking to the upstream. | TCP refused, TLS handshake failed, upstream DNS down, request timeout. |
| `UpstreamRejected(u16)` | Upstream responded with a non-2xx HTTP status. | Upstream rate-limit (429), upstream misconfig (500), upstream revoked our client (401). |
| `TokenRevoked` | Upstream explicitly said the refresh token is invalid, OR the returned `sub` does not match the session's original `sub`. | User revoked upstream consent, upstream rotated our identity, connector bug returning wrong subject. |
| `ConnectorMissing` | The connector referenced by `Oauth2Session::upstream_connector` is not registered. | Admin deleted the `OAuth2Client` entry, or the registry was not populated for this connector. |
| `Serialization(String)` | The opaque blob is unreadable by the connector. | Blob format changed incompatibly between connector versions (connector-internal bug). |
| `Other(String)` | Anything else. | Connector returned an error the trait author did not anticipate; message is surfaced in the log. |

**Invariants**:
- Every variant MUST map to `Oauth2Error::InvalidGrant` at the refresh call site. There is no variant that means "ignore me, fall through to cached claims" (consistent with FR-003 fail-closed semantics).
- The `String` payload on `Network`, `UpstreamRejected`, `Serialization`, `Other` is for logs — it MUST NOT be surfaced to the RP (which would leak upstream implementation details across a trust boundary).

---

## State transitions: refresh path

One state-transition diagram covers the whole PR. A successful refresh token exchange moves the system through this sequence:

```
                                    refresh-token presented
                                             │
                                             ▼
                          ┌──────────────────────────────────┐
                          │ validate refresh token (existing)│
                          └──────────────────────────────────┘
                                             │
                                   valid ────┴──── invalid → invalid_grant
                                             │
                                             ▼
                          ┌──────────────────────────────────┐
                          │ load Oauth2Session from Person   │
                          └──────────────────────────────────┘
                                             │
                                             ▼
                                 upstream_connector ?
                             ┌───────────┴───────────┐
                           None                     Some(c)
                             │                         │
                             ▼                         ▼
                ┌─────────────────────┐    ┌──────────────────────────────┐
                │ existing path:      │    │ registry.get(c) ?            │
                │ mint from cached    │    └──────────────────────────────┘
                │ claims              │                │
                └─────────────────────┘       ┌────────┴─────────┐
                             │               None              Some(impl)
                             │                 │                  │
                             │                 ▼                  ▼
                             │          invalid_grant       impl.refresh(blob, prev_claims)
                             │         (ConnectorMissing)        │
                             │                              ┌────┴────┐
                             │                             Err        Ok(outcome)
                             │                              │              │
                             │                              ▼              ▼
                             │                        invalid_grant     sub matches prev?
                             │                                        ┌───┴───┐
                             │                                       No      Yes
                             │                                        │       │
                             │                                        ▼       ▼
                             │                                invalid_grant  reconcile & mint
                             │                               (TokenRevoked)      │
                             │                                                   ▼
                             │                                   ┌───────────────────────────────┐
                             │                                   │ preflight: desired vs existing│
                             │                                   │ upstream-synced marker set    │
                             │                                   └───────────────────────────────┘
                             │                                                   │
                             │                                            ┌──────┴──────┐
                             │                                          same         different
                             │                                            │             │
                             │                                            ▼             ▼
                             │                                       skip write    reconcile_upstream_
                             │                                       skip span     memberships(...)
                             │                                            │             │
                             │                                            │             ▼
                             │                                            │      emit change span (FR-013)
                             │                                            │             │
                             │                                            └──────┬──────┘
                             │                                                   │
                             └───────────────────────────────────────────────────┤
                                                                                 ▼
                                                          ┌─────────────────────────────────────────┐
                                                          │ mint new access + refresh + id tokens;  │
                                                          │ rotate refresh state on session         │
                                                          │ (including outcome.new_session_state    │
                                                          │  if Some(_)); preserve upstream_connector│
                                                          └─────────────────────────────────────────┘
                                                                                 │
                                                                                 ▼
                                                                         token response (200)
```

**Key invariants on this diagram**:
- The left branch (`upstream_connector = None`) is literal backwards compatibility: byte-for-byte identical behaviour to DL26. FR-006 enforces this.
- The right branch never reaches the mint step on any error — FR-003 fail-closed.
- The `reconcile` step runs inside the same write transaction as the mint, so the Person entry's memberOf and the outgoing token can never disagree (constitution Security Standards — no partial-auth states).
- The "same upstream-synced marker set → skip write, skip span" branch is the FR-010 persist-on-change and FR-013 change-tracing-only requirements, both fused into a single preflight diff.

---

## Relationships (summary)

- `Person` 1 — * `Oauth2Session` (value-set membership, unchanged)
- `Oauth2Session` 0..1 — 1 `OAuth2Client` via `upstream_connector` (new, DL27; nullable — reflects provider-initiated vs. local auth)
- `OAuth2Client` 1 — 0..1 `dyn RefreshableConnector` via `ConnectorRegistry::by_uuid` (new, in-memory only; nullable — connector might not be registered, e.g. in test or after connector-entry deletion)
- `Oauth2Session` 1 — 1 `Person` via the value-set (unchanged)
- `Oauth2Session` 1 — 1 `OAuth2ResourceServer` via `rs_uuid` (unchanged)
- `ExternalUserClaims` 1 — 1 `Oauth2Session` via the refresh outcome (transient — not persisted; flows into the new token claims and, for `claims.groups`, into the reconciliation helper)
