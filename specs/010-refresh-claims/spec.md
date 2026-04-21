# Feature Specification: OAuth2 Refresh-Token Claim Re-Fetch (PR-REFRESH-CLAIMS)

**Feature Branch**: `010-refresh-claims`  
**Created**: 2026-04-21  
**Status**: Draft  
**Input**: User description: "PR-REFRESH-CLAIMS — OAuth2 refresh-token claim re-fetch. PR #3 of the 17-PR dex-parity roadmap (Gap #5). Dex re-decodes claims (re-fetches groups from the upstream connector that originally minted the session) every time an RP exchanges a refresh token for a new access token. Netidm stores the refresh token but never re-fetches, so a user whose upstream group membership changes keeps stale group claims for the refresh-token lifetime — which in netidm is long. Introduces a refresh hook on the OAuth2Session, a `RefreshableConnector` trait, per-session upstream-refresh state (DL27), and the policy that an upstream refresh failure returns `invalid_grant` rather than falling through to stale claims. Scope explicitly excludes any new connector implementation — only the plumbing + a test-only mock connector."

## Clarifications

### Session 2026-04-21

- Q: What audit signal does the refresh reconciler emit on each re-fetch? → A: Structured tracing span per refresh recording user UUID, connector UUID, groups-added, groups-removed — emitted only when the group set changed. Unchanged refreshes stay quiet.
- Q: What does the per-session upstream-refresh state look like on disk? → A: Opaque binary blob on OAuth2Session. Each connector owns its own serialization format; the netidm core stores and returns the blob unchanged on refresh. Matches dex's `connectorData []byte` approach.
- Q: When a refresh re-fetch yields a *changed* group set, does netidm persist to the Person entry or apply to the outgoing token only? → A: Persist-on-change. Compute the new upstream-synced group set, diff against the Person entry, write only if different. Refreshes whose group set is unchanged are read-only; write load is proportional to churn, not refresh rate.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Upstream group change flows to downstream RP on refresh (Priority: P1)

Alice logs in to netidm through an upstream identity provider (e.g. her corporate OIDC). At login she belongs to the upstream group `platform`, which the connector's group-mapping table translates into netidm membership of `platform-admin`. Portainer, a downstream OAuth2 relying party, receives an access token containing `"groups": ["platform-admin"]` and a long-lived refresh token.

Later that week, Alice is removed from the `platform` group at the upstream. Portainer, still holding its refresh token, exchanges it for a new access token before making an authorization decision.

**Why this priority**: This is the operational guarantee the whole feature exists to deliver. Without this, any RP that relies on the `groups` claim for authorization (Portainer, Grafana, a reverse proxy's `forward-auth`, etc.) silently gives Alice access she is no longer entitled to, for the full refresh-token lifetime. That is a production-relevant security regression — any audit will flag it.

**Independent Test**: Drive a full OIDC code-flow login through a mock upstream connector that initially returns `["platform"]`. Mutate the mock to return `[]`. Exchange the refresh token. Assert the new access token's `groups` claim reflects the mutation. Verify in isolation via `netidmd_testkit` — no real upstream, no CLI changes required.

**Acceptance Scenarios**:

1. **Given** Alice authenticated via an upstream connector that placed her in netidm group `platform-admin`, **When** the upstream removes her from the source group and Portainer exchanges its refresh token, **Then** the new access token's `groups` claim no longer contains `platform-admin`.
2. **Given** Alice authenticated via an upstream connector that placed her in `platform-admin`, **When** the upstream adds her to a second source group that maps to `platform-operator` and Portainer refreshes, **Then** the new access token contains both `platform-admin` and `platform-operator`.
3. **Given** Alice's upstream group membership is unchanged between refreshes, **When** Portainer refreshes, **Then** the new access token's `groups` claim is identical to the previous token's `groups` claim (no accidental churn).

---

### User Story 2 - Upstream refresh failure rejects the RP refresh (Priority: P2)

Alice's session was minted via an upstream connector. Between access-token expiries, the upstream provider becomes unreachable (network partition, upstream outage, rate-limit, the upstream's refresh token has been revoked, Alice's upstream account is suspended, etc.). Portainer exchanges its refresh token.

**Why this priority**: Without this behaviour the feature defeats its own purpose — if a connector failure silently falls through to "reuse the last claims we had," the access token continues to carry groups the upstream has (possibly deliberately) revoked. For a security-sensitive IdM, failing closed is the only defensible default. Dex's behaviour here is acknowledged as worth cross-checking, but the direction is: reject.

**Independent Test**: Configure a mock upstream connector to return an error on its refresh hook. Drive the same code-flow → refresh sequence. Assert the token endpoint returns `{"error": "invalid_grant"}` per RFC 6749 §5.2 and no new tokens are minted.

**Acceptance Scenarios**:

1. **Given** Alice's session is bound to an upstream connector that returns a transient network error on refresh, **When** Portainer exchanges the refresh token, **Then** the token endpoint responds with `invalid_grant` and no new access/refresh/ID tokens are issued.
2. **Given** Alice's upstream refresh token has been revoked by the upstream, **When** Portainer refreshes, **Then** the token endpoint responds with `invalid_grant`.
3. **Given** the upstream connector consistently fails on refresh, **When** Portainer falls back to a fresh authorization-code flow, **Then** the new flow succeeds or fails based on live upstream state (i.e. there is a working recovery path — rejection is not permanent).

---

### User Story 3 - Locally-granted memberships survive refresh (Priority: P2)

Alice is in upstream group `platform` (mapped to netidm group `platform-admin`) AND a netidm administrator has directly granted her membership of the local group `audit-readers`. Both groups appear in her original access token. Portainer refreshes.

**Why this priority**: Without this, every refresh would wipe admin-granted permissions because the upstream has no opinion on them. Admins would have to re-grant after every refresh cycle, which is absurd. The PR-GROUPS-PIPELINE (DL25) tagging system already distinguishes locally-managed from upstream-synced memberships — this PR just has to honour it in the refresh reconciler.

**Independent Test**: Seed Alice with both kinds of group (one upstream-synced tag, one locally-granted). Refresh. Assert both groups remain in the new access token. Mutate the mock upstream to return an empty group list. Refresh again. Assert the upstream-synced group is gone but the locally-granted group remains.

**Acceptance Scenarios**:

1. **Given** Alice has one upstream-synced group membership and one locally-granted group membership, **When** Portainer refreshes with the upstream still asserting the synced group, **Then** both groups are in the new access token.
2. **Given** Alice has one upstream-synced group membership and one locally-granted group membership, **When** the upstream revokes its group and Portainer refreshes, **Then** the upstream-synced group is gone from the new token and the locally-granted group is still present.
3. **Given** the upstream-synced group is gone from the new token, **When** the netidm administrator inspects Alice's entry, **Then** the locally-granted membership is still listed on the Person entry (the refresh did not mutate local state either).

---

### User Story 4 - Forward compatibility for sessions minted before this feature (Priority: P3)

A refresh token minted under netidm v0.1.11 (DL26, before this PR) is presented after the upgrade to DL27. The OAuth2Session row for that token has no connector-ref attribute because the concept did not exist when the session was minted.

**Why this priority**: Users do not tolerate "upgrade netidm and every long-lived refresh token is suddenly invalid." The refresh path must gracefully handle sessions that pre-date the new metadata. The chosen default is: sessions without connector-ref fall through to the pre-existing (non-refreshing) code path — they keep working exactly as before, with stale claims, until the RP completes a fresh authorization-code flow. That is the same risk profile as v0.1.11, so the upgrade is non-disruptive.

**Independent Test**: Seed an OAuth2Session entry without the new connector-ref attribute (simulating a pre-DL27 row). Exchange the refresh token. Assert the exchange succeeds and mints a new access token using the original cached claims.

**Acceptance Scenarios**:

1. **Given** a refresh token bound to an OAuth2Session without a connector-ref, **When** Portainer exchanges it, **Then** the exchange succeeds and mints new tokens carrying the claims cached on the original session (no re-fetch, no failure).
2. **Given** a fresh login after the DL27 upgrade places a connector-ref on the new OAuth2Session, **When** Portainer refreshes that new session, **Then** the refresh invokes the upstream re-fetch path (Scenarios 1–3 above apply).

---

### Edge Cases

- **Connector was removed between login and refresh**: an admin deletes the upstream connector entry after Alice's session was minted against it. The refresh path MUST treat this as equivalent to an upstream failure and return `invalid_grant` — there is no safe way to continue re-synchronising upstream groups against a connector the operator has chosen to decommission.
- **Locally-granted group conflicts with an upstream assertion**: the upstream and a local admin both grant the same netidm group. PR-GROUPS-PIPELINE's tagging treats these as independent concepts (locally-managed AND upstream-synced are orthogonal flags). The refresh reconciler MUST preserve the union: the group stays in the token as long as either source still asserts it.
- **User is disabled in netidm between login and refresh**: the refresh MUST be rejected with `invalid_grant` regardless of upstream state. This is existing behaviour and must not regress.
- **Refresh rate limiting**: a chatty RP that refreshes every few seconds could hammer the upstream. The feature MUST NOT mint a new access token without re-fetching (that would defeat the purpose). This PR ships with no cache — every connector-bound refresh performs one upstream call, bounded only by the connector's own per-call timeout. Adding a per-connector TTL is a follow-up that can land after operational experience shows it is needed (see `research.md` R8). If an RP's refresh cadence is an operational concern, the right lever is the RP's access-token lifetime, not claim caching.
- **Token introspection during the refresh**: an admin or RP introspecting a still-valid-but-soon-to-be-refreshed access token sees the stale groups. This is expected — the access token is what it says it is, until it expires. Introspection is not a refresh hook.
- **Refresh token rotation**: netidm rotates refresh tokens on each exchange. The new refresh token MUST remain bound to the same upstream connector-ref and upstream refresh state so the next cycle can re-fetch. Losing the binding across rotation is a silent regression to pre-DL27 behaviour and MUST be caught by a test.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: On every `grant_type=refresh_token` exchange at `/oauth2/token`, the system MUST re-resolve the caller's `groups` claim before minting new tokens — i.e. NOT reuse the `groups` value that was cached on the original token mint.
- **FR-002**: Re-resolution MUST combine locally-managed group memberships (read live from the Person entry) and upstream-managed group memberships (fetched live from the connector that minted the session and run through the connector's group-mapping table).
- **FR-003**: If the OAuth2Session has a connector-ref and the connector's refresh hook returns an error for any reason (network failure, upstream HTTP 4xx, upstream-refresh-token revoked, connector entry missing, etc.), the token endpoint MUST respond with `invalid_grant` per RFC 6749 §5.2 and MUST NOT mint new tokens.
- **FR-004**: Locally-granted group memberships MUST survive a refresh in which the upstream asserts an empty or reduced group set. The PR-GROUPS-PIPELINE locally-managed tagging is authoritative — a group tagged as locally-managed is included regardless of the upstream assertion.
- **FR-005**: (Elaborates FR-001 for the removal case.) Upstream-managed group memberships MUST be re-reconciled on every refresh. A group that was present on the original token MUST be removed from the new token if the upstream no longer asserts its source group.
- **FR-006**: An OAuth2Session minted before the introduction of the connector-ref attribute (i.e. sessions minted under any prior DL) MUST continue to support `grant_type=refresh_token` exchanges. On such sessions, the refresh path falls through to the pre-existing (non-refreshing) code path using the claims cached on the session.
- **FR-007**: Refresh-token rotation MUST preserve the connector-ref binding: after the exchange, the new refresh token's underlying OAuth2Session MUST carry the same connector-ref (and any necessary upstream-refresh state) as the exchanged session.
- **FR-008**: The system MUST provide a `RefreshableConnector` abstraction that upstream connectors implement, receiving the per-session upstream-refresh state and returning either fresh external user claims (groups, sub, verified email, etc.) or a failure.
- **FR-009**: The system MUST persist, on the OAuth2Session entry of sessions that support refresh re-fetch, (a) a reference to the connector that minted the session and (b) an opaque binary blob of connector-owned state needed for refresh. The netidm core MUST store and return this blob unchanged; the connector owns the blob's internal format (typically JSON) and is solely responsible for serialization, versioning, and interpretation. This state MUST be durable across netidm restarts. Rationale: matches dex's `connectorData []byte` approach, keeps the schema frozen across heterogeneous connectors (OIDC, SAML, LDAP, etc.), and decouples connector evolution from DL migrations.
- **FR-010**: The refresh reconciliation MUST write the newly-resolved upstream-synced group memberships to the Person entry *only when the set has actually changed* relative to what the Person entry already stores. Refreshes whose upstream-synced group set is unchanged MUST be read-only with respect to the Person entry — no write, no replication event, no audit noise. Locally-managed group memberships on the Person MUST be left untouched in either case. (The same reconciliation helper introduced by PR-GROUPS-PIPELINE for login-time updates is reused; it already enforces the locally-managed-vs-upstream-synced invariant. This PR's contribution is calling it from the refresh path with the added change-detection guard.)
- **FR-011**: The feature MUST ship with a test-only mock connector that implements `RefreshableConnector` with (a) a mutable in-memory group list so integration tests can drive the "upstream changed → refresh → claim mutated" loop, AND (b) a stagable error surface so tests can return any `ConnectorRefreshError` variant on the next refresh. Both capabilities are required for testing the happy path (US1, US3) and the fail-closed path (US2) without a real upstream provider.
- **FR-012**: The feature MUST NOT introduce any new external HTTP endpoints, admin CLI verbs, or client SDK methods. All new state is server-internal; admin visibility into the connector-ref binding is a follow-up concern.
- **FR-013**: The refresh reconciler MUST emit one structured tracing span per exchange when — and only when — the re-resolved `groups` claim differs from the previously issued token's `groups` claim. The span MUST include the user UUID, the connector UUID, the set of netidm groups added since the last issuance, and the set removed since the last issuance. Refreshes whose group set is unchanged MUST NOT emit this span (ordinary token-endpoint request logging still applies in every case).

### Key Entities *(include if feature involves data)*

- **OAuth2Session (extended)**: existing entity representing a downstream RP session. Gains two new optional attributes: a reference (UUID) to the upstream connector that minted it (if any), and an opaque connector-owned binary blob holding the state that connector needs at refresh time. The netidm core treats the blob as bytes — it does not parse, validate, or normalize its contents. Sessions without these attributes fall through to the pre-existing refresh path.
- **Upstream Connector (concept)**: a netidm-internal adapter that knows how to talk to a specific upstream identity provider. A connector that supports refresh-time claim re-fetch implements the `RefreshableConnector` contract: given per-session upstream-refresh state, return fresh external claims or an error. Concrete connector implementations are explicitly out of scope for this PR — only the contract and a test mock are in scope.
- **External User Claims (re-resolved)**: existing conceptual entity representing the claims surface the connector provides. On refresh it is re-computed from the live upstream assertion (not reused from the original token).
- **Group Mapping Table (reused)**: existing PR-GROUPS-PIPELINE entity. The refresh reconciler MUST run upstream group assertions through the same mapping table the login reconciler uses — if the admin has reconfigured the mapping between login and refresh, the refresh picks up the new mapping.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An upstream group change is visible to a downstream RP within one refresh cycle. On the next `grant_type=refresh_token` exchange after the upstream mutation, the new access token's `groups` claim reflects the current upstream state.
- **SC-002**: When the upstream is unreachable during refresh, 100% of refresh attempts on connector-bound sessions are rejected with `invalid_grant`. Zero refreshes silently fall through to stale claims.
- **SC-003**: Locally-granted group memberships survive 100% of refreshes, regardless of what the upstream asserts about upstream-synced groups.
- **SC-004**: Refresh tokens issued before the feature shipped continue to work after the upgrade. A deployment running a population of pre-DL27 refresh tokens sees zero new `invalid_grant` errors attributable to this feature's introduction.
- **SC-005**: An RP that refreshes on every API call does not experience a measurable increase in refresh latency (>20% tail latency) attributable to the re-fetch. The re-fetch path is bounded by the upstream's own latency budget; the netidm-internal overhead is negligible.
- **SC-006**: Manual operator validation: removing a user from an upstream group and waiting one refresh cycle observably removes that user's downstream authorization, without an admin having to revoke or log the user out of netidm.

## Assumptions

- **PR-GROUPS-PIPELINE (DL25) is deployed**: the group-mapping tables, the locally-managed/upstream-synced tagging, and the reconciliation helper already exist. This feature is a second consumer of that plumbing — the first consumer was the login path.
- **Each later connector PR owns its own `RefreshableConnector` implementation**: the trait shape is frozen in this PR, and PR-CONNECTOR-GITHUB, PR-CONNECTOR-GENERIC-OIDC, etc. each provide a concrete impl for their upstream. Connectors that cannot support refresh (no upstream refresh token, no stable sub) return an error — the session's refresh is then rejected, which is the desired fail-closed behaviour.
- **The "upstream refresh" is claim re-fetch, not upstream refresh-token exchange**: for OIDC upstreams, the connector may itself hold an upstream refresh token and exchange it against the upstream's token endpoint to get fresh claims. For non-OAuth2 upstreams (e.g. LDAP), "refresh" means re-binding or re-querying. The trait abstracts this — the session state is whatever each connector needs.
- **Refresh-token lifetime is unchanged by this feature**: netidm's existing refresh-token expiry semantics still apply. The re-fetch runs on every otherwise-valid exchange; it does not extend, shorten, or otherwise mutate the refresh-token lifetime.
- **Dex parity is the direction, not a straitjacket**: where dex silently falls open on connector refresh failure (connector without a `Refresh` method), netidm deliberately diverges toward "reject." This is consistent with the PR-RP-LOGOUT precedent (back-channel durability is also a netidm-beyond-dex extension, flagged in the dex-parity memory).
- **No CLI or SDK verbs for this PR**: admins cannot directly inspect the connector-ref binding on an OAuth2Session via CLI in this release. That visibility is a follow-up (likely bundled with PR-CONNECTOR-GITHUB when there's a real connector whose behaviour warrants admin inspection).
- **Release notes are hand-written at tag time**: per project convention, RELEASE_NOTES.md entry goes in with the version bump, not during the feature branch.
