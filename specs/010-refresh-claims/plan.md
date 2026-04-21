# Implementation Plan: OAuth2 Refresh-Token Claim Re-Fetch (PR-REFRESH-CLAIMS)

**Branch**: `010-refresh-claims` | **Date**: 2026-04-21 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/010-refresh-claims/spec.md`

## Summary

On every `grant_type=refresh_token` exchange at `/oauth2/token`, re-resolve the caller's `groups` claim before minting new tokens — instead of reusing whatever was cached on the original session. For sessions bound to an upstream connector (federated logins), the netidm core calls the connector's new `RefreshableConnector::refresh` hook, receives fresh `ExternalUserClaims`, runs them through PR-GROUPS-PIPELINE's existing `reconcile_upstream_memberships` helper (with a persist-on-change guard), and mints the new token from the reconciled set. Upstream refresh failures are fail-closed: return `Oauth2Error::InvalidGrant`, no tokens issued. Locally-granted memberships pass through untouched — PR-GROUPS-PIPELINE's locally-managed-vs-upstream-synced tagging is authoritative. Sessions minted before DL27 (no connector-ref) fall through to the existing cached-claims path so the upgrade is non-disruptive. One structured tracing span is emitted only when the group set actually changed, matching the persist-on-change write semantics.

Zero new external surface: no HTTP route, no CLI verb, no client SDK method. All new state lives on the existing `Oauth2Session` value shape — two new optional fields (connector-ref UUID + opaque connector-owned byte blob). DL27 migration teaches the serializer about the new fields without invalidating any existing session record.

## Technical Context

**Language/Version**: Rust stable (see `rust-toolchain.toml`)
**Primary Dependencies**: Existing — `netidmd_lib` (MVCC entry DB, schema/migration framework, existing `reconcile_upstream_memberships` helper from PR-GROUPS-PIPELINE), `netidm_proto` (Attribute / EntryClass / constants), `compact_jwt` (already used for OIDC), `async-trait` (for `RefreshableConnector`), `hashbrown` (std `HashSet` banned by clippy), `tracing` (for the change-detection span — FR-013). No new workspace deps.
**New Dependencies**: None.
**Storage**: Netidm MVCC entry database. DL27 migration extends the `Oauth2Session` value struct (`server/lib/src/value.rs`) with two new optional fields:
- `upstream_connector: Option<Uuid>` — UUID reference to the connector entry (`OAuth2Client`) that minted this session via a provider-initiated login. `None` for locally-authenticated sessions and sessions minted pre-DL27.
- `upstream_refresh_state: Option<Vec<u8>>` — opaque connector-owned byte blob (typically the connector's own JSON), stored and returned by netidm unchanged. `None` when `upstream_connector` is `None` or when the connector chose not to record any refresh state.

No new entry class, no new top-level attribute, no new ACP — `Oauth2Session` is a value-valued attribute on the Person entry, not its own entry class. The serialization change is internal to `ValueSetOauth2Session`; DL27 gates the new serializer so DL26 databases continue to round-trip their existing sessions.

**Testing**: `cargo test` via `server/testkit` integration infrastructure (real in-process netidmd); unit tests co-located in the new `idm::oauth2::connector` module and in the modified `check_oauth2_token_refresh` path. A `TestMockConnector` lives under `#[cfg(test)]` in the new module and is re-exported from `netidmd_testkit` for integration-test use (the trait + mock together unblock integration tests; no real upstream required).
**Target Platform**: Linux server (same as rest of netidm).
**Project Type**: Library changes only (`server/lib`). No `server/core` surface, no `tools/cli` surface.
**Performance Goals**:
- Refresh handler latency budget unchanged: under normal local conditions still bounded by the single `internal_modify` commit (sub-millisecond netidm-internal). With an upstream connector, latency is bounded by the upstream's response time — this is intrinsic to the feature. The netidm-internal overhead on top of the upstream call MUST stay under 5% (connector dispatch + reconciliation helper + possible entry write).
- Refreshes whose upstream group set is unchanged MUST NOT issue a database write — SC-003 enforces this at the operational level, FR-010 enforces it at the code level.

**Constraints**:
- All new doc comments per constitution §Documentation Standards.
- `cargo clippy -- -D warnings` must remain clean (constitution §IV).
- `cargo test` (default features) must pass — no `--all-features` (dhat profiler singleton conflicts with parallel harness, per project memory).
- The `RefreshableConnector` trait MUST use `async_trait` — the hook will do network I/O in later connector PRs.
- The change-detection guard (FR-010) MUST run inside the same write transaction as the token mint, so that the Person entry's memberOf state and the outgoing token never diverge within a single refresh.
- The opaque byte blob (FR-009) is at most a few kilobytes per session (typical OIDC refresh-token-sized payloads); no compression, no external KMS, no encryption beyond what netidm's existing DB encryption already provides.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Ethics & Human Rights | PASS | No new PII fields. The upstream connector UUID is already-observable admin metadata; the opaque byte blob carries connector-internal state (e.g. an upstream refresh token) that belongs to the user's federated session — same sensitivity class as the existing `rs_uuid` on `Oauth2Session`. User self-control unchanged: revoking the session or logging out still reaches the same `terminate_session` path (PR-RP-LOGOUT) and invalidates the refresh attempt before it reaches the connector. |
| II. Humans First | PASS | A user whose upstream group membership was revoked sees the revocation reflected on the very next refresh — no admin intervention, no re-login required. Failure mode is user-visible (RP re-prompts for authentication) rather than silently wrong (stale groups). |
| III. Correct & Simple | PASS | `cargo test` remains self-contained — the `TestMockConnector` runs in-process, no external upstream required. No new external dependency. No new storage engine. The trait `RefreshableConnector` is a single method with a single opaque input and a single output; fits on one page. |
| IV. Clippy & Zero Warnings | PASS | No `#[allow(...)]` planned. `hashbrown::HashSet` reused for group-set diffs. `async_trait` is already in workspace deps. |
| V. Security by Hierarchy | PASS | **Elimination**: the default behaviour for an unrecoverable upstream is to reject the refresh — not to warn-and-proceed with stale claims. **Substitution**: the opaque byte blob replaces the alternative of mirroring every connector's state into the core schema; connectors that want to store less (or more) can, without a schema migration per connector. **Engineering Control**: the change-detection guard (FR-010) reduces the attack surface for replication storms / audit-log spam that a chatty RP could trigger. |
| Security Standards | PASS | FR-003 denies the refresh on any upstream failure — no partial-auth state. The opaque blob MUST NOT appear in logs (FR-013 emits user UUID, connector UUID, groups-added, groups-removed — not the blob contents). FR-010's persist-on-change keeps audit logs meaningful (entries appear only when something changed). |
| Documentation Standards | REQUIRED | Doc comments on every new `pub` item: `RefreshableConnector` trait, `ConnectorRefreshError` enum, `Oauth2Session` new fields. `# Errors` on every `Result`-returning `pub fn` added. `# Examples` on `RefreshableConnector`. `//!` module doc on any new module (e.g. `idm::oauth2::connector`). |
| Testing Standards | REQUIRED | Unit tests for (a) `TestMockConnector::refresh` round-trip, (b) `check_oauth2_token_refresh` calling the connector hook when `upstream_connector` is `Some`, (c) connector error → `Oauth2Error::InvalidGrant`, (d) unchanged group set → no Person-entry write, (e) changed group set → exactly one tracing span emitted. Integration test (testkit) driving the full "upstream changed → refresh → token groups updated, Person entry touched exactly once" loop. |
| DL Migration | REQUIRED | DL27 migration introduced; round-trip test in `migrations.rs` asserts (a) an existing DL26 DB with active sessions upgrades cleanly, (b) the new session fields default to `None` on existing sessions, (c) new sessions can round-trip with `upstream_connector = Some(_)` and a non-empty `upstream_refresh_state` blob. |

No constitution violations. No Complexity Tracking entries required.

## Project Structure

### Documentation (this feature)

```text
specs/010-refresh-claims/
├── plan.md              # This file
├── research.md          # Design decisions + alternatives (Phase 0)
├── data-model.md        # Entity model (Phase 1)
├── quickstart.md        # Test scenarios (Phase 1)
├── contracts/
│   └── refreshable-connector.md  # Trait contract (Phase 1)
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Generated by /speckit.tasks
```

### Source Code Changes

```text
proto/src/
└── (no changes — no new attribute or class; Oauth2Session is a value, not an entry)

server/lib/src/
├── constants/
│   └── mod.rs                                  # DOMAIN_LEVEL_27; bump TGT/MAX; PREVIOUS follows
├── value.rs                                    # + Oauth2Session::upstream_connector,
│                                                 + Oauth2Session::upstream_refresh_state
│                                                 + serialization round-trip
├── valueset/oauth2session.rs                   # DL27-gated encode/decode for the two new fields
├── server/migrations.rs                        # DL26 → DL27 phase; round-trip test
├── idm/
│   ├── mod.rs                                  # + pub mod oauth2_connector;
│   ├── oauth2_connector.rs                     # NEW (sibling file to the existing
│   │                                                    flat idm/oauth2.rs): RefreshableConnector
│   │                                                    trait, RefreshOutcome, ConnectorRefreshError
│   │                                                    enum, ConnectorRegistry, TestMockConnector
│   │                                                    (#[cfg(any(test, feature = "testkit"))]
│   │                                                    + testkit re-export)
│   ├── oauth2.rs                               # modify check_oauth2_token_refresh:
│   │                                                    read session.upstream_connector;
│   │                                                    if Some → dispatch refresh;
│   │                                                    call reconcile_upstream_memberships;
│   │                                                    diff-against-entry guard for
│   │                                                    persist-on-change (FR-010);
│   │                                                    emit change-detection tracing span
│   │                                                    (FR-013); on connector error →
│   │                                                    Oauth2Error::InvalidGrant
│   ├── group_mapping.rs                        # no change — reuses existing
│   │                                              reconcile_upstream_memberships; the
│   │                                              PR's diff-guard wraps it at the refresh site
│   └── authsession/
│       └── provider_initiated.rs               # when minting the first access+refresh
│                                                 token for a provider-initiated login,
│                                                 populate session.upstream_connector and
│                                                 session.upstream_refresh_state on the
│                                                 new Oauth2Session entry
│
└── server/
    └── idmserver.rs                            # IdmServer::connector_registry: an
                                                  Arc<ConnectorRegistry> keyed by connector
                                                  UUID; populated at boot from the DB's
                                                  OAuth2Client entries that declare an
                                                  upstream trust; looked up on refresh

server/testkit/src/
└── lib.rs                                      # re-export TestMockConnector + a helper
                                                  `setup_connector_with_mock` that seeds an
                                                  OAuth2Client with provider-initiated trust
                                                  and binds the mock to it for the duration
                                                  of the test

server/testkit/tests/testkit/
└── refresh_claims_test.rs                      # NEW: US1–US4 integration tests
```

**Structure Decision**: Library-only changes, with one testkit re-export to enable integration tests. The HTTP / CLI / SDK surfaces remain untouched (FR-012). The heaviest churn is in `idm::oauth2.rs` (the token-endpoint handler) and `value.rs` / `valueset/oauth2session.rs` (the serialization of the new session fields). A new `idm::oauth2_connector` module (sibling file to the existing flat `idm::oauth2` — not a sub-module of it — because `idm/oauth2.rs` is a ~9 kLOC flat file and converting it to a directory is an unrelated refactor) collects the trait, errors, and registry in one place so later connector PRs (#4 PR-CONNECTOR-GITHUB, #5 PR-CONNECTOR-GENERIC-OIDC, …) plug in by implementing `RefreshableConnector` and registering with `ConnectorRegistry` at boot — no further changes to `idm::oauth2.rs` from their side.

## Complexity Tracking

No constitution violations, no extra complexity to justify.

## Phases

### Phase 0: Research (research.md)

1. **Dex parity for connector refresh failure**
   - Read `github.com/dexidp/dex/server/handlers.go` around the refresh grant.
   - Confirm the claim that dex silently falls open when a connector implements no `Refresh`.
   - Document the intentional divergence: netidm diverges toward fail-closed (FR-003), consistent with the PR-RP-LOGOUT back-channel-durability extension.
2. **Trait shape: dex `storage.Connector.Refresh`**
   - Look at dex's `storage/storage.go` for the `RefreshConnector` interface (`Refresh(ctx, scopes, identity Identity) (Identity, error)`).
   - Decide whether netidm's trait takes `(session_state: &[u8])` only, or `(session_state: &[u8], previous_claims: &ExternalUserClaims)` — dex passes the previous identity so the connector can preserve fields the upstream doesn't re-assert.
   - **Tentative decision**: follow dex — take `&ExternalUserClaims` alongside the blob, so the connector can choose to preserve `email`, `email_verified`, `username_hint`, etc. when the upstream refresh returns a narrower claim set.
3. **`reconcile_upstream_memberships` reuse**
   - Confirm the signature `(qs_write, person_uuid, provider_uuid, mapping, upstream_group_names) -> Result<(), OperationError>` is callable from the refresh path.
   - Confirm the "persist only on change" guard needs to live at the refresh call site, not inside the helper (keeps the helper's contract unchanged — login-time callers don't need diff-guarding because logins already write the memberOf entry).
4. **Oauth2Session DL-gated serialization**
   - Review the PR-RP-LOGOUT DL26 precedent (no Oauth2Session struct changes there, but DL26 added `LogoutDelivery` / `SamlSession` classes) for the migration-test pattern.
   - Review how `value.rs`'s `Oauth2Session` is serialized in `valueset/oauth2session.rs`; identify the exact DL-gate point (the decode branch that picks the serializer version based on `dl_version`).
5. **Connector registry population at boot**
   - Where does netidmd register provider-initiated trust today (PR-LINKBY, PR-OIDC-CONNECTOR, PR-SAML-CONNECTOR)? Likely `IdmServer::start` or `QueryServer` init.
   - The registry is a `HashMap<Uuid, Arc<dyn RefreshableConnector>>` populated at boot from the DB's `OAuth2Client` entries with a non-empty `OAuth2ClientAuthorisationEndpoint` (upstream trust marker).
   - **Deferral**: actual registry implementation — this PR only lands the trait + an in-memory registry seeded at boot. Concrete connectors (#4+) do their own registration at boot-time.
6. **Connector deletion semantics**
   - Spec edge case: an admin deletes the connector entry after a session was minted against it. Registry lookup returns `None`. Refresh MUST treat as failure → `Oauth2Error::InvalidGrant`.
   - **Decision**: on missing connector, return `ConnectorRefreshError::ConnectorMissing`, mapped to `Oauth2Error::InvalidGrant` at the refresh call site.
7. **Test-mock location**
   - Spec question deferred from clarify: does the mock live in `#[cfg(test)]` inside `idm::oauth2::connector` (lib-tests only) or in `netidmd_testkit` (reachable from integration tests)?
   - **Decision**: define it inside `idm::oauth2::connector` gated on `#[cfg(any(test, feature = "testkit"))]`, re-export from `netidmd_testkit` behind the feature so integration tests can use it. Adds zero release-mode code.
8. **Refresh-cache TTL policy**
   - Spec edge case flagged for planning: should there be a small-window cache of "last upstream fetch"?
   - **Decision**: no cache in this PR. Chatty RPs are a known pathology but each upstream call is already bounded by the connector's own per-call timeout, and dex does not cache either. If operational experience shows hammering, add caching as a follow-up behind a per-connector config attr.

**Output**: `specs/010-refresh-claims/research.md` with all seven decisions documented in the standard Decision / Rationale / Alternatives format.

### Phase 1: Design & Contracts

1. **Entity model** → `specs/010-refresh-claims/data-model.md`:
   - `Oauth2Session` (modified): two new optional fields, no lifecycle change. Lifecycle transitions unchanged — same as DL26.
   - `ConnectorRegistry` (new, in-memory): `HashMap<Uuid, Arc<dyn RefreshableConnector + Send + Sync>>` populated once at boot.
   - `ConnectorRefreshError` (new enum): `Network(String)`, `UpstreamRejected(u16)`, `TokenRevoked`, `ConnectorMissing`, `Serialization(String)`, `Other(String)`.
2. **Interface contracts** → `specs/010-refresh-claims/contracts/refreshable-connector.md`:
   - Trait signature + `# Errors` + `# Examples` in spec form.
   - Invariants: (a) the returned `ExternalUserClaims::sub` MUST match the session's original subject — any mismatch is a security-class error mapped to `TokenRevoked`; (b) the returned `ExternalUserClaims::groups` is the authoritative new upstream assertion — no merging with the old set (the PR-GROUPS-PIPELINE reconciler handles locally-granted preservation); (c) the trait implementer MAY mutate and return an updated `upstream_refresh_state` blob — on success, the new blob replaces the old on the session.
3. **Quickstart scenarios** → `specs/010-refresh-claims/quickstart.md`:
   - Scenario 1: Mutate upstream groups → refresh → assert new token reflects mutation.
   - Scenario 2: Connector errors → refresh → assert `invalid_grant`.
   - Scenario 3: Mix of local-granted and upstream-synced groups → refresh with empty upstream → only upstream-synced group removed.
   - Scenario 4: Refresh with `upstream_connector = None` (pre-DL27 session) → falls through, succeeds with cached claims.
4. **Agent context update**: run `.specify/scripts/bash/update-agent-context.sh claude` to refresh `CLAUDE.md`.

**Output**: data-model.md, contracts/refreshable-connector.md, quickstart.md, updated CLAUDE.md.
