# Tasks: OAuth2 Refresh-Token Claim Re-Fetch (PR-REFRESH-CLAIMS)

**Feature**: [spec.md](spec.md)
**Branch**: `010-refresh-claims`
**Plan**: [plan.md](plan.md)
**Generated**: 2026-04-21

Tasks are organized by user story to support independent implementation and review. Each phase is a shippable increment: finishing Phase 3 (US1) alone is an MVP that delivers the operational guarantee this PR exists for.

**Test policy (non-optional)**: Netidm's constitution §Testing Standards requires tests for every feature — unit + integration covering primary success and primary failure paths per user story. Test tasks below are not optional and must land in the same commit(s) as the implementation they cover.

---

## Phase 1: Setup

**Purpose**: Introduce the domain-level bump.

- [ ] T001 Add `DOMAIN_LEVEL_27` + bump `DOMAIN_TGT_LEVEL` / `DOMAIN_MAX_LEVEL` / `DOMAIN_PREVIOUS_TGT_LEVEL` / `DOMAIN_TGT_NEXT_LEVEL` / replication levels in `server/lib/src/constants/mod.rs`

---

## Phase 2: Foundational (blocking prerequisites for US1–US4)

**Purpose**: Land the trait, the session-struct extension, DL27 serialization, the migration, and the (empty) registry. Every user story depends on these; nothing here is user-visible on its own.

- [ ] T002 Create new module `server/lib/src/idm/oauth2_connector.rs` declaring `pub trait RefreshableConnector`, `pub struct RefreshOutcome`, `pub enum ConnectorRefreshError` per `contracts/refreshable-connector.md`; wire `pub mod oauth2_connector;` in `server/lib/src/idm/mod.rs`
- [ ] T003 Add `pub struct TestMockConnector` in `server/lib/src/idm/oauth2_connector.rs` gated by `#[cfg(any(test, feature = "testkit"))]` per `contracts/refreshable-connector.md` §"`TestMockConnector` shape"
- [ ] T004 Add `pub struct ConnectorRegistry { by_uuid: HashMap<Uuid, Arc<dyn RefreshableConnector + Send + Sync>> }` with `new_empty()`, `get(uuid) -> Option<Arc<…>>`, and a test-only `register(uuid, impl)` in `server/lib/src/idm/oauth2_connector.rs`
- [ ] T005 Extend `pub struct Oauth2Session` in `server/lib/src/value.rs:1323` with `pub upstream_connector: Option<Uuid>` and `pub upstream_refresh_state: Option<Vec<u8>>`; update the one constructor call site to default both to `None`
- [ ] T006 Update `ValueSetOauth2Session` encode/decode in `server/lib/src/valueset/oauth2session.rs` with a DL-gated branch: DL27 serializes both new fields, DL26 drops them on encode and defaults to `None` on decode of DL27 records
- [ ] T007 [P] Add DL26 → DL27 migration phase in `server/lib/src/server/migrations.rs` alongside the existing DL25 → DL26 phase; new fields default to `None` on upgrade — no data rewrite required
- [ ] T008 [P] Add `connector_registry: Arc<ConnectorRegistry>` field on `IdmServer` in `server/lib/src/idm/server.rs` and initialise it to `Arc::new(ConnectorRegistry::new_empty())` during `IdmServer::start`
- [ ] T009 [P] Re-export `RefreshableConnector`, `RefreshOutcome`, `ConnectorRefreshError`, `TestMockConnector` from `server/testkit/src/lib.rs` behind the existing `testkit` feature-gate
- [ ] T010 [P] Migration round-trip unit test in `server/lib/src/server/migrations.rs`: seed a DL26 DB with one `Oauth2Session` entry on a Person; migrate to DL27; assert the session round-trips with `upstream_connector = None` and `upstream_refresh_state = None`; assert a new session with `upstream_connector = Some(uuid)` and a non-empty blob round-trips through write → read unchanged

**Checkpoint**: foundation compiles; the registry is reachable from `IdmServer`; `cargo test -p netidmd_lib --lib` passes. No behaviour change yet on the refresh path.

---

## Phase 3: User Story 1 — Upstream group change flows to downstream RP on refresh (Priority: P1) 🎯 MVP

**Goal**: A `grant_type=refresh_token` exchange on a connector-bound session re-resolves the user's claims by dispatching to the connector, runs the reconciler with a persist-on-change guard, and mints a new token whose `groups` claim reflects the current upstream assertion. Unchanged refreshes cause no Person-entry write and emit no span.

**Independent Test**: `quickstart.md` Scenario 1. Integration test `test_refresh_claims_upstream_mutation_flows_to_token` drives mutation → refresh → assert `groups` claim changed; a sibling test asserts unchanged upstream → no write, no span.

### Implementation for User Story 1

- [ ] T011 [US1] Add a preflight helper `read_synced_markers(qs_write, person_uuid, provider_uuid) -> Result<HashSet<Uuid>, OperationError>` in `server/lib/src/idm/oauth2_connector.rs` that reads the Person entry's `OAuth2UpstreamSyncedGroup` markers filtered to the given connector UUID (parses via the existing `parse_marker` helper from `idm/group_mapping.rs`)
- [ ] T012 [US1] In `server/lib/src/idm/authsession/provider_initiated.rs` (the path that mints the first access+refresh token from a provider-initiated login), populate `Oauth2Session::upstream_connector = Some(provider_uuid)` and set `upstream_refresh_state` to whatever the connector chooses to persist (`None` if the connector has no state to store). For this PR the only connector in play is `TestMockConnector`, which sets the blob to an empty `Vec<u8>` when a test explicitly registers it
- [ ] T013 [US1] Modify `IdmServerProxyWriteTransaction::check_oauth2_token_refresh` in `server/lib/src/idm/oauth2.rs` to load the `Oauth2Session` for the refresh token and branch on `session.upstream_connector`: the `None` branch keeps the existing DL26 behaviour byte-for-byte (US4 requirement); the `Some(connector_uuid)` branch enters the new refresh-dispatch code path
- [ ] T014 [US1] In the `Some(connector_uuid)` branch, look up the connector via `IdmServer::connector_registry.get(connector_uuid)`; on `None` return `Oauth2Error::InvalidGrant` (maps `ConnectorRefreshError::ConnectorMissing`). Otherwise call `connector.refresh(session.upstream_refresh_state.as_deref().unwrap_or(&[]), &previous_claims).await`. Convert any `Err(_)` into `Oauth2Error::InvalidGrant` and log the variant at `error` level with `connector_uuid` + `user_uuid` (US2 requirement — the handler site is shared so it lands in US1's edit; US2's tests assert the behaviour)
- [ ] T015 [US1] After a successful `RefreshOutcome`, assert `outcome.claims.sub == previous_claims.sub`; mismatch → treat as `ConnectorRefreshError::TokenRevoked` → `Oauth2Error::InvalidGrant` (R2 invariant; scoped to this site not the trait). Propagate `outcome.claims` downstream and rotate `Oauth2Session::upstream_refresh_state` to `outcome.new_session_state` when `Some(_)`, otherwise copy the old blob forward; always copy `upstream_connector` forward
- [ ] T016 [US1] In the same handler, compute the desired upstream-synced group UUID set from `outcome.claims.groups` and the connector's group-mapping table; call `read_synced_markers` (T011) to get the existing set; if `desired != existing`, call the existing `reconcile_upstream_memberships(qs_write, person_uuid, connector_uuid, &mapping, &outcome.claims.groups)` (no changes to that helper); if `desired == existing`, skip the call (FR-010 persist-on-change)
- [ ] T017 [US1] When `desired != existing` in T016, emit exactly one structured tracing span named `refresh_claims.groups_changed` with fields `user_uuid`, `connector_uuid`, `groups_added` (array of group UUIDs added), `groups_removed` (array of group UUIDs removed). Use `tracing::info_span!` so the signal appears by default; the span is not emitted when the set is unchanged (FR-013)

### Tests for User Story 1

- [ ] T018 [P] [US1] Unit test `test_refresh_dispatches_to_connector_when_bound` in `server/lib/src/idm/oauth2_connector.rs` tests module: register a `TestMockConnector` via `ConnectorRegistry::register`; seed an `Oauth2Session` with `upstream_connector = Some(uuid)`; invoke `check_oauth2_token_refresh` directly; assert `TestMockConnector::refresh` was called (via a counter on the mock) and the returned token reflects the mock's current groups
- [ ] T019 [P] [US1] Unit test `test_refresh_persist_on_change_skips_write_when_unchanged` in `server/lib/src/idm/oauth2.rs` tests module: seed Person with upstream-synced marker for group `G`; configure mock to return groups `[G]`; refresh → assert Person entry's `OAuth2UpstreamSyncedGroup` attribute was NOT rewritten (count writes via an internal test-only counter or by diffing `entry.get_ava_updated_since`); mutate mock to `[H]`; refresh → assert the attribute WAS rewritten exactly once
- [ ] T020 [P] [US1] Unit test `test_refresh_emits_change_span_only_on_change` in `server/lib/src/idm/oauth2.rs` tests module: install a capturing `tracing::Subscriber` (use `tracing::subscriber::with_default` + a test-local `Vec<_>` sink); drive two refreshes (same groups, then different groups); assert exactly one span named `refresh_claims.groups_changed` with the expected `groups_added` / `groups_removed` values on the change and zero on the unchanged refresh
- [ ] T021 [P] [US1] Integration test `test_refresh_claims_upstream_mutation_flows_to_token` in `server/testkit/tests/testkit/refresh_claims_test.rs` driving `quickstart.md` Scenario 1: setup a connector-bound session via test-only mock registration, mutate mock groups, refresh via the token endpoint, assert the new access token's `groups` claim reflects the mutation; includes the negative variant (unchanged upstream → unchanged token, no write, no span)

**Checkpoint**: US1 complete. End-to-end operational guarantee is live. US2–US4 refine the failure and forward-compat paths; none are blocking for MVP ship.

---

## Phase 4: User Story 2 — Connector failure rejects the RP refresh (Priority: P2)

**Goal**: Any `ConnectorRefreshError` from the connector, or a missing-registry lookup, causes the token endpoint to return `Oauth2Error::InvalidGrant` per RFC 6749 §5.2. Upstream detail is logged server-side but never surfaced to the RP.

**Independent Test**: `quickstart.md` Scenario 2. Integration test drives connector into error mode, refreshes, asserts `invalid_grant` on the wire.

### Implementation for User Story 2

- [ ] T022 [US2] Audit the error-mapping block added in T014: confirm every `ConnectorRefreshError` variant (`Network`, `UpstreamRejected`, `TokenRevoked`, `ConnectorMissing`, `Serialization`, `Other`) maps to `Oauth2Error::InvalidGrant`; confirm the `error!` log call carries `connector_uuid`, `user_uuid`, and the `Debug` form of the variant but never logs `session.upstream_refresh_state`
- [ ] T023 [US2] Confirm the token-endpoint response body on failure is `{"error": "invalid_grant"}` with no `error_description` that could leak upstream state; if `check_oauth2_token_exchange`'s existing error → HTTP mapping already carries a description, suppress it for this path

### Tests for User Story 2

- [ ] T024 [P] [US2] Unit test `test_refresh_connector_error_invalid_grant` in `server/lib/src/idm/oauth2.rs` tests module: parameterised over each `ConnectorRefreshError` variant; for each, configure mock to return the variant on next refresh; invoke `check_oauth2_token_refresh`; assert `Err(Oauth2Error::InvalidGrant)`; assert no new tokens minted; assert no `refresh_claims.groups_changed` span emitted; assert no Person-entry write
- [ ] T025 [P] [US2] Unit test `test_refresh_connector_missing_invalid_grant` in `server/lib/src/idm/oauth2.rs` tests module: seed session with `upstream_connector = Some(uuid)`; leave registry empty for that UUID; refresh; assert `Oauth2Error::InvalidGrant`; assert an `error!` log line was captured with `connector_uuid` matching the session's value (use a log-capture subscriber or a stub)
- [ ] T026 [P] [US2] Integration test `test_refresh_claims_connector_error_rejects_with_invalid_grant` in `server/testkit/tests/testkit/refresh_claims_test.rs` driving `quickstart.md` Scenario 2: setup connector-bound session, put mock in error mode, refresh via the HTTP token endpoint, assert HTTP 400 with body `{"error":"invalid_grant"}`, assert no new `access_token` / `refresh_token` in the response

**Checkpoint**: US1 + US2 give the full operational guarantee with correct fail-closed semantics.

---

## Phase 5: User Story 3 — Locally-granted memberships survive refresh (Priority: P2)

**Goal**: A user with one upstream-synced group membership and one locally-granted group membership refreshes; upstream revokes its group; the new token contains only the locally-granted group; the Person entry's direct `MemberOf` for the locally-granted group is untouched.

**Independent Test**: `quickstart.md` Scenario 3. Integration test seeds the mixed-membership user, mutates upstream to empty, refreshes, asserts both the token and the entry state.

### Implementation for User Story 3

- [ ] T027 [US3] Verify (via unit test coverage in T028; no code change expected) that `reconcile_upstream_memberships` already filters markers by `provider_uuid` and only touches those — this is existing PR-GROUPS-PIPELINE behaviour and must not be broken by the refresh-path invocation. If a scan reveals the helper actually modifies non-connector-scoped markers, file a follow-up and fence the refresh call site to only act on the per-connector slice

### Tests for User Story 3

- [ ] T028 [P] [US3] Unit test `test_refresh_preserves_locally_granted_groups` in `server/lib/src/idm/oauth2.rs` tests module: seed Person with direct `MemberOf` of group `L` (no upstream marker) and `OAuth2UpstreamSyncedGroup` marker for connector `C` on group `U`; both groups initially in the access token; configure mock to return `[]`; refresh; assert new token's `groups` claim contains the stable name of `L` only; assert Person entry's `OAuth2UpstreamSyncedGroup` set for connector `C` is empty; assert Person entry's direct `MemberOf` still includes `L`
- [ ] T029 [P] [US3] Integration test `test_refresh_claims_local_groups_survive_narrowing_upstream` in `server/testkit/tests/testkit/refresh_claims_test.rs` driving `quickstart.md` Scenario 3: setup Person with mixed membership via testkit helpers, narrow upstream via mock, refresh via HTTP, assert token body

**Checkpoint**: US1 + US2 + US3 together deliver the full feature contract for connector-bound sessions.

---

## Phase 6: User Story 4 — Pre-DL27 sessions fall through (Priority: P3)

**Goal**: Refresh tokens minted before this PR shipped (sessions with `upstream_connector = None`) continue to work via the existing cached-claims code path. The upgrade is non-disruptive.

**Independent Test**: `quickstart.md` Scenario 4. Integration test seeds a session with `upstream_connector = None`, refreshes, asserts cached-claims token; asserts the rotated session still has `None`.

### Implementation for User Story 4

- [ ] T030 [US4] Confirm the `None` branch added in T013 is byte-identical to the DL26 cached-claims path — diff the old and new implementations of `check_oauth2_token_refresh` to verify no accidental behavioural change on the `None` branch; add an inline comment pointing at this spec (FR-006, US4) so a future refactor doesn't silently drop the fallback
- [ ] T031 [US4] Confirm that when the source session has `upstream_connector = None`, the rotated replacement session also has `upstream_connector = None` and `upstream_refresh_state = None` (no migration-by-accident via refresh-token rotation) — this is T015's default copy-forward behaviour, but audit specifically for the `None` case

### Tests for User Story 4

- [ ] T032 [P] [US4] Unit test `test_refresh_predl27_session_passes_through` in `server/lib/src/idm/oauth2.rs` tests module: seed an `Oauth2Session` with `upstream_connector = None`; register no connectors; refresh; assert success; assert the `ConnectorRegistry` was not consulted (via a counter); assert the rotated session's `upstream_connector` is still `None`; assert the outgoing token carries the same `groups` claim as before (cached semantics)
- [ ] T033 [P] [US4] Integration test `test_refresh_claims_predl27_session_falls_through` in `server/testkit/tests/testkit/refresh_claims_test.rs` driving `quickstart.md` Scenario 4: directly mutate the testkit user's `Oauth2Session` value-set to set `upstream_connector = None` on an existing session (simulating a pre-DL27 record); refresh via HTTP; assert success and matching `groups` claim

**Checkpoint**: US1 + US2 + US3 + US4 cover the full spec. Ready for Polish.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Constitution-mandated documentation, full verification pass, release-notes stub.

- [ ] T034 [P] Doc-comment pass on every new `pub` item: `RefreshableConnector` (trait) with `# Errors` + `# Examples`, `RefreshOutcome`, `ConnectorRefreshError` (each variant documented), `ConnectorRegistry` + its methods, `TestMockConnector` + its test-only setters, `read_synced_markers` (with `# Errors`). Every `Result`-returning new `pub fn` has `# Errors` listing each `OperationError` / `Oauth2Error` / `ConnectorRefreshError` variant that can be returned (constitution §Documentation Standards)
- [ ] T035 [P] Module-level `//!` doc on new module: `server/lib/src/idm/oauth2_connector.rs` — one-line summary, blank line, extended description referencing spec FR-008 / FR-009 / FR-013 and the dex parity R1
- [ ] T036 [P] Update `CLAUDE.md` "Recent Changes" section (the auto-update already added the tech-context line in Phase 1 of the plan; confirm the DL27 entry is present and phrased the same way as DL26's entry on the same file)
- [ ] T037 Run `cargo doc --no-deps 2>&1 | grep "warning\[missing"` — assert empty (zero missing-doc warnings on new items)
- [ ] T038 Run `cargo fmt --check` from repo root — assert clean
- [ ] T039 Run `cargo clippy --lib --bins --examples -- -D warnings` — assert clean
- [ ] T040 Run `cargo test --workspace` — assert clean (default features, per project memory — no `--all-features`)
- [ ] T041 [P] Manual quickstart validation on a live dev netidmd: run all 4 scenarios from `quickstart.md` — **deferred to tag-time per project memory** (can be marked complete at ship time, not during development). Programmatic coverage is already in T021 / T026 / T029 / T033
- [ ] T042 [P] Add RELEASE_NOTES.md entry for this feature under the next release section — **deferred to tag-time per project memory** (not during development); entry covers: DL27 migration, `RefreshableConnector` trait intro, fail-closed divergence from dex, persist-on-change semantics, zero new external surface
- [ ] T043 [P] Perf-smoke test `test_refresh_overhead_within_budget` in `server/lib/src/idm/oauth2.rs` tests module: measure the wall-clock time of 100 sequential `check_oauth2_token_refresh` calls against a `TestMockConnector` configured with zero delay and unchanged groups, and the same 100 against a pre-DL27 session (the `None` branch that skips connector dispatch); assert the delta is ≤ 20% of the `None`-branch baseline (SC-005). This covers the netidm-internal overhead only — upstream latency is intrinsic to the feature and not in scope for this budget.

---

## Dependencies

**Strict ordering (blocks)**:
- Phase 1 (T001) → Phase 2 (T002–T010)
- Phase 2 (all tasks) → every US phase (Phases 3–6)
- Within each US phase: the implementation tasks block the integration test (e.g. T013–T017 block T021); unit tests (e.g. T018–T020) can proceed in parallel once the foundation is in place
- Phase 7 (T037–T040) → PR mergeable state

**Independent user stories (can be implemented in any order after Phase 2)**:
- US1 (Phase 3), US2 (Phase 4), US3 (Phase 5), US4 (Phase 6) are logically independent — they each exercise different branches of the modified `check_oauth2_token_refresh`. In practice US1 ships first because it's the MVP; US2–US4 are three small follow-on commits in any order.

**Within-phase parallelism** (all `[P]` tasks in the same phase can run concurrently):
- Phase 2: T007, T008, T009, T010 run in parallel once T002–T006 are done.
- Phase 3: T018, T019, T020, T021 run in parallel once T011–T017 are done.
- Phase 4: T024, T025, T026 run in parallel once T022–T023 are done.
- Phase 5: T028, T029 run in parallel once T027 is done.
- Phase 6: T032, T033 run in parallel once T030–T031 are done.
- Phase 7: T034, T035, T036, T041, T042, T043 run in parallel; T037–T040 run sequentially at the end (full-workspace cargo operations compete for the target directory).

---

## Parallel execution examples

### After Phase 2 completes, kick off US1 implementation in parallel:

```text
Task: "T011 [US1] Add preflight helper read_synced_markers in server/lib/src/idm/oauth2_connector.rs"
Task: "T012 [US1] Populate upstream_connector on first mint in server/lib/src/idm/authsession/provider_initiated.rs"
```

(These touch different files and only share the `Oauth2Session` struct from T005; both can proceed as soon as Phase 2 is merged.)

### Once US1 implementation (T013–T017) is complete, run all four US1 tests in parallel:

```text
Task: "T018 [P] [US1] Unit test test_refresh_dispatches_to_connector_when_bound"
Task: "T019 [P] [US1] Unit test test_refresh_persist_on_change_skips_write_when_unchanged"
Task: "T020 [P] [US1] Unit test test_refresh_emits_change_span_only_on_change"
Task: "T021 [P] [US1] Integration test test_refresh_claims_upstream_mutation_flows_to_token"
```

### At polish time, run all [P] polish tasks in parallel, then the verification chain sequentially:

```text
Parallel: T034, T035, T036, T041, T042
Sequential: T037 → T038 → T039 → T040
```

---

## Implementation strategy

**MVP = Phase 1 + Phase 2 + Phase 3 (US1)**. Ship this as the first shippable increment. At this point:
- The `RefreshableConnector` trait exists and is stable for later connector PRs (#4+).
- DL27 is live; existing sessions migrate cleanly.
- A connector-bound session refreshes with fresh upstream claims.
- The persist-on-change guard and change-tracking span are live.

**Add US2 next** (Phase 4): hardens the failure path — the feature is operationally sound only once fail-closed semantics are tested. US2 is a small commit bolted onto US1 — the handler code is already in T014; US2 just adds tests and the audit in T022–T023.

**US3 (Phase 5)** and **US4 (Phase 6)** are low-risk follow-ups, each ≤ 3 tasks. They could be bundled into the same PR as US1+US2 if the review bandwidth allows, or split into a second PR labelled "PR-REFRESH-CLAIMS hardening" if reviewability benefits.

**Polish (Phase 7)** lands with whichever PR takes the feature over the finish line — doc comments and lint passes are required for every merge.

---

## Notes

- Zero new HTTP endpoints, zero new CLI verbs, zero new client-SDK methods (FR-012). Every file touched is under `server/lib/` except the testkit re-export and the integration test.
- No new workspace dependencies. `async_trait`, `tracing`, `hashbrown`, `thiserror` are all already in-tree.
- The 6 `ConnectorRefreshError` variants collapse to one `Oauth2Error::InvalidGrant` at the call site. The variant is preserved in logs for triage.
- The spec's "refresh-cache TTL" edge case is explicitly deferred to planning (R8 in research.md). This tasks file does not introduce caching.
- SAML SLO and LDAP inbound are out of scope for this PR — the trait shape covers them, but no concrete impl lands here.
- Commit order suggestion per roadmap memory: foundation commit (T001–T010), then US1 commit (Phase 3), then US2+US3+US4 combined (small enough to bundle), then polish commit with the verification run.
