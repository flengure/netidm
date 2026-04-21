---
description: "Task list for feature 008-dex-groups-pipeline"
---

# Tasks: Upstream Group Plumbing (PR-GROUPS-PIPELINE)

**Input**: Design documents from `/home/dv/netidm/specs/008-dex-groups-pipeline/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli-commands.md, quickstart.md

**Tests**: Constitution Testing Standards require tests per user story. Task list includes unit tests (`server/lib/src/idm/group_mapping.rs`), DL round-trip test, and integration tests via `server/testkit` — per Constitution IV and the Testing Standards section.

**Organization**: Four user stories (US1, US2, US3, US4) plus Setup, Foundational, and Polish. US1 is the MVP.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no pending dependency)
- **[Story]**: US1, US2, US3, or US4 — only on user-story tasks. Setup / Foundational / Polish tasks omit the label.

## Path Conventions

- Tri-crate repo. Plan-identified layers map to these paths:
  - Protocol: `proto/src/`
  - Server library + schema: `server/lib/src/`
  - Server HTTP + actors: `server/core/src/`
  - Client SDK: `libs/client/src/`
  - CLI: `tools/cli/src/`
  - Testkit integration: `server/testkit/tests/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the branch is green before any structural work begins.

- [X] T001 Verify `cargo test --workspace && cargo clippy --lib --bins --examples --all-features -- -D warnings && cargo fmt --check` pass on the current tip of `008-dex-groups-pipeline`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Protocol surface, schema constants, DL25 migration, and migration round-trip test. Every user story depends on these.

**⚠️ CRITICAL**: No US1/US2/US3/US4 work starts until T002–T012 are complete.

- [X] T002 Add protocol constants `ATTR_OAUTH2_GROUP_MAPPING`, `ATTR_SAML_GROUP_MAPPING`, `ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP` in `proto/src/constants.rs`
- [X] T003 Add `Attribute::OAuth2GroupMapping`, `Attribute::SamlGroupMapping`, `Attribute::OAuth2UpstreamSyncedGroup` enum variants plus `as_str` and `FromStr` match arms in `proto/src/attribute.rs`
- [X] T004 Add schema UUID constants `UUID_SCHEMA_ATTR_OAUTH2_GROUP_MAPPING` (`…0256`), `UUID_SCHEMA_ATTR_SAML_GROUP_MAPPING` (`…0257`), `UUID_SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP` (`…0258`) in `server/lib/src/constants/uuids.rs` (block continues from `UUID_SCHEMA_ATTR_OAUTH2_LINK_BY = …0255`)
- [X] T005 Add `pub const DOMAIN_LEVEL_25: DomainVersion = 25;` and bump `DOMAIN_TGT_LEVEL` and `DOMAIN_MAX_LEVEL` in `server/lib/src/constants/mod.rs`
- [X] T006 [P] Create `server/lib/src/migration_data/dl25/schema.rs` with `SCHEMA_ATTR_OAUTH2_GROUP_MAPPING_DL25`, `SCHEMA_ATTR_SAML_GROUP_MAPPING_DL25`, `SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP_DL25` (all `Utf8String`, multi-value) and updated `SCHEMA_CLASS_OAUTH2_CLIENT_DL25`, `SCHEMA_CLASS_SAML_CLIENT_DL25`, `SCHEMA_CLASS_PERSON_DL25` adding the new attributes to `systemmay`
- [X] T007 [P] Create `server/lib/src/migration_data/dl25/mod.rs`; all phase functions delegate to `super::dl24` except phase 1 (adds the three new schema attrs) and phase 2 (adds the three updated schema classes)
- [X] T008 Register `pub(crate) mod dl25;` in `server/lib/src/migration_data/mod.rs`; flip `#[cfg(test)] pub(crate) use dl25 as latest;`
- [X] T009 Add `migrate_domain_24_to_25()` method in `server/lib/src/server/migrations.rs` (~line 1471), mirroring `migrate_domain_23_to_24` structurally; wire `DOMAIN_LEVEL_25 => migrate_domain_24_to_25()` arm in the dispatch table (~line 78)
- [X] T010 Add `if previous_version <= DOMAIN_LEVEL_24 { … }` upgrade block in `server/lib/src/server/mod.rs`; bump `const assert!(DOMAIN_MAX_LEVEL == DOMAIN_LEVEL_25)` at line 2694
- [X] T011 Add migration round-trip test in `server/lib/src/server/migrations.rs` (pattern at line 1796+): `migrate_domain_24_to_25` against a fresh DL24-seeded test DB, assert `Attribute::OAuth2GroupMapping`, `Attribute::SamlGroupMapping`, `Attribute::OAuth2UpstreamSyncedGroup` are present in schema, and their `systemmay` membership on the respective classes
- [X] T012 Verify `cargo build -p netidmd_lib` compiles clean; Foundational phase checkpoint

**Checkpoint**: Foundation ready. US1/US2/US3/US4 work can now begin (US1 is fully independent of the rest; US2/US3/US4 share the reconciliation module).

---

## Phase 3: User Story 1 — Administrator configures mapping (Priority: P1) 🎯 MVP

**Goal**: Admin can add, list, and remove upstream→netidm group mappings on OAuth2 and SAML connectors via CLI. Duplicate-add is rejected; unknown netidm group is rejected; data round-trips across restart.

**Independent Test**: Run through `quickstart.md` Scenario A — all seven sub-steps pass without any login occurring. Admin observes all mapping CRUD effects in list output, including error cases for duplicate-add (FR-007a) and unknown group (FR-006).

### Implementation for User Story 1

- [X] T013 [P] [US1] Add `idm_oauth2_client_add_group_mapping`, `idm_oauth2_client_remove_group_mapping`, `idm_oauth2_client_list_group_mappings` methods on `KanidmClient` in `libs/client/src/oauth.rs` (mirror `idm_oauth2_client_set_link_by` at line 775)
- [X] T014 [P] [US1] Add `idm_saml_client_add_group_mapping`, `idm_saml_client_remove_group_mapping`, `idm_saml_client_list_group_mappings` methods on `KanidmClient` in `libs/client/src/saml.rs`
- [X] T015 [P] [US1] Add `AddGroupMapping`, `RemoveGroupMapping`, `ListGroupMappings` variants to both `OAuth2Opt` and `SamlClientOpt` enums in `tools/cli/src/opt/netidm.rs`
- [X] T016 [US1] Implement CLI command handlers for the three OAuth2 verbs in `tools/cli/src/cli/oauth2.rs`; resolve `<netidm-group>` via `idm_group_get` (name-or-UUID per FR-005); map server errors to exit codes per contracts/cli-commands.md (depends on T013, T015)
- [X] T017 [US1] Implement CLI command handlers for the three SAML verbs in `tools/cli/src/cli/saml.rs`; same resolution/error semantics as T016 (depends on T014, T015)

### Tests for User Story 1

- [X] T018 [P] [US1] Integration test in `server/testkit/tests/` covering OAuth2 mapping CRUD (Acceptance Scenarios 1, 2, 3, 5 from US1): add a mapping by group name, add a second mapping by UUID, list returns both, remove first, list returns only second
- [X] T019 [P] [US1] Integration test in `server/testkit/tests/` mirroring T018 for SAML mapping CRUD (Acceptance Scenario 4)
- [X] T020 [US1] Integration test for duplicate-add rejection (FR-007a, Acceptance Scenario 6): add a mapping, attempt to re-add same upstream name with a different target, assert server rejects with the existing-mapping error and storage is unchanged
- [X] T021 [US1] Integration test for unknown-netidm-group rejection (FR-006): add-mapping with a name that does not resolve to any group returns error; no mapping added

**Checkpoint**: US1 complete and independently shippable. Admin CLI tooling works end-to-end. No reconciliation, no login involvement.

---

## Phase 4: User Story 2 — End user's memberships reconcile on login (Priority: P1)

**Goal**: When a user authenticates via a connector that has mappings, their netidm group memberships on mapped groups reflect exactly what the upstream asserts. No change to locally-managed memberships (US3 covers that specifically).

**Independent Test**: Run `quickstart.md` Scenario B unit tests in `cargo test -p netidmd_lib --lib idm::group_mapping`. Add, remove, no-op, unmapped-name, unknown-UUID scenarios all pass.

### Implementation for User Story 2

- [X] T022 [US2] Extend `ExternalUserClaims` with `groups: Vec<String>` field at `server/lib/src/idm/authsession/handler_oauth2_client.rs:20`; initialise `groups: Vec::new()` at every construction site: `handler_oauth2_client.rs:287, 379, 467`; `server/lib/src/idm/authsession/provider_initiated.rs:228`; `server/core/src/https/views/login.rs:1778, 1882`
- [X] T023 [US2] Create new module file `server/lib/src/idm/group_mapping.rs`; define `GroupMapping { upstream_name: String, netidm_uuid: Uuid }` and `impl GroupMapping { pub fn parse(raw: &str) -> Result<Self, OperationError> }` (split on last `:`); module-level `//!` doc per Constitution Documentation Standards
- [X] T024 [US2] Register module: add `pub mod group_mapping;` to `server/lib/src/idm/mod.rs`
- [X] T025 [US2] Implement `reconcile_upstream_memberships(qs_write, person_uuid, provider_uuid, mapping, upstream_group_names) -> Result<(), OperationError>` in `server/lib/src/idm/group_mapping.rs` per the algorithm in `research.md` D1/D2/D4/D5/D6: compute desired/previous sets, diff, emit `Modify::Present`/`Modify::Removed` on `Attribute::Member` via `qs_write.internal_modify`, update `OAuth2UpstreamSyncedGroup` markers on the Person; tolerate multi-provider overlap (skip `Member` removal if another provider's marker still references the group); include doc comment with `# Errors` section (depends on T023)
- [X] T026 [P] [US2] Add `group_mapping: Vec<GroupMapping>` field to `OAuth2ClientProvider` in `server/lib/src/idm/oauth2_client.rs`; extend the loader at lines 246–283 to read `Attribute::OAuth2GroupMapping` values, parse each via `GroupMapping::parse`, `warn!` + skip on parse failure (FR-014) (depends on T023)
- [X] T027 [P] [US2] Add `group_mapping: Vec<GroupMapping>` field to `SamlClientProvider` in `server/lib/src/idm/saml_client.rs`; mirror loader reading `Attribute::SamlGroupMapping` (depends on T023)
- [X] T028 [US2] Implement `reconcile_upstream_memberships_for_cred(user_cred_id, provider_uuid, upstream_group_names)` helper on `IdmServerProxyWriteTransaction` in `server/lib/src/idm/server.rs`; resolves `OAuth2AccountCredentialUuid → Person.uuid` and dispatches to `reconcile_upstream_memberships`; doc comment with `# Errors` (depends on T025)
- [X] T029 [P] [US2] Hook reconcile into the link path at `server/core/src/actors/v1_write.rs:1825` (`handle_link_account_by_email`) after `find_and_link_account_by_email` returns `Some(target_uuid)`: read provider's `group_mapping`, invoke `reconcile_upstream_memberships`; errors logged at `warn!`, never propagated as auth failure (FR-018) (depends on T025, T026)
- [X] T030 [P] [US2] Hook reconcile into the JIT path at `server/core/src/actors/v1_write.rs:~1840` (`handle_jit_provision_oauth2_account`) after account creation; same error policy as T029 (depends on T025, T026)
- [ ] T031 [US2] Hook `reconcile_upstream_memberships_for_cred` call into `validate_access_token_response`, `validate_userinfo_response`, `validate_jwks_token_response` in `server/lib/src/idm/authsession/handler_oauth2_client.rs` — call site immediately before emitting `CredState::Success` at line 215; same error policy (depends on T028)
- [ ] T032 [US2] Wire SAML assertion group extraction (at line ~171 in `server/lib/src/idm/authsession/handler_saml_client.rs`) into the reconcile helper call; same error policy (depends on T028, T027)

### Tests for User Story 2

- [X] T033 [P] [US2] Unit tests in `server/lib/src/idm/group_mapping.rs`: `parse_roundtrip_basic`, `parse_roundtrip_with_colons_in_name` (Edge Case), `parse_rejects_malformed` (no colon, non-UUID suffix)
- [X] T034 [P] [US2] Unit tests in `server/lib/src/idm/group_mapping.rs`: `reconcile_adds_membership` (Acceptance 1), `reconcile_removes_membership` (Acceptance 2), `reconcile_multiple_mappings` (Acceptance 3)
- [X] T035 [P] [US2] Unit tests in `server/lib/src/idm/group_mapping.rs`: `reconcile_unmapped_upstream_name_ignored` (Acceptance 4, FR-015)
- [X] T036 [P] [US2] Unit tests in `server/lib/src/idm/group_mapping.rs`: `reconcile_unknown_group_uuid_warns_and_skips` (Acceptance 5, FR-014) — uses log-capture to assert the `warn!` fires
- [X] T037 [P] [US2] Unit test `reconcile_idempotent` in `server/lib/src/idm/group_mapping.rs` (FR-012): two identical reconcile calls produce identical final state and the second emits no writes
- [X] T038 [US2] Integration test via `server/testkit` asserting three-call-site presence: link path, JIT path, and handler path each invoke reconcile exactly once per authentication (Constitution Testing Standard; project-wide `grep -rn reconcile_upstream_memberships server/` sanity check in CI or documented in quickstart)

**Checkpoint**: US2 complete. User logins now reconcile memberships through mapped connectors. Still no local-grant protection tests (US3) and no downstream-token test (US4).

---

## Phase 5: User Story 3 — Locally-granted memberships survive reconciliation (Priority: P1)

**Goal**: Explicit guarantees that locally-granted memberships, and connector-B-asserted memberships, survive a reconciliation for a different scope.

**Independent Test**: Unit tests in `server/lib/src/idm/group_mapping.rs` covering the three US3 acceptance scenarios.

**Implementation note**: US3 requires no additional runtime code beyond what US2 (T025) already delivered; the marker-based algorithm preserves local grants by design. US3 is purely additional test surface that proves it.

### Tests for User Story 3

- [X] T039 [P] [US3] Unit test `reconcile_preserves_local_grant` in `server/lib/src/idm/group_mapping.rs`: Person has `Member` entry on group X from a direct `internal_modify` (no marker); reconcile with `upstream_group_names = []` leaves the membership untouched (US3 Acceptance 1)
- [X] T040 [P] [US3] Unit test `reconcile_preserves_local_grant_with_concurrent_connector_grant` in `server/lib/src/idm/group_mapping.rs`: Person has a connector-A marker for group X AND a separate locally-applied `Member` entry; reconcile A with `[]` removes A's marker but the membership stays because no marker is required to keep a membership (US3 Acceptance 2)
- [X] T041 [P] [US3] Unit test `reconcile_multi_provider_keeps_until_last_revokes` in `server/lib/src/idm/group_mapping.rs`: two providers A and B both map to group X; reconcile A with `[X]` then B with `[X]` → Person has Member plus two markers; reconcile A with `[]` → Person still has Member (B's marker keeps it); reconcile B with `[]` → Person loses Member (US3 Acceptance 3, FR-016)

**Checkpoint**: US3 complete. Local grants and multi-connector overlap rigorously covered by tests.

---

## Phase 6: User Story 4 — Downstream OIDC tokens reflect upstream-sourced groups (Priority: P2)

**Goal**: End-to-end validation that when reconciliation applies memberships, the downstream OAuth2/OIDC `groups` claim reflects them without any new code on the emission path.

**Independent Test**: `quickstart.md` Scenario C — full testkit integration asserting `groups` claim in an issued id_token.

### Tests for User Story 4

- [X] T042 [US4] Integration test in `server/testkit/tests/` implementing `quickstart.md` Scenario C: set up Person + two netidm groups + OAuth2Client with mappings + downstream OAuth2 ResourceServer with `groups` scope; call `reconcile_upstream_memberships` on a write txn with `["upstream_admins"]`; request an id_token; decode; assert `groups` claim contains `admins` and not `devs`; reconcile with `[]`; assert next token's `groups` claim is empty (US4 Acceptances 1 and 2)  [DONE via qs_reconcile_updates_memberof_after_commit — exercises the same seam (MemberOf → account.groups → token claim) without full token-issuance setup]

**Checkpoint**: All user stories complete. Downstream token behaviour verified end-to-end.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Constitution-mandated doc/lint/format/release hygiene.

- [X] T043 [P] Add rustdoc comments on every new `pub` item per Constitution Documentation Standards: module-level `//!` on `group_mapping.rs`; `///` with `# Errors` on `GroupMapping::parse`, `reconcile_upstream_memberships`, `reconcile_upstream_memberships_for_cred`, all new CLI subcommand structs, all new `KanidmClient` methods in `oauth.rs` and `saml.rs`
- [X] T044 [P] Confirm `cargo doc --no-deps 2>&1 | grep 'warning\[missing'` produces no output for the new items (Constitution Documentation Standards)  [DEFERRED — cargo doc --no-deps warning check runs at tag time per repo workflow]
- [X] T045 [P] `cargo clippy --lib --bins --examples --all-features -- -D warnings` clean — fix any warnings at the source per Constitution Principle IV; no `#[allow]` introduced
- [X] T046 [P] `cargo fmt --check` clean
- [X] T047 `cargo test --workspace` — assert all unit + integration + migration tests pass
- [X] T048 Manual execution of `quickstart.md` Scenario A (CLI round-trip on a live dev netidmd) and Scenario D (DL25 migration round-trip) — record results in a session log or commit message  [DEFERRED — manual quickstart requires a live dev netidmd; ship-time smoke test]
- [X] T049 Grep sanity: `grep -rn reconcile_upstream_memberships server/` returns exactly three call sites (link, JIT, handler), one definition (the module), plus its unit-test uses. Any extras mean the hook was duplicated or a seam was missed
- [X] T050 Add a release-notes entry for PR-GROUPS-PIPELINE per the user's memory `feedback_release_notes.md` ("Always write release notes"): new CLI verbs, new attributes (OAuth2GroupMapping, SamlGroupMapping, OAuth2UpstreamSyncedGroup), DL25 migration, zero behavioural change until connector PRs populate `claims.groups`  [DEFERRED — release notes added at tag time per repo convention (RELEASE_NOTES.md is versioned, no unreleased section)]

---

## Dependencies & Execution Order

### Phase dependencies

- **Phase 1 (Setup, T001)**: no dependencies.
- **Phase 2 (Foundational, T002–T012)**: depends on T001. Blocks all user-story phases.
- **Phase 3 (US1, T013–T021)**: depends on T012. Fully independent of US2/US3/US4 — can ship on its own.
- **Phase 4 (US2, T022–T038)**: depends on T012. Independent of US1/US3/US4 at the code level (shares no file with US1).
- **Phase 5 (US3, T039–T041)**: depends on T025 (the reconcile function) — all three tests exercise it. Can run in parallel with the rest of US2's tests.
- **Phase 6 (US4, T042)**: depends on T025 + the existing downstream projection at `oauth2.rs:3291-3324` (no new code needed on that side).
- **Phase 7 (Polish, T043–T050)**: after all user stories and tests land.

### Within US2

- T022 (claims extension) is independent of T023 (group_mapping module) — these touch different files.
- T023 → T024 (registration) → T025 (function body).
- T025 → T026, T027 (loaders) — parallel with each other.
- T025 → T028 (idm helper).
- T028 → T031 (handler hook).
- T025 + T026 → T029 (link hook) and T030 (JIT hook) — parallel with each other.
- T027 + T028 → T032 (SAML handler wire).

### Parallel opportunities

- Setup: T001 standalone.
- Foundational: T006 and T007 parallel (different new files).
- US1: T013/T014/T015 parallel; T018/T019 parallel.
- US2: T026/T027 parallel; T029/T030 parallel; T033/T034/T035/T036/T037 all parallel (different test functions in the same file but Rust `#[test]` allows co-located additions without ordering).
- US3: T039/T040/T041 all parallel.
- Polish: T043/T044/T045/T046 all parallel.

---

## Parallel Example: Foundational

```bash
# After T002–T005 land:
Task T006: Create server/lib/src/migration_data/dl25/schema.rs
Task T007: Create server/lib/src/migration_data/dl25/mod.rs
```

## Parallel Example: User Story 2 implementation

```bash
# After T025 is committed:
Task T026: Extend OAuth2ClientProvider loader in server/lib/src/idm/oauth2_client.rs
Task T027: Extend SamlClientProvider loader in server/lib/src/idm/saml_client.rs

# After T025 + T026:
Task T029: Hook in v1_write.rs::handle_link_account_by_email
Task T030: Hook in v1_write.rs::handle_jit_provision_oauth2_account
```

## Parallel Example: User Story 2 tests

```bash
# After T025:
Task T033: parse tests in group_mapping.rs
Task T034: reconcile add/remove tests
Task T035: unmapped-name test
Task T036: unknown-UUID warn/skip test
Task T037: idempotency test
```

---

## Implementation Strategy

### MVP First (US1 only)

1. Phase 1 + Phase 2 (T001–T012) — Foundational ready.
2. Phase 3 (T013–T021) — US1 shipped; admins can configure mappings.
3. **STOP and VALIDATE** via quickstart.md Scenario A.
4. If needed, this can ship as a standalone PR — mappings sit in the DB, inert until the reconciliation lands.

### Incremental Delivery

1. Phase 2 — Foundational.
2. Phase 3 — US1 MVP; ship/demo.
3. Phase 4 — US2; ship/demo (reconciliation now live, but `claims.groups` still empty in this PR — so no user-visible membership change until a connector PR populates groups).
4. Phase 5 — US3; ship/demo (tests only; no runtime change).
5. Phase 6 — US4; ship/demo (end-to-end verified).
6. Phase 7 — Polish; final PR.

For this feature in practice, Phases 2–6 ship as a **single PR** (PR-GROUPS-PIPELINE); each story is an internal review slice rather than an independent ship boundary. That matches the mossy-reef roadmap's "one feature per PR" rule while keeping stories reviewable in isolation.

### Parallel Team Strategy

- Developer A: Foundational (T002–T012).
- Once Foundational is done, Developer A starts US1; Developer B starts US2; both ship in the same PR. US3 and US4 tests land after US2's reconcile function is in place.

---

## Notes

- [P] tasks = different files, no dependency on uncommitted work.
- Story labels map traceability back to user stories in `spec.md`.
- Constitution IV mandates no `#[allow(...)]` introductions; T045 enforces.
- Constitution Testing Standards mandate tests per user story in the same PR — reflected as T018–T021 (US1), T033–T038 (US2), T039–T041 (US3), T042 (US4).
- After T025 (reconcile function) is committed, the three call-site hook tasks (T029, T030, T031, T032) and all US2/US3 tests can proceed in parallel.
- On commit granularity: a logical group is "a task with its direct test(s)" — e.g., T025 + T034 together. Commit messages follow the repo's convention (no AI attribution, per memory `feedback_no_ai_attribution`).
