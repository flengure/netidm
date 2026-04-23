# Tasks: GitHub Upstream Connector (PR-CONNECTOR-GITHUB)

**Feature**: [spec.md](spec.md)
**Branch**: `012-github-connector`
**Plan**: [plan.md](plan.md)
**Generated**: 2026-04-21

Tasks are organized by user story. US1 (P1) is the MVP shippable increment — a working GitHub login flow. US2–US6 are small layered refinements, each adding one admin-config dimension plus its test. The production code weight is front-loaded in US1; US2–US5 each add ≤ 3 code tasks plus tests.

**Test policy (non-optional)**: Constitution §Testing Standards requires tests for every feature — unit + integration covering primary success and primary failure paths per user story. Test tasks below are not optional.

---

## Phase 1: Setup

**Purpose**: Introduce the domain-level bump and seed the new proto attributes.

- [x] T001 Add `DOMAIN_LEVEL_28` + bump `DOMAIN_TGT_LEVEL` / `DOMAIN_MAX_LEVEL` / `DOMAIN_PREVIOUS_TGT_LEVEL` / `DOMAIN_TGT_NEXT_LEVEL` / replication levels in `server/lib/src/constants/mod.rs`
- [x] T002 [P] Add 8 new variants to the `Attribute` enum in `proto/src/attribute.rs`: `OAuth2ClientProviderKind`, `OAuth2ClientGithubHost`, `OAuth2ClientGithubOrgFilter`, `OAuth2ClientGithubAllowedTeams`, `OAuth2ClientGithubTeamNameField`, `OAuth2ClientGithubLoadAllGroups`, `OAuth2ClientGithubPreferredEmailDomain`, `OAuth2ClientGithubAllowJitProvisioning`. Update `Attribute::as_str()` and `FromStr for Attribute` to cover each. Add matching `ATTR_*` const strings in `proto/src/constants.rs`.
- [x] T003 [P] Reserve 8 `UUID_SCHEMA_ATTR_*` constants in `server/lib/src/constants/uuids.rs` for the new attributes.

---

## Phase 2: Foundational (blocking prerequisites for US1–US6)

**Purpose**: DL28 schema definitions + ACP extensions + the dispatch hook + the provider-kind-aware callback. Every user story depends on these; nothing here is user-visible on its own.

- [x] T004 Create `server/lib/src/migration_data/dl28/mod.rs` with `phase_1_schema_attrs()` and `phase_7_acp_updates()` following the DL26/DL27 precedent. No `phase_2_schema_classes` (no new classes).
- [x] T005 Create `server/lib/src/migration_data/dl28/schema.rs` declaring 8 `SCHEMA_ATTR_*` statics per the type/cardinality table in `specs/012-github-connector/data-model.md` §"OAuth2Client (extended, DL28)". Each attribute has syntax/index/multivalue/sensitive flags set per the table.
- [x] T006 Create `server/lib/src/migration_data/dl28/access.rs` declaring `IDM_ACP_OAUTH2_MANAGE_DL28`, a fork of `IDM_ACP_OAUTH2_MANAGE_DL26` that adds the 8 new attributes to the search/modify/create allowlists. Swap out the previous ACP UUID in favour of a new one for DL28.
- [x] T007 Add `migrate_domain_27_to_28` to `server/lib/src/server/migrations.rs` following the DL26/DL27 precedent. Run `phase_1_schema_attrs` and `phase_7_acp_updates` from `dl28::`; no system-entry phases since DL28 adds no entries. Update the dispatch table at migrations.rs line ~80 to add `DOMAIN_LEVEL_28 => write_txn.migrate_domain_27_to_28()?`. Bump the `const { assert!(DOMAIN_MAX_LEVEL == DOMAIN_LEVEL_28) }` guard in `server/lib/src/server/mod.rs` per PR-REFRESH-CLAIMS's precedent.
- [x] T008 [P] Add DL28 migration round-trip unit test in `server/lib/src/server/migrations.rs` — seed a DL27 DB with an `OAuth2Client` entry, migrate to DL28, assert (a) bootstrap succeeds with the 8 new attributes reachable via the schema, (b) setting each attribute round-trips through a write → read cycle.
- [x] T009 Locate the provider-initiated callback handler (search `find_and_link_account` callers in `server/core/src/https/views/`). Add a dispatch branch at the top reading `OAuth2ClientProviderKind` from the entry; route `"github"` → new `github_connector::handle_callback` (stubbed in this task), fall through to the existing OIDC path for `"generic-oidc"` / absent. Absence of the attribute MUST be byte-identical behaviour to DL27 (FR-016). The stub returns a placeholder rendered error page for now; full implementation lands in T013.

**Checkpoint**: foundation compiles; `cargo test -p netidmd_lib --lib` passes. No behaviour change yet — no `OAuth2Client` entries have `ProviderKind = "github"` in any test DB.

---

## Phase 3: User Story 1 — End user logs in via GitHub, groups flow through (Priority: P1) 🎯 MVP

**Goal**: A first-time GitHub user with a pre-provisioned matching Person (link-by-verified-email, step 1 of the linking chain) completes the authorization-code flow and lands in netidm with their team memberships mapped to netidm groups.

**Independent Test**: `quickstart.md` Scenario 1. An integration test seeds the connector entry + group mappings + a matching Person, drives the full HTTP flow through `spawn_mock_github_server()`, and asserts Alice's outgoing session carries the expected `groups` claim.

### Infrastructure for User Story 1

- [x] T010 [P] [US1] Create the `spawn_mock_github_server()` helper in `server/testkit/src/lib.rs`. Returns a `MockGithub` struct with a bound `SocketAddr` + mutator methods: `set_user(id, login, name, emails)`, `set_orgs(id, Vec<&str>)`, `set_teams(id, Vec<(org, slug, name)>)`, `fail_next(endpoint, status)`. Routes implemented via in-process `axum`: `GET /login/oauth/authorize`, `POST /login/oauth/access_token`, `GET /user`, `GET /user/emails`, `GET /user/orgs`, `GET /user/teams`. Pagination via `Link` header when team/org counts exceed `per_page`. Reuse the pattern from PR-RP-LOGOUT's `spawn_bcl_receiver`.
- [x] T011 [P] [US1] Create `server/lib/src/idm/github_connector.rs` with module-level `//!` doc, the `GitHubConfig` struct per data-model.md §"GitHubConfig", `GitHubSessionState` per §"GitHubSessionState", `GithubUserProfile` / `GithubEmail` / `GithubOrg` / `GithubTeam` per §"GitHub REST response types", and the `GitHubConnector` struct per §"GitHubConnector". Also add `pub mod github_connector;` in `server/lib/src/idm/mod.rs`.

### Implementation for User Story 1

- [x] T012 [US1] Implement `GitHubConfig::from_entry(entry: &EntrySealedCommitted) -> Result<GitHubConfig, OperationError>` in `github_connector.rs`: parse all 8 DL28 attributes with their documented defaults; validate `OAuth2ClientGithubHost` as absolute `https://` URL; derive `api_base` = `<host>/api/v3` for GHE or `https://api.github.com` for `github.com`; normalise `org_filter` + `allowed_teams` to lowercase; build a shared `reqwest::Client` with the standard headers (`Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, `User-Agent: netidm/<version> (connector-github)`) and 10 s timeout. `# Errors` documented.
- [x] T013 [US1] Implement `GitHubConnector::handle_callback(&self, qs_write, code, state) -> Result<Response, OperationError>` in `github_connector.rs` and wire it into the dispatch hook (T009's stub). Function performs, in order: (1) `post_token(code)` — code exchange with `Basic` client auth per contracts/github-api.md §2; (2) `fetch_user(token)` — `GET /user`; (3) `fetch_emails(token)` — `GET /user/emails`; (4) `fetch_orgs(token)` — `GET /user/orgs` with pagination; (5) `fetch_teams(token)` — `GET /user/teams` with pagination and the 5000-team cap from FR-011. Each step short-circuits to a rendered error page on failure; no Person state written on any failure leaf.
- [x] T014 [US1] Implement the 4-step linking chain (FR-013a) as `resolve_or_provision_person(&self, qs_write, profile, emails, login_at_github) -> Result<PersonRef, LinkError>` in `github_connector.rs`. Step 1: search for a Person whose verified email matches ANY of the user's verified GitHub emails. Step 2: search for a Person with `(OAuth2AccountProvider = self.config.entry_uuid, OAuth2AccountUniqueUserId = profile.id.to_string())`. Step 3: same filter but `UniqueUserId = profile.login`. Step 4: if `config.allow_jit_provisioning == true` → provision a new Person (name derived from `profile.login`, display name from `profile.name`, verified email if any); else return `LinkError::JitDisabled`. On every successful step 1–4, write BOTH link records (ID and current login) to the Person via `internal_modify`.
- [x] T015 [US1] Implement the rendered-upstream-group-name function `render_team_names(&self, teams: &[GithubTeam]) -> Vec<String>` honouring `OAuth2ClientGithubTeamNameField` (FR-006): `slug` → `org_login:team_slug`; `name` → `org_login:team_name`; `both` → emits both. Plus the `load_all_groups` fallback (FR-004a via config): when `config.load_all_groups == true`, append bare `org_login` entries for every org the user is in (no team required). Lowercase everything for consistency with the case-insensitivity of GitHub slugs.
- [x] T016 [US1] Implement session-state blob writing at the end of `handle_callback`: serialise `GitHubSessionState { format_version: 1, github_id, github_login, access_token, refresh_token, access_token_expires_at }` to JSON bytes, set `upstream_connector = Some(self.config.entry_uuid)` + `upstream_refresh_state = Some(blob)` on the freshly-minted `Oauth2Session`. (This plumbs through the existing Oauth2Session-mint path that PR-REFRESH-CLAIMS already wired to carry these fields.)
- [x] T017 [US1] Wire the connector-registration hook in `IdmServer::start` (the file and function location will be identified in T009's audit). Enumerate `OAuth2Client` entries with `OAuth2ClientProviderKind = "github"`, build `GitHubConfig::from_entry(entry)`, construct `Arc::new(GitHubConnector::new(config))`, `self.connector_registry().register(entry.uuid(), connector)`. Failures to parse a connector entry's config MUST be logged at error but MUST NOT prevent netidmd from starting.

### Tests for User Story 1

- [x] T018 [P] [US1] Unit test `test_github_render_team_names_slug` in `github_connector.rs` tests module: fixture of 3 teams across 2 orgs; assert the `slug` path emits `[org1:team1, org1:team2, org2:team3]` (lowercased).
- [x] T019 [P] [US1] Unit test `test_github_render_team_names_name_and_both` in `github_connector.rs`: same fixture, assert `name` and `both` paths.
- [x] T020 [P] [US1] Unit test `test_github_linking_chain_step_1_email` in `github_connector.rs`: seed a Person with verified email; invoke `resolve_or_provision_person`; assert link is made on step 1 (verify via a call counter on the search helper if one is introduced, or via asserting the specific Person UUID returned).
- [x] T021 [P] [US1] Unit test `test_github_pagination_link_header` in `github_connector.rs`: stub HTTP responses with `Link: <.../page=2>; rel="next"`; assert the paginator follows to page 2 and merges results.
- [x] T022 [P] [US1] Integration test `test_github_login_links_by_email_and_maps_teams_to_groups` in `server/testkit/tests/testkit/github_connector_test.rs` driving `quickstart.md` Scenario 1 end-to-end through `spawn_mock_github_server()`. Assert: Person entry's memberOf contains the mapped netidm groups; outgoing session's groups claim matches.

**Checkpoint**: US1 complete. A GitHub user with a pre-provisioned Person can log in and see their teams reflected in their session. US2–US6 are refinements on this foundation.

---

## Phase 4: User Story 2 — Team-based access gate (Priority: P2)

**Goal**: When `OAuth2ClientGithubAllowedTeams` is non-empty, a user whose team memberships don't intersect the list is rejected at the login boundary — no Person provisioning, no linking, no session.

**Independent Test**: `quickstart.md` Scenario 2. Configure `allowed_teams`; attempt login as a user in disallowed teams; assert login is rejected, no Person created.

### Implementation for User Story 2

- [x] T023 [US2] Add the access-gate check to `handle_callback` (T013) immediately after team/org fetch completes and BEFORE the linking chain runs. If `config.allowed_teams` is non-empty, compute intersection with the user's flat team set (lowercased `org:slug` form, regardless of `team_name_field`). Empty intersection → render the "access denied" page and return WITHOUT touching Person state or the reconciler. Emit a structured log line at info: `github_access_gate_denied { connector_uuid, github_id, github_login, teams }` — this is the audit trail for rejections.

### Tests for User Story 2

- [x] T024 [P] [US2] Unit test `test_github_access_gate_empty_intersection_rejects` in `github_connector.rs`: unit-level check of the intersection logic given a config and a team set. Assert the function returns `Err(LoginError::AccessGateDenied)` on empty intersection and `Ok(())` when populated. Also assert empty `allowed_teams` is treated as gate-off (accept).
- [x] T025 [P] [US2] Integration test `test_github_login_rejected_by_team_access_gate` in `github_connector_test.rs` driving quickstart Scenario 2. Assert the rejected user results in (a) a visible error response, (b) no Person entry created, (c) no OAuth2Session row, (d) no upstream-synced markers. Then mutate the mock to add the user to an allowed team and assert a second login succeeds.

---

## Phase 5: User Story 3 — JIT provisioning toggle (Priority: P2)

**Goal**: `OAuth2ClientGithubAllowJitProvisioning` controls whether step 4 of the linking chain (T014) provisions a fresh Person or rejects.

**Independent Test**: `quickstart.md` Scenario 3. Toggle the flag off and on; confirm the first login of an unknown user is rejected / provisions accordingly.

### Implementation for User Story 3

- [x] T026 [US3] Verify T014's step 4 implementation correctly gates on `config.allow_jit_provisioning`. No new code expected — T014 already embeds the flag read — but this task is the audit: step 4's `if config.allow_jit_provisioning` branch is exercised by the tests below. Document the specific error variant returned when JIT is off + no prior match: `LinkError::JitDisabled` → rendered page: "No netidm account is provisioned for your GitHub user. Please contact your administrator."

### Tests for User Story 3

- [x] T027 [P] [US3] Unit test `test_github_jit_disabled_rejects_unknown_user` in `github_connector.rs` tests: mock the connector-internal Person-search helper; configure `allow_jit_provisioning = false`; call `resolve_or_provision_person` with a profile that matches no existing Person; assert `Err(LinkError::JitDisabled)`.
- [x] T028 [P] [US3] Integration test `test_github_jit_provisioning_toggle_respects_admin_flag` in `github_connector_test.rs` driving quickstart Scenario 3 in both halves. Part A: attempt login with JIT off → visible rejection, no Person created. Part B: flip the attribute to `true`, restart the in-test server (or call the connector-registry re-register hook), attempt login again → Person auto-provisioned with name/display-name/email from GitHub profile. Assert the new Person carries both link records (ID and login).

---

## Phase 6: User Story 4 — Org filter for group mapping (Priority: P2)

**Goal**: When `OAuth2ClientGithubOrgFilter` is non-empty, teams from orgs outside the list are silently dropped from the group-mapping input — but login succeeds regardless of whether the user's orgs intersect the filter.

**Independent Test**: `quickstart.md` Scenario 4. Two variants: (a) user in mixed orgs sees only allowed-org teams in their groups claim; (b) user in zero allowed orgs logs in successfully but has an empty groups claim.

### Implementation for User Story 4

- [x] T029 [US4] Add the org-filter step in `handle_callback` (T013) AFTER the access-gate (T023) and BEFORE the linking chain (T014). When `config.org_filter` is non-empty, filter the in-memory team set before it's passed to `render_team_names` (T015). The filter is strictly a group-mapping filter per FR-005 — never rejects the login.

### Tests for User Story 4

- [x] T030 [P] [US4] Unit test `test_github_org_filter_drops_outside_orgs` in `github_connector.rs` tests: given a team set across two orgs and `org_filter = ["acme"]`, assert only the `acme:*` entries survive the filter. Also assert empty `org_filter` is a no-op pass-through.
- [x] T031 [P] [US4] Integration test `test_github_org_filter_narrows_group_mapping_without_rejecting_login` in `github_connector_test.rs` driving quickstart Scenario 4. Test both variants: (a) mixed-org user's session carries only allowed-org-derived groups; (b) non-intersecting-org user's login SUCCEEDS with no upstream-synced groups (proving FR-005 is not an access gate).

---

## Phase 7: User Story 5 — GitHub Enterprise host routing (Priority: P2)

**Goal**: A non-`github.com` host in `OAuth2ClientGithubHost` routes all OAuth2 + REST traffic to the configured host; no leakage to `github.com` / `api.github.com`.

**Independent Test**: `quickstart.md` Scenario 5. Configure a custom host (pointing at the mock), drive a login, assert every outbound request hits the configured host.

### Implementation for User Story 5

- [x] T032 [US5] Verify T012's `GitHubConfig::from_entry` correctly derives `api_base` and `host` from `OAuth2ClientGithubHost`. Audit T013's `handle_callback` fetch-helpers to ensure they use the `api_base` / `host` fields exclusively — no hard-coded `github.com` or `api.github.com` strings anywhere in the connector code. If any are found, replace them with field accesses.

### Tests for User Story 5

- [x] T033 [P] [US5] Integration test `test_github_enterprise_host_routing` in `github_connector_test.rs` driving quickstart Scenario 5. Instrument the mock with a per-host request counter (`mock.requests_on_host(&host)`); assert that requests to the configured mock host are non-zero and requests to `github.com` / `api.github.com` are zero throughout the login flow.

---

## Phase 8: User Story 6 — Refresh re-fetches team membership (Priority: P2)

**Goal**: Implement `RefreshableConnector::refresh` for the GitHub connector. Every refresh-token exchange dispatches here, re-fetches team membership, re-runs the reconciler with the PR-REFRESH-CLAIMS preflight diff, and rotates the session-state blob if GitHub issued a new access/refresh token.

**Independent Test**: `quickstart.md` Scenario 6. Drive a US1 login; mutate the mock's team set; exchange the refresh token; assert the new access token's groups claim reflects the mutation; assert the `refresh_claims.groups_changed` span emitted; assert the rotated session's blob carries any new tokens.

### Implementation for User Story 6

- [x] T034 [US6] Implement `#[async_trait] impl RefreshableConnector for GitHubConnector` in `github_connector.rs`. Method body: (a) deserialise the opaque blob via `GitHubSessionState::from_bytes(session_state)`; on failure → `ConnectorRefreshError::Serialization(...)`. (b) If `access_token_expires_at` is `Some` AND now > expiry AND `refresh_token` is `Some` → call `refresh_access_token(refresh_token)` against `<host>/login/oauth/access_token`; on failure → `TokenRevoked`. (c) Call `fetch_orgs(token)` + `fetch_teams(token)` (the same helpers US1 added); map HTTP errors per contracts/github-api.md §3–§6 to the appropriate `ConnectorRefreshError` variant. (d) Compute the new `ExternalUserClaims` with `sub = github_id.to_string()` (stable), `groups = render_team_names(filtered_teams)` (applying `org_filter`). (e) Return `RefreshOutcome { claims, new_session_state: Some(blob_with_any_rotated_tokens) }`.
- [x] T035 [US6] Apply the access-gate check (from US2's T023) ALSO on the refresh path inside the new `refresh` method — a user whose team membership has changed such that they no longer intersect `allowed_teams` MUST be rejected (`ConnectorRefreshError::TokenRevoked` — the RP is forced to restart auth; if the user still fails the gate at the next login, they hit the login-path rejection). This keeps the access gate invariant across sessions: being in the allowed teams is required at BOTH login AND every refresh, not just once.

### Tests for User Story 6

- [x] T036 [P] [US6] Unit test `test_github_refresh_returns_fresh_claims` in `github_connector.rs` tests: mock-HTTP the `/user/orgs` + `/user/teams` endpoints; build a synthetic session blob; call `GitHubConnector::refresh`; assert `outcome.claims.groups` matches the mocked team set with the configured `team_name_field` applied; assert `outcome.claims.sub == github_id.to_string()`.
- [x] T037 [P] [US6] Unit test `test_github_refresh_error_variants` in `github_connector.rs` tests: parameterised over the mock returning 401, 403+rate-limit, 500, malformed JSON, sub-mismatch. Assert each maps to the correct `ConnectorRefreshError` variant per FR-012.
- [x] T038 [P] [US6] Unit test `test_github_refresh_rotates_access_token_when_expired` in `github_connector.rs` tests: set `access_token_expires_at` to the past + `refresh_token = Some(...)`; mock `/login/oauth/access_token` to return a new pair; call `refresh`; assert `outcome.new_session_state.unwrap()` contains the NEW access/refresh tokens, not the old ones.
- [x] T039 [P] [US6] Unit test `test_github_refresh_access_gate_enforced` in `github_connector.rs` tests: configure `allowed_teams = ["acme:employees"]`; mock the upstream to return a user in `acme:contractors` only (having left `employees` since login); call `refresh`; assert `Err(ConnectorRefreshError::TokenRevoked)`.
- [x] T040 [P] [US6] Integration test `test_github_refresh_reflects_upstream_team_mutation` in `github_connector_test.rs` driving quickstart Scenario 6. Drive a US1 login; mutate `mock.set_teams(id, [])`; exchange the refresh token at `/oauth2/token`; assert the new access token's groups claim lost the mapped groups; assert one `refresh_claims.groups_changed` span was emitted (per PR-REFRESH-CLAIMS FR-013) with the expected `groups_removed`.

**Checkpoint**: US1 through US6 give the full feature contract. Ready for Polish.

---

## Phase 9: Admin CLI + client SDK

**Purpose**: Without CLI verbs, admins cannot configure this connector without direct DB modification. Required by FR-014.

- [x] T041 [P] Add 9 client SDK methods in `libs/client/src/oauth.rs` following the shape of `idm_oauth2_client_set_backchannel_logout_uri` from PR-RP-LOGOUT: `idm_oauth2_client_set_provider_kind(id, kind)`, `idm_oauth2_client_github_set_host(id, url)`, `idm_oauth2_client_github_add_org_filter(id, org)`, `idm_oauth2_client_github_remove_org_filter(id, org)`, `idm_oauth2_client_github_add_allowed_team(id, team)`, `idm_oauth2_client_github_remove_allowed_team(id, team)`, `idm_oauth2_client_github_set_team_name_field(id, field)`, `idm_oauth2_client_github_set_load_all_groups(id, bool)`, `idm_oauth2_client_github_set_preferred_email_domain(id, domain)`, `idm_oauth2_client_github_set_allow_jit_provisioning(id, bool)`. Plus the `clear` siblings where applicable. Doc-comments per constitution §Documentation Standards.
- [x] T042 [P] Add CLI variants on `OAuth2Opt` in `tools/cli/src/opt/netidm.rs`: new `SetProviderKind { name, kind }` at the top level + a new `GitHub` subcommand tree with subcommands `SetHost { name, url }`, `AddOrgFilter { name, org }`, `RemoveOrgFilter { name, org }`, `AddAllowedTeam { name, team }`, `RemoveAllowedTeam { name, team }`, `SetTeamNameField { name, field }`, `SetLoadAllGroups { name, value }`, `SetPreferredEmailDomain { name, domain }`, `SetAllowJitProvisioning { name, value }` + `Clear*` siblings. Match the shape of PR-RP-LOGOUT's `OAuth2Opt::SetBackchannelLogoutUri`.
- [x] T043 [US1] Add CLI handlers in `tools/cli/src/cli/oauth2.rs` dispatching each new variant to its client-SDK method. Validate `team` entries as `org:team` at CLI boundary (fail early with a helpful error message); validate URL + domain inputs per FR-014.
- [x] T044 [P] Integration test `test_github_cli_verbs_round_trip` in `server/testkit/tests/testkit/github_connector_test.rs` — for each CLI verb, call it, then read the entry back via the admin-read path and assert the attribute took. Covers FR-014.

---

## Phase 10: Polish & Cross-Cutting Concerns

**Purpose**: Constitution-mandated documentation, full verification pass, release-notes stub (deferred to tag-time).

- [x] T045 [P] Doc-comment pass on every new `pub` item: `GitHubConnector`, `GitHubConfig`, `GitHubConfig::from_entry`, `GitHubSessionState`, `GithubUserProfile` / `GithubEmail` / `GithubOrg` / `GithubTeam`, `TeamNameField`, `LinkError`, all `Attribute::OAuth2ClientGithub*` variants in `proto/src/attribute.rs`, all 9 client SDK methods, all 18 CLI variants, all HTTP helpers in `github_connector.rs`. Every `Result`-returning `pub fn` has `# Errors`; every public handler has `# Examples`.
- [x] T046 [P] Module-level `//!` doc on new modules: `server/lib/src/idm/github_connector.rs`, `server/lib/src/migration_data/dl28/mod.rs`, `server/lib/src/migration_data/dl28/schema.rs`, `server/lib/src/migration_data/dl28/access.rs`. Summary + extended description referencing spec FR-005 / FR-005a / FR-013a / FR-017 and research.md decisions.
- [x] T047 Run `cargo doc --no-deps 2>&1 | grep "warning\[missing"` — assert empty (zero missing-doc warnings on new items).
- [x] T048 Run `cargo fmt --check` from repo root — assert clean.
- [x] T049 Run `cargo clippy --lib --bins --examples -- -D warnings` — assert clean. Note any `clippy::needless_pass_by_value` hits and fix (don't `#[allow]` — per constitution §IV).
- [x] T050 Run `cargo test --workspace` — assert clean (default features, per project memory — no `--all-features`).
- [ ] T051 [P] Manual quickstart validation on a live dev netidmd: run all 6 scenarios from `quickstart.md` against a real GitHub OAuth app — **deferred to tag-time per project memory** (can be marked complete at ship time, not during development). Programmatic coverage is already in T022 / T025 / T028 / T031 / T033 / T040.
- [ ] T052 [P] Add RELEASE_NOTES.md entry under the next release section — **deferred to tag-time per project memory** (not during development); entry covers: DL28 migration, `OAuth2ClientProviderKind` discriminator + 7 GitHub-specific attrs, the new access gate + JIT toggle + 4-step linking chain, GitHub Enterprise support, refresh re-fetch.

---

## Dependencies

**Strict ordering (blocks)**:
- Phase 1 (T001–T003) → Phase 2 (T004–T009) — DL constants + proto attrs before schema/migration/dispatch.
- Phase 2 (all) → every US phase — foundation must compile + migrate before any US's code path runs.
- Within each US phase: implementation tasks block the integration test (e.g. T012–T017 block T022). Unit tests (T018–T021) can proceed in parallel with impl once the module scaffold (T011) is in place.
- Phase 9 (CLI+SDK) can run in parallel with Phases 4–8 once Phase 2 is done (it only depends on T002 proto additions).
- Phase 10 (T047–T050) → PR mergeable state. T051/T052 are explicitly deferred to tag time.

**Independent user stories** (can be implemented in any order after Phase 2):
- US1 ships the MVP foundation; US2/US3/US4/US5 each add one config-dimension of behaviour plus its test; US6 adds the refresh path (reuses US1's fetch helpers). In practice, ship order is US1 first, then US2/US3/US4/US5 in any order, then US6 once the fetch helpers are stable.

**Within-phase parallelism** (all `[P]` tasks in the same phase can run concurrently):
- Phase 1: T002, T003 parallelisable once T001 lands.
- Phase 2: T008 parallelisable once the schema tasks (T004–T007) are in; T009 can run in parallel with T008.
- Phase 3: T018–T022 run in parallel once T011–T017 are done.
- Phases 4–8: the test tasks in each (T024/T025, T027/T028, T030/T031, T033, T036–T040) all run in parallel with each other and with their phase's implementation tasks once T023/T026/T029/T032/T034 are in.
- Phase 9: T041, T042, T044 run in parallel; T043 depends on T041 + T042 (CLI handlers need both SDK methods + Opt variants to exist).
- Phase 10: T045–T046, T051–T052 run in parallel; T047–T050 run sequentially at the end (full-workspace cargo operations compete for the target directory).

---

## Parallel execution examples

### After Phase 2 completes, kick off US1 infrastructure in parallel:

```text
Task: "T010 [P] [US1] Create spawn_mock_github_server() in server/testkit/src/lib.rs"
Task: "T011 [P] [US1] Create server/lib/src/idm/github_connector.rs module scaffold"
```

### Once US1 implementation (T012–T017) is complete, run all US1 tests in parallel:

```text
Task: "T018 [P] [US1] Unit test test_github_render_team_names_slug"
Task: "T019 [P] [US1] Unit test test_github_render_team_names_name_and_both"
Task: "T020 [P] [US1] Unit test test_github_linking_chain_step_1_email"
Task: "T021 [P] [US1] Unit test test_github_pagination_link_header"
Task: "T022 [P] [US1] Integration test test_github_login_links_by_email_and_maps_teams_to_groups"
```

### At polish time, run all [P] polish tasks in parallel, then the verification chain sequentially:

```text
Parallel: T045, T046, T051, T052
Sequential: T047 → T048 → T049 → T050
```

---

## Implementation strategy

**MVP = Phase 1 + Phase 2 + Phase 3 (US1)**. Ship this as the first shippable increment. At this point:
- DL28 is live; a GitHub-configured connector can be stood up.
- A pre-provisioned user can log in via GitHub (linking chain step 1).
- Teams flow into the groups claim.
- The `RefreshableConnector` trait is implemented only as a stub that returns `Other("not yet implemented")` — refresh-path coverage comes in US6.

**Add US2+US3+US4 next** (Phases 4–6): the three admin-config knobs (team gate, JIT toggle, org filter) are small commits on top of the MVP. Each adds ≤ 10 lines of production code + its test.

**US5 (Phase 7)**: GitHub Enterprise is a one-task audit + one-test commit. Can bundle with US2–US4.

**US6 (Phase 8)** is the largest post-MVP chunk — the `RefreshableConnector::refresh` implementation + 4 unit tests + 1 integration test. Closes the loop with PR-REFRESH-CLAIMS so the feature works end-to-end on the refresh path.

**Phase 9 (admin CLI/SDK)** can run in parallel with US2–US6; it only depends on Phase 2's proto additions. Landing early lets us exercise config changes in integration tests without direct DB modification.

**Phase 10 (polish)** lands with the PR that takes the feature over the finish line — doc comments, clippy, fmt, test.

---

## Notes

- No new workspace deps. `reqwest`, `serde`, `serde_json`, `async-trait`, `hashbrown`, `url` are all already in tree.
- Mock GitHub server is hand-rolled in `spawn_mock_github_server()` (research.md R4). No `wiremock` dependency added.
- The 8 `ConnectorRefreshError` variants (from PR-REFRESH-CLAIMS) collapse to `Oauth2Error::InvalidGrant` at the refresh call site — the GitHub connector produces the specific variant, the refresh handler propagates the InvalidGrant response to the RP and logs the variant server-side.
- Commit order suggestion per roadmap memory: foundation commit (T001–T009), US1 commit (Phase 3, ship the MVP), US2+US3+US4+US5 bundle, US6 commit, Phase 9 CLI/SDK commit, polish commit with the verification run.
- No external-service dependencies at test time (constitution §III) — every test uses `spawn_mock_github_server()`.
