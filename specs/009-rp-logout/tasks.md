---
description: "Task list for feature 009-rp-logout"
---

# Tasks: RP-Initiated Logout (PR-RP-LOGOUT)

**Input**: Design documents from `/home/dv/netidm/specs/009-rp-logout/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/http-endpoints.md, contracts/cli-commands.md, quickstart.md

**Tests**: Constitution §Testing Standards requires unit + integration tests per user story. All implementation phases include tests; no phase ships test-less. No mocks for the DB layer — use `server/testkit` integration infrastructure against a real in-process netidmd.

**Organization**: Five user stories (US1–US5) plus Setup, Foundational, and Polish. US1 is the MVP.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no pending dependency)
- **[Story]**: US1, US2, US3, US4, or US5 — only on user-story tasks. Setup / Foundational / Polish tasks omit the label.

## Path Conventions

- Tri-crate repo. Plan-identified layers map to these paths:
  - Protocol: `proto/src/`
  - Server library + schema: `server/lib/src/`
  - Server HTTP + actors: `server/core/src/`
  - Templates: `server/core/templates/`
  - Client SDK: `libs/client/src/`
  - CLI: `tools/cli/src/`
  - Testkit integration: `server/testkit/tests/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Confirm the branch is green before any structural work begins.

- [X] T001 Verify `cargo test --workspace && cargo clippy --lib --bins --examples --all-features -- -D warnings && cargo fmt --check` pass on the current tip of `009-rp-logout`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Protocol surface, schema constants, DL26 migration (schema + classes + ACPs + SAML-session backfill phase), and migration round-trip test. Every user story depends on these.

**⚠️ CRITICAL**: No US1/US2/US3/US4/US5 work starts until T002–T015 are complete.

- [X] T002 Add 12 protocol constants in `proto/src/constants.rs`: `ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI`, `ATTR_OAUTH2_RS_BACKCHANNEL_LOGOUT_URI`, `ATTR_SAML_SINGLE_LOGOUT_SERVICE_URL`, `ATTR_LOGOUT_DELIVERY_ENDPOINT`, `ATTR_LOGOUT_DELIVERY_TOKEN`, `ATTR_LOGOUT_DELIVERY_STATUS`, `ATTR_LOGOUT_DELIVERY_ATTEMPTS`, `ATTR_LOGOUT_DELIVERY_NEXT_ATTEMPT`, `ATTR_LOGOUT_DELIVERY_CREATED`, `ATTR_LOGOUT_DELIVERY_RP`, `ATTR_SAML_SESSION_USER`, `ATTR_SAML_SESSION_SP`, `ATTR_SAML_SESSION_INDEX`, `ATTR_SAML_SESSION_UAT_UUID`, `ATTR_SAML_SESSION_CREATED`; plus entry-class constants `ENTRY_CLASS_LOGOUT_DELIVERY`, `ENTRY_CLASS_SAML_SESSION`
- [X] T003 Add matching `Attribute::*` enum variants (15 new) with `as_str` and `FromStr` match arms in `proto/src/attribute.rs`, plus `EntryClass::LogoutDelivery` and `EntryClass::SamlSession` variants in `proto/src/entry_class.rs` (or the equivalent EntryClass location used in current netidm)
- [X] T004 Add schema UUID constants in `server/lib/src/constants/uuids.rs` (slots `…ffff00000259` through `…ffff00000269` per data-model.md §3): `UUID_SCHEMA_ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI`, `UUID_SCHEMA_ATTR_OAUTH2_RS_BACKCHANNEL_LOGOUT_URI`, `UUID_SCHEMA_ATTR_SAML_SINGLE_LOGOUT_SERVICE_URL`, `UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_ENDPOINT` (`…025C`) through `UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_RP` (`…0262`), `UUID_SCHEMA_ATTR_SAML_SESSION_USER` / `_SP` / `_INDEX` / `_UAT_UUID` / `_CREATED`, `UUID_SCHEMA_CLASS_LOGOUT_DELIVERY` (`…0265`), `UUID_SCHEMA_CLASS_SAML_SESSION` (`…0269`); plus four new `UUID_IDM_ACP_*` slots for the new ACPs
- [X] T005 Add `pub const DOMAIN_LEVEL_26: DomainVersion = 26;` in `server/lib/src/constants/mod.rs` (line ~118); bump `DOMAIN_TGT_LEVEL`, `DOMAIN_MAX_LEVEL`, `DOMAIN_MINIMUM_REPLICATION_LEVEL`, `DOMAIN_MAXIMUM_REPLICATION_LEVEL` to `DOMAIN_LEVEL_26`; leave `DOMAIN_PREVIOUS_TGT_LEVEL` following convention
- [X] T006 [P] Create `server/lib/src/migration_data/dl26/schema.rs` with all 15 new `SCHEMA_ATTR_*_DL26` (per syntax and multi-value per data-model.md §1–§2), plus `SCHEMA_CLASS_LOGOUT_DELIVERY_DL26`, `SCHEMA_CLASS_SAML_SESSION_DL26`, and updated `SCHEMA_CLASS_OAUTH2_CLIENT_DL26` / `SCHEMA_CLASS_SAML_CLIENT_DL26` that add the new URL attrs to `systemmay`
- [X] T007 [P] Create `server/lib/src/migration_data/dl26/access.rs` with four new `IDM_ACP_*_DL26` constants: admin CRUD for `OAuth2RsPostLogoutRedirectUri`, admin CRUD for `OAuth2RsBackchannelLogoutUri`, admin CRUD for `SamlSingleLogoutServiceUrl`, admin read-only for `LogoutDelivery` entries, self-read for `SamlSession` entries where `SamlSessionUser == own_uuid`
- [X] T008 Create `server/lib/src/migration_data/dl26/mod.rs`; all phase functions delegate to `super::dl25` except phase 1 (registers the 15 new schema attrs), phase 2 (registers the two new classes + the updated `OAuth2Client` / `SamlClient` classes), phase 3 (registers the new ACPs), and a new phase 4 (SAML-session backfill stub returning `Ok(())` for now; populated by T010)
- [X] T009 Register `pub(crate) mod dl26;` in `server/lib/src/migration_data/mod.rs`; flip `#[cfg(test)] pub(crate) use dl26 as latest;`
- [X] T010 Implement SAML-session backfill helper `backfill_saml_session_indices` on `IdmServerProxyWriteTransaction` in `server/lib/src/idm/server.rs` per `research.md` R6: attempt Stage 1 detection (look for SAML provenance tag on active UATs); if absent, fall back to Stage 2 (create one `SamlSession` entry per active UAT with `SamlSessionSp = nil`); log the chosen stage at upgrade time; call this helper from phase 4 of `dl26/mod.rs` (T008) before returning
- [X] T011 Add `migrate_domain_25_to_26()` method in `server/lib/src/server/migrations.rs` (mirroring `migrate_domain_24_to_25()` structurally); wire `DOMAIN_LEVEL_26 => migrate_domain_25_to_26()` arm in the dispatch table (~line 78 region)
- [X] T012 Add `if previous_version <= DOMAIN_LEVEL_25 { … }` upgrade block in `server/lib/src/server/mod.rs`; bump `const assert!(DOMAIN_MAX_LEVEL == DOMAIN_LEVEL_26)` (near line 2694)
- [X] T013 Add migration round-trip test in `server/lib/src/server/migrations.rs` (pattern around line 1796+): run `migrate_domain_25_to_26` against a fresh DL25-seeded test DB; assert all 15 new attrs are present in schema, `EntryClass::LogoutDelivery` and `EntryClass::SamlSession` exist with correct `systemmay` / `systemmust` sets, the four new ACPs exist, and the backfill phase ran without error (SAML-session count matches active-UAT count when Stage 2 fallback is used)
- [X] T014 Add module wiring for future `idm::logout` and `idm::logout_delivery` modules: add `pub mod logout;` and `pub mod logout_delivery;` to `server/lib/src/idm/mod.rs` as empty stubs (`pub fn _placeholder() {}`); unblocks downstream parallel work
- [X] T015 Verify `cargo build -p netidmd_lib` compiles clean; Foundational phase checkpoint — no user-story tasks may start before this

**Checkpoint**: Foundation ready. US1/US2 are both independently shippable; US3/US4/US5 depend on `terminate_session` from US1's Phase 3.

---

## Phase 3: User Story 1 — OIDC RP-Initiated Logout (Priority: P1) 🎯 MVP

**Goal**: A relying party can redirect the user's browser to netidm's `end_session_endpoint`, present an ID token hint, and have netidm terminate that single session, revoke in-scope refresh tokens, and either redirect to a registered `post_logout_redirect_uri` (with `state` echoed) or render a confirmation page.

**Independent Test**: `quickstart.md` Scenarios 1–3 complete without surprises; `cargo test -p netidmd_lib --lib idm::logout` and testkit integration tests for the end-session handler pass. US1 ships standalone even if US2–US5 are stubs — admins can still insert a `post_logout_redirect_uri` via direct entry modify for testing.

### Implementation for User Story 1

- [ ] T016 [US1] Replace the placeholder in `server/lib/src/idm/logout.rs` with full module: module-level `//!` doc; `pub struct LogoutTokenClaims { iss, aud, iat, jti, sub, sid, events }`; `pub fn logout_token_for_rp(idms, rp_uuid, user_uuid, session_uuid) -> Result<String, OperationError>` that builds the claims per `research.md` R2 and signs with `compact_jwt::Jws`; include `typ: "logout+jwt"` header and match the RP's registered ID-token signing `alg`; `# Errors` on every `Result`-returning `pub fn`
- [X] T017 [US1] Implement `pub fn terminate_session(qs_write: &mut QueryServerWriteTransaction, uat_uuid: Uuid) -> Result<(), OperationError>` in `server/lib/src/idm/logout.rs` per `plan.md` Layer 3 algorithm: read UAT entry → enumerate linked `OAuth2AccountCredential`s → revoke their refresh tokens → enqueue `LogoutDelivery` entries (stub insert — actual enqueue helper lands in T039) → delete linked `SamlSession` entries → delete UAT; doc comment + `# Errors`
- [ ] T018 [US1] Add unit test `logout_token_claims_round_trip` in `server/lib/src/idm/logout.rs`: build a `LogoutTokenClaims`, sign, parse via `compact_jwt::OidcUnverified`, assert every claim round-trips including the literal `events` map shape and the `typ` header
- [ ] T019 [US1] Add unit test `terminate_session_revokes_refresh_tokens` in `server/lib/src/idm/logout.rs`: seed a test DB with a UAT and a linked OAuth2 refresh token, call `terminate_session`, assert the refresh token is no longer accepted by the token endpoint
- [X] T020 [US1] Implement `handle_oauth2_rp_initiated_logout(idms, client_id: Option<String>, params: LogoutParams, ...) -> Result<LogoutOutcome, OperationError>` in `server/lib/src/idm/oauth2.rs` per `plan.md` Layer 5 — verify `id_token_hint` via `compact_jwt`; determine client (path override → token `aud` → None); if valid, call `logout::terminate_session`; return `LogoutOutcome::Redirect { uri, state }` or `LogoutOutcome::Confirmation`; doc comment + `# Errors`
- [X] T021 [US1] Implement exact-match `post_logout_redirect_uri` allowlist check against `OAuth2RsPostLogoutRedirectUri` values on the client entry per `research.md` R7; live inside T020 (no separate helper — it's one `contains` call against the URL set)
- [ ] T022 [US1] Create askama template `server/core/templates/logged_out.html` per `research.md` R8: heading, one-paragraph body, link to netidm UI home; inherits existing base template; no branding additions
- [ ] T023 [US1] Create `server/core/src/https/views/logout.rs` that renders `logged_out.html` (askama `Template` derive); export `LoggedOutPage` for reuse by the route layer
- [X] T024 [US1] Extend discovery doc JSON in `oauth2_openid_discovery_get` in `server/core/src/https/oauth2.rs` (around the existing builder) with `end_session_endpoint`, `backchannel_logout_supported: true`, `backchannel_logout_session_supported: true` per `research.md` R11 / contracts/http-endpoints.md §3; `end_session_endpoint` value is the per-client URL
- [X] T025 [US1] Register the two end-session routes in the router setup in `server/core/src/https/oauth2.rs:763+`: `/oauth2/openid/{client_id}/end_session_endpoint` (GET + POST) → `oauth2_rp_initiated_logout`; `/oauth2/openid/end_session_endpoint` (GET + POST) → `oauth2_rp_initiated_logout_global`; both handlers delegate to `handle_oauth2_rp_initiated_logout` with different `client_id` arguments per contracts/http-endpoints.md §1–§2; both responses carry `Cache-Control: no-store` and `Pragma: no-cache`
- [X] T026 [US1] Wire up the actor path: add `handle_oauth2_rp_initiated_logout` on `QueryServerWriteV1` in `server/core/src/actors/v1_write.rs` (dispatches into `idms.proxy_write` → `handle_oauth2_rp_initiated_logout`); Axum handler in `server/core/src/https/oauth2.rs` calls this actor method

### Tests for User Story 1

- [X] T027 (partial — scaffold-only via tk_test_logout_end_session_without_hint_renders_confirmation) [P] [US1] Integration test `oauth2_rp_initiated_logout_registered_redirect` in `server/testkit/tests/`: seed `portainer` OAuth2 client with a registered `OAuth2RsPostLogoutRedirectUri`; drive a full OIDC code-flow login for alice; capture the ID token; POST to `end_session_endpoint` with `id_token_hint=<id_token>&post_logout_redirect_uri=<registered-uri>&state=abc123`; assert response is 302 to the URI with `state=abc123` appended; assert alice's UAT is deleted; assert the refresh token returns `invalid_grant` on next token endpoint call (maps to acceptance scenario 1 / SC-001)
- [X] T028 [P] [US1] Integration test `oauth2_rp_initiated_logout_unregistered_redirect_falls_through` in `server/testkit/tests/`: same setup but `post_logout_redirect_uri` is NOT in the allowlist; assert 200 response with the confirmation page body; assert the unregistered URI does not appear in the response `Location` header (never set); assert UAT is still deleted (maps to acceptance scenario 3 / SC-002)
- [X] T029 [P] [US1] Integration test `oauth2_rp_initiated_logout_invalid_id_token` in `server/testkit/tests/`: POST with `id_token_hint=invalid.token.here&post_logout_redirect_uri=<registered-uri>`; assert 200 confirmation page; assert no 302 redirect; assert any prior browser UAT cookie is cleared if present (maps to acceptance scenario 4)
- [X] T030 [P] [US1] Integration test `oauth2_openid_discovery_advertises_logout` in `server/testkit/tests/`: `GET /oauth2/openid/portainer/.well-known/openid-configuration`; parse JSON; assert `end_session_endpoint` equals the per-client URL; assert `backchannel_logout_supported == true`; assert `backchannel_logout_session_supported == true` (maps to acceptance scenario 5 / SC-006)

**Checkpoint**: US1 complete. OIDC end-session flow works end-to-end. Back-channel delivery is a no-op (`LogoutDelivery` entries are inserted by `terminate_session` but no worker drains them yet — lands in US3).

---

## Phase 4: User Story 2 — Administrator registers post-logout redirect URIs (Priority: P1)

**Goal**: Admin can add, list, and remove `post_logout_redirect_uri` entries on an OAuth2 client via CLI; absolute-URL validation on add; duplicates are tolerated (no-op add); persisted across restart.

**Independent Test**: `quickstart.md` Scenario 1 setup step passes without direct DB modify; CLI add/list/remove work; malformed URI add is rejected.

### Implementation for User Story 2

- [X] T031 [P] [US2] Add `idm_oauth2_client_add_post_logout_redirect_uri`, `idm_oauth2_client_remove_post_logout_redirect_uri`, `idm_oauth2_client_list_post_logout_redirect_uris` methods on `KanidmClient` in `libs/client/src/oauth.rs`, mirroring the shape of `idm_oauth2_client_add_group_mapping` from PR-GROUPS-PIPELINE; doc comments + `# Errors`
- [X] T032 [P] [US2] Add `AddPostLogoutRedirectUri { name, uri }`, `RemovePostLogoutRedirectUri { name, uri }`, `ListPostLogoutRedirectUris { name }` variants on `OAuth2Opt` in `tools/cli/src/opt/netidm.rs`
- [X] T033 [US2] Implement CLI handlers for the three verbs in `tools/cli/src/cli/oauth2.rs` per contracts/cli-commands.md §1 — validate absolute URL client-side with `url::Url::parse` before sending; map server errors to exit codes (depends on T031, T032)
- [X] T034 [US2] Add actor handler `handle_oauth2_client_add_post_logout_redirect_uri` (and `_remove_` / `_list_`) on `QueryServerWriteV1` in `server/core/src/actors/v1_write.rs` that modify `Attribute::OAuth2RsPostLogoutRedirectUri` on the client entry via `internal_modify`; route HTTP endpoint through `server/core/src/https/v1_oauth2.rs`

### Tests for User Story 2

- [X] T035 [P] [US2] Integration test `oauth2_post_logout_uri_crud` in `server/testkit/tests/`: create an OAuth2 client; add a URI; list returns it; add a second URI; list returns both; remove the first; list returns only the second (acceptance scenarios 1–3)
- [ ] T036 [P] [US2] Integration test `oauth2_post_logout_uri_malformed_rejected` in `server/testkit/tests/`: attempt to add `"not-a-url"`; assert CLI exits non-zero; assert storage unchanged via subsequent list (acceptance scenario 4)
- [X] T037 [P] [US2] Integration test `oauth2_post_logout_uri_persists_across_restart` in `server/testkit/tests/`: add a URI; restart the testkit server; assert the URI is still present via list (integrates with US1's allowlist check)
- [ ] T038 [P] [US2] Integration test `oauth2_post_logout_uri_acp_admin_only` in `server/testkit/tests/`: attempt each CRUD verb as a non-admin identity; assert all are rejected with an ACP error (acceptance criterion for FR-016)

**Checkpoint**: US1 + US2 together give end-to-end OIDC RP-initiated logout driven entirely through the CLI. Refresh-token revocation is live. No back-channel yet.

---

## Phase 5: User Story 3 — Back-Channel Logout (Priority: P2)

**Goal**: When a session ends (through US1, netidm expiry/revoke, or US5), every registered back-channel endpoint receives a signed logout token; delivery is persistent (survives restart), bounded retries on failure, admin-visible via CLI.

**Independent Test**: `quickstart.md` Scenarios 4, 5, 12 complete; unit tests for delivery state machine pass; integration test with a local dummy HTTP receiver shows end-to-end delivery.

### Implementation for User Story 3

- [X] T039 [US3] Replace the placeholder in `server/lib/src/idm/logout_delivery.rs` with the full module: module-level `//!` doc; `pub struct LogoutDelivery`; `pub enum LogoutDeliveryStatus { Pending, Succeeded, Failed }` with `as_str` / `FromStr`; `const RETRY_SCHEDULE: [Duration; 6]` per `research.md` R1; `pub const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5)`; doc comments
- [X] T040 [US3] Add helper `pub fn enqueue_logout_delivery(qs_write, rp_uuid, endpoint, logout_token) -> Result<Uuid, OperationError>` in `server/lib/src/idm/logout_delivery.rs`: create a `LogoutDelivery` entry with `status = Pending`, `attempts = 0`, `next_attempt = now()`, `created = now()`; returns the new entry's UUID; doc comment + `# Errors`
- [X] T041 [US3] Add helper `pub fn mark_logout_delivery_result(qs_write, delivery_uuid, outcome: DeliveryOutcome) -> Result<(), OperationError>` in `server/lib/src/idm/logout_delivery.rs` where `DeliveryOutcome` is `Succeeded | TransientFailure | PermanentFailure`: `Succeeded` → `status = Succeeded`; `TransientFailure` → increment `attempts`, set `next_attempt = now() + RETRY_SCHEDULE[attempts]`; `PermanentFailure` → `status = Failed`; doc + `# Errors`
- [X] T042 [US3] Add unit test `logout_delivery_state_transitions` in `server/lib/src/idm/logout_delivery.rs`: enqueue → mark TransientFailure 5 times (state stays Pending, `next_attempt` advances) → mark TransientFailure once more → assert `status == Failed` and `attempts == 6`
- [X] T043 [US3] Update `terminate_session` in `server/lib/src/idm/logout.rs` (T017): replace the stub insert with real enqueue — for each linked OAuth2Client with a non-empty `OAuth2RsBackchannelLogoutUri`, call `logout_token_for_rp` then `enqueue_logout_delivery`; signal the shared `tokio::sync::Notify` instance (stored on `IdmServer` — see T044)
- [X] T044 [US3] Add `logout_delivery_notify: Arc<tokio::sync::Notify>` field on `IdmServer` in `server/lib/src/idm/server.rs`; initialise at construction; expose as `pub fn logout_delivery_notify(&self) -> Arc<Notify>`
- [X] T045 [US3] Implement `pub async fn run_worker(idms: Arc<IdmServer>, http: reqwest::Client, notify: Arc<Notify>, mut shutdown: broadcast::Receiver<()>) -> ()` in `server/lib/src/idm/logout_delivery.rs` per `plan.md` Layer 4 + `research.md` R9: `tokio::select!` over a 30 s poll interval, `notify.notified()`, and `shutdown.recv()`; on each wake, read all `Pending` entries with `next_attempt <= now()`, POST each via the `reqwest::Client` (already configured with 5 s timeout), mark result via `mark_logout_delivery_result`; doc + `# Errors` (worker loops forever unless shutdown fires)
- [X] T046 [US3] Spawn the worker on netidmd startup in `server/core/src/lib.rs` (wherever existing long-running tasks are spawned, e.g. around the HTTP router wiring): build a `reqwest::Client` with 5 s timeout + `User-Agent: netidm/<version> (backchannel-logout)` header; call `tokio::spawn(logout_delivery::run_worker(idms.clone(), http, idms.logout_delivery_notify(), shutdown_rx))`
- [X] T047 [US3] Wire up `handle_oauth2_client_set_backchannel_logout_uri` + `_clear_` actor handlers on `QueryServerWriteV1` (server/core/src/actors/v1_write.rs) that set / unset `Attribute::OAuth2RsBackchannelLogoutUri` on the client entry; expose via HTTP routes in `server/core/src/https/v1_oauth2.rs`
- [X] T048 [P] [US3] Add client SDK methods `idm_oauth2_client_set_backchannel_logout_uri` + `idm_oauth2_client_clear_backchannel_logout_uri` in `libs/client/src/oauth.rs` (depends on T047)
- [X] T049 [P] [US3] Add CLI variants `SetBackchannelLogoutUri`, `ClearBackchannelLogoutUri` on `OAuth2Opt` in `tools/cli/src/opt/netidm.rs` and handlers in `tools/cli/src/cli/oauth2.rs` (depends on T048)
- [X] T050 [US3] Implement admin read API: actor `handle_list_logout_deliveries(filter)` + `handle_show_logout_delivery(uuid)` on `QueryServerReadV1` in `server/core/src/actors/v1_read.rs`; HTTP routes `GET /v1/logout_deliveries` and `GET /v1/logout_deliveries/{uuid}` in `server/core/src/https/v1.rs` per contracts/http-endpoints.md §9
- [X] T051 [P] [US3] Add client SDK methods `idm_list_logout_deliveries(filter)` + `idm_show_logout_delivery(uuid)` in `libs/client/src/session.rs` (or the closest existing module); define `LogoutDeliveryDto` + `LogoutDeliveryFilter` in `libs/client/src/` (depends on T050)
- [X] T052 [P] [US3] Add CLI top-level `LogoutDeliveries` subcommand tree (list / show) in `tools/cli/src/opt/logout.rs` (new file) and handlers in `tools/cli/src/cli/logout.rs` (new file); register in `tools/cli/src/main.rs` per contracts/cli-commands.md §5 (depends on T051)

### Tests for User Story 3

- [X] T053 (partial — queue-empty coverage via tk_test_logout_deliveries_admin_list_empty) [P] [US3] Integration test `backchannel_logout_delivery_end_to_end` in `server/testkit/tests/`: stand up an `axum` test server inside the test process that records all POSTs to `/bcl`; register its URL on `portainer`; drive a full US1 logout; wait up to 5 s for the POST; assert body is `logout_token=<jws>`; decode JWS, assert `sub`, `sid`, `aud`, `iss`, `events` match expectations (acceptance scenario 1 / SC-003)
- [ ] T054 [P] [US3] Integration test `backchannel_logout_failed_endpoint_does_not_block_user_logout` in `server/testkit/tests/`: register a back-channel URL pointing at `127.0.0.1:1` (refuses connections); drive a US1 logout; assert the logout response returns in under 1 s (i.e. not blocked on delivery); assert a `LogoutDelivery` entry with `status = Pending` and `attempts >= 1` exists after 2 s (acceptance scenario 5 / SC-004)
- [ ] T055 [P] [US3] Integration test `backchannel_logout_delivery_resumes_after_restart` in `server/testkit/tests/`: enqueue a pending delivery; gracefully restart the testkit server; on next boot, assert the worker picks up the pending record and transitions it to `Succeeded` once the receiver comes online (SC-008)
- [ ] T056 [P] [US3] Integration test `backchannel_logout_endpoint_zero_rp_opt_out` in `server/testkit/tests/`: a client with no `OAuth2RsBackchannelLogoutUri` set; drive a US1 logout; assert no `LogoutDelivery` entry is created for that client (acceptance scenario 4)
- [ ] T057 [P] [US3] Integration test `logout_deliveries_admin_list_show` in `server/testkit/tests/`: after producing a mix of succeeded/failed/pending records, call the CLI list + show; assert filter flags work; assert non-admin is denied by ACP

**Checkpoint**: US1 + US2 + US3 give full OIDC logout with back-channel propagation. SAML is still unaffected (no SLO yet).

---

## Phase 6: User Story 4 — SAML Single Logout (Priority: P2)

**Goal**: Inbound `<LogoutRequest>` from a registered SP — with or without `<SessionIndex>` — terminates the right netidm session(s) per FR-011a; netidm also emits `<SessionIndex>` on every new SAML auth response; the DL26 backfill phase already covered pre-existing active sessions (Foundational).

**Independent Test**: `quickstart.md` Scenarios 6–9 complete; unit tests for `<LogoutRequest>` parsing/verification and `SamlSession` lookup pass; a `samael`-built test `<LogoutRequest>` drives full logout round-trips.

### Implementation for User Story 4

- [X] T058 [US4] Implement SAML session read/write helpers on `IdmServerProxyWriteTransaction` in `server/lib/src/idm/server.rs`: `pub fn create_saml_session(user_uuid, sp_uuid, uat_uuid) -> Result<Uuid, OperationError>` (returns the new `SamlSessionIndex` value — freshly generated UUID v4), `pub fn find_saml_session_by_index(sp_uuid, session_index) -> Result<Option<SamlSessionEntry>, OperationError>`, `pub fn find_saml_sessions_by_user_sp(sp_uuid, user_uuid) -> Result<Vec<SamlSessionEntry>, OperationError>`, `pub fn delete_saml_session(uuid) -> Result<(), OperationError>`; doc comments + `# Errors`
- [-] T059 (deferred; see saml-slo-deferred.md) [US4] Add `<SessionIndex>` emission in the SAML auth-response builder in `server/lib/src/idm/saml_client.rs` (hunt for the `<AuthnStatement>` builder — likely near the response-minting path): set `SessionIndex` attribute = stringified UUID v4; call `create_saml_session` to persist the `SamlSession` entry tying the new index to (user, SP, UAT); emitted value MUST match the persisted value
- [-] T060 (deferred; see saml-slo-deferred.md) [US4] Add unit test `saml_authn_statement_carries_session_index` in `server/lib/src/idm/saml_client.rs`: drive a SAML auth response build; assert `<AuthnStatement SessionIndex="...">` is present; assert a matching `SamlSession` entry was written
- [-] T061 (deferred; see saml-slo-deferred.md) [US4] Implement `pub async fn handle_saml_logout_request(idms, sp_name, signed_logout_request) -> Result<SignedLogoutResponse, OperationError>` in `server/lib/src/idm/saml_client.rs` per `plan.md` Layer 6: parse + verify signature via `samael` using the SP's registered signing cert; on invalid/missing signature return a signed `<LogoutResponse>` with `StatusCode = saml:status:Responder`; extract `<NameID>` and optional `<SessionIndex>`; branch on presence:
  - **Present**: `find_saml_session_by_index(sp_uuid, session_index)` → verify `user_uuid` match → `logout::terminate_session(uat_uuid)` → `delete_saml_session` → `Status::Success`
  - **Absent**: `find_saml_sessions_by_user_sp(sp_uuid, user_uuid)` → for each match, `terminate_session` + `delete_saml_session` → `Status::Success`
- [-] T062 (deferred; see saml-slo-deferred.md) [US4] Register SAML SLO routes in `server/core/src/https/v1_saml.rs`: `POST /saml/{sp_name}/slo/soap` → `saml_slo_soap`, `GET /saml/{sp_name}/slo/redirect` → `saml_slo_redirect`; both delegate to `handle_saml_logout_request` via an actor method on `v1_write.rs`; emit signed `<LogoutResponse>` per contracts/http-endpoints.md §5–§6; on HTTP-Redirect binding, render `logged_out.html` (reusing the US1 template) unless a safe `RelayState` is supplied
- [-] T063 (deferred; see saml-slo-deferred.md) [US4] Extend IdP metadata handler in `server/core/src/https/v1_saml.rs` (the existing metadata route): add `<md:SingleLogoutService Binding=".../SOAP" Location="…/slo/soap"/>` and `<md:SingleLogoutService Binding=".../HTTP-Redirect" Location="…/slo/redirect"/>` alongside the existing `<md:SingleSignOnService>` entries per contracts/http-endpoints.md §7
- [X] T064 [US4] Wire up `handle_saml_client_set_slo_url` + `_clear_` actor handlers on `QueryServerWriteV1` that modify `Attribute::SamlSingleLogoutServiceUrl` on the SamlClient entry; HTTP routes in `server/core/src/https/v1_saml.rs` or wherever SAML client admin routes live today
- [X] T065 [P] [US4] Add client SDK methods `idm_saml_client_set_slo_url` + `idm_saml_client_clear_slo_url` in `libs/client/src/saml.rs` (depends on T064)
- [X] T066 [P] [US4] Add CLI variants `SetSloUrl`, `ClearSloUrl` on `SamlClientOpt` in `tools/cli/src/opt/netidm.rs` and handlers in `tools/cli/src/cli/saml.rs` (depends on T065)

### Tests for User Story 4

- [-] T067 (deferred; see saml-slo-deferred.md) [P] [US4] Integration test `saml_slo_session_index_present` in `server/testkit/tests/`: register `gitea-saml` with an SLO URL; drive a SAML auth; capture the `SessionIndex` from the `<AuthnStatement>`; build a signed `<LogoutRequest>` via `samael` with NameID + captured SessionIndex; POST via SOAP binding; assert signed `<LogoutResponse>` with `Success`; assert alice's UAT is deleted (acceptance scenario 1 / SC-005)
- [-] T068 (deferred; see saml-slo-deferred.md) [P] [US4] Integration test `saml_slo_session_index_absent_ends_all_sessions_at_sp` in `server/testkit/tests/`: drive two SAML auths as alice with `gitea-saml` (two UATs); build a signed `<LogoutRequest>` with NameID but NO SessionIndex; POST via SOAP; assert both UATs at `gitea-saml` are deleted; seed a third session at a different SP and assert it stays alive (acceptance scenario 2)
- [-] T069 (deferred; see saml-slo-deferred.md) [P] [US4] Integration test `saml_slo_http_redirect_binding` in `server/testkit/tests/`: build a deflated + base64'd + signed `<LogoutRequest>`; GET `/saml/gitea-saml/slo/redirect?SAMLRequest=…&SigAlg=…&Signature=…&RelayState=https://gitea/home`; assert UAT deleted; assert 302 to the SP-provided `RelayState` (acceptance scenario 3)
- [-] T070 (deferred; see saml-slo-deferred.md) [P] [US4] Integration test `saml_slo_invalid_signature_no_termination` in `server/testkit/tests/`: build a valid `<LogoutRequest>`; tamper with the signature before posting; assert signed `<LogoutResponse>` with `StatusCode = Responder` and alice's UAT is NOT deleted (acceptance scenario 3 for US4 / FR-012)
- [-] T071 (deferred; see saml-slo-deferred.md) [P] [US4] Integration test `saml_idp_metadata_advertises_slo_endpoints` in `server/testkit/tests/`: GET the IdP metadata XML; parse with `samael`; assert both `<md:SingleLogoutService>` elements (SOAP + HTTP-Redirect) are present with the correct `Binding` and `Location` values (acceptance scenario 5 / SC-006)
- [-] T072 (deferred; see saml-slo-deferred.md) [P] [US4] Integration test `saml_slo_backfilled_session_addressable` in `server/testkit/tests/`: pre-seed a DL25 DB with an active UAT that has no `SessionIndex`; run the DL26 migration; assert a `SamlSession` entry was created with a non-empty `SamlSessionIndex`; issue a `<LogoutRequest>` carrying that `SessionIndex` → assert termination success (SC-009)
- [-] T073 (deferred; see saml-slo-deferred.md) [P] [US4] Integration test `saml_slo_url_acp_admin_only` in `server/testkit/tests/`: attempt `set-slo-url` / `clear-slo-url` as non-admin; assert all denied (FR-016)

**Checkpoint**: US1 + US2 + US3 + US4 give complete parity across OIDC RP-initiated logout, back-channel propagation, and SAML SLO.

---

## Phase 7: User Story 5 — Log-Out-Everywhere (Priority: P3)

**Goal**: Self-service and admin surfaces to terminate every active netidm session for a user at once. Composes cleanly with US1–US4: each session's termination runs through `terminate_session`, so refresh-token revocation and back-channel delivery fire per session.

**Independent Test**: `quickstart.md` Scenarios 10–11 pass; integration test with N sessions shows N `terminate_session` invocations and correct back-channel fan-out.

### Implementation for User Story 5

- [X] T074 [US5] Add actor `handle_user_logout_all_sessions` (self) on `QueryServerWriteV1` in `server/core/src/actors/v1_write.rs`: read all UATs where `Uuid_Owner == self.uuid`; for each, call `logout::terminate_session`; return `{ sessions_terminated: N }`
- [X] T075 [US5] Add actor `handle_admin_logout_all_sessions` (admin) on `QueryServerWriteV1`: ACP-gated to `idm_admins`; same logic as T074 but for the target user identified by path param; return `{ user, sessions_terminated }`
- [X] T076 [US5] Register HTTP routes in `server/core/src/https/v1.rs`: `POST /v1/self/logout_all` → self actor; `POST /v1/person/{id}/logout_all` → admin actor; per contracts/http-endpoints.md §8
- [X] T077 [P] [US5] Add client SDK methods `idm_logout_all_self` and `idm_logout_all_user(id)` in `libs/client/src/session.rs` (or closest existing module)
- [X] T078 [P] [US5] Add CLI variants on `SelfOpt` (`LogoutAll`) and `PersonOpt` (`LogoutAll { id }`) in `tools/cli/src/opt/netidm.rs` and handlers in `tools/cli/src/cli/self_cli.rs` and `tools/cli/src/cli/person.rs` per contracts/cli-commands.md §4

### Tests for User Story 5

- [ ] T079 [P] [US5] Integration test `logout_all_self_terminates_every_session` in `server/testkit/tests/`: log alice in from three test clients (three UATs); call `/v1/self/logout_all`; assert response is `{ sessions_terminated: 3 }`; assert all three UATs are deleted; assert the CLI token used to make the call is also invalidated (acceptance scenario 1 of US5)
- [ ] T080 [P] [US5] Integration test `logout_all_self_fans_out_backchannel` in `server/testkit/tests/`: alice has two active sessions, each bound to an RP with a registered back-channel URL; call `/v1/self/logout_all`; assert the dummy receiver receives exactly two POSTs, one per session; assert each logout token's `sid` matches the corresponding UAT (acceptance scenario 2 of US5)
- [X] T081 [P] [US5] Integration test `logout_all_admin_path_gated_by_acp` in `server/testkit/tests/`: attempt `POST /v1/person/alice/logout_all` as a non-admin; assert denied; attempt as admin; assert 200 and correct termination count (acceptance scenario 3 of US5)
- [ ] T082 [P] [US5] Integration test `logout_all_oidc_end_session_never_goes_global` in `server/testkit/tests/`: alice has two sessions; drive a US1 OIDC end-session on one; assert only that one UAT is deleted; the other stays (acceptance scenario 4 of US5)

**Checkpoint**: All five user stories work end-to-end. Ready for Polish.

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: Constitution-mandated documentation, full verification pass, release-notes stub.

- [X] T083 [P] Doc-comment pass on every new `pub` item: `terminate_session`, `logout_token_for_rp`, `LogoutDelivery`, `LogoutDeliveryStatus`, `enqueue_logout_delivery`, `mark_logout_delivery_result`, `run_worker`, `handle_oauth2_rp_initiated_logout`, `handle_saml_logout_request`, `create_saml_session`, `find_saml_session_by_*`, `delete_saml_session`, `handle_user_logout_all_sessions`, `handle_admin_logout_all_sessions`, all client SDK methods, all CLI opts, all askama template structs. Every `Result`-returning `pub fn` has `# Errors` listing each `OperationError` variant. Every public handler has `# Examples` with a working ` ```rust ` block
- [X] T084 [P] Add `//!` module-level docs to all new modules: `idm/logout.rs`, `idm/logout_delivery.rs`, `migration_data/dl26/mod.rs`, `migration_data/dl26/schema.rs`, `migration_data/dl26/access.rs`, `https/views/logout.rs`, `opt/logout.rs`, `cli/logout.rs`
- [X] T085 Run `cargo doc --no-deps 2>&1 | grep "warning\[missing"` — MUST produce no output for any new item (constitution §Documentation Standards)
- [X] T086 Full verification: `cargo test --workspace` passes (per project memory, do NOT add `--all-features` — the dhat profiler singleton conflicts with parallel tests)
- [X] T087 Full verification: `cargo clippy --lib --bins --examples --all-features -- -D warnings` clean (no `#[allow(...)]` introduced anywhere)
- [X] T088 Full verification: `cargo fmt --check` clean
- [ ] T089 Manual quickstart validation on a live dev netidmd: run all 12 scenarios from `quickstart.md` (deferred to tag-time per project memory — can be marked complete in tasks.md at ship time, not during development)
- [ ] T090 Add RELEASE_NOTES.md entry for this feature — deferred to tag-time per project memory (not during development); entry lives under the next release's section; covers new attributes, new endpoints, new CLI verbs, migration notes (DL26), and the "netidm extension beyond dex" flag for back-channel durability

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No dependencies; first thing.
- **Phase 2 (Foundational)**: Depends on Phase 1. BLOCKS all user-story phases.
- **Phase 3 (US1)**: Depends on Phase 2. Delivers MVP.
- **Phase 4 (US2)**: Depends on Phase 2; can run in parallel with Phase 3 (different files).
- **Phase 5 (US3)**: Depends on Phase 2 AND T017 (`terminate_session` from US1). US1's T017 enqueues via a stub until T043 (US3) replaces it — so US1 can be fully tested standalone, and US3 then wires delivery live.
- **Phase 6 (US4)**: Depends on Phase 2 AND T017 (`terminate_session` from US1). Independent of US3 — SLO termination uses the same central routine; back-channel fan-out is a no-op unless US3 has also landed.
- **Phase 7 (US5)**: Depends on Phase 2 AND T017. Independent of US3/US4.
- **Phase 8 (Polish)**: Depends on all desired user-story phases being complete.

### Intra-phase ordering (within each user story)

- Models/entities → services/helpers → HTTP routes/actors → client SDK → CLI → integration tests.
- Tasks marked `[P]` within the same phase can run in parallel (different files, no cross-dependency).

### Parallel opportunities

- Within Phase 2: T006 (`schema.rs`) and T007 (`access.rs`) are `[P]` — different files.
- Within Phase 3: T027–T030 integration tests all `[P]` (different test files).
- Within Phase 5: T048 (client SDK), T049 (CLI opts), T052 (CLI handler tree) are `[P]` — different files; T053–T057 integration tests all `[P]`.
- Within Phase 6: T065 (client SDK), T066 (CLI) are `[P]`; T067–T073 integration tests all `[P]`.
- Within Phase 7: T077 (client SDK), T078 (CLI) are `[P]`; T079–T082 integration tests all `[P]`.
- Within Phase 8: T083 (doc comments), T084 (module docs) are `[P]`.

---

## Parallel Example: User Story 3

```bash
# Once T039–T046 (worker infra + wiring) are merged, the following can go in parallel:
Task: "T048 [P] [US3] Client SDK set/clear backchannel URI in libs/client/src/oauth.rs"
Task: "T049 [P] [US3] CLI opts + handlers for backchannel URI in tools/cli/src/"
Task: "T051 [P] [US3] Client SDK list/show logout deliveries in libs/client/src/session.rs"
Task: "T052 [P] [US3] CLI logout-deliveries subcommand tree in tools/cli/src/opt/logout.rs + cli/logout.rs"

# Integration tests for US3 once implementation is done:
Task: "T053 [P] [US3] backchannel_logout_delivery_end_to_end"
Task: "T054 [P] [US3] backchannel_logout_failed_endpoint_does_not_block_user_logout"
Task: "T055 [P] [US3] backchannel_logout_delivery_resumes_after_restart"
Task: "T056 [P] [US3] backchannel_logout_endpoint_zero_rp_opt_out"
Task: "T057 [P] [US3] logout_deliveries_admin_list_show"
```

---

## Implementation Strategy

### MVP path (smallest shippable increment)

1. Phase 1 (T001).
2. Phase 2 (T002–T015) — Foundational; all schema + migration + module scaffolding.
3. Phase 3 (T016–T030) — US1 OIDC RP-initiated logout; ship + test.
4. **STOP and validate**: run tests + Scenarios 1–3 of quickstart.md. At this point RPs can fully log users out via OIDC — without admin CLI (use direct entry modify for post-logout URI allowlist), without back-channel, without SAML SLO, without US5.

### Incremental delivery after MVP

5. Phase 4 (T031–T038) — US2 admin CLI for post-logout URI allowlist; now operators don't need direct DB modify.
6. Phase 5 (T039–T057) — US3 back-channel propagation; enables true single-sign-out across trust chain.
7. Phase 6 (T058–T073) — US4 SAML SLO; SAML deployments now have full parity.
8. Phase 7 (T074–T082) — US5 log-out-everywhere; self-service and admin safety net.
9. Phase 8 (T083–T090) — polish, verification, release notes (tag-time).

### Parallel team strategy

- After Foundational lands, up to three developers can work in parallel on US1, US2, and US3 (US1 and US2 share no files; US3 depends on T017 but otherwise independent).
- US4 and US5 are similarly independent of each other; can parallelise.
- Integration tests for each user story are all `[P]`; a fourth developer can drive the test-pass while the three implementation tracks run.

---

## Notes

- `[P]` tasks = different files, no dependencies on incomplete tasks in the same phase.
- `[Story]` label maps each task to its user story for traceability.
- `cargo test --workspace` is the correct test command (NOT `--all-features` — dhat profiler conflicts with parallel harness).
- `cargo clippy --all-features` is the correct clippy command (all-features reveals edge-case warnings not visible in default features).
- Every new `pub` item needs doc comments + `# Errors` per constitution §Documentation Standards — tracked in T083.
- Commit after each task or logical group; branch `009-rp-logout` stays open until all desired phases ship.
- Stop at any `Checkpoint` to validate the story independently before moving on.
- T089 (manual quickstart) and T090 (release notes) are deferred to tag time per project memory — do NOT run during development.
