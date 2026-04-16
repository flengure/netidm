# Tasks: Social Login with JIT Provisioning

**Input**: Design documents from `specs/001-social-login-jit/`
**Prerequisites**: plan.md ✅ spec.md ✅ research.md ✅ data-model.md ✅ contracts/ ✅ quickstart.md ✅

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup

**Purpose**: Project initialization — new DL15 migration module and constants.

- [ ] T001 Create `server/lib/src/migration_data/dl15/` directory and `mod.rs` following the DL14 pattern in `server/lib/src/migration_data/dl14/mod.rs`
- [ ] T002 Add 5 new `ATTR_OAUTH2_*` constants to `proto/src/constants.rs`: `ATTR_OAUTH2_USERINFO_ENDPOINT`, `ATTR_OAUTH2_JIT_PROVISIONING`, `ATTR_OAUTH2_CLAIM_MAP_NAME`, `ATTR_OAUTH2_CLAIM_MAP_DISPLAYNAME`, `ATTR_OAUTH2_CLAIM_MAP_EMAIL`
- [ ] T003 Wire the DL15 migration level into the migration registry in `server/lib/src/migration_data/mod.rs` (follow the DL14 registration pattern)
- [ ] T004 Run `cargo test` and `cargo clippy -- -D warnings` to verify baseline passes before any feature code is added

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Schema attributes and provider struct extensions that every user story depends on. No user story work can begin until this phase is complete.

- [ ] T005 [P] Add `SchemaAttribute` for `oauth2_userinfo_endpoint` (Url syntax, optional) in `server/lib/src/migration_data/dl15/schema.rs`
- [ ] T006 [P] Add `SchemaAttribute` for `oauth2_jit_provisioning` (Boolean syntax, optional) in `server/lib/src/migration_data/dl15/schema.rs`
- [ ] T007 [P] Add `SchemaAttribute` for `oauth2_claim_map_name` (Utf8String syntax, optional) in `server/lib/src/migration_data/dl15/schema.rs`
- [ ] T008 [P] Add `SchemaAttribute` for `oauth2_claim_map_displayname` (Utf8String syntax, optional) in `server/lib/src/migration_data/dl15/schema.rs`
- [ ] T009 [P] Add `SchemaAttribute` for `oauth2_claim_map_email` (Utf8String syntax, optional) in `server/lib/src/migration_data/dl15/schema.rs`
- [ ] T010 Extend `SCHEMA_CLASS_OAUTH2_CLIENT.systemmay` in `server/lib/src/migration_data/dl15/schema.rs` to include all 5 new attributes (depends on T005–T009)
- [ ] T011 Add `userinfo_endpoint: Option<Url>`, `jit_provisioning: bool`, and `claim_map: HashMap<KanidmAttr, String>` fields to `OAuth2ClientProvider` struct in `server/lib/src/idm/oauth2_client.rs`
- [ ] T012 Update `reload_oauth2_client_providers()` in `server/lib/src/idm/oauth2_client.rs` to extract `oauth2_userinfo_endpoint`, `oauth2_jit_provisioning`, and all three `oauth2_claim_map_*` attributes from DB entries (depends on T011)
- [ ] T013 Define `ExternalUserClaims` struct in `server/lib/src/idm/authsession/handler_oauth2_client.rs` with fields: `sub: String`, `email: Option<String>`, `email_verified: Option<bool>`, `display_name: Option<String>`, `username_hint: Option<String>`
- [ ] T014 Add `CredState::ProvisioningRequired { provider_uuid: Uuid, claims: ExternalUserClaims }` variant to the `CredState` enum in `server/lib/src/idm/authsession/mod.rs`
- [ ] T015 Add `AuthState::ProvisioningRequired { provider_uuid: Uuid, claims: ExternalUserClaims }` variant to the external-facing `AuthState` enum in `server/lib/src/idm/authsession/mod.rs`
- [ ] T016 Add `find_account_by_oauth2_provider_and_user_id(provider_uuid: Uuid, sub: &str) -> Result<Option<Account>, OperationError>` to the appropriate IdmServer read/write transaction in `server/lib/src/idm/server.rs` using compound filter on `OAuth2AccountProvider` + `OAuth2AccountUniqueUserId`
- [ ] T017 Run `cargo test` and `cargo clippy -- -D warnings`; fix all warnings by resolving the underlying code issues — no `#[allow(...)]` suppression

**Checkpoint**: Schema, provider struct, core types, and account lookup all in place. User story implementation can begin.

---

## Phase 3: User Story 1 — First-Time Social Login (Priority: P1) 🎯 MVP

**Goal**: A first-time user authenticating via GitHub or Google gets a Kanidm account created automatically and is logged in, all within one flow.

**Independent Test**: Configure a JIT-enabled GitHub provider, attempt login with a brand-new GitHub account, verify a Kanidm account is created and the user lands on the dashboard. See `quickstart.md` § "Validation: First-Time Login (Happy Path)".

### Implementation for User Story 1

- [ ] T018 [P] [US1] Add `userinfo_endpoint: Option<Url>`, `jit_provisioning: bool`, and `claim_map: HashMap<KanidmAttr, String>` fields to `CredHandlerOAuth2Client` in `server/lib/src/idm/authsession/handler_oauth2_client.rs` and populate them from `OAuth2ClientProvider` in `CredHandlerOAuth2Client::new()`
- [ ] T019 [US1] Implement Google claim extraction path in `validate_access_token_response()` in `server/lib/src/idm/authsession/handler_oauth2_client.rs`: when `response.id_token` is present, decode the JWT and extract `sub`, `email`, `email_verified`, `name` into `ExternalUserClaims`
- [ ] T020 [US1] Implement GitHub claim extraction path in `validate_access_token_response()` in `server/lib/src/idm/authsession/handler_oauth2_client.rs`: when `userinfo_endpoint` is set and no `id_token`, call the userinfo endpoint with `Bearer <access_token>` (5s timeout), parse JSON for `id` (→ sub as string), `login` (→ username_hint), `name` (→ display_name), `email` (depends on T019)
- [ ] T021 [US1] Implement GitHub two-step email fetch in `server/lib/src/idm/authsession/handler_oauth2_client.rs`: if `email` is null after `/user` call, call `https://api.github.com/user/emails`, select entry where `primary: true` and `verified: true`; if still none, leave `email: None` (depends on T020)
- [ ] T022 [US1] Add `jit_provision_oauth2_account(provider_uuid: Uuid, claims: &ExternalUserClaims, desired_name: &str) -> Result<Uuid, OperationError>` to `IdmServerWriteTransaction` in `server/lib/src/idm/server.rs`: create entry with classes Object/Account/Person/OAuth2Account, set name/displayName/mail/oauth2AccountProvider/oauth2AccountUniqueUserId/oauth2AccountCredentialUuid
- [ ] T023 [US1] Implement username derivation helper in `server/lib/src/idm/account.rs` or `server/lib/src/idm/server.rs`: derive candidate name from `username_hint` (normalize to valid iname), try collision resolution with numeric suffix `_2`…`_100`, then 8-char sub fragment fallback
- [ ] T024 [US1] Wire `CredState::ProvisioningRequired` into the auth session dispatch in `server/lib/src/idm/authsession/mod.rs`: after `validate_access_token_response()` returns `ProvisioningRequired`, call `find_account_by_oauth2_provider_and_user_id()`; if account found return `CredState::Success`; if not found and JIT enabled return `CredState::ProvisioningRequired`; if not found and JIT disabled return `CredState::Denied` (depends on T016, T014)
- [ ] T025 [US1] Propagate `CredState::ProvisioningRequired` → `AuthState::ProvisioningRequired` in the auth state machine in `server/lib/src/idm/authsession/mod.rs`; ensure `issue_uat()` is unreachable from `ProvisioningRequired` state (depends on T015, T024)
- [ ] T026 [US1] Add `COOKIE_OAUTH2_PROVISION_REQ` constant in `server/core/src/https/views/login.rs`
- [ ] T027 [US1] Modify `view_login_oauth2_landing()` in `server/core/src/https/views/login.rs`: when `AuthState::ProvisioningRequired`, serialize `ExternalUserClaims` + `provider_uuid` into signed `COOKIE_OAUTH2_PROVISION_REQ` (HTTP-only, SameSite=Strict, 10-min TTL) and return 302 redirect to `/ui/login/provision` (depends on T025, T026)
- [ ] T028 [US1] Create Askama HTML template `server/core/src/https/templates/login_provision.html` with: editable username field (pre-filled), read-only display name, read-only email, provider name label, submit button, cancel link to `/ui/login`
- [ ] T029 [US1] Implement `view_login_provision_get()` handler in `server/core/src/https/views/login.rs`: read and verify `COOKIE_OAUTH2_PROVISION_REQ`, derive proposed username via T023 logic, render `login_provision.html`; on missing/invalid cookie redirect to `/ui/login` with flash (depends on T027, T028)
- [ ] T030 [US1] Implement `view_login_provision_post()` handler in `server/core/src/https/views/login.rs`: read cookie, validate submitted username (non-empty, valid iname format, not taken), call `jit_provision_oauth2_account()`, clear `COOKIE_OAUTH2_PROVISION_REQ`, re-enter auth flow to issue UAT, set `COOKIE_BEARER_TOKEN`, redirect to original destination (depends on T022, T029)
- [ ] T031 [US1] Register `GET /ui/login/provision` and `POST /ui/login/provision` routes in the Axum router in `server/core/src/https/views/` router setup (depends on T029, T030)
- [ ] T032 [US1] Run `cargo test` and `cargo clippy -- -D warnings`; resolve all warnings by fixing the underlying code — no `#[allow(...)]`

**Checkpoint**: User Story 1 fully functional. First-time social login creates an account and logs the user in end-to-end.

---

## Phase 4: User Story 2 — Admin Configures a Social Provider (Priority: P2)

**Goal**: An administrator can register GitHub or Google as a social login provider, enable JIT provisioning, and map claims using only CLI commands.

**Independent Test**: Run the CLI commands from `quickstart.md` § "Setup: GitHub Provider", then verify `kanidm system oauth2 get mygithub` shows correct JIT and claim-map fields.

### Implementation for User Story 2

- [ ] T033 [P] [US2] Add `CreateGithub { name, client_id, client_secret }` variant to `Oauth2Opt` enum in `tools/cli/src/opt/kanidm.rs`
- [ ] T034 [P] [US2] Add `CreateGoogle { name, client_id, client_secret }` variant to `Oauth2Opt` enum in `tools/cli/src/opt/kanidm.rs`
- [ ] T035 [P] [US2] Add `EnableJitProvisioning { name }` variant to `Oauth2Opt` enum in `tools/cli/src/opt/kanidm.rs`
- [ ] T036 [P] [US2] Add `DisableJitProvisioning { name }` variant to `Oauth2Opt` enum in `tools/cli/src/opt/kanidm.rs`
- [ ] T037 [P] [US2] Add `SetIdentityClaimMap { name, kanidm_attr, provider_claim }` variant to `Oauth2Opt` enum in `tools/cli/src/opt/kanidm.rs`
- [ ] T038 [US2] Implement `exec()` for `CreateGithub` in `tools/cli/src/opt/kanidm.rs`: call `oauth2_client_create()` with pre-filled GitHub defaults (authorisation/token/userinfo endpoints, scopes `user:email read:user`, claim maps `login`/`name`/`email`) (depends on T033)
- [ ] T039 [US2] Implement `exec()` for `CreateGoogle` in `tools/cli/src/opt/kanidm.rs`: call `oauth2_client_create()` with pre-filled Google defaults (OIDC endpoints, scopes `openid email profile`, claim maps `name`/`email`) (depends on T034)
- [ ] T040 [US2] Implement `exec()` for `EnableJitProvisioning` and `DisableJitProvisioning` in `tools/cli/src/opt/kanidm.rs`: single attribute write to `oauth2_jit_provisioning` (depends on T035, T036)
- [ ] T041 [US2] Implement `exec()` for `SetIdentityClaimMap` in `tools/cli/src/opt/kanidm.rs`: validate `kanidm_attr` ∈ {name, displayname, email}, write the corresponding `oauth2_claim_map_*` attribute (depends on T037)
- [ ] T042 [US2] Update `kanidm system oauth2 get` output in `tools/cli/src/opt/kanidm.rs` to display the new JIT fields (`jit_provisioning`, `userinfo_endpoint`, claim maps)
- [ ] T043 [US2] Run `cargo test` and `cargo clippy -- -D warnings`; resolve all warnings

**Checkpoint**: User Stories 1 and 2 both independently functional. Full admin setup + first-time user flow works end-to-end.

---

## Phase 5: User Story 3 — Account Confirmation Page (Priority: P3)

**Goal**: First-time social login users are always shown a confirmation page before account creation, with an editable username field.

**Note**: The confirmation page UI (T028–T031) was already implemented as part of User Story 1 because it is integral to the provisioning flow. This phase covers validation hardening, username collision UX, and edge-case flows that are specific to User Story 3's acceptance scenarios.

**Independent Test**: Pre-create a Kanidm account with the same name as your GitHub `login`. Trigger a first-time GitHub login. Verify the confirmation page appears with a suggested alternate username (e.g. `login_2`). See `quickstart.md` § "Validation: Username Collision".

### Implementation for User Story 3

- [ ] T044 [US3] Harden `view_login_provision_get()` in `server/core/src/https/views/login.rs`: when the derived proposed username is already taken, display the page with the `_2`-suffix suggestion pre-filled and an inline notice "Username already taken — we've suggested an alternative"
- [ ] T045 [US3] Harden `view_login_provision_post()` in `server/core/src/https/views/login.rs`: if submitted username is taken at POST time (race between GET and POST), re-render the confirmation page with a new suggestion rather than returning an error page
- [ ] T046 [US3] Add inline username format validation to `view_login_provision_post()` in `server/core/src/https/views/login.rs`: validate format (lowercase alphanumeric + hyphens, 2–64 chars) and display field-level error on the same page without losing other pre-filled values
- [ ] T047 [US3] Add flash message for expired `COOKIE_OAUTH2_PROVISION_REQ` in `view_login_provision_get()` and `view_login_provision_post()` in `server/core/src/https/views/login.rs`: redirect to `/ui/login` with "Your session has expired. Please sign in again."
- [ ] T048 [US3] Run `cargo test` and `cargo clippy -- -D warnings`; resolve all warnings

**Checkpoint**: All three user stories independently functional. Confirmation page covers all edge cases from spec.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Error message quality, logging, and full end-to-end validation.

- [ ] T049 [P] Review all user-facing error messages added in this feature across `server/core/src/https/views/login.rs` and `server/lib/src/idm/server.rs` for clarity and consistency with existing Kanidm message style
- [ ] T050 [P] Verify no sensitive fields (`access_token`, `client_secret`, `sub`, `email`) appear in any log output added by this feature; audit all `tracing::` calls added in `server/lib/src/idm/authsession/handler_oauth2_client.rs` and `server/lib/src/idm/server.rs`
- [ ] T051 Validate the full quickstart.md scenario end-to-end: GitHub happy path, returning user, JIT disabled denial, username collision (depends on T048)
- [ ] T052 [P] Update `book/src/` developer documentation if any public-facing admin configuration docs need to reference the new CLI commands
- [ ] T053 Final `cargo test` and `cargo clippy -- -D warnings` across the full workspace; resolve all warnings

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No dependencies — start immediately
- **Phase 2 (Foundational)**: Depends on Phase 1 — blocks all user stories
- **Phase 3 (US1)**: Depends on Phase 2 — MVP deliverable
- **Phase 4 (US2)**: Depends on Phase 2 — can run in parallel with Phase 3 (different files: CLI vs. auth/UI)
- **Phase 5 (US3)**: Depends on Phase 3 (confirmation page from T028–T031 must exist first)
- **Phase 6 (Polish)**: Depends on all story phases complete

### User Story Dependencies

- **US1 (P1)**: Can start after Phase 2 — no dependency on US2 or US3
- **US2 (P2)**: Can start after Phase 2 — no dependency on US1 or US3 (CLI is independent of auth/UI code)
- **US3 (P3)**: Depends on US1 (confirmation page infrastructure from T028–T031)

### Within Each User Story

- Schema attributes (T005–T010) before provider struct loading (T011–T012)
- Types (T013–T015) before auth session wiring (T024–T025)
- Claim extraction (T019–T021) before provisioning function (T022)
- Server-side provisioning (T022–T025) before UI handlers (T027–T031)
- GET handler (T029) before POST handler (T030)
- Both handlers (T029–T030) before route registration (T031)

### Parallel Opportunities

- T005–T009 (schema attributes): all parallel within Phase 2
- T033–T037 (CLI enum variants): all parallel within Phase 4
- T019 and T020 (Google/GitHub extraction paths): parallel within Phase 3

---

## Parallel Example: Phase 2 Foundational

```
# Launch all schema attribute tasks together:
T005: Add oauth2_userinfo_endpoint SchemaAttribute
T006: Add oauth2_jit_provisioning SchemaAttribute
T007: Add oauth2_claim_map_name SchemaAttribute
T008: Add oauth2_claim_map_displayname SchemaAttribute
T009: Add oauth2_claim_map_email SchemaAttribute

# Then, once T005–T009 complete:
T010: Extend SCHEMA_CLASS_OAUTH2_CLIENT.systemmay

# In parallel with T010:
T011: Add fields to OAuth2ClientProvider struct
T013: Define ExternalUserClaims struct
T014: Add CredState::ProvisioningRequired variant
T015: Add AuthState::ProvisioningRequired variant
```

## Parallel Example: Phase 3 (US1) + Phase 4 (US2)

```
# After Phase 2 completes, these can run in parallel on different files:
[Developer A — auth/UI path]
T018: Extend CredHandlerOAuth2Client
T019: Google claim extraction
T020: GitHub claim extraction
...

[Developer B — CLI path]
T033: CreateGithub variant
T034: CreateGoogle variant
T035: EnableJitProvisioning variant
...
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL — blocks all stories)
3. Complete Phase 3: User Story 1 (T018–T032)
4. **STOP and VALIDATE**: Run quickstart.md "First-Time Login" scenario
5. Demo: first-time GitHub/Google login creates account and lands user on dashboard

### Incremental Delivery

1. Setup + Foundational → schema and types ready
2. User Story 1 → end-to-end first-time social login works (MVP)
3. User Story 2 → admin can configure providers via CLI (operational)
4. User Story 3 → confirmation page hardened with full collision/validation UX
5. Polish → logging, docs, final clippy clean

---

## Notes

- `[P]` tasks = different files, no blocking dependencies
- `[USn]` label maps each task to a user story for traceability
- Every Rust task includes a `cargo clippy -- -D warnings` step — fix warnings, never suppress
- Confirmation page infrastructure (T028–T031) is implemented in US1 because it is part of the provisioning flow; US3 adds hardening on top
- GitHub email fetch is two-step (T020 + T021) — missing email must never block account creation
