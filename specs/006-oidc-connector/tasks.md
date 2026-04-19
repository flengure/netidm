# Tasks: Generic OIDC Upstream Connector

**Input**: Design documents from `/specs/006-oidc-connector/`
**Prerequisites**: plan.md ✓, spec.md ✓, research.md ✓, data-model.md ✓, contracts/ ✓, quickstart.md ✓

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to
- Exact file paths included in every description

---

## Phase 1: Setup

**Purpose**: Verify branch state and that all design documents are in place before coding begins.

- [X] T001 Confirm branch is `006-oidc-connector` and all spec artifacts exist under `specs/006-oidc-connector/`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Protocol-level additions that all three user stories depend on. Must be complete before any user story work begins.

**⚠️ CRITICAL**: These files define the attribute names and UUIDs that every subsequent task references.

- [X] T002 Add `OAuth2Issuer` and `OAuth2JwksUri` variants to the `Attribute` enum in `proto/src/attribute.rs`, with `to_string()` returning `"oauth2_issuer"` / `"oauth2_jwks_uri"` and matching `from_str()` arms
- [X] T003 [P] Add `UUID_SCHEMA_ATTR_OAUTH2_ISSUER = uuid!("00000000-0000-0000-0000-ffff00000249")` and `UUID_SCHEMA_ATTR_OAUTH2_JWKS_URI = uuid!("00000000-0000-0000-0000-ffff0000024a")` to `server/lib/src/constants/uuids.rs`
- [X] T004 [P] Add `pub const DOMAIN_LEVEL_21: DomainVersion = 21;` to `server/lib/src/constants/mod.rs` (do NOT yet change `DOMAIN_TGT_LEVEL` or `DOMAIN_MAX_LEVEL` — those are updated in Phase 3 once the migration is wired up)

**Checkpoint**: `cargo build` passes with the two new attributes and constants visible.

---

## Phase 3: User Story 1 — OIDC Provider via Discovery URL (Priority: P1) 🎯 MVP

**Goal**: An admin can create an OIDC provider by supplying only an issuer URL; the system auto-discovers all endpoints and stores them including `issuer` and `jwks_uri`. The provider appears in the SSO button list and a login flow can be initiated.

**Independent Test**: Create a provider entry via `idm_oauth2_client_create_oidc`, verify the entry has correct `OAuth2AuthorisationEndpoint`, `OAuth2TokenEndpoint`, `OAuth2Issuer`, and `OAuth2JwksUri` values derived from a mock discovery document.

### Implementation for User Story 1

- [X] T005 [P] [US1] Create `server/lib/src/migration_data/dl21/schema.rs` with three `LazyLock<SchemaAttribute/SchemaClass>` statics: `SCHEMA_ATTR_OAUTH2_ISSUER_DL21` (Url, single-value, systemmay on OAuth2Client), `SCHEMA_ATTR_OAUTH2_JWKS_URI_DL21` (Url, single-value, systemmay), and `SCHEMA_CLASS_OAUTH2_CLIENT_DL21` (extends DL20 class with both new attrs in `systemmay`). Mirror the pattern in `server/lib/src/migration_data/dl20/schema.rs`.
- [X] T006 [P] [US1] Create `server/lib/src/migration_data/dl21/mod.rs` delegating all phases to `super::dl20` except `phase_1_schema_attrs` (adds both new attrs) and `phase_2_schema_classes` (adds updated OAuth2Client class). Include `#[cfg(test)] pub(crate) use super::dl14::accounts;` and `#[cfg(test)] pub(crate) use self::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;` re-exports as in dl20.
- [X] T007 [US1] Add `pub(crate) mod dl21;` to `server/lib/src/migration_data/mod.rs` and change `#[cfg(test)] pub(crate) use dl21 as latest;` (was `dl20`)
- [X] T008 [US1] Add `pub(crate) fn migrate_domain_20_to_21(&mut self) -> Result<(), OperationError>` to `server/lib/src/server/migrations.rs` following the identical structure of `migrate_domain_19_to_20`: checks `DOMAIN_TGT_LEVEL`, runs phases 1–8 via `migration_data::dl21::phase_N_*()`, calls `self.reload()`, `self.reindex(false)`, `self.set_phase(ServerPhase::SchemaReady)`
- [X] T009 [US1] In `server/lib/src/server/mod.rs`: add the migration hook `if previous_version <= DOMAIN_LEVEL_20 && domain_info_version >= DOMAIN_LEVEL_21 { write_txn.migrate_domain_20_to_21()?; }` in the migration dispatch block. Update `const { assert!(DOMAIN_MAX_LEVEL == DOMAIN_LEVEL_21) }`. Now update `DOMAIN_TGT_LEVEL = DOMAIN_LEVEL_21` and `DOMAIN_MAX_LEVEL = DOMAIN_LEVEL_21` in `server/lib/src/constants/mod.rs`.
- [X] T010 [US1] Add `pub(crate) issuer: Option<Url>` and `pub(crate) jwks_uri: Option<Url>` fields to the `OAuth2ClientProvider` struct in `server/lib/src/idm/oauth2_client.rs`. In `reload_oauth2_client_providers()` read both via `provider_entry.get_ava_single_url(Attribute::OAuth2Issuer).cloned()` / `...OAuth2JwksUri...`. Add `issuer: None, jwks_uri: None` to `new_test()` and the struct constructor literal. Also add `jwks_uri: Option<Url>` field to `CredHandlerOAuth2Client` in `server/lib/src/idm/authsession/handler_oauth2_client.rs` and copy it from the provider in the handler constructor.
- [X] T011 [US1] Add `fetch_oidc_discovery` private helper and `pub async fn idm_oauth2_client_create_oidc(&self, name: &str, issuer: &Url, client_id: &str, client_secret: &str) -> Result<(), ClientError>` to `libs/client/src/oauth.rs`. The helper GETs `<issuer>/.well-known/openid-configuration`, deserialises into `OidcDiscoveryDocument { issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri }`, validates issuer match and required fields, then `create_oidc` builds the entry with `ATTR_OAUTH2_ISSUER`, `ATTR_OAUTH2_JWKS_URI` (if present), all discovered endpoints, default scopes `openid profile email`, and POSTs to `/v1/oauth2/_client`.
- [X] T012 [US1] Write integration tests for US1 in `server/lib/src/idm/tests/` (or nearest testkit module): (a) create provider with valid mock discovery doc → verify entry fields; (b) create provider where discovery URL returns 404 → error; (c) create provider where discovery doc missing `authorization_endpoint` → error; (d) create provider where discovery doc `issuer` field doesn't match → error. Use the existing testkit pattern.

**Checkpoint**: `cargo test` passes; a provider can be created via `idm_oauth2_client_create_oidc`; the entry stores correct endpoint URLs, issuer, and jwks_uri.

---

## Phase 4: User Story 2 — JWKS id_token Verification (Priority: P2)

**Goal**: When an OIDC provider returns an `id_token` and has a `jwks_uri` configured, the token's signature is cryptographically verified before claims are extracted. Invalid signatures are rejected.

**Independent Test**: Simulate the full auth loop with a mock token endpoint returning a real ES256-signed `id_token`; verify `AuthState::Success`. Then repeat with a token signed by a different key and verify `AuthState::Denied`.

**Depends on**: Phase 3 complete (needs `jwks_uri` field on `OAuth2ClientProvider` and `CredHandlerOAuth2Client`).

### Implementation for User Story 2

- [X] T013 [US2] Add `OAuth2JwksRequest { jwks_url: Url, id_token: String, access_token: String }` variant to `AuthExternal` in `server/lib/src/idm/authentication.rs`, with a `Debug` arm. Add `OAuth2JwksTokenResponse { claims_body: String }` variant to `AuthCredential` with a `Debug` arm.
- [X] T014 [US2] In `server/lib/src/idm/authsession/handler_oauth2_client.rs`: (a) in the `OAuth2AccessTokenResponse` processing, when `id_token` is present AND `self.jwks_uri.is_some()`, return `CredState::External(AuthExternal::OAuth2JwksRequest { jwks_url, id_token, access_token })` before the existing unverified decode path; (b) add `validate(AuthCredential::OAuth2JwksTokenResponse { claims_body }, ct)` arm that calls `claims_from_oidc_json`; (c) add `fn claims_from_oidc_json(json: &serde_json::Value, claim_map: &BTreeMap<Attribute, String>) -> Option<ExternalUserClaims>` reading `sub` (required), `email`, `email_verified`, `name`/claim_map override for display_name, `preferred_username`/claim_map override for username_hint.
- [X] T015 [US2] In `server/core/src/https/views/login.rs`: (a) add `AuthExternal::OAuth2JwksRequest { jwks_url, id_token, access_token }` arm to the `AuthState::External` match — call `verify_oidc_id_token(&jwks_url, &id_token, now_secs).await`, on success continue loop with `AuthCredential::OAuth2JwksTokenResponse { claims_body }`; (b) add `async fn verify_oidc_id_token(client: &reqwest::Client, jwks_url: &Url, id_token: &str, now_secs: i64) -> Result<String, OperationError>` that: GETs jwks_url → `JwkKeySet`, parses `OidcUnverified::from_str(id_token)`, finds matching `Jwk` by `kid` + `alg`, retries with fresh JWKS fetch if kid not found, builds `JwsEs256Verifier` or `JwsRs256Verifier`, calls `.verify(&unverified)?.verify_exp(now_secs)?`, serialises the resulting OidcToken claims (sub + extra fields) to JSON string.
- [ ] T016 [US2] Write integration tests for US2 in the testkit: (a) full login flow with real ES256-signed id_token from mock OIDC server → `AuthState::Success`; (b) id_token signed by wrong key → `AuthState::Denied`; (c) expired id_token → `AuthState::Denied`; (d) kid not in first JWKS fetch, present after re-fetch (key rotation) → `AuthState::Success`; (e) provider without `jwks_uri` (GitHub-style) with no id_token → existing userinfo path still works (regression test).

**Checkpoint**: `cargo test` passes; id_tokens are verified; invalid signatures rejected; GitHub/Google providers unaffected.

---

## Phase 5: User Story 3 — CLI Management Commands (Priority: P3)

**Goal**: Administrators can create, list, and delete OIDC providers entirely from the CLI.

**Independent Test**: Run `netidm system oauth2-client create-oidc --name test --issuer <url> --client-id id --client-secret sec` against a running instance with a mock discovery server; verify provider appears in `list` output.

**Depends on**: Phase 3 complete (needs `idm_oauth2_client_create_oidc` in the SDK).

### Implementation for User Story 3

- [X] T017 [US3] Add `CreateOidc { #[clap(long)] name: String, #[clap(long)] issuer: Url, #[clap(long)] client_id: String, #[clap(long)] client_secret: String, #[clap(long)] displayname: Option<String> }` variant to `Oauth2Opt` enum in `tools/cli/src/opt/netidm.rs` with a doc comment matching the CLI contract in `contracts/cli.md`.
- [X] T018 [US3] Add `Oauth2Opt::CreateOidc { name, issuer, client_id, client_secret, displayname }` match arm to `tools/cli/src/cli/oauth2.rs` calling `client.idm_oauth2_client_create_oidc(&name, &issuer, &client_id, &client_secret).await` and printing success or error.

**Checkpoint**: `cargo build --bin netidm` passes; `netidm system oauth2-client create-oidc --help` shows the expected flags.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Documentation, clippy compliance, and full test suite.

- [X] T019 [P] Add `//!` module doc comment to `server/lib/src/migration_data/dl21/mod.rs` and `server/lib/src/migration_data/dl21/schema.rs`
- [X] T020 [P] Add `///` doc comments with `# Errors` sections to all new `pub` functions: `OAuth2ClientProvider::issuer()` accessor (if added), `idm_oauth2_client_create_oidc` in `libs/client/src/oauth.rs`, `verify_oidc_id_token` in `server/core/src/https/views/login.rs`
- [X] T021 Run `cargo clippy -- -D warnings` and fix every warning without using `#[allow(...)]` suppressions
- [X] T022 Run `cargo test` and confirm all tests pass including the new US1, US2, and migration tests

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No dependencies — start immediately
- **Phase 2 (Foundational)**: Depends on Phase 1 — BLOCKS all user story phases
- **Phase 3 (US1)**: Depends on Phase 2 — BLOCKS Phase 5 (US3 needs the SDK method)
- **Phase 4 (US2)**: Depends on Phase 2 + T010 from Phase 3 (needs `jwks_uri` on handler)
- **Phase 5 (US3)**: Depends on Phase 3 complete (needs `idm_oauth2_client_create_oidc`)
- **Phase 6 (Polish)**: Depends on Phases 3, 4, 5 all complete

### User Story Dependencies

- **US1 (P1)**: Requires Phase 2 foundational attrs. No dependency on US2 or US3.
- **US2 (P2)**: Requires Phase 2 + T010 (OAuth2ClientProvider `jwks_uri` field). Can start as soon as T010 is done. No dependency on US3.
- **US3 (P3)**: Requires Phase 3 complete (SDK method T011 must exist). No dependency on US2.

### Within Each User Story

- T005 and T006 can run in parallel [P] (different files: `schema.rs` vs `mod.rs`)
- T003 and T004 can run in parallel [P] with T002 (different files)
- T007 → T008 → T009 must be sequential (each builds on the previous)
- T010 can run in parallel with T005–T008 once T002–T004 are done
- T013 and T014 can be done in either order but T015 needs both
- T017 and T018 can run in parallel [P] (different files)
- T019 and T020 can run in parallel [P]

---

## Parallel Execution Examples

### Phase 2 (Foundational)

```
T002 (attribute.rs)   ─┐
T003 (uuids.rs)       ─┤─ all parallel
T004 (mod.rs)         ─┘
```

### Phase 3 (US1)

```
T005 (dl21/schema.rs) ─┐
T006 (dl21/mod.rs)    ─┘─ parallel → T007 → T008 → T009
T010 (oauth2_client + handler) can start after T002-T004, parallel with T005-T009
T011 (SDK client) → after T010
T012 (tests) → after T011
```

### Phase 4 (US2)

```
T013 (authentication.rs) → T014 (handler) → T015 (login.rs)
T016 (tests) → after T015
```

### Phase 5 (US3)

```
T017 (opt/netidm.rs) ─┐
T018 (cli/oauth2.rs)  ─┘─ parallel
```

---

## Implementation Strategy

### MVP (User Story 1 Only)

1. Phase 1: Setup (T001)
2. Phase 2: Foundational (T002–T004) — parallel
3. Phase 3: US1 (T005–T012) — provider creation + discovery
4. **STOP and VALIDATE**: provider created from issuer URL, endpoints stored correctly
5. US2 and US3 can be added in subsequent iterations

### Full Feature Delivery

1. Phase 1 + Phase 2 → foundation ready
2. Phase 3 → provider creation works
3. Phase 4 → JWKS verification works (can overlap with Phase 5)
4. Phase 5 → CLI commands work
5. Phase 6 → polish and confirm clean build

### Parallel Team Strategy

- Developer A: Phase 3 (US1 schema/migration/SDK)
- Developer B: Phase 4 (US2 auth handler + verification) — can start on T013/T014 as soon as T010 merges
- Developer C: Phase 5 (US3 CLI) — can start as soon as T011 merges
