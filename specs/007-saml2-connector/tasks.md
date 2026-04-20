# Tasks: SAML 2.0 Upstream Connector

**Input**: Design documents from `specs/007-saml2-connector/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/saml-flow.md, contracts/cli.md, quickstart.md

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Add `samael` crate, define all new protocol symbols, and reserve UUID constants.

- [X] T001 Add `samael = { version = "0.0.20", features = ["xmlsec"] }` to `server/lib/Cargo.toml` and `server/core/Cargo.toml`
- [X] T002 [P] Add 9 new `Attribute` variants (`SamlIdpSsoUrl`, `SamlIdpCertificate`, `SamlEntityId`, `SamlAcsUrl`, `SamlNameIdFormat`, `SamlAttrMapEmail`, `SamlAttrMapDisplayname`, `SamlAttrMapGroups`, `SamlJitProvisioning`) and `EntryClass::SamlClient` to `proto/src/attribute.rs` with string values `"saml_idp_sso_url"`, `"saml_idp_certificate"`, `"saml_entity_id"`, `"saml_acs_url"`, `"saml_name_id_format"`, `"saml_attr_map_email"`, `"saml_attr_map_displayname"`, `"saml_attr_map_groups"`, `"saml_jit_provisioning"`, `"samlclient"`
- [X] T003 [P] Add UUID constants `UUID_SCHEMA_ATTR_SAML_IDP_SSO_URL` (`ffff0000024b`) through `UUID_SCHEMA_ATTR_SAML_JIT_PROVISIONING` (`ffff00000253`), `UUID_SCHEMA_CLASS_SAML_CLIENT` (`ffff00000090`), `UUID_IDM_SAML_CLIENT_ADMINS` (`000...000057`), `UUID_IDM_ACP_SAML_CLIENT_ADMIN` (`000...000082`) to `server/lib/src/constants/uuids.rs`
- [X] T004 Add `DOMAIN_LEVEL_22: DomainVersion = 22` constant and update `DOMAIN_TGT_LEVEL` and `DOMAIN_MAX_LEVEL` to `DOMAIN_LEVEL_22` in `server/lib/src/constants/mod.rs`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: DL22 migration (schema + access + group), `SamlClientProvider` data model, and auth protocol messages. All user story phases depend on this.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T005 Create `server/lib/src/migration_data/dl22/schema.rs` with `LazyLock<SchemaAttribute>` statics for all 9 SAML attributes (`SamlIdpSsoUrl` → Url/systemmust, `SamlIdpCertificate` → Utf8String/systemmust, `SamlEntityId` → Url/systemmust, `SamlAcsUrl` → Url/systemmust, `SamlNameIdFormat` → Utf8String/systemmay, `SamlAttrMapEmail/Displayname/Groups` → Utf8String/systemmay, `SamlJitProvisioning` → Boolean/systemmay) and `SCHEMA_CLASS_SAML_CLIENT_DL22` (`systemmust`: SamlIdpSsoUrl, SamlIdpCertificate, SamlEntityId, SamlAcsUrl, DisplayName; `systemmay`: remaining 5 attrs)
- [X] T006 [P] Create `server/lib/src/migration_data/dl22/access.rs` with `IDM_GROUP_SAML_CLIENT_ADMINS` builtin group (UUID `000...000057`) and `IDM_ACP_SAML_CLIENT_ADMIN_DL22` builtin ACP (receiver: `UUID_IDM_SAML_CLIENT_ADMINS`, target: `EntryClass::SamlClient`, create_classes: `[Object, SamlClient]`, all SAML attrs in create_attrs)
- [X] T007 Create `server/lib/src/migration_data/dl22/mod.rs` with phase functions delegating to `super::dl21` except: phase 1 (add 9 schema attrs), phase 2 (add `SCHEMA_CLASS_SAML_CLIENT_DL22`), phase 6 (add `IDM_GROUP_SAML_CLIENT_ADMINS`), phase 7 (add `IDM_ACP_SAML_CLIENT_ADMIN_DL22`) — follow the exact pattern of `server/lib/src/migration_data/dl21/mod.rs`
- [X] T008 Add `pub mod dl22;` to `server/lib/src/migration_data/mod.rs` and update the `latest` type alias to point to `dl22`
- [X] T009 Add `migrate_domain_21_to_22()` function to `server/lib/src/server/migrations.rs` — identical structure to `migrate_domain_20_to_21()` referencing `dl22` statics
- [X] T010 Register `migrate_domain_21_to_22()` migration hook in `server/lib/src/server/mod.rs` and update the domain level assertion to `DOMAIN_LEVEL_22`
- [X] T011 Create `server/lib/src/idm/saml_client.rs` with `SamlClientProvider` struct (fields: `name`, `display_name`, `uuid`, `entity_id: Url`, `idp_sso_url: Url`, `idp_certificate: String`, `acs_url: Url`, `name_id_format: Option<String>`, `attr_map_email/displayname/groups: Option<String>`, `jit_provisioning: bool`) and `reload_saml_client_providers()` method on `IdmServerProxyReadTransaction` that reads all `EntryClass::SamlClient` entries from the DB — mirror `reload_oauth2_client_providers()` in `server/lib/src/idm/oauth2_client.rs`
- [X] T012 Add `SamlAuthnRequest { sso_url: Url, saml_request: String, relay_state: String }` variant to `AuthExternal`, `SamlAcsResponse { saml_response: String, relay_state: String, provider_name: String }` variant to `AuthCredential`, and `SamlFederated` variant to `AuthType` in `server/lib/src/idm/authentication.rs`

**Checkpoint**: DL22 migration complete, SamlClientProvider loads from DB, auth protocol messages defined — user story implementation can now begin.

---

## Phase 3: User Story 1 — Register a SAML IdP and Log In (Priority: P1) 🎯 MVP

**Goal**: Admin registers a SAML IdP; users can authenticate via SP-initiated SSO; SAML Responses are validated and sessions established.

**Independent Test**: With a test-signed SAML Response (using `samael` in a test helper), call `InitSamlProvider`, capture `SamlAuthnRequest`, craft a valid `SamlAcsResponse` with `InResponseTo` set, submit to ACS handler, verify `CredState::Success` returned and session token is valid.

- [X] T013 [US1] Create `server/lib/src/idm/authsession/handler_saml_client.rs` — implement the `init_saml` step: load `SamlClientProvider` by name, generate `request_id = format!("_{}", Uuid::new_v4().simple())`, build `AuthnRequest` XML via `samael::AuthnRequestBuilder` (issuer = `entity_id`, ACS URL, NameIDPolicy format), deflate-compress + base64-encode to `saml_request`, generate `relay_state = Uuid::new_v4().to_string()`, return `CredState::External(AuthExternal::SamlAuthnRequest { sso_url, saml_request, relay_state })`
- [X] T014 [US1] Add `validate_acs_response` step to `server/lib/src/idm/authsession/handler_saml_client.rs`: base64-decode `saml_response`, XML-parse via `samael::Response::try_from_xml()`, verify `InResponseTo` is present and matches the stored request ID passed in via handler context, verify XML signature against `idp_certificate` via `samael`'s signature verification API, return `CredState::Denied` on any failure
- [X] T015 [US1] Add conditions + nonce checking to `validate_acs_response` in `server/lib/src/idm/authsession/handler_saml_client.rs`: extract `Assertion.Conditions.NotBefore` and `NotOnOrAfter`, enforce ±5min clock skew, call `check_and_update_assertion_nonce(sha256_hex(assertion_id))` from `server/lib/src/server/assert.rs` to detect replays, extract `NameID` (reject if absent)
- [X] T016 [US1] Register `handler_saml_client.rs` in `server/lib/src/idm/authsession/mod.rs`: add match arms for `AuthCredential::SamlAcsResponse` routing to the new handler — mirror the `AuthCredential::OAuth2AuthorisationResponse` arm in the same file
- [X] T017 [US1] Add `saml_pending_requests: DashMap<String, SamlPendingRequest>` field to `ServerState` in `server/core/src/https/mod.rs` where `SamlPendingRequest` holds `{ request_id: String, provider_name: String, issued_at: Instant }`; add TTL eviction (entries older than 5 minutes are ignored on lookup)
- [X] T018 [US1] Add `GET /ui/sso/:name` handler `view_saml_sso_get` to `server/core/src/https/views/login.rs`: call `handle_auth(InitSamlProvider { name })`, receive `AuthExternal::SamlAuthnRequest`, store `relay_state → SamlPendingRequest` in `state.saml_pending_requests`, return HTTP 302 to `<sso_url>?SAMLRequest=<saml_request>&RelayState=<relay_state>`
- [X] T019 [US1] Add `POST /ui/login/saml/:name/acs` handler `view_saml_acs_post` to `server/core/src/https/views/login.rs`: parse `application/x-www-form-urlencoded` body for `SAMLResponse` and `RelayState`, look up `relay_state` in `state.saml_pending_requests` (reject with 400 if expired/missing), call `handle_auth(SamlAcsResponse { ... })`, on `CredState::Success` issue session cookie and redirect to `/ui/`, on `CredState::Denied` render login error page
- [X] T020 [US1] Register routes in `server/core/src/https/views/mod.rs`: add `.route("/ui/sso/:name", get(login::view_saml_sso_get))` and `.route("/ui/login/saml/:name/acs", post(login::view_saml_acs_post))` to the unguarded CSP router (no HTMX guard — IdP POSTs directly)

**Checkpoint**: Full SP-initiated SSO flow functional — AuthnRequest generated, SAML Response validated, session established.

---

## Phase 4: User Story 2 — Manage SAML IdP Providers via CLI (Priority: P2)

**Goal**: Admin can create, get, list, delete, and update-cert for SAML providers via CLI without DB access.

**Independent Test**: Run `client.idm_saml_client_create(...)` then `client.idm_saml_client_get(name)`, confirm attributes match; run `client.idm_saml_client_delete(name)` then `client.idm_saml_client_list()`, confirm provider absent.

- [X] T021 [P] [US2] Create `libs/client/src/saml.rs` implementing `idm_saml_client_create(name, display_name, sso_url, pem_cert, entity_id, acs_url, opts...)`, `idm_saml_client_get(name)`, `idm_saml_client_list()`, `idm_saml_client_delete(name)`, `idm_saml_client_update_cert(name, pem_cert)` as methods on `KanidmClient` — follow the pattern in `libs/client/src/oauth.rs`; add `mod saml;` to `libs/client/src/lib.rs`
- [X] T022 [P] [US2] Add `SamlClientOpt` enum (variants: `Create { name, displayname, sso_url, idp_cert_path, entity_id, acs_url, nameid_format, email_attr, displayname_attr, groups_attr, jit_provisioning }`, `Get { name }`, `List`, `Delete { name }`, `UpdateCert { name, idp_cert_path }`) and `SamlClient { cmd: SamlClientOpt }` top-level opt to `tools/cli/src/opt/netidm.rs`
- [X] T023 [US2] Create `tools/cli/src/cli/saml.rs` with handler function for each `SamlClientOpt` variant: read PEM from file path (`std::fs::read_to_string`), call corresponding `client.idm_saml_client_*` SDK method, print result; add `mod saml;` and `SamlClient` dispatch arm in `tools/cli/src/cli/lib.rs` (or `main.rs`)

**Checkpoint**: `netidm system saml-client create/get/list/delete` all functional via CLI.

---

## Phase 5: User Story 3 — Attribute Mapping and JIT Provisioning (Priority: P3)

**Goal**: Admin can configure SAML attribute mappings; JIT provisioning creates accounts with mapped attributes on first login; group membership applied.

**Independent Test**: Create provider with `attr_map_email = "email"`; submit SAML Response with `<saml:Attribute Name="email"><saml:AttributeValue>alice@corp.example</saml:AttributeValue></saml:Attribute>`; verify provisioned account has `mail = "alice@corp.example"`.

- [X] T024 [US3] Add attribute extraction to `validate_acs_response` in `server/lib/src/idm/authsession/handler_saml_client.rs`: after NameID extraction, iterate `Assertion.AttributeStatement.Attribute` elements; if attribute `Name` matches `attr_map_email`, collect the first value as `email`; similarly for `attr_map_displayname` and `attr_map_groups` (multi-value → `Vec<String>`)
- [X] T025 [US3] Add `jit_provision_saml_account()` to `server/lib/src/idm/server.rs` analogous to `jit_provision_oauth2_account()`: create a new `Person` entry keyed on a derived SPN from the `NameID`; set `mail`, `displayname` if provided by attribute mapping; set `SamlExternalId` attribute (or reuse `OAuth2AccountUniqueUserId` pattern) for future lookups
- [X] T026 [US3] Wire JIT provisioning and existing-account lookup into `handler_saml_client.rs`: after attribute extraction, call `find_account_by_saml_external_id(provider_name, name_id)` (analogous to OAuth2 account lookup); if not found and `jit_provisioning = true`, call `jit_provision_saml_account()`; if not found and `jit_provisioning = false`, return `CredState::Denied`; on success return `CredState::Success { auth_type: AuthType::SamlFederated, ... }`
- [X] T027 [US3] Add group membership application in `jit_provision_saml_account()` in `server/lib/src/idm/server.rs`: for each group name in `groups` from attribute mapping, look up the matching netidm group by name; if found, add the provisioned account as a member; silently skip group names that have no matching netidm group

**Checkpoint**: First-time SAML login provisions account with correct email, display name, and group membership.

---

## Final Phase: Login UX + Integration Tests + Polish

**Purpose**: Wire SAML providers into the login page UI, add end-to-end integration tests, ensure clippy passes.

- [X] T028 Add SAML providers to the provider list in `LoginView` in `server/core/src/https/views/login.rs`: call `reload_saml_client_providers()` alongside `reload_oauth2_client_providers()` and include them in the providers vec passed to the template
- [X] T029 Add "Login with [display_name]" SSO buttons for SAML providers in `server/core/templates/login.html`: follow the existing OAuth2 SSO button pattern; link href is `/ui/saml/sso/<provider_name>`
- [ ] T030 [P] Add integration test `tk_test_idm_saml_client_create_and_login` to `server/testkit/tests/testkit/oauth2_client_test.rs` (or new `saml_test.rs`): create provider via `idm_saml_client_create`, generate test key pair, build signed SAML Response using `samael`, submit to ACS handler via HTTP POST, assert HTTP 302 and session cookie set (covers Scenario 2 from quickstart.md)
- [ ] T031 [P] Add integration test `tk_test_idm_saml_invalid_signature_rejected` and `tk_test_idm_saml_replay_rejected` to the same test file: wrong-key signature → 200 with error page (Scenario 3); valid response resubmitted → 200 with error page (Scenario 5)
- [X] T032 Run `cargo clippy -- -D warnings` and `cargo test` in CI configuration; fix any warnings introduced by new code in `proto/`, `server/lib/`, `server/core/`, `libs/client/`, `tools/cli/`

---

## Dependencies

```
Phase 1 (T001–T004) must complete before Phase 2
Phase 2 (T005–T012) must complete before Phases 3, 4, 5
Phase 3 (T013–T020) must complete before Final Phase T028–T031
Phase 4 (T021–T023) is independent of Phase 3 and 5 (only needs Phase 2)
Phase 5 (T024–T027) depends on Phase 3 (T013–T016)
Final Phase (T028–T032) depends on all prior phases
```

## Parallel Execution Opportunities

**Within Phase 1**: T002, T003 can run in parallel (different files — `proto/`, `server/lib/constants/`)

**Within Phase 2**: T005, T006 can run in parallel (different files — `schema.rs`, `access.rs`)

**Phases 4 and 5 can run in parallel** once Phase 2 is complete (different files — `libs/client/`, `tools/cli/` vs `server/lib/src/idm/`)

**Within Final Phase**: T030 and T031 can run in parallel (different test functions)

## Implementation Strategy

**MVP**: Phases 1–3 deliver a working SP-initiated SAML SSO login. Admin must use the SDK directly (no CLI yet); attribute mapping uses NameID as the only identifier. This is shippable for developers integrating against a real IdP.

**Full delivery**: Add Phase 4 (CLI) and Phase 5 (attribute mapping + JIT) incrementally. Each phase is independently testable.

**Suggested first commit**: T001–T004 (deps + protocol symbols) as a single chore commit with no logic changes.
