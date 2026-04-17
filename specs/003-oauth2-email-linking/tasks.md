# Tasks: OAuth2 Email-Based Account Linking

**Input**: Design documents from `specs/003-oauth2-email-linking/`
**Prerequisites**: plan.md ✓, spec.md ✓, research.md ✓, data-model.md ✓, contracts/cli.md ✓

**Organization**: Tasks grouped by user story to enable independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Which user story this task belongs to (US1–US4)

---

## Phase 1: Setup

**Purpose**: No new project structure needed — this is an existing Rust workspace. Verify branch and confirm DL numbering.

- [X] T001 Confirm current branch is `003-oauth2-email-linking` (`git branch --show-current`)
- [X] T002 Confirm `server/lib/src/migration_data/mod.rs` currently points `dl17` as latest, establishing DL18 as the next migration

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Schema migration, attribute enum variants, and struct changes that ALL user stories depend on. No user story work can begin until this phase is complete.

**⚠️ CRITICAL**: Complete in task order — later tasks depend on earlier ones.

- [X] T003 Add `OAuth2EmailLinkAccounts` and `OAuth2DomainEmailLinkAccounts` variants to the `Attribute` enum in `proto/src/` (same file as `Attribute::OAuth2JitProvisioning`)
- [X] T004 Define UUID constants for both new attributes in the appropriate constants file (same file/module as existing OAuth2 attribute UUIDs)
- [X] T005 Create `server/lib/src/migration_data/dl18/` directory with empty `mod.rs` and `schema.rs`
- [X] T006 [P] Define `SCHEMA_ATTR_OAUTH2_EMAIL_LINK_ACCOUNTS_DL18` in `server/lib/src/migration_data/dl18/schema.rs` — Boolean, not indexed, not multivalue, `systemmay` of `OAuth2Client`
- [X] T007 [P] Define `SCHEMA_ATTR_OAUTH2_DOMAIN_EMAIL_LINK_ACCOUNTS_DL18` in `server/lib/src/migration_data/dl18/schema.rs` — Boolean, not indexed, not multivalue, `systemmay` of `DomainInfo`
- [X] T008 Define modified `SCHEMA_CLASS_OAUTH2_CLIENT_DL18` in `server/lib/src/migration_data/dl18/schema.rs` extending dl17 class with `Attribute::OAuth2EmailLinkAccounts` added to `systemmay`
- [X] T009 Define modified `SCHEMA_CLASS_DOMAIN_INFO_DL18` in `server/lib/src/migration_data/dl18/schema.rs` extending dl17 class with `Attribute::OAuth2DomainEmailLinkAccounts` added to `systemmay`
- [X] T010 Implement `phase_1_schema_attrs()` and `phase_2_schema_classes()` in `server/lib/src/migration_data/dl18/mod.rs` — extend dl17 with the two new attributes and two modified classes
- [X] T011 Update `server/lib/src/migration_data/mod.rs` to `pub(crate) use dl18 as latest` (replacing dl17)
- [X] T012 Add `email_link_accounts: bool` field to `OAuth2ClientProvider` struct in `server/lib/src/idm/oauth2_client.rs`; resolve effective value at load time: `per_provider.get_ava_single_bool(OAuth2EmailLinkAccounts).unwrap_or(domain.get_ava_single_bool(OAuth2DomainEmailLinkAccounts).unwrap_or(false))`
- [X] T013 Add `email_link_accounts: bool` field to `CredHandlerOAuth2Client` in `server/lib/src/idm/authsession/handler_oauth2_client.rs`; populate from `client_provider.email_link_accounts` at handler construction
- [X] T014 Extend `CredState::ProvisioningRequired` in `server/lib/src/idm/authsession/mod.rs` with `email_link_accounts: bool` field; update all match sites that destructure `ProvisioningRequired` to include the new field
- [X] T015 Update the `ProvisioningRequired` emission in `server/lib/src/idm/authsession/handler_oauth2_client.rs` to propagate `self.email_link_accounts` into the new field
- [X] T016 Run `cargo check` and confirm the workspace compiles cleanly with no errors before proceeding to user story phases

**Checkpoint**: Foundation ready — all user story phases can now begin.

---

## Phase 3: User Story 1 — Admin Configures Email Linking (Priority: P1)

**Goal**: Admins can enable/disable email-based linking globally and per-provider via CLI, with per-provider setting overriding the global.

**Independent Test**: Set global to false, set per-provider to true for one provider, set another provider to false. Confirm: first provider links on verified email match, second does not, unset providers follow global.

- [X] T017 [US1] Add CLI subcommand `netidm system oauth2 set-email-link-accounts <true|false>` in `tools/cli/src/` that writes `Attribute::OAuth2DomainEmailLinkAccounts` to the domain object (follow the `domain_allow_easter_eggs` or similar domain boolean command as a template)
- [X] T018 [US1] Add `--email-link-accounts [true|false|inherit]` flag to `netidm system oauth2 update <provider>` in `tools/cli/src/`; `true`/`false` sets the attribute, `inherit` purges it so the provider falls back to the global default

**Checkpoint**: Admin can configure email linking at both global and provider level. Verify with `netidm system oauth2 get <provider>` showing the attribute.

---

## Phase 4: User Story 2 — Existing User Links via Social Login (Priority: P1)

**Goal**: When a user logs in via OAuth2 and their verified email matches a local Person account, the system silently links the OAuth2 identity to that account and logs them in — no duplicate is created.

**Independent Test**: Create a local Person with `mail = test@example.com`. Enable email linking on the provider. Complete OAuth2 login with verified email `test@example.com`. Assert: only one account in the directory, that account now has `OAuth2AccountProvider` set, and the user is logged in as the existing account.

- [X] T019 [US2] Implement `find_and_link_account_by_email(provider_uuid: Uuid, claims: &ExternalUserClaims) -> Result<Option<Uuid>, OperationError>` in `server/lib/src/idm/server.rs` — searches by verified email, writes OAuth2Account class + 3 linking attrs, returns linked UUID or None
- [X] T020 [US2] In `server/core/src/https/views/login.rs`, intercept `AuthState::ProvisioningRequired` with `email_link_accounts=true` before provision cookie: call `handle_link_account_by_email()` via `qe_w_ref`, redirect to `/ui/login` on success, fall through to normal provision on miss/error
- [ ] T021 [US2] Write integration test: local Person with matching verified email + linking enabled → one account, OAuth2 attributes present, session issued for existing account (in `server/testkit/` or inline test module in `server.rs`)
- [ ] T022 [US2] Write integration test: after first link, second login from same provider uses `find_account_by_oauth2_provider_and_user_id()` and skips email search entirely

**Checkpoint**: A pre-provisioned user can log in via social login without creating a duplicate. `cargo test` passes for the new tests.

---

## Phase 5: User Story 3 — Unverified Email Does Not Auto-Link (Priority: P1)

**Goal**: When the provider email is absent, unverified, or the match is ambiguous, no linking occurs and the system falls through to normal JIT behaviour. This prevents account takeover.

**Independent Test**: Simulate OAuth2 login with `email_verified: false` against a local account with a matching email. Assert: two accounts exist (original + new JIT account), original account unchanged, no OAuth2 attributes written to it.

- [ ] T023 [US3] Write test: `email_verified = Some(false)` with matching local email → `find_and_link_account_by_email` returns `Ok(None)`, JIT creates second account (in `server/testkit/` or inline)
- [ ] T024 [US3] Write test: `email = None` (GitHub with private email) → returns `Ok(None)`, JIT proceeds
- [ ] T025 [P] [US3] Write test: two local accounts share the same email (ambiguous) → returns `Ok(None)`, JIT proceeds
- [ ] T026 [P] [US3] Write test: found account already has `OAuth2AccountProvider` set → returns `Ok(None)`, does not overwrite existing link

**Checkpoint**: All guard conditions proven by failing tests that are now passing. `cargo test` clean.

---

## Phase 6: User Story 4 — No Local Match Falls Through to JIT (Priority: P2)

**Goal**: When email linking is enabled but no local account matches the verified email, JIT provisioning creates a new account exactly as it did before this feature. Existing behaviour is preserved.

**Independent Test**: Enable email linking on a provider. Complete social login with a verified email that has no matching local account. Assert: new account created normally by JIT, no errors.

- [ ] T027 [US4] Write test: email linking enabled, no local account with matching email → `find_and_link_account_by_email` returns `Ok(None)`, `jit_provision_oauth2_account` creates new account normally
- [ ] T028 [US4] Write test: `email_link_accounts = false` on provider (with global also false) → email search never called, JIT runs immediately (verify with a mock or by asserting no DB search for Mail attribute occurs)

**Checkpoint**: JIT provisioning behaves identically to pre-feature behaviour when linking conditions are not met.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [X] T029 Run `cargo clippy -- -D warnings` across the full workspace and fix every warning without using `#[allow(...)]` suppressions
- [X] T030 Run `cargo test` across the full workspace and confirm all existing tests still pass alongside new tests
- [X] T031 [P] Update `CLAUDE.md` active technologies section to reflect DL18

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately
- **Foundational (Phase 2)**: Depends on Phase 1 — **BLOCKS all user story phases**
- **US1 (Phase 3)**: Depends on Phase 2 (attribute enum + schema)
- **US2 (Phase 4)**: Depends on Phase 2 (structs + state propagation)
- **US3 (Phase 5)**: Depends on T019 (find_and_link_account_by_email must exist to test its guards)
- **US4 (Phase 6)**: Depends on T019, T020 (fallthrough path must exist)
- **Polish (Phase 7)**: Depends on all story phases complete

### User Story Dependencies

- **US1** and **US2** can proceed in parallel after Phase 2 — different files (`tools/cli/` vs `server/lib/src/idm/server.rs`)
- **US3** depends on T019 only (Phase 4 task 1) — can start as soon as `find_and_link_account_by_email` signature exists
- **US4** depends on T019 + T020 — final story, minimal work

### Parallel Opportunities Within Phase 2

- T006 and T007 are parallel (different schema attributes, same file — careful of merge conflicts)
- T008 and T009 are parallel (different class modifications)
- T003 and T005 are parallel (different directories)

---

## Parallel Example: Phase 2 Foundation

```
# Group 1 (can start immediately, parallel):
T003 — Add Attribute enum variants (proto/src/)
T005 — Create dl18/ directory

# Group 2 (after T003 + T005):
T006 — Define SCHEMA_ATTR_OAUTH2_EMAIL_LINK_ACCOUNTS_DL18
T007 — Define SCHEMA_ATTR_OAUTH2_DOMAIN_EMAIL_LINK_ACCOUNTS_DL18

# Group 3 (after T006 + T007):
T008 — Modified OAuth2Client class
T009 — Modified DomainInfo class

# Sequential (after T008 + T009):
T010 → T011 → T012 → T013 → T014 → T015 → T016
```

## Parallel Example: User Story Phases

```
# After Phase 2 complete:
Developer A → Phase 3 (US1): T017, T018  [tools/cli/]
Developer B → Phase 4 (US2): T019, T020  [server/lib/src/idm/server.rs]
```

---

## Implementation Strategy

### MVP (User Story 2 only — the core linking flow)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (T001–T016)
3. Skip Phase 3 (US1 — CLI config) for now — hardcode `email_link_accounts = true` in tests
4. Complete Phase 4: US2 (T019–T022)
5. **STOP and VALIDATE**: Verified email match links correctly, one account in DB
6. Add Phase 3 (US1) to give admins the on/off control

### Incremental Delivery

1. Phase 1 + 2 → Foundation ready
2. Phase 4 (US2) → Core linking works
3. Phase 5 (US3) → Guards proven
4. Phase 3 (US1) → Admin control
5. Phase 6 (US4) → Fallthrough confirmed
6. Phase 7 → Clippy + full test suite clean

---

## Notes

- [P] tasks touch different files — safe to run in parallel
- Each user story phase is independently testable before moving to the next
- `cargo check` after T016 is mandatory before any story work
- Never use `#[allow(...)]` — fix the underlying code (constitution Principle IV)
- The `find_and_link_account_by_email` guards (T019) serve both US2 and US3 — implement all guards in one pass
