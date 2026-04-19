# Tasks: SSO Login Choice UX

**Branch**: `005-sso-login-choice`
**Input**: Design documents from `specs/005-sso-login-choice/`

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel with other [P] tasks in the same phase (different files, no shared state)
- **[Story]**: Maps to user story from spec.md (US1–US3)
- Exact file paths are mandatory in every task description

---

## Phase 1: Setup

**Purpose**: Verify prerequisites and confirm the codebase baseline before any changes.

- [X] T001 Confirm `COOKIE_NEXT_REDIRECT` is written in `view_index_get` (`server/core/src/https/views/login.rs:437–445`) for relative-path `?next=` values — verify the `view_sso_initiate_get` handler can write the same cookie using the same guard. Run `cargo test` before any changes to establish a clean baseline.
- [X] T002 Trace `find_and_link_account_by_email` from `server/lib/src/idm/server.rs` — confirm it is accessible (pub or pub(crate)) from `IdmServerAuthTransaction` methods and that it returns a `Uuid` or similar handle needed by the callback flow. Document the function signature in a code comment in the provider-initiated session handler (to be created in Phase 2).

**Checkpoint**: Baseline tests pass; `find_and_link_account_by_email` call chain understood.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Add the shared types and data model changes needed by all three user stories.

**⚠️ CRITICAL**: Must complete before any user story implementation.

- [X] T003 Add `InitOAuth2Provider { provider_name: String, issue: AuthIssueSession }` variant to `AuthStep` in `proto/src/v1/auth.rs`. Add matching `AuthEventStep::InitOAuth2Provider` variant in `server/lib/src/idm/authentication.rs` (mirroring the existing `AuthEventStep::Init` pattern). Update ALL exhaustive `match ae.step` and `match auth_step` sites — there are sites in `server/lib/src/idm/server.rs` and `server/core/src/https/v1.rs` and `server/core/src/https/views/login.rs`. Each unhandled site should return `Err(OperationError::InvalidState)` as a placeholder stub until Phase 3. `cargo build` must compile clean.

- [X] T004 Add `display_name: String` field to `OAuth2ClientProvider` in `server/lib/src/idm/oauth2_client.rs`. In `reload_oauth2_client_providers`, read `Attribute::DisplayName` with `get_ava_single_utf8(Attribute::DisplayName).map(str::to_string)` and fall back to `name.clone()` if absent. Update the `OAuth2ClientProvider { ... }` struct literal constructor. `cargo build` must compile clean.

- [X] T005 [P] Define `SsoProviderInfo { pub name: String, pub display_name: String, pub logo_uri: Option<Url> }` struct in `server/core/src/https/views/login.rs` (above `LoginDisplayCtx`). Add `pub(crate) fn list_sso_providers(&self) -> Vec<SsoProviderInfo>` to the `IdmServerProxyReadTransaction` trait in `server/lib/src/idm/server.rs` and implement it on the concrete type: iterate `self.oauth2_client_providers.values()`, map each to `SsoProviderInfo { name, display_name, logo_uri: None }` (logo_uri is None until P3/T017), sort by `display_name`. `cargo build` must compile clean.

- [X] T006 Add `available_sso_providers: Vec<SsoProviderInfo>` field to `LoginDisplayCtx` in `server/core/src/https/views/login.rs`. Update every `LoginDisplayCtx { ... }` constructor in the file to include `available_sso_providers: Vec::new()` — there are ~10 call sites. Add `show_internal_first: bool` field to `LoginView` (the struct used for the initial landing template). `cargo build` must compile clean.

- [X] T007 [P] Add `pub const COOKIE_AUTH_METHOD_PREF: &str = "auth_method_pref";` constant to `server/core/src/https/views/cookies.rs` alongside the existing `COOKIE_BEARER_TOKEN` and similar constants. `cargo build` must compile clean.

**Checkpoint**: `cargo build` passes. `SsoProviderInfo`, `InitOAuth2Provider`, `display_name` field, `COOKIE_AUTH_METHOD_PREF` all compile. All three user story phases can now proceed.

---

## Phase 3: User Story 1 — SSO-first landing page (Priority: P1) 🎯 MVP

**Goal**: Login page shows configured SSO provider buttons above a collapsible internal auth form. No SSO providers → page unchanged. Clicking an SSO button redirects to the provider's authorization URL.

**Independent Test**: Load `/ui/login` with ≥1 provider configured → SSO button appears above "Use internal authentication". Load with 0 providers → only the username form. `GET /ui/sso/<provider>` → 302 to provider auth URL.

- [X] T008 [US1] Implement provider-initiated auth session creation in `server/lib/src/idm/server.rs`. In `IdmServerAuthTransaction::auth`, add a match arm for `AuthEventStep::InitOAuth2Provider { provider_name, issue }`:
  1. Look up the provider by name: `self.oauth2_client_providers.values().find(|p| p.name == provider_name)` — return `Err(OperationError::NoMatchingEntries)` if not found.
  2. Create a `ProviderInitiatedSession` struct (define it in `server/lib/src/idm/authsession/mod.rs`): `{ provider: Arc<OAuth2ClientProvider>, pkce_secret: PkceS256Secret, csrf_state: String, issue: AuthIssueSession, client_auth_info: ClientAuthInfo }`. Allocate a `sessionid` and store in a new `provider_sessions: DashMap<Uuid, ProviderInitiatedSession>` field on `IdmServer` (parallel to the existing `sessions` field).
  3. Call `ProviderInitiatedSession::start_auth_request()` (analogous to `CredHandlerOAuth2Client::start_auth_request`) to get `(authorisation_url, AuthorisationRequest)`.
  4. Return `AuthResult { sessionid, state: AuthState::External(AuthExternal::OAuth2AuthorisationRequest { authorisation_url, request }) }`.
  `cargo build` must compile clean.

- [X] T009 [US1] Implement callback handling for provider-initiated sessions in `server/lib/src/idm/server.rs`. In `IdmServerAuthTransaction::auth`, in the `AuthEventStep::Cred` arm, before looking up the session in `self.sessions`, also check `self.provider_sessions`:
  - If `session_id` is found in `provider_sessions`: remove it, get the `ProviderInitiatedSession`.
  - Validate `OAuth2AuthorisationResponse.state == provider_session.csrf_state`.
  - Build `OAuth2AccessTokenRequest` using the provider config + PKCE verifier (reuse logic from `CredHandlerOAuth2Client::validate_authorisation_response`).
  - Return `AuthState::External(AuthExternal::OAuth2AccessTokenRequest { ... })`.
  - For the subsequent `OAuth2AccessTokenResponse` and `OAuth2UserinfoResponse` credential steps (which arrive via the existing `view_login_step` loop), add a parallel `provider_access_sessions: DashMap<Uuid, ProviderAccessSession>` that stores the partial state (provider + access token) between steps.
  - After userinfo is received: call `find_and_link_account_by_email(email)` to resolve the account Uuid. If found: call `qe_r_ref.internal_search_uuid(account_uuid)` to get the account entry, build an `Account`, and create a proper `AuthSession` for that account (reusing `AuthSession::new_oauth2_direct` — add this constructor). Return `AuthState::Success`.
  - If not found and `jit_provisioning: true`: return `AuthState::ProvisioningRequired` (reuses existing JIT UI).
  - If not found and no JIT: return `AuthState::Denied("No matching account for this identity provider")`.
  `cargo clippy -- -D warnings` must pass.

- [X] T010 [US1] Implement `view_sso_initiate_get` handler in `server/core/src/https/views/login.rs`. Signature:
  ```rust
  pub async fn view_sso_initiate_get(
      State(state): State<ServerState>,
      VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
      Extension(kopid): Extension<KOpId>,
      Path(provider_name): Path<String>,
      Query(query): Query<SsoInitiateQuery>,  // { next: Option<String> }
      jar: CookieJar,
  ) -> Response
  ```
  - Call `state.qe_r_ref.handle_auth(None, AuthStep::InitOAuth2Provider { provider_name, issue: AuthIssueSession::Cookie }, kopid.eventid, client_auth_info)`.
  - On `Err(OperationError::NoMatchingEntries)`: return `StatusCode::NOT_FOUND.into_response()`.
  - On `Ok(AuthResult { state: AuthState::External(OAuth2AuthorisationRequest { .. }) })`: store `COOKIE_NEXT_REDIRECT` if `query.next` is a valid relative path (starts with `/`, same guard as in `view_index_get`); store auth session cookie; redirect to authorization URL.
  - Add `SsoInitiateQuery` struct above the handler.
  Add `/// # Errors` doc comment. `cargo build` must compile clean.

- [X] T011 [US1] Register `GET /ui/sso/:provider_name` in `server/core/src/https/views/mod.rs` inside `unguarded_csp_router` (no HTMX guard). Add `use login::view_sso_initiate_get;` import. `cargo build` must compile clean.

- [X] T012 [US1] Update `view_index_get` in `server/core/src/https/views/login.rs` to populate the SSO provider list. Call `state.qe_r_ref.list_sso_providers().await` (or sync equivalent) and set `available_sso_providers` in `LoginDisplayCtx`. Set `show_internal_first: false` in `LoginView`. `cargo build` must compile clean.

- [X] T013 [US1] Update `server/core/templates/login.html` to render the SSO section. Layout (per `contracts/template_contracts.md`):
  - Wrap the existing form in `<div id="internal-auth" {% if !show_internal_first %} class="d-none"{% endif %}>`.
  - Above it, conditionally render (`{% if !display_ctx.available_sso_providers.is_empty() %}`):
    - One `<a href="/ui/sso/{{ provider.name }}" class="btn btn-outline-secondary w-100 mb-2">Sign in with {{ provider.display_name }}</a>` per provider in a `{% for %}` loop
    - Divider: `<div class="d-flex align-items-center my-3"><hr class="flex-grow-1"/><span class="mx-2 text-muted small">or</span><hr class="flex-grow-1"/></div>`
    - Toggle button: `<button type="button" class="btn btn-link p-0 mb-3" onclick="document.getElementById('internal-auth').classList.toggle('d-none')">Use internal authentication</button>`
  - When `available_sso_providers` is empty: no change to page rendering.
  Run `cargo build` to verify template compiles. Visually verify layout in browser.

- [ ] T014 [US1] Write integration tests for US1 in `server/testkit/tests/sso_login_choice.rs` (new file):
  - Test `login_page_shows_sso_section_when_providers_configured`: Create an OAuth2 client provider, load `/ui/login`, assert response HTML contains `"/ui/sso/"` and the provider name.
  - Test `login_page_no_sso_section_when_no_providers`: Load `/ui/login` on a fresh instance with no providers, assert HTML does NOT contain `"/ui/sso/"` and the page renders identically to the current login page.
  - Test `sso_initiate_redirects_to_provider`: `GET /ui/sso/<valid_provider_name>` → assert `302` + `Location` starts with the provider's `authorisation_endpoint`.
  - Test `sso_initiate_unknown_provider_returns_404`: `GET /ui/sso/nonexistent` → assert `404`.
  - Test `sso_initiate_preserves_next_param`: `GET /ui/sso/<provider>?next=/ui/apps` → assert `Set-Cookie` contains `kanidm-next=/ui/apps` (or whatever the cookie name resolves to for `COOKIE_NEXT_REDIRECT`).
  Add test module to `server/testkit/tests/` build. Run `cargo test -p testkit`.

**Checkpoint**: US1 fully functional. SSO buttons visible on login page; redirect to provider works; 404 for unknown providers. MVP deliverable.

---

## Phase 4: User Story 2 — Remembered internal auth preference (Priority: P2)

**Goal**: Users who last logged in via internal auth see the username form expanded on their next visit.

**Independent Test**: Complete an internal login (password/TOTP/passkey). Navigate to `/ui/login`. Username form must be immediately visible without clicking the toggle.

- [X] T015 [US2] Write `COOKIE_AUTH_METHOD_PREF` on successful login in `view_login_step` (`server/core/src/https/views/login.rs`). In the `AuthState::Success` arm, after building the bearer cookie, determine auth method:
  - Inspect `session_context` to detect the credential type used. If the session was completed via an OAuth2 provider callback (check `client_auth_info` or session type), write `COOKIE_AUTH_METHOD_PREF = "sso"`.
  - Otherwise (password, TOTP, passkey, backup code), write `COOKIE_AUTH_METHOD_PREF = "internal"`.
  - Use `cookies::make_unsigned(&state, COOKIE_AUTH_METHOD_PREF, "internal"|"sso")` (session cookie — no `make_permanent()`).
  `cargo build` must compile clean.

- [X] T016 [US2] Read `COOKIE_AUTH_METHOD_PREF` in `view_index_get` (`server/core/src/https/views/login.rs`). Before constructing `LoginView`, check `jar.get(COOKIE_AUTH_METHOD_PREF)`. If value is `"internal"`, set `show_internal_first: true`; otherwise `false`. `cargo build` must compile clean.

- [ ] T017 [US2] Write integration tests for US2 in `server/testkit/tests/sso_login_choice.rs`:
  - Test `login_page_shows_internal_form_after_internal_login`: Complete a password login, then GET `/ui/login`; assert `show_internal_first` causes the form to be visible (no `d-none` on `#internal-auth`).
  - Test `login_page_shows_sso_first_after_sso_login`: After an SSO login (provider-first), GET `/ui/login`; assert SSO section is shown first and `#internal-auth` has `d-none`.
  - Test `login_page_shows_sso_first_with_no_preference_cookie`: No cookie set → `show_internal_first: false`.
  Run `cargo test -p testkit`.

**Checkpoint**: US2 fully functional. `cargo test && cargo clippy -- -D warnings` clean.

---

## Phase 5: User Story 3 — SSO button branding (Priority: P3)

**Goal**: Provider buttons show the configured display name. If a logo URI is configured, the logo appears on the button.

**Independent Test**: Set display name "GitHub" on a provider → button shows "Sign in with GitHub". Set a logo URI → `<img>` visible on button. Provider without logo → text-only button, no broken image.

- [X] T018 [US3] Add `OAuth2ClientLogoUri` variant to `Attribute` enum in `proto/src/attribute.rs`. Add `Attribute::OAuth2ClientLogoUri => "oauth2_client_logo_uri"` in `to_string()` and reverse in `from_str()`. Add UUID constant `UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LOGO_URI: Uuid = uuid!("00000000-0000-0000-0000-ffff00000248")` to `server/lib/src/constants/uuids.rs`. `cargo build` must compile clean.

- [X] T019 [US3] Create DL20 migration module at `server/lib/src/migration_data/dl20/` with `mod.rs` and `schema.rs`. In `schema.rs`: define `SCHEMA_ATTR_OAUTH2_CLIENT_LOGO_URI_DL20` as a `Url`-type, single-value, `systemmay` attribute on `EntryClass::OAuth2Client`. In `mod.rs`: wire into `phase_5_schema_attributes()` and `phase_6_schema_classes()` following the DL19 pattern. Add `DOMAIN_LEVEL_20 = 20` to `server/lib/src/constants/mod.rs` and update `DOMAIN_TGT_LEVEL = DOMAIN_LEVEL_20`, `DOMAIN_MAX_LEVEL = DOMAIN_LEVEL_20`. Add `mod dl20;` in `server/lib/src/migration_data/mod.rs`. Run `cargo test` — migration test must pass.

- [X] T020 [US3] Add `logo_uri: Option<Url>` field to `OAuth2ClientProvider` in `server/lib/src/idm/oauth2_client.rs`. In `reload_oauth2_client_providers`, read with `provider_entry.get_ava_single_url(Attribute::OAuth2ClientLogoUri).cloned()`. Update the `OAuth2ClientProvider { ... }` constructor. Update `list_sso_providers()` in `server/lib/src/idm/server.rs` to populate `SsoProviderInfo.logo_uri` from the provider. `cargo build` must compile clean.

- [X] T021 [US3] Update `server/core/templates/login.html` SSO button to conditionally render a logo: within the provider button `<a>`, add `{% if let Some(logo) = provider.logo_uri %}<img src="{{ logo }}" alt="" class="sso-logo me-2" height="20" loading="lazy" />{% endif %}`. Button still renders cleanly with text only when `logo_uri` is `None`. Run `cargo build`.

- [ ] T022 [US3] Write integration tests for US3 in `server/testkit/tests/sso_login_choice.rs`:
  - Test `provider_button_uses_display_name`: Set `DisplayName = "GitHub"` on a provider, load `/ui/login`, assert HTML contains "Sign in with GitHub" (not the internal name slug).
  - Test `provider_button_uses_name_when_no_display_name`: Provider with no `DisplayName` → button uses internal name as fallback.
  - Test `provider_button_shows_logo_when_configured`: Set `oauth2_client_logo_uri = "https://example.com/logo.svg"` on a provider, load `/ui/login`, assert `<img src="https://example.com/logo.svg"` present in HTML.
  - Test `provider_button_no_img_when_no_logo`: Provider without logo URI → HTML does not contain `<img` inside the SSO button div.
  Run `cargo test -p testkit`.

**Checkpoint**: US3 fully functional. All three user stories complete.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [X] T023 [P] Add `//!` module doc comment and `///` doc comments to all new public items: `SsoProviderInfo` struct + fields, `view_sso_initiate_get` handler (`# Errors`, `# Examples` with a `curl` call), `list_sso_providers` (`# Returns` section). Run `cargo doc --no-deps 2>&1 | grep "warning\[missing"` — must produce no output for new items.

- [X] T024 [P] Run the full quickstart validation from `specs/005-sso-login-choice/quickstart.md` against a running netidmd instance. Confirm all 9 scenarios produce the expected responses. Document any deviations.

- [X] T025 Final check: `cargo test && cargo clippy -- -D warnings` from repo root — must be clean. Fix any regressions before marking feature complete.

---

## Dependencies & Execution Order

### Phase Dependencies

```
Phase 1 (T001, T002)
    ↓
Phase 2 (T003–T007)  — blocks all user story phases
    ↓
Phase 3 (T008–T014)  — US1, MVP
    ↓
Phase 4 (T015–T017)  — US2 [can start after T008 completes, no US3 dependency]
Phase 5 (T018–T022)  — US3 [can run in parallel with US2]
    ↓
Phase 6 (T023–T025)  — polish, docs, final validation
```

Phase 4 and Phase 5 can run in parallel once Phase 3 is complete.

### Within Phase Parallelism

**Phase 2**: T005 and T007 can run in parallel (different files). T003 must complete before T004 (auth.rs changes affect compilation). T006 requires T005 (needs SsoProviderInfo type).

**Phase 3**: T008 before T009 (both in server.rs auth, sequential). T010 and T011 can run in parallel after T008. T012 requires T005 (list_sso_providers). T013 requires T012. T014 requires T010–T013.

**Phase 5**: T018 before T019 before T020 (attribute → migration → struct field → template). T021 and T022 after T020.

**Phase 6**: T023 and T024 can run in parallel.

---

## Parallel Examples

### Phase 2 — parallel start (after T003)
```
Agent A: T004 — add display_name to OAuth2ClientProvider
Agent B: T005 — define SsoProviderInfo + list_sso_providers()
Agent C: T007 — add COOKIE_AUTH_METHOD_PREF constant
```

### Phase 4 + 5 — parallel after US1
```
Agent A: T015, T016, T017 — preference cookie (US2)
Agent B: T018, T019, T020, T021, T022 — logo URI + DL20 (US3)
```

### Phase 6 — parallel polish
```
Agent A: T023 — doc comments
Agent B: T024 — quickstart validation
```

---

## Implementation Strategy

### MVP (User Story 1 Only)

1. Phase 1: T001, T002 — prerequisites
2. Phase 2: T003–T007 — shared types and model
3. Phase 3: T008–T014 — SSO-first landing page + redirect + tests
4. **STOP and VALIDATE**: run quickstart.md Scenarios 1–5
5. Deployable — SSO buttons visible; redirect to provider works end-to-end

### Full Feature Delivery

Phase 1 → Phase 2 → Phase 3 (MVP) → Phase 4+5 (parallel) → Phase 6

Each phase is independently testable before proceeding.

---

## Notes

- All Rust tasks end with `cargo clippy -- -D warnings` — fix code, never suppress
- T003 is the highest-risk task: adding `AuthStep::InitOAuth2Provider` touches shared proto types; compile all crates after completing it before proceeding
- T008+T009 are the most architecturally complex: the provider-initiated session parallels the existing auth session machinery; keep `provider_sessions` separate from `sessions` to avoid breaking existing flows
- DL20 migration (T019) bumps `DOMAIN_TGT_LEVEL` — all existing integration tests must still pass
- `COOKIE_AUTH_METHOD_PREF` is unsigned (UI preference, not security-sensitive) — consistent with `COOKIE_USERNAME`
