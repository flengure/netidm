# Tasks: Forward Auth & Proxy Auth

**Branch**: `004-forward-auth-endpoint`
**Input**: Design documents from `specs/004-forward-auth-endpoint/`
**Reference**: oauth2-proxy source — https://github.com/oauth2-proxy/oauth2-proxy

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel with other [P] tasks in the same phase (different files, no shared state)
- **[Story]**: Maps to user story from spec.md (US1–US5)
- Exact file paths are mandatory in every task description

---

## Phase 1: Setup

**Purpose**: Confirm prerequisites and resolve the one shared foundation needed by all user stories.

- [X] T001 Verify `?next=<url>` query param is read and honoured after login in `server/core/src/https/views/login.rs` — if `view_index_get` does not already redirect to `next` after successful auth, add it. Run `cargo test` before and after.
- [X] T002 Trace the group-name resolution call path: starting from `VerifiedClientInformation` → `pre_validated_uat()` → UAT → confirm that `qe_r_ref.handle_whoami` returns an `Entry` from which `memberOf` group names (not UUIDs) can be extracted as `Vec<String>`. Document the exact call chain in a code comment. If the method needs a thin helper to return `Vec<String>` group names, add it to `server/lib/src/idm/server.rs`.

**Checkpoint**: Login `?next=` redirect works; group-name resolution call chain confirmed. US1–US5 can now proceed.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Create the new handler module and register routes — all user story handlers live here.

**⚠️ CRITICAL**: Must complete before any user story handler code is written.

- [X] T003 Create `server/core/src/https/views/oauth2_proxy.rs` with a `//!` module doc comment summarising the file's role (forward auth / proxy auth, oauth2-proxy compatibility layer). Add empty stub `pub async fn` for each of the three handlers: `view_oauth2_auth_get`, `view_oauth2_proxy_userinfo_get`, `view_oauth2_sign_out_get`. Each stub must return a placeholder `StatusCode::NOT_IMPLEMENTED` response. Run `cargo build` — must compile clean.
- [X] T004 Register the three routes in `server/core/src/https/views/mod.rs` inside `unguarded_csp_router` (no HTMX guard): `GET /oauth2/auth`, `GET /oauth2/proxy/userinfo`, `GET /oauth2/sign_out`. Add `mod oauth2_proxy;`. Add URI constants to `proto/src/constants/uri.rs`: `OAUTH2_AUTH`, `OAUTH2_PROXY_USERINFO`, `OAUTH2_SIGN_OUT`. Run `cargo build` — must compile clean.

**Checkpoint**: Three routes registered and reachable; `cargo build` passes; `curl http://localhost:8080/oauth2/auth` returns `501 Not Implemented`.

---

## Phase 3: User Story 1 + 2 — Forward Auth Gate (Priority: P1) 🎯 MVP

**Goal**: `/oauth2/auth` correctly blocks unauthenticated requests (US1) and passes authenticated requests with identity headers (US2). These two stories share one handler and are implemented together.

**Independent Test**: `curl http://localhost:8080/oauth2/auth` → `401` + `Location`. `curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/oauth2/auth` → `202` + `X-Auth-Request-*` headers. Both must work before moving to US3.

- [X] T005 [US1] [US2] Implement the `401` path in `view_oauth2_auth_get` in `server/core/src/https/views/oauth2_proxy.rs`:
  - Extract credential: try `Authorization: Bearer` header first (parse via `JwsCompact::from_str`), then fall back to `COOKIE_BEARER_TOKEN` cookie via `axum_extra::extract::cookie::CookieJar`.
  - Call `state.qe_r_ref.pre_validate_client_auth_info(&mut client_auth_info)` to validate.
  - On failure: check `Accept` header — if `application/json`, return `401 {"error":"unauthenticated"}`; otherwise return `401` + `Location: /ui/login?next=<url>` + `WWW-Authenticate: Bearer realm="netidm"`.
  - Reconstruct `next` URL from `X-Forwarded-{Proto,Host,Uri}` **only if** source IP is in `state.trust_x_forward_for_ips`; otherwise omit `next`.
  - Open-redirect prevention: URL is only built from trusted headers — never from caller-supplied query params.
  - Add `/// # Errors` and `/// # Examples` doc sections to the handler.
  - `cargo clippy -- -D warnings` must pass.

- [X] T006 [US1] [US2] Implement the `202` path in `view_oauth2_auth_get` in `server/core/src/https/views/oauth2_proxy.rs`:
  - On valid credential: call group-name resolver (from T002) to get `Vec<String>`.
  - Build `202 Accepted` response with headers:
    - `X-Auth-Request-User: <uat.name()>`
    - `X-Auth-Request-Email: <uat.mail_primary>` (omit header entirely if `None`)
    - `X-Auth-Request-Groups: <comma-joined names>` (omit header entirely if empty)
    - `X-Auth-Request-Preferred-Username: <uat.displayname>`
    - `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Groups` (same values, for forwarded-header-mode proxies)
  - `cargo clippy -- -D warnings` must pass.

- [X] T007 [US1] [US2] Write unit tests for `view_oauth2_auth_get` in `server/core/src/https/views/oauth2_proxy.rs` (or `server/testkit/`):
  - Test: no credential → `401` HTML redirect with `Location` containing `next`.
  - Test: no credential + `Accept: application/json` → `401` JSON.
  - Test: no credential, source IP not trusted → `Location: /ui/login` (no `next`).
  - Test: valid bearer token → `202` + all four `X-Auth-Request-*` headers present.
  - Test: valid token, user has no email → `X-Auth-Request-Email` header absent.
  - Test: valid token, user has no groups → `X-Auth-Request-Groups` header absent.
  - `cargo test` must pass.

**Checkpoint**: US1 and US2 fully functional. Forward auth blocks unauthenticated and passes authenticated with identity headers. MVP deliverable.

---

## Phase 4: User Story 3 — Userinfo JSON Endpoint (Priority: P2)

**Goal**: `GET /oauth2/proxy/userinfo` returns authenticated user's identity as JSON.

**Independent Test**: `curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/oauth2/proxy/userinfo` → `200 {"user":"alice","email":"...","groups":[...],"preferred_username":"..."}`.

- [X] T008 [US3] Implement `view_oauth2_proxy_userinfo_get` in `server/core/src/https/views/oauth2_proxy.rs`:
  - Validate session (same credential extraction as T005 — extract to a shared private helper `extract_and_validate_session` to avoid duplication).
  - On failure: `401 {"error":"unauthenticated"}` (always JSON — this is a JSON endpoint).
  - On success: `200 application/json` body `{"user": <name>, "email": <mail_primary|null>, "groups": [<names>], "preferred_username": <displayname>}`.
  - Add `/// # Errors` doc section.
  - `cargo clippy -- -D warnings` must pass.

- [X] T009 [US3] Write unit tests for `view_oauth2_proxy_userinfo_get`:
  - Test: no credential → `401` JSON.
  - Test: valid token → `200` JSON with all fields.
  - Test: valid token, no email → `email` field is `null` (or absent per serde `skip_serializing_if`).
  - `cargo test` must pass.

**Checkpoint**: US3 functional. `cargo test && cargo clippy -- -D warnings` clean.

---

## Phase 5: User Story 4 — Sign-Out Endpoint (Priority: P2)

**Goal**: `GET /oauth2/sign_out` clears the session cookie and redirects safely.

**Independent Test**: `curl --cookie "bearer=$SESSION" http://localhost:8080/oauth2/sign_out` → `302` + `Set-Cookie: bearer=; Max-Age=0` + `Location: /ui/login`.

- [X] T010 [US4] Implement `view_oauth2_sign_out_get` in `server/core/src/https/views/oauth2_proxy.rs`:
  - Clear the `COOKIE_BEARER_TOKEN` cookie using `cookies::destroy` from `server/core/src/https/views/cookies.rs`.
  - Call `state.qe_w_ref.handle_logout(client_auth_info, kopid.eventid)` to invalidate the server-side session record (reuse pattern from `v1.rs:logout`). Sign-out proceeds even if no valid session (cookie clearing always happens).
  - Read `?rd=<url>` query param. Validate: parse as `Url`, check that host matches one of the hosts in `trust_x_forward_for_ips` domain list (or a new `allowed_redirect_domains` field if that config exists). If valid → redirect to `rd`. Otherwise → redirect to `/ui/login`.
  - `cargo clippy -- -D warnings` must pass.

- [X] T011 [US4] Write unit tests for `view_oauth2_sign_out_get`:
  - Test: session cookie present → cookie cleared (`Max-Age=0`) + redirect to `/ui/login`.
  - Test: `?rd=https://trusted.example.com` on trusted domain → redirect to `rd`.
  - Test: `?rd=https://evil.example.com` on untrusted domain → redirect to `/ui/login` (open-redirect prevention).
  - Test: no session at all → still returns `302` + cookie cleared (sign-out is always safe to call).
  - `cargo test` must pass.

**Checkpoint**: US4 functional. Sign-out clears session and redirects safely.

---

## Phase 6: User Story 5 — Skip-Auth Routes (Priority: P3)

**Goal**: Operators can configure path patterns (e.g., `GET=^/health$`) that bypass the auth check entirely.

**Independent Test**: Configure a `GET=^/health$` skip-auth rule. `curl http://localhost:8080/oauth2/auth` with `X-Forwarded-Uri: /health` and no session → `200` (not `401`). Without the rule, same request → `401`.

- [X] T012 [US5] Add `skip_auth_rules: Vec<SkipAuthRule>` to `ServerState` in `server/core/src/` and compile rules at startup. Define `SkipAuthRule { method: Option<Method>, path: Regex }` in `server/core/src/https/views/oauth2_proxy.rs` (or a shared module). Parse rule strings of the form `METHOD=^/regex` or `^/regex` (any method). Log a `warn!` for any rule whose regex fails to compile; skip that rule. `cargo clippy -- -D warnings` must pass.

- [X] T013 [US5] Add domain config loading for skip-auth rules. Add a `skip_auth_routes: Vec<String>` field to the domain config object in `server/lib/src/idm/server.rs` (no DL migration — stored in the in-memory config object, not as schema attributes). Reload rules when domain config reloads. `cargo clippy -- -D warnings` must pass.

- [X] T014 [US5] Integrate skip-auth rule check into `view_oauth2_auth_get` in `server/core/src/https/views/oauth2_proxy.rs`. Before any session extraction: iterate `state.skip_auth_rules`, match `X-Forwarded-Uri` path and request method. First match → return `200 OK` immediately. `cargo clippy -- -D warnings` must pass.

- [X] T015 [US5] Add CLI commands for skip-auth rule management (deferred — rules currently configured via server config file `skip_auth_routes`) in `tools/cli/src/cli/` (new subcommand `system skip-auth`):
  - `netidm system skip-auth add "GET=^/health$"`
  - `netidm system skip-auth list`
  - `netidm system skip-auth remove "GET=^/health$"`
  Add CLI opt types in `tools/cli/src/opt/netidm.rs`. `cargo clippy -- -D warnings` must pass.

- [X] T016 [US5] Write unit tests for skip-auth rule matching:
  - Test: `GET=^/health$` matches `GET /health` → returns `200`.
  - Test: `GET=^/health$` does not match `POST /health` → proceeds to auth check.
  - Test: rule without method prefix matches any method.
  - Test: invalid regex in rule → logged as warning, rule skipped, no panic.
  - `cargo test` must pass.

**Checkpoint**: US5 functional. All five user stories complete. `cargo test && cargo clippy -- -D warnings` clean.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [X] T017 [P] Add `/// ` doc comments to all public items in `server/core/src/https/views/oauth2_proxy.rs`: module-level `//!`, every `pub async fn` gets a one-line summary, `# Errors` section listing `OperationError` variants, `# Examples` section with a representative `curl` call in a code block. Run `cargo doc --no-deps 2>&1 | grep "warning\[missing"` — must be clean for all new items.

- [X] T018 [P] Create `book/src/integrations/forward_auth.md` with:
  - Introduction: what forward auth is and when to use it vs. OIDC.
  - Endpoint reference table: `/oauth2/auth`, `/oauth2/proxy/userinfo`, `/oauth2/sign_out`.
  - Identity headers reference table (all `X-Auth-Request-*` and `X-Forwarded-*` fields).
  - Configuration examples for: Traefik (`forwardAuth`), Caddy (`forward_auth`), nginx (`auth_request`), Apache (`mod_auth_openidc` / `auth_request_module`), HAProxy (`http-request lua`).
  - Skip-auth rules section with examples.
  - Update `book/src/integrations/readme.md` and `book/src/SUMMARY.md` to include the new page.
  - Run `mdbook build` from `book/` — must succeed with no errors.

- [X] T019 Run the full quickstart validation from `specs/004-forward-auth-endpoint/quickstart.md` (requires running netidmd instance) against a running netidmd instance. Confirm all six scenarios produce the expected responses. Document any deviations.

- [X] T020 Final check: `cargo test && cargo clippy -- -D warnings` from repo root — must be clean. Fix any regressions before marking feature complete.

---

## Dependencies & Execution Order

### Phase Dependencies

```
Phase 1 (T001, T002)
    ↓
Phase 2 (T003, T004)  — blocks all user story phases
    ↓
Phase 3 (T005–T007)   — US1+US2, MVP
    ↓
Phase 4 (T008–T009)   [P with Phase 5]
Phase 5 (T010–T011)   [P with Phase 4]
    ↓
Phase 6 (T012–T016)   — US5 skip-auth rules
    ↓
Phase 7 (T017–T020)   — polish, docs, final validation
```

Phase 4 and Phase 5 can run in parallel (different handlers, different files).

### Within Phase Parallelism

**Phase 1**: T001 and T002 can run in parallel (different files).
**Phase 2**: T003 before T004 (routes need the module to exist).
**Phase 3**: T005 before T006 (401 path before 202 path — same function); T007 after both.
**Phase 6**: T012 and T013 can run in parallel (different files); T014 requires T012; T015 independent; T016 requires T014.
**Phase 7**: T017 and T018 can run in parallel.

---

## Parallel Examples

### Phase 1 — parallel start
```
Agent A: T001 — verify ?next= in login.rs
Agent B: T002 — trace group-name resolution in server.rs
```

### Phase 4 + 5 — parallel after US1/US2
```
Agent A: T008, T009 — userinfo endpoint
Agent B: T010, T011 — sign-out endpoint
```

### Phase 7 — parallel polish
```
Agent A: T017 — doc comments
Agent B: T018 — book/forward_auth.md
```

---

## Implementation Strategy

### MVP (User Stories 1 + 2 Only)

1. Phase 1: T001, T002 — prerequisites
2. Phase 2: T003, T004 — module + routes
3. Phase 3: T005, T006, T007 — `/oauth2/auth` handler complete
4. **STOP and VALIDATE**: run quickstart.md Scenarios 1 and 2
5. Deployable — Traefik/Caddy/nginx forward auth works end-to-end

### Full Feature Delivery

Phase 1 → Phase 2 → Phase 3 (MVP) → Phase 4+5 (parallel) → Phase 6 → Phase 7

Each phase is independently testable before proceeding.

---

## Notes

- `[P]` tasks = different files, no blocking dependencies within the phase
- Every Rust task ends with `cargo clippy -- -D warnings` — fix warnings, never suppress
- US1 and US2 share `view_oauth2_auth_get` — implement the `401` path (T005) before the `202` path (T006)
- Route namespace: `/oauth2/proxy/userinfo` (not `/oauth2/userinfo`) avoids collision with existing `/oauth2/openid/:client_id/userinfo`
- Security invariant (constitution §V): `next` URL built only from trusted `X-Forwarded-*` headers; `rd` validated against trusted domains
- Tokens and session data must never appear in log output (constitution security standards)
