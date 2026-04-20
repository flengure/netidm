# Implementation Plan: Forward Auth & Proxy Auth

**Branch**: `004-forward-auth-endpoint` | **Date**: 2026-04-18 | **Spec**: [spec.md](spec.md)

## Summary

Add a complete oauth2-proxy-compatible forward auth layer to netidm: `/oauth2/auth` (forward auth endpoint), `/oauth2/proxy/userinfo` (identity JSON), `/oauth2/sign_out` (session clear + redirect), and skip-auth route rules. Reuses existing session validation, cookie handling, and DB read paths. Zero new dependencies.

Reference: https://github.com/oauth2-proxy/oauth2-proxy

---

## Technical Context

**Language/Version**: Rust stable (see `rust-toolchain.toml`)
**Primary Dependencies**: `axum`, `axum-extra` (cookies), `compact_jwt`, `netidmd_lib`, `netidm_proto`, `regex` — all already present; zero new deps
**Storage**: No new storage. Group resolution via existing MVCC read path (`qe_r_ref.handle_whoami`)
**Testing**: `cargo test` — unit tests; integration via `server/testkit`
**Target Platform**: Linux server (netidmd daemon)
**Project Type**: Web service — new HTTP handler module within `server/core`
**Performance Goals**: Single in-process async DB read per auth check; no visible latency increase
**Constraints**: Zero new dependencies; `cargo clippy -- -D warnings` clean

---

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Ethics & Human Rights | ✅ Pass | Identity headers are read-only; no new data collected |
| II. Humans First | ✅ Pass | POST-login redirect to original URL preserves user intent |
| III. Correct & Simple | ✅ Pass | Reuses existing session validation; no new auth mechanism |
| IV. Clippy Zero Warnings | ✅ Required | All new code must pass `cargo clippy -- -D warnings` |
| V. Security by Hierarchy | ✅ Pass | Open-redirect eliminated via trusted-header-only URL construction; token not logged |
| Security Standards | ✅ Pass | Auth fails closed (deny on any validation failure); tokens never logged |

---

## Project Structure

### Documentation (this feature)

```text
specs/004-forward-auth-endpoint/
├── plan.md              ← this file
├── research.md          ← Phase 0 output
├── data-model.md        ← Phase 1 output
├── quickstart.md        ← Phase 1 output
├── contracts/
│   └── http_endpoints.md
└── tasks.md             ← Phase 2 output (/speckit.tasks)
```

### Source Code (affected paths)

```text
server/core/src/https/
├── views/
│   ├── mod.rs                    ← add routes + mod oauth2_proxy
│   ├── oauth2_proxy.rs           ← NEW: forward auth handlers
│   └── login.rs                  ← verify/add ?next= param handling
└── middleware/
    └── mod.rs                    ← no change (reuse trust_x_forward_for_ips)

server/lib/src/idm/
└── server.rs                     ← expose group-name resolution if not already public

proto/src/internal/
└── token.rs                      ← no change (UserAuthToken fields sufficient)
```

---

## Phase 0: Research ✅

See [research.md](research.md). All unknowns resolved:
- Endpoint names: `/oauth2/auth`, `/oauth2/proxy/userinfo`, `/oauth2/sign_out`
- Auth return code: `202` (oauth2-proxy convention)
- Group names: DB read via `handle_whoami` at request time
- Skip-auth rules: `(Option<Method>, Regex)` pairs in domain config
- Trusted proxy: reuse existing `trust_x_forward_for_ips`

---

## Phase 1: Design ✅

See [data-model.md](data-model.md), [contracts/http_endpoints.md](contracts/http_endpoints.md), [quickstart.md](quickstart.md).

---

## Phase 2: Implementation Tasks

### T001 — Verify `?next=` handling in login view

**File**: `server/core/src/https/views/login.rs`

Check if `view_index_get` already reads a `next` query param and redirects after login. If not, add it. This must land before T003 since T003 relies on it.

**Test**: Log in with `?next=/some/path` in the URL. Confirm redirect to `/some/path` after success.

---

### T002 — Expose group-name resolution method

**File**: `server/lib/src/idm/server.rs` (or via `handle_whoami`)

Ensure there is a callable path from an HTTP handler to get `Vec<String>` group names for a given `UserAuthToken`. If `handle_whoami` already returns an `Entry` with `memberOf` names resolvable as strings, document the call path. If not, add a lightweight helper.

**Test**: Unit test that given a UAT, the method returns the correct group names.

---

### T003 — Create `server/core/src/https/views/oauth2_proxy.rs`

New module with three handlers:

#### `view_oauth2_auth_get`

```
GET /oauth2/auth
```

1. Check skip-auth rules (from `ServerState`) — if match, return `200 OK`.
2. Extract credential: try `Authorization: Bearer` header first, then `COOKIE_BEARER_TOKEN` cookie.
3. Validate via `VerifiedClientInformation` pattern (call `pre_validate_client_auth_info`).
4. On failure:
   - If `Accept: application/json` → `401 {"error": "unauthenticated"}`
   - Else → `401` + `Location: /ui/login?next=<reconstructed_url>` + `WWW-Authenticate`
   - Reconstruct URL from `X-Forwarded-{Proto,Host,Uri}` only if source IP is trusted
5. On success:
   - Call group-name resolver (T002)
   - Build `202` response with `X-Auth-Request-*` headers
   - If forwarded-header mode: also add `X-Forwarded-{User,Email,Groups}`

#### `view_oauth2_userinfo_get`

```
GET /oauth2/proxy/userinfo
```

1. Validate credential (same as above, no skip-auth).
2. On failure → `401 {"error": "unauthenticated"}`.
3. On success → `200 JSON {user, email, groups, preferred_username}`.

#### `view_oauth2_sign_out_get`

```
GET /oauth2/sign_out
```

1. Clear the `COOKIE_BEARER_TOKEN` cookie via `cookies::destroy`.
2. Call existing `handle_logout` (optional — clears server-side session record).
3. Read `rd` query param. If present and host is in trusted domains → redirect there.
4. Otherwise → redirect to `/ui/login`.

**Tests**: Unit tests for each status code path. Test open-redirect prevention in sign_out. Test JSON vs HTML 401. Test header omission when email/groups are absent.

---

### T004 — Register routes in `views/mod.rs`

Add to `unguarded_csp_router` (no HTMX guard — these are called bare by reverse proxies):

```rust
mod oauth2_proxy;
// ...
.route("/oauth2/auth", get(oauth2_proxy::view_oauth2_auth_get))
.route("/oauth2/proxy/userinfo", get(oauth2_proxy::view_oauth2_userinfo_get))
.route("/oauth2/sign_out", get(oauth2_proxy::view_oauth2_sign_out_get))
```

**Test**: `cargo test` passes; routes appear in `curl -v http://localhost:8080/oauth2/auth`.

---

### T005 — Skip-auth rule storage and compilation

**Files**: Domain config type in `server/lib/src/idm/server.rs` + `ServerState`

1. Add `skip_auth_rules: Vec<(Option<Method>, Regex)>` to `ServerState` (compiled at startup).
2. Add configuration loading from domain config object (CLI-configurable).
3. Compile regex patterns once at startup; log a warning for invalid patterns.

**Test**: Unit test that a configured skip-auth rule bypasses the auth check for matching paths and methods.

---

### T006 — CLI commands for skip-auth rules

**File**: `tools/cli/src/cli/` (new subcommand or extend `system` commands)

```
netidm system skip-auth-rule add "GET=^/health$"
netidm system skip-auth-rule list
netidm system skip-auth-rule remove "GET=^/health$"
```

**Test**: Add a rule, list it, remove it. Confirm effect on `/oauth2/auth` endpoint.

---

### T007 — Doc comments (Rust best practices)

**Files**: `server/core/src/https/views/oauth2_proxy.rs` (new), all modified files

All new and modified public items MUST have:
- `///` doc comment on every `pub fn`, `pub struct`, `pub enum`
- `//!` module-level doc on `oauth2_proxy.rs`
- `# Examples` section with a `\`\`\`rust` code block on handler functions
- `# Errors` section on every `Result`-returning function documenting each variant
- Intra-doc links `[TypeName]` to related types (`UserAuthToken`, `VerifiedClientInformation`, etc.)

**Standard** (from The Rust Book + rustdoc guide):
```rust
//! Module-level doc with one-line summary, then blank line, then detail.

/// One-line summary ending with a period.
///
/// Longer description paragraph.
///
/// # Errors
///
/// Returns [`OperationError::NotAuthenticated`] if no valid session is present.
///
/// # Examples
///
/// \`\`\`rust
/// // example code here
/// \`\`\`
pub async fn view_oauth2_auth_get(...) -> Response { ... }
```

**Test**: `cargo doc --no-deps 2>&1 | grep "warning\[missing"` must be clean for all new items.

---

### T008 — Book documentation

**Files** (new):
- `book/src/integrations/forward_auth.md` — how to use netidm forward auth with any reverse proxy
- Update `book/src/integrations/readme.md` or `SUMMARY.md` to include new page

**Content for `forward_auth.md`**:
- What forward auth does and when to use it
- The three endpoints: `/oauth2/auth`, `/oauth2/proxy/userinfo`, `/oauth2/sign_out`
- Configuration examples for: Traefik, Caddy, nginx, Apache (`mod_auth_request`), HAProxy
- Skip-auth rules configuration
- Identity headers reference table
- Difference from OIDC (when to use each)

**Test**: `mdbook build` succeeds without errors.

---

### T010 — Integration test

**File**: `server/testkit/`

End-to-end test:
1. Start netidmd in test mode.
2. Create a user, authenticate, get session token.
3. Call `/oauth2/auth` with token → assert `202` + identity headers.
4. Call `/oauth2/auth` without token → assert `401`.
5. Call `/oauth2/proxy/userinfo` with token → assert `200` JSON.
6. Call `/oauth2/sign_out` → assert cookie cleared + redirect.

---

## Dependency Order

```
T001 ──→ T003 ──→ T004 ──→ T010
T002 ──→ T003
T005 ──→ T003
T005 ──→ T006
T003 ──→ T007
T004 ──→ T008
```

T001 and T002 can run in parallel. T003 requires both. T004 and T005 can be done alongside T003. T006 requires T005. T007 (doc comments) runs alongside T003. T008 (book) can start after routes are final (T004). T010 (integration test) requires T003 + T004 + T005.

---

## Route Namespace Notes

The `/oauth2/` namespace is shared between two roles in netidm:

| Prefix | Role | Examples |
|--------|------|---------|
| `/oauth2/authorise`, `/oauth2/token`, etc. | **OAuth2 AS** (RFC 6749) — netidm as authorization server | existing |
| `/oauth2/openid/:client_id/*` | **OIDC provider** per-client endpoints | existing |
| `/oauth2/auth`, `/oauth2/sign_out` | **Forward auth proxy** (oauth2-proxy compat) | this feature |
| `/oauth2/proxy/userinfo` | **Forward auth proxy userinfo** | this feature (namespaced to avoid collision with `/oauth2/openid/:id/userinfo`) |

**Future dex connectors** (features 006–007) add upstream IdP callbacks:
- Generic OIDC connector: reuses existing `/ui/login/oauth2/...` callback path — no new routes needed.
- SAML 2.0 connector: new `POST /ui/login/saml/callback` — no conflict with any existing path.

---

## Verification

```bash
cargo test && cargo clippy -- -D warnings
```

Manual:
```bash
# Unauthenticated
curl -v http://localhost:8080/oauth2/auth
# → 401 + Location

# Authenticated
curl -v -H "Authorization: Bearer $TOKEN" http://localhost:8080/oauth2/auth
# → 202 + X-Auth-Request-* headers

# Userinfo
curl -v -H "Authorization: Bearer $TOKEN" http://localhost:8080/oauth2/proxy/userinfo
# → 200 JSON

# Sign-out
curl -v --cookie "bearer=$SESSION" http://localhost:8080/oauth2/sign_out
# → 302 + cookie cleared
```
