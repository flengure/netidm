# Research: Forward Auth & Proxy Auth

**Branch**: `004-forward-auth-endpoint` | **Date**: 2026-04-18

## Reference Implementation

**oauth2-proxy** (https://github.com/oauth2-proxy/oauth2-proxy) is the reference. All endpoint names, header names, and behavioural contracts in this spec are derived from its source code.

---

## Decision 1: Endpoint Naming

**Decision**: Use `/oauth2/auth`, `/oauth2/proxy/userinfo`, `/oauth2/sign_out` — matching oauth2-proxy exactly.

**Rationale**: Drop-in compatibility. Operators who previously used oauth2-proxy can point Traefik/nginx at netidm with minimal config change. The `/oauth2/` prefix is a well-known convention for these proxy endpoints.

**Alternatives considered**:
- `/ui/auth` (original intent doc) — rejected; non-standard and requires proxy reconfiguration vs. any other oauth2-proxy install.
- `/v1/forward_auth` — rejected; the v1 prefix implies REST API management, not proxy middleware.

---

## Decision 2: Auth Endpoint Return Code

**Decision**: Return `202 Accepted` (not `200 OK`) on successful auth check.

**Rationale**: oauth2-proxy uses `202` for `/oauth2/auth`. NGINX `auth_request` and Traefik `forwardAuth` both accept any 2xx. `202` signals "accepted for pass-through" vs. `200 OK` which implies content was returned. Traefik and nginx both handle this correctly.

**Alternatives considered**: `200 OK` — works with all proxies but breaks oauth2-proxy compatibility for integrations that specifically check for `202`.

---

## Decision 3: Group Name Resolution

**Decision**: Resolve group names from UUIDs via a `whoami` DB call on each forward auth request.

**Rationale**: The `UserAuthToken` (JWT stored in the session cookie) does not contain group names — only the token's identity claims (`spn`, `mail_primary`, `displayname`). Group membership is stored as `Attribute::MemberOf` (UUIDs) in the identity. To return human-readable group names in `X-Auth-Request-Groups`, a read-only DB lookup via `qe_r_ref.handle_whoami` is required. This is already done by other endpoints (e.g., the OAuth2 scope group check at `oauth2.rs:781`).

**Performance implication**: One additional async DB read per forward auth call. Acceptable — the read is in-process (no network hop), and the DB layer uses MVCC (concurrent reads). If this becomes a bottleneck, group names can be cached in the session JWT in a future enhancement.

**Alternatives considered**:
- Embed group names in the JWT — adds complexity to token issuance and token size; deferred.
- Return group UUIDs instead of names — rejected; downstream apps expect human-readable names.

---

## Decision 4: Skip-Auth Rule Storage

**Decision**: Store skip-auth rules as a list of `(Method, Regex)` pairs in the domain configuration (DB), managed via CLI.

**Rationale**: Domain config already holds `trust_x_forward_for_ips` and similar operational settings. Skip-auth rules are global to the netidm instance (not per-user), so domain config is the right place. Regex compilation happens at startup/reload — no per-request compilation overhead.

**Alternatives considered**:
- Per-resource-server rules (OAuth2 RS entries) — more granular but adds complexity; deferred to per-app ACL feature.
- File-based config — rejected; netidm doesn't use file-based config for runtime settings.

---

## Decision 5: Trusted Proxy IPs

**Decision**: Reuse the existing `trust_x_forward_for_ips` config field for validating `X-Forwarded-*` headers in the forward auth path.

**Rationale**: Already exists in `ServerState` and is used by `ip_address_middleware`. No new config field needed. The field contains CIDR ranges; requests from those IPs have their `X-Forwarded-*` headers trusted.

---

## Decision 6: Sign-Out Endpoint

**Decision**: Add `GET /oauth2/sign_out` as a thin wrapper over the existing `POST /v1/logout` logic.

**Rationale**: The existing logout path (`handle_logout` in `server/lib/src/idm/server.rs`) already clears the session server-side. The new endpoint adds the cookie-clearing and redirect behaviour expected by oauth2-proxy consumers. The `rd` parameter redirect is validated against `trust_x_forward_for_ips` domain or a new `allowed_redirect_domains` config field.

---

## Technical Context Resolved

| Item | Resolution |
|------|-----------|
| Language/Version | Rust stable (see `rust-toolchain.toml`) |
| Primary Dependencies | `axum`, `axum-extra` (cookies), `compact_jwt`, `netidmd_lib`, `netidm_proto` — all already in scope; zero new deps |
| Storage | No new storage. Group resolution via existing MVCC read path (`qe_r_ref`) |
| Testing | `cargo test` — unit tests for header logic; integration via `server/testkit` |
| Target Platform | Linux server (netidmd daemon) |
| Project Type | Web service — new HTTP handler module within `server/core` |
| Performance | One additional DB read per auth check for group resolution. Acceptable for now |
| Constraints | Zero new dependencies; `cargo clippy -- -D warnings` must pass |

---

## Files Identified for Change

| File | Change |
|------|--------|
| `server/core/src/https/views/mod.rs` | Register new routes; add `mod oauth2_proxy;` |
| `server/core/src/https/views/oauth2_proxy.rs` | **New** — `/oauth2/auth`, `/oauth2/proxy/userinfo`, `/oauth2/sign_out` handlers |
| `server/core/src/https/views/login.rs` | Verify/add `?next=` query param handling |
| `server/core/src/https/extractors/mod.rs` | Confirm `VerifiedClientInformation` extractor reuse |
| `server/lib/src/idm/server.rs` | Expose group-name resolution path for forward auth use |
| `proto/src/internal/token.rs` | No change — `UserAuthToken` fields sufficient for non-group headers |
| Domain config / `server/lib/src/idm/` | Add skip-auth rules to domain config type |
