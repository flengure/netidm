# Feature Specification: Forward Auth & Proxy Auth

**Feature Branch**: `004-forward-auth-endpoint`
**Created**: 2026-04-18
**Status**: Draft
**Reference**: oauth2-proxy source (https://github.com/oauth2-proxy/oauth2-proxy)

## Overview

Add the complete reverse-proxy authentication layer to netidm, making it a full replacement for oauth2-proxy. Netidm already handles identity, sessions, OIDC, LDAP, and SSH. This feature adds the forward auth endpoints, identity header injection, userinfo API, session sign-out, and skip-auth route rules — everything a reverse proxy needs to protect downstream applications without those apps speaking OIDC themselves.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Unauthenticated Request Is Blocked and Redirected (Priority: P1)

A visitor accesses a protected application (Grafana, Portainer, any internal tool). The reverse proxy calls netidm's auth endpoint. The visitor has no session.

**Why this priority**: The security gate. Everything else is meaningless if this fails.

**Independent Test**: Configure Traefik `forwardAuth` to point at `/oauth2/auth`. Visit the protected app without a session. Confirm `401` + `Location` redirect to the login page.

**Acceptance Scenarios**:

1. **Given** a request with no session cookie or Bearer token, **When** the auth endpoint is called, **Then** it returns `401` with `Location: /ui/login?next=<original_url>` and `WWW-Authenticate: Bearer realm="netidm"`.
2. **Given** an expired token, **When** evaluated, **Then** returns `401` (not silent pass, not `500`).
3. **Given** a `401` with `next` param, **When** the user completes login, **Then** they land on the originally requested URL.
4. **Given** a request with `Accept: application/json`, **When** auth fails, **Then** returns `401` JSON `{"error": "unauthenticated"}` instead of an HTML redirect (for API clients).

---

### User Story 2 — Authenticated Request Passes with Identity Headers (Priority: P1)

A user with a valid netidm session visits a protected application. The reverse proxy calls the auth endpoint and injects identity headers so the downstream app knows who the user is.

**Why this priority**: Equal to blocking — the endpoint must permit authenticated users and convey identity.

**Independent Test**: Authenticate to netidm, call `/oauth2/auth` with the session token, confirm `202` + all identity headers.

**Acceptance Scenarios**:

1. **Given** a valid session cookie, **When** evaluated, **Then** returns `202` with `X-Auth-Request-User` (username), `X-Auth-Request-Email`, `X-Auth-Request-Groups`, `X-Auth-Request-Preferred-Username`.
2. **Given** a valid `Authorization: Bearer <token>`, **When** evaluated, **Then** returns `202` with identity headers (supports headless/API callers).
3. **Given** a user with no email, **When** evaluated, **Then** `X-Auth-Request-Email` is omitted (not empty string).
4. **Given** a user with no group membership, **When** evaluated, **Then** `X-Auth-Request-Groups` is omitted.
5. **Given** `X-Forwarded-*` mode is configured, **When** evaluated, **Then** also returns `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Groups`.

---

### User Story 3 — Userinfo JSON Endpoint (Priority: P2)

An authenticated user or downstream application can retrieve the authenticated user's claims as JSON from a dedicated endpoint.

**Why this priority**: Enables downstream apps to read identity without parsing injected headers. Also enables oauth2-proxy-compatible integrations that call `/oauth2/proxy/userinfo`.

**Independent Test**: Authenticate, call `GET /oauth2/proxy/userinfo` with session, confirm JSON response with user fields.

**Acceptance Scenarios**:

1. **Given** a valid session, **When** `GET /oauth2/proxy/userinfo` is called, **Then** returns `200` JSON containing `user`, `email`, `groups`, `preferred_username`.
2. **Given** no valid session, **When** `GET /oauth2/proxy/userinfo` is called, **Then** returns `401`.

---

### User Story 4 — Sign-Out Endpoint (Priority: P2)

A user or downstream app can trigger session termination via a dedicated sign-out endpoint that clears the session cookie and optionally redirects.

**Why this priority**: oauth2-proxy compatibility requires `/oauth2/sign_out`. Some apps call this directly.

**Independent Test**: Authenticate, call `GET /oauth2/sign_out`, confirm cookie cleared and redirect to configured URL or login page.

**Acceptance Scenarios**:

1. **Given** a valid session, **When** `GET /oauth2/sign_out` is called, **Then** the session cookie is cleared and the user is redirected to `/ui/login`.
2. **Given** `?rd=<url>` in the query string and the URL is on a trusted domain, **When** sign-out completes, **Then** redirect to that URL.
3. **Given** `?rd=<url>` pointing to an untrusted domain, **When** sign-out is requested, **Then** redirect to `/ui/login` (open-redirect prevention).

---

### User Story 5 — Skip-Auth Routes (Priority: P3)

An operator can configure path patterns that bypass authentication entirely (e.g., `/health`, `/metrics`, `/public/*`), so health checkers and public assets are not blocked.

**Why this priority**: Operational necessity for health checks and public content. Not a core security feature but required for production deployability.

**Independent Test**: Configure a skip-auth rule for `GET /health`, access it without a session, confirm `200` pass-through (not `401`).

**Acceptance Scenarios**:

1. **Given** a skip-auth rule `GET=^/health`, **When** a request matches, **Then** the auth check is bypassed and the request is allowed through.
2. **Given** a non-matching path, **When** the same request arrives, **Then** normal auth check applies.
3. **Given** an OPTIONS request and skip-preflight is enabled, **When** evaluated, **Then** CORS preflight passes without auth.

---

### Edge Cases

- Expired session: returns `401`, not silent pass.
- Deleted/suspended account with a structurally valid token: returns `401`.
- `X-Forwarded-Uri` with query string or fragment: preserved in `next` parameter.
- Open redirect: `next` URL reconstructed only from trusted `X-Forwarded-*` headers, not from caller-supplied query params.
- Both cookie and Bearer token present: Bearer token takes precedence.
- `sign_out` with untrusted `rd` param: fall back to `/ui/login`.
- Skip-auth routes match before auth check — ordering matters.

---

## Requirements *(mandatory)*

### Functional Requirements

**Forward Auth Endpoint (`/oauth2/auth`)**:
- **FR-001**: `GET /oauth2/auth` MUST return `202` for valid sessions, `401` for invalid/missing.
- **FR-002**: On `401`, response MUST include `Location: /ui/login?next=<original_url>` and `WWW-Authenticate: Bearer realm="netidm"`.
- **FR-003**: The original URL MUST be reconstructed from trusted `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Uri` headers only.
- **FR-004**: On `202`, response MUST include `X-Auth-Request-User` (username), `X-Auth-Request-Email` (if set), `X-Auth-Request-Groups` (comma-separated, if any), `X-Auth-Request-Preferred-Username` (display name).
- **FR-005**: Session credentials MUST be accepted from both the session cookie (`bearer`) and `Authorization: Bearer <token>` header.
- **FR-006**: `401` JSON MUST be returned when the `Accept` header is `application/json`.
- **FR-007**: Sessions belonging to deleted/disabled accounts MUST return `401`.
- **FR-008**: The endpoint MUST introduce zero new runtime dependencies.

**X-Forwarded Headers Mode**:
- **FR-009**: When a downstream app is configured for forwarded-header mode, the endpoint MUST also set `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Groups` on `202`.

**Userinfo Endpoint (`/oauth2/proxy/userinfo`)**:
- **FR-010**: `GET /oauth2/proxy/userinfo` MUST return `200` JSON `{user, email, groups, preferred_username}` for valid sessions.
- **FR-011**: `GET /oauth2/proxy/userinfo` MUST return `401` for invalid/missing sessions.

**Sign-Out Endpoint (`/oauth2/sign_out`)**:
- **FR-012**: `GET /oauth2/sign_out` MUST clear the session cookie.
- **FR-013**: On sign-out, redirect to `?rd=<url>` if `<url>` is on a trusted domain; otherwise redirect to `/ui/login`.
- **FR-014**: Open-redirect MUST be prevented — untrusted `rd` URLs MUST be rejected.

**Skip-Auth Rules**:
- **FR-015**: Operators MUST be able to configure skip-auth rules as method+path patterns (e.g., `GET=^/health`).
- **FR-016**: Skip-auth rules MUST be evaluated before the session check.
- **FR-017**: OPTIONS preflight requests MUST be passable via a `skip_auth_preflight` flag.

**Security**:
- **FR-018**: `X-Forwarded-*` headers MUST only be trusted when the request source IP is in a configured trusted-proxy CIDR list.
- **FR-019**: Sensitive fields (tokens, secrets) MUST NOT appear in logs.

### Key Entities

- **Forward Auth Request**: Proxy-originated request with `X-Forwarded-*` headers and a session credential.
- **Session Credential**: Cookie `bearer` or `Authorization: Bearer <jwt>`.
- **Identity Headers**: `X-Auth-Request-{User,Email,Groups,Preferred-Username}` / `X-Forwarded-{User,Email,Groups}`.
- **Skip-Auth Rule**: A method + path-regex pair that bypasses auth for matching requests.
- **Trusted Proxy**: A CIDR range from which `X-Forwarded-*` headers are accepted.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Unauthenticated requests are blocked in a single round-trip — no additional latency steps visible to the user.
- **SC-002**: Authenticated users pass through with all identity headers in one round-trip.
- **SC-003**: After login, users land on the originally requested page 100% of the time (when proxy sends correct `X-Forwarded-*` headers).
- **SC-004**: The implementation passes all existing tests and introduces zero new clippy warnings.
- **SC-005**: An operator can protect any application using only reverse-proxy configuration changes.
- **SC-006**: Health-check and public paths bypass auth with zero impact on protected paths.
- **SC-007**: The sign-out endpoint clears the session on the first call, with no stale sessions observable afterwards.

---

## Assumptions

- Any reverse proxy that sends `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Uri` headers (Traefik, nginx, Caddy, Apache, HAProxy, Envoy, etc.) is supported. No proxy-specific behaviour is assumed.
- `COOKIE_BEARER_TOKEN` (`bearer`) cookie name and JWT format are stable.
- The login page at `/ui/login` already honours `?next=<url>` (to be verified; if not, patched in this feature).
- Group names in `X-Auth-Request-Groups` are short names, not UUIDs.
- Per-service group-based access control (403 for non-members) is out of scope for this feature; a future enhancement adds `allowed_groups` per upstream.
- The `UserAuthToken` struct does not contain groups; groups are fetched via a `whoami` DB call.
- Trusted proxy CIDR configuration reuses the existing `trust_x_forward_for_ips` config field.
