# HTTP Contracts: Forward Auth & Proxy Auth

**Branch**: `004-forward-auth-endpoint` | **Date**: 2026-04-18
**Reference**: oauth2-proxy source — https://github.com/oauth2-proxy/oauth2-proxy

---

## `GET /oauth2/auth`

Forward auth endpoint. Called by the reverse proxy on every request to a protected upstream.

### Request

| Component | Value |
|-----------|-------|
| Method | `GET` |
| Path | `/oauth2/auth` |
| Auth | Session cookie `bearer` OR `Authorization: Bearer <jwt>` |
| Headers read | `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Uri` (trusted proxy only), `Accept` |

### Response — 202 Accepted (valid session)

```
HTTP/1.1 202 Accepted
X-Auth-Request-User: alice
X-Auth-Request-Email: alice@example.com
X-Auth-Request-Groups: admins,developers
X-Auth-Request-Preferred-Username: Alice Smith
X-Forwarded-User: alice                       (if forwarded-header mode enabled)
X-Forwarded-Email: alice@example.com          (if forwarded-header mode enabled)
X-Forwarded-Groups: admins,developers         (if forwarded-header mode enabled)
```

- `X-Auth-Request-Email` omitted if user has no email.
- `X-Auth-Request-Groups` omitted if user has no group memberships.
- Groups are comma-separated short names (not UUIDs).

### Response — 401 Unauthorized (no/invalid session, `Accept: text/html`)

```
HTTP/1.1 401 Unauthorized
Location: /ui/login?next=https%3A%2F%2Fapp.example.com%2Fdashboard
WWW-Authenticate: Bearer realm="netidm"
```

- `next` URL reconstructed from `X-Forwarded-{Proto,Host,Uri}`.
- If forwarded headers are absent or from untrusted source: `Location: /ui/login` (no `next`).

### Response — 401 Unauthorized (no/invalid session, `Accept: application/json`)

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error": "unauthenticated"}
```

### Response — 200 OK (skip-auth rule matched)

```
HTTP/1.1 200 OK
```

No identity headers. Request is allowed through without authentication.

---

## `GET /oauth2/proxy/userinfo`

Returns the authenticated user's identity as JSON. Equivalent to the oauth2-proxy `/oauth2/proxy/userinfo` endpoint.

> **Namespace note**: The path `/oauth2/proxy/userinfo` is avoided because netidm already has
> `/oauth2/openid/:client_id/userinfo` (OIDC per-client userinfo, RFC 7662). Using `/oauth2/proxy/userinfo`
> avoids confusion. Reverse proxies must be configured to call `/oauth2/proxy/userinfo`, not `/oauth2/proxy/userinfo`.

### Request

| Component | Value |
|-----------|-------|
| Method | `GET` |
| Path | `/oauth2/proxy/userinfo` |
| Auth | Session cookie `bearer` OR `Authorization: Bearer <jwt>` |

### Response — 200 OK

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "user": "alice",
  "email": "alice@example.com",
  "groups": ["admins", "developers"],
  "preferred_username": "Alice Smith"
}
```

- `email` omitted if not set.
- `groups` is an empty array `[]` if user has no memberships.

### Response — 401 Unauthorized

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error": "unauthenticated"}
```

---

## `GET /oauth2/sign_out`

Clears the session cookie and redirects the user.

### Request

| Component | Value |
|-----------|-------|
| Method | `GET` |
| Path | `/oauth2/sign_out` |
| Query | `rd=<url>` — optional redirect URL after sign-out |
| Auth | Session cookie (optional — sign-out always clears cookie regardless) |

### Response — 302 Found

```
HTTP/1.1 302 Found
Set-Cookie: bearer=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax
Location: /ui/login
```

- If `rd` is present and the URL's host matches a configured trusted domain: `Location: <rd>`.
- If `rd` is present but untrusted: `Location: /ui/login` (open-redirect prevention).
- Cookie clearing uses the same attributes as cookie creation (domain, path, SameSite).

---

## Skip-Auth Rule Matching

Before any auth check, the request is tested against configured skip-auth rules.

### Rule format (CLI / config)

```
METHOD=^/path/regex
```

Examples:
```
GET=^/health$
GET=^/metrics$
^/public/          (no method = any method)
OPTIONS            (any path, OPTIONS method — for CORS preflight)
```

### Behaviour

- Rules are evaluated in order. First match wins.
- A matching rule returns `200 OK` with no auth and no identity headers.
- Non-matching requests proceed to normal session validation.

---

## Trusted Proxy Header Validation

`X-Forwarded-*` headers are only trusted when the request source IP is in the `trust_x_forward_for_ips` CIDR list (existing config field on `ServerState`).

If the source IP is not trusted:
- `X-Forwarded-*` headers are ignored.
- The `next` redirect on 401 is `/ui/login` with no `next` param.
- The auth check itself still proceeds normally.
