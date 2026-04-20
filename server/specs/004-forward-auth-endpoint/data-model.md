# Data Model: Forward Auth & Proxy Auth

**Branch**: `004-forward-auth-endpoint` | **Date**: 2026-04-18

## New Entities / Types

### `ForwardAuthIdentity` (in-memory, not persisted)

Built from the validated `UserAuthToken` + group name resolution. Used to construct identity headers.

| Field | Type | Source | Header |
|-------|------|--------|--------|
| `username` | `String` | `uat.name()` (spn without `@domain`) | `X-Auth-Request-User` / `X-Forwarded-User` |
| `email` | `Option<String>` | `uat.mail_primary` | `X-Auth-Request-Email` / `X-Forwarded-Email` |
| `groups` | `Vec<String>` | DB lookup via `handle_whoami` → `Entry::memberOf` names | `X-Auth-Request-Groups` / `X-Forwarded-Groups` |
| `preferred_username` | `String` | `uat.displayname` | `X-Auth-Request-Preferred-Username` |

### `SkipAuthRule` (persisted in domain config)

| Field | Type | Description |
|-------|------|-------------|
| `method` | `Option<String>` | HTTP method to match (`GET`, `POST`, etc.), or `None` for any |
| `path_regex` | `String` | Regex pattern matched against request path |

Compiled to `(Option<Method>, Regex)` at server startup/reload.

---

## Existing Entities Used (No Schema Change)

| Entity | Location | Usage |
|--------|----------|-------|
| `UserAuthToken` | `proto/src/internal/token.rs:34` | Decoded from session cookie/bearer; provides `spn`, `mail_primary`, `displayname` |
| `ClientAuthInfo` | extracted by `VerifiedClientInformation` | Carries pre-validated token; `.pre_validated_uat()` returns `&UserAuthToken` |
| `trust_x_forward_for_ips` | `ServerState` | CIDR list for trusting `X-Forwarded-*` headers |
| Domain config | `server/lib/src/idm/server.rs` | Extended with `skip_auth_rules: Vec<SkipAuthRule>` |

---

## No New DB Schema

Group names are resolved at request-time via the existing `handle_whoami` read path. No new schema attributes or DL migration is required for the core forward auth functionality.

If `SkipAuthRule` is stored in the domain config object (not as schema attributes), no DL migration is needed. If stored as proper attributes on the domain entry, a DL migration (DL19) is required.

**Decision**: Store skip-auth rules in the domain config object type — avoids a DL migration for this feature.

---

## HTTP Contract Summary

### Inputs consumed

| Header | Source | When trusted |
|--------|--------|-------------|
| `X-Forwarded-Proto` | Reverse proxy | Source IP in `trust_x_forward_for_ips` |
| `X-Forwarded-Host` | Reverse proxy | Source IP in `trust_x_forward_for_ips` |
| `X-Forwarded-Uri` | Reverse proxy | Source IP in `trust_x_forward_for_ips` |
| `Authorization: Bearer <jwt>` | Caller | Always (validated cryptographically) |
| Cookie `bearer` | Browser session | Always (validated cryptographically) |
| `Accept` | Caller | Always (determines JSON vs redirect response) |

### Outputs produced

| Header | Endpoint | Condition |
|--------|----------|-----------|
| `X-Auth-Request-User` | `/oauth2/auth` | Session valid (202) |
| `X-Auth-Request-Email` | `/oauth2/auth` | Session valid + email set |
| `X-Auth-Request-Groups` | `/oauth2/auth` | Session valid + groups exist |
| `X-Auth-Request-Preferred-Username` | `/oauth2/auth` | Session valid |
| `X-Forwarded-User` | `/oauth2/auth` | Session valid (forwarded-header mode) |
| `X-Forwarded-Email` | `/oauth2/auth` | Session valid + email set |
| `X-Forwarded-Groups` | `/oauth2/auth` | Session valid + groups exist |
| `Location` | `/oauth2/auth` | Session invalid (401) |
| `WWW-Authenticate` | `/oauth2/auth` | Session invalid (401) |
| `Location` | `/oauth2/sign_out` | Always (post sign-out redirect) |
