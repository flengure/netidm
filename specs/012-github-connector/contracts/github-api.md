# Contract: GitHub REST API surface consumed by the GitHub connector

This document enumerates every outbound HTTP call the `GitHubConnector` makes to GitHub. It is the authoritative list for:
- Scopes the OAuth app on GitHub must be configured with.
- Request shape the mock GitHub server must accept in integration tests.
- Response fields the connector relies on (other fields are tolerated but unused).
- Recognised error responses and their mapping to `ConnectorRefreshError` / login-path failures.

Every request carries these headers (see research.md R8):
- `Accept: application/vnd.github+json`
- `X-GitHub-Api-Version: 2022-11-28`
- `User-Agent: netidm/<crate-version> (connector-github)`

Authorization header varies by call (see each section).

Base URL:
- For `OAuth2ClientGithubHost = https://github.com` (default): REST calls go to `https://api.github.com`; OAuth calls go to `https://github.com`.
- For GHE (`OAuth2ClientGithubHost = https://<gh-enterprise>`): REST calls go to `<gh-enterprise>/api/v3`; OAuth calls go to `<gh-enterprise>`.

---

## §1 — OAuth2 authorize redirect (user-agent, not a server-side call)

**Method / URL**: `GET <host>/login/oauth/authorize`
**Caller**: User's browser, redirected here by the netidm login page after clicking "Log in with GitHub".
**Required scopes**: `user:email` (userinfo + emails) AND `read:org` (org + team membership).
**Query parameters**:
- `client_id` — from the OAuth2Client entry.
- `redirect_uri` — the netidm callback URL.
- `scope=user:email read:org`.
- `state` — random CSRF token netidm generates and validates on the callback.
- `response_type=code`.

**Outcome**: User authenticates at GitHub, is redirected to netidm's callback URL with `?code=...&state=...`.

---

## §2 — Code exchange

**Method / URL**: `POST <host>/login/oauth/access_token`
**Caller**: `GitHubConnector::handle_callback` on the netidm side.
**Headers**:
- `Accept: application/json` (overrides GitHub's default urlencoded response).
- `Content-Type: application/x-www-form-urlencoded`.
- Authorization: none (client auth via form body).

**Request body** (urlencoded):
- `client_id`, `client_secret` — from the OAuth2Client entry.
- `code` — from the callback.
- `redirect_uri` — MUST match the one in §1.

**Response** (JSON, 200):
```json
{
  "access_token": "gho_...",
  "token_type": "bearer",
  "scope": "user:email,read:org",
  "refresh_token": "ghr_...",                              // optional
  "refresh_token_expires_in": 15897600,                    // optional, seconds
  "expires_in": 28800                                      // optional, seconds
}
```

The connector persists `access_token`, `refresh_token` (if present), and computes `access_token_expires_at` from `expires_in` (if present).

**Error responses** (all map to login failure with rendered error page; no Person touched):
- `200` with `{"error": "bad_verification_code", ...}` — user's `code` was invalid/expired. Error page: "Your GitHub sign-in expired. Please try again."
- `200` with `{"error": "incorrect_client_credentials", ...}` — the admin rotated the client_secret on GitHub but not in netidm. Error page: "GitHub connector misconfigured. Contact your administrator."
- Non-200 — network/upstream issue. Error page: "GitHub is temporarily unavailable. Please try again."

---

## §3 — Userinfo

**Method / URL**: `GET <api-base>/user`
**Authorization**: `Bearer <access_token>` from §2.
**Response** (JSON, 200): deserialised as `GithubUserProfile`. Only `id` (i64) and `login` (String) are used; `name` is preserved for JIT-provisioning display name.

**Error responses**:
- `401` — access token revoked. Maps to `ConnectorRefreshError::TokenRevoked` on refresh path; login-path error page: "Your GitHub authorisation was revoked."
- `403` + `X-RateLimit-Remaining: 0` — rate limited. Refresh: `UpstreamRejected(403)`. Login: error page: "GitHub is rate-limiting netidm. Please try again in a few minutes."
- `5xx` — upstream error. Refresh: `Network(...)`. Login: "GitHub is temporarily unavailable."

---

## §4 — Verified emails

**Method / URL**: `GET <api-base>/user/emails`
**Authorization**: `Bearer <access_token>`.
**Response** (JSON, 200): array of `GithubEmail` — the connector iterates looking for `verified: true` entries; prefers `primary: true` and applies `preferred_email_domain` (FR-007) where set.

**Error responses**: same as §3. A `403` specifically from this endpoint typically indicates the `user:email` scope was not granted — treat as a login failure with a dedicated error page: "GitHub didn't share your email with netidm. Please re-authorise."

---

## §5 — Org membership

**Method / URL**: `GET <api-base>/user/orgs?per_page=100`
**Authorization**: `Bearer <access_token>`.
**Pagination**: follow `Link: <...>; rel="next"` header; cap at 50 pages per FR-011.
**Response**: array of `GithubOrg`. Only `login` (String) is used — that's the org slug.

**Usage**: consulted for the `load_all_groups` feature (FR, `OAuth2ClientGithubLoadAllGroups`) — when true, each org the user is in produces an upstream-group name equal to the org slug; this is a fallback for users in orgs without any mapped teams.

---

## §6 — Team membership

**Method / URL**: `GET <api-base>/user/teams?per_page=100`
**Authorization**: `Bearer <access_token>`.
**Pagination**: follow `Link: <...>; rel="next"` header; cap at 50 pages per FR-011. On the 51st page a `warn!` log fires and the connector returns the teams it has collected.
**Response**: array of `GithubTeam`. Uses `slug`, `name`, and `organization.login`. The rendered upstream-group name depends on `OAuth2ClientGithubTeamNameField`:
- `slug` (default) → `<organization.login>:<slug>`
- `name` → `<organization.login>:<name>`
- `both` → BOTH strings are emitted, and each is independently matched against the group-mapping table.

**Error responses**: same as §3. Specifically for teams, a `403` with `{"message": "Resource not accessible by integration", ...}` indicates the `read:org` scope wasn't granted — login failure: "GitHub didn't share your team list with netidm. Please re-authorise."

---

## §7 — Token refresh (optional, when the OAuth app issues refresh tokens)

**Method / URL**: `POST <host>/login/oauth/access_token`
**Headers**: same as §2.
**Request body** (urlencoded):
- `client_id`, `client_secret`.
- `grant_type=refresh_token`.
- `refresh_token` — from the stored session state.

**Response**: same shape as §2. The connector replaces the stored `access_token` + `refresh_token` + `access_token_expires_at` with the new values.

**Error responses**:
- `200` with `{"error": "bad_refresh_token", ...}` or `{"error": "invalid_grant", ...}` → `ConnectorRefreshError::TokenRevoked`.
- Non-200 → `ConnectorRefreshError::Network(...)` or `UpstreamRejected(status)` per FR-012.

---

## Summary — call counts per operation

Per FR SC-006:

| Operation | Upper bound |
|---|---|
| Login | 1 code exchange (§2) + 1 GET /user (§3) + 1 GET /user/emails (§4) + 1 GET /user/orgs (§5) + 1 GET /user/teams (§6) + pagination on §5 and §6 |
| Refresh | At most 1 token refresh (§7) + 1 GET /user/orgs (§5) + 1 GET /user/teams (§6) + pagination |

Pagination is counted as "additional requests beyond the first page" — typical users hit 1 page of orgs and 1–2 pages of teams. The cap in FR-011 caps total team-pages at 50.
