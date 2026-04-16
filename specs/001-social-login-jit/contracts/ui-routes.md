# UI Route Contracts: Social Login with JIT Provisioning

**Branch**: `001-social-login-jit` | **Date**: 2026-04-16

These routes extend `server/core/src/https/views/login.rs`.

---

## Existing Route (modified behaviour)

### `GET /ui/login/oauth2_landing`

**Current**: Always dispatches to `credential_step()` and issues UAT on success.

**Modified**: When `credential_step()` returns `AuthState::ProvisioningRequired`:
1. Serialize `ExternalUserClaims` + `provider_uuid` into `COOKIE_OAUTH2_PROVISION_REQ` (signed, HTTP-only, SameSite=Strict, 10-minute TTL).
2. Return HTTP 302 redirect to `GET /ui/login/provision`.

All other existing behaviour unchanged.

---

## New Routes

### `GET /ui/login/provision`

**Purpose**: Show the account confirmation page for first-time social login.

**Handler**: `view_login_provision_get()`

**Request**:
```
GET /ui/login/provision
Cookie: COOKIE_OAUTH2_PROVISION_REQ=<signed-claims>
        COOKIE_AUTH_SESSION_ID=<session>
```

**Behaviour**:
1. Read and verify `COOKIE_OAUTH2_PROVISION_REQ`. If missing or invalid → redirect to `/ui/login` with error.
2. Deserialize `ExternalUserClaims` from cookie.
3. Derive proposed username using claim map + collision-handling logic.
4. Render confirmation page (Askama template) with:
   - Proposed username (editable text field, pre-filled)
   - Display name (read-only, from claims)
   - Email (read-only, from claims, may be empty)
   - Provider name (read-only, e.g. "GitHub")
   - Submit button: "Create my account"
   - Cancel link: returns to `/ui/login`

**Response**: `200 OK` — HTML confirmation page

**Error cases**:
- Cookie missing/expired → `302 /ui/login` + flash: "Your session has expired. Please sign in again."
- Cookie signature invalid → `302 /ui/login` + flash: "Invalid session. Please sign in again."

---

### `POST /ui/login/provision`

**Purpose**: Accept the confirmed (possibly edited) username and create the account.

**Handler**: `view_login_provision_post()`

**Request**:
```
POST /ui/login/provision
Cookie: COOKIE_OAUTH2_PROVISION_REQ=<signed-claims>
        COOKIE_AUTH_SESSION_ID=<session>
Content-Type: application/x-www-form-urlencoded

Body:
  username=<user-chosen-or-confirmed-name>
```

**Behaviour**:
1. Read and verify `COOKIE_OAUTH2_PROVISION_REQ`. If invalid → redirect to `/ui/login` with error.
2. Validate the submitted `username`:
   - Non-empty
   - Valid Kanidm iname format (lowercase alphanumeric + hyphens, 2–64 chars)
   - Not already taken (check via account lookup)
3. If username taken → re-render confirmation page with error: "That username is already taken. Please choose another."
4. Call `jit_provision_oauth2_account(provider_uuid, claims, username)`.
5. On success: clear `COOKIE_OAUTH2_PROVISION_REQ`, re-enter auth flow with new account UUID → call `issue_uat()` → set `COOKIE_BEARER_TOKEN` → redirect to original application destination.
6. On provisioning error (e.g. `OperationError::AccessDenied`) → redirect to `/ui/login` with appropriate flash message.

**Success response**: `302 <original-app-redirect-uri>`

**Error cases**:
- Invalid username format → re-render with inline validation error
- Username collision → re-render with suggestion
- Cookie expired mid-submission → `302 /ui/login` + flash: "Session expired."
- Provisioning error → `302 /ui/login` + flash: "Account creation failed. Please contact your administrator."

---

## Cookie Summary

| Cookie | Set by | Cleared by | TTL | Purpose |
|---|---|---|---|---|
| `COOKIE_OAUTH2_PROVISION_REQ` | `GET /ui/login/oauth2_landing` (on ProvisioningRequired) | `POST /ui/login/provision` (on success) | 10 min | Carries provider claims across confirmation page |
| `COOKIE_AUTH_SESSION_ID` | Login flow (existing) | Logout (existing) | Session | Auth session ID |
| `COOKIE_BEARER_TOKEN` | `issue_uat()` (existing) | Logout (existing) | Per-token | Issued after account creation + auth |
