# HTTP Route Contracts: SSO Login Choice UX

**Branch**: `005-sso-login-choice`
**Phase**: 1 — Design

## New Routes

### GET /ui/sso/:provider_name

Initiates a provider-first OAuth2 authentication flow. No session or username required.

**Path parameters**:
- `:provider_name` — the internal `name` of the OAuth2 client provider (e.g. `github`, `google`)

**Query parameters**:
- `next` (optional) — relative redirect path to follow after successful authentication. Must start with `/`. Stored in `COOKIE_NEXT_REDIRECT` if valid.

**Success response** (`302 Found`):
- `Location`: provider's OAuth2 authorization URL with `client_id`, `redirect_uri`, `scope`, `state`, and any PKCE parameters
- `Set-Cookie: auth_session_id=<signed_session_id>; HttpOnly; SameSite=Lax`
- `Set-Cookie: kanidm-next=<next_path>; HttpOnly; SameSite=Lax` (only if `next` provided and valid)

**Error responses**:
- `404 Not Found` — provider name not found in configured providers
- `500 Internal Server Error` — auth session creation failed

**Router registration**: `unguarded_csp_router` in `server/core/src/https/views/mod.rs` — no HTMX guard, no auth guard.

**Handler**: `view_sso_initiate_get` in `server/core/src/https/views/login.rs`

---

## Modified Routes

### GET /ui/login (view_index_get)

**Change**: Populates `LoginDisplayCtx.available_sso_providers` from `state.qe_r_ref.list_sso_providers()`.

**Template change**: If `available_sso_providers` is non-empty:
1. Renders SSO buttons section above the username form
2. If `COOKIE_AUTH_METHOD_PREF == "internal"`, username form is visible immediately
3. Otherwise, username form has `d-none` CSS class (hidden), revealed by JS toggle

**Existing behaviour preserved**: When `available_sso_providers` is empty, page renders identically to current (only username form, no SSO section, no divider).

---

## Existing Routes (Unchanged)

### POST /ui/login/begin

No change. The username form submission still works identically.

### GET /ui/login/oauth2_landing

No change to the existing signature. Handles the OAuth2 callback for both the existing username-first flow AND the new provider-initiated flow (session ID differentiates them internally).

---

## IDM Method Contracts

### `IdmServerProxyReadTransaction::list_sso_providers() -> Vec<SsoProviderInfo>`

Returns a sorted list of configured OAuth2 client providers as `SsoProviderInfo` structs. Reads from the in-memory `oauth2_client_providers` cache — no database query. Sort order: alphabetical by `display_name`.

### `IdmServerAuthTransaction::auth` — `AuthStep::InitOAuth2Provider`

**Input**: `AuthStep::InitOAuth2Provider { provider_name, issue }`

**Processing**:
1. Look up provider by `name` in `oauth2_client_providers`
2. If not found: return `Err(OperationError::NoMatchingEntries)`
3. Create auth session with no pre-bound user (`account_id: None`)
4. Delegate to `CredHandlerOAuth2Client::init_provider_first` to construct the authorization URL
5. Return `AuthResult { sessionid, state: AuthState::External(AuthExternal::OAuth2AuthorisationRequest { ... }) }`

**On callback** (`AuthStep::Cred(OAuth2AuthorisationResponse)`):
- Same as existing flow, but account resolution uses identity claims from the provider response
- Calls `find_and_link_account_by_email` (or sub-claim lookup) to resolve the user account
- If no matching account: returns `AuthState::ProvisioningRequired` (triggers the existing JIT provisioning UI)
