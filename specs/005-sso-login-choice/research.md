# Research: SSO Login Choice UX

**Branch**: `005-sso-login-choice`
**Phase**: 0 — Technical Research
**Generated**: 2026-04-18

## Findings

---

### Finding 1: Existing OAuth2 Auth Session Architecture

**Decision**: The SSO-first button flow requires a new `AuthStep::InitOAuth2Provider` variant, not a parallel code path.

**Rationale**: The current auth flow requires a username upfront (`AuthStep::Init { username }`), which creates an auth session tied to a specific user account. The OAuth2 callback (`view_login_oauth2_landing`) retrieves that session by ID (`COOKIE_AUTH_SESSION_ID`) and validates against the stored user context. A provider-first flow must create an auth session tied to a provider (not a user), then resolve the user from the OAuth2 identity claims on callback.

**Implementation path**:
1. Add `AuthStep::InitOAuth2Provider { provider_name: String }` to `proto/src/v1/auth.rs`
2. Add handling in `IdmServerAuthTransaction::auth` in `server/lib/src/idm/server.rs` — looks up the provider by name, creates an auth session with no pre-bound user, returns `AuthState::External(AuthExternal::OAuth2AuthorisationRequest { ... })`
3. In `CredHandlerOAuth2Client`, when finalising a provider-initiated session, resolve the user account from the identity token/userinfo response using `find_and_link_account_by_email` (already implemented for JIT provisioning, `server/lib/src/idm/server.rs:2394`)
4. New view handler `view_sso_initiate_get(provider_name: Path<String>)` in `server/core/src/https/views/login.rs` — calls `handle_auth(None, AuthStep::InitOAuth2Provider { provider_name })`, then processes `AuthState::External` via the existing `view_login_step`

**Alternatives considered**:
- *Build redirect URL without an auth session (stateless)*: Rejected — creates a state mismatch vulnerability (OAuth2 `state` parameter validates the callback belongs to our request; without a server-side session the state is unforgeable only via PKCE, which adds more new code than the auth session approach)
- *Pre-fill username and submit form*: Rejected — requires the user's netidm username to be known, which is the problem we're solving

**Files**:
- `proto/src/v1/auth.rs` — add `InitOAuth2Provider` to `AuthStep`
- `server/lib/src/idm/server.rs` — handle new `AuthStep` variant
- `server/lib/src/idm/authsession/mod.rs` — provider-initiated session creation
- `server/lib/src/idm/authsession/handler_oauth2_client.rs` — resolve user on callback
- `server/core/src/https/views/login.rs` — `view_sso_initiate_get`
- `server/core/src/https/views/mod.rs` — register `GET /ui/sso/:provider_name`

---

### Finding 2: Provider List Exposure

**Decision**: Add `pub(crate) fn list_sso_providers() -> Vec<SsoProviderInfo>` to `IdmServerProxyReadTransaction`.

**Rationale**: `IdmServer.oauth2_client_providers: HashMap<Uuid, OAuth2ClientProvider>` is populated by `reload_oauth2_client_providers()` and cached in memory. A simple read accessor on the read transaction returns the display-relevant subset needed for the login page. No database query is needed at render time — providers are already in the cache.

**`SsoProviderInfo` struct** (new, in `server/core/src/https/views/login.rs`):
```rust
pub struct SsoProviderInfo {
    pub name: String,           // internal name — used in URL /ui/sso/<name>
    pub display_name: String,   // human-readable label for the button
    pub logo_uri: Option<Url>,  // optional branding logo (P3)
}
```

**Files**:
- `server/lib/src/idm/server.rs` — add `list_sso_providers()` to read transaction trait and impl
- `server/core/src/https/views/login.rs` — define `SsoProviderInfo`, populate in `view_index_get`

---

### Finding 3: Provider Display Name

**Decision**: Read from `Attribute::DisplayName` on the OAuth2Client entry, with fallback to `name`. No new schema attribute needed.

**Rationale**: `Attribute::DisplayName` already exists in the schema and is in the `systemmay` list for all entries. Provider entries can already have a `DisplayName` value. `reload_oauth2_client_providers()` does not currently read it — adding one optional `get_ava_single_utf8(Attribute::DisplayName)` read is a zero-migration change.

**FR-002 compliance**: "if no display name is set, the provider's internal name is used as a fallback" — handled by `Option::unwrap_or(name.clone())`.

**Files**:
- `server/lib/src/idm/oauth2_client.rs` — add `display_name: String` field to `OAuth2ClientProvider`, load from `Attribute::DisplayName` with `name` fallback

---

### Finding 4: Provider Logo URI

**Decision**: New `Attribute::OAuth2ClientLogoUri` (URL type, optional, single-value) on `EntryClass::OAuth2Client`. Requires DL20 schema migration.

**Rationale**: No logo URI attribute exists in the schema. Reusing an existing attribute (e.g., a generic image attribute) is inappropriate because logo URIs are semantically distinct from profile images. A new URL-typed attribute is the correct and minimal change. This is scoped to P3 (polish); the P1 and P2 flows work without it.

**Migration scope**: Schema attribute only — no class change needed since `systemmay` on `OAuth2Client` is already open to extension, and the attribute is optional.

**Files** (P3 scope):
- `proto/src/attribute.rs` — add `OAuth2ClientLogoUri`
- `server/lib/src/migration_data/dl20/schema.rs` — `SCHEMA_ATTR_OAUTH2_CLIENT_LOGO_URI_DL20`
- `server/lib/src/migration_data/dl20/mod.rs` — new DL migration module
- `server/lib/src/constants/` — new UUID constants
- `server/lib/src/idm/oauth2_client.rs` — add `logo_uri: Option<Url>` field

---

### Finding 5: Auth Method Preference (P2)

**Decision**: Short-lived unsigned cookie `COOKIE_AUTH_METHOD_PREF` (value: `"internal"` or `"sso"`) stored on successful login, read in `view_index_get` to determine initial form state.

**Rationale**: Spec §Assumptions: "The 'Use internal authentication' toggle state is persisted client-side (short-lived browser cookie or local storage) — no server-side state is needed." A cookie is preferable to localStorage because it works without JavaScript and is readable server-side (avoids JS-required progressive enhancement complexity).

**Cookie lifetime**: Session cookie (no `Max-Age` / `Expires`) — cleared on browser close, which is the appropriate "short-lived" lifetime for a UI preference.

**Existing cookie infrastructure**: `server/core/src/https/views/cookies.rs` has `make_unsigned` and `destroy` helpers — both are directly applicable.

**Files**:
- `server/core/src/https/views/cookies.rs` — add `COOKIE_AUTH_METHOD_PREF` constant
- `server/core/src/https/views/login.rs` — write cookie on `AuthState::Success`, read cookie in `view_index_get`

---

### Finding 6: Template Architecture

**Decision**: Modify `server/core/templates/login.html` to show conditional SSO section above the existing form. No new template files needed.

**Rationale**: The existing template uses Askama (`(% if %)` / `(% for %)`) with access to `display_ctx`. Adding `available_sso_providers: Vec<SsoProviderInfo>` to `LoginDisplayCtx` (rendered in `LoginView`) lets the template conditionally render the SSO section using a `(% for %)` loop — zero new template infrastructure required.

**Layout**:
```
(% if !display_ctx.available_sso_providers.is_empty() %)
  [SSO buttons for each provider]
  [divider]
  ["Use internal authentication" toggle button]
(% endif %)
[existing username form — conditionally hidden via CSS class when SSO section shown]
```

**Auth method preference integration**: If `COOKIE_AUTH_METHOD_PREF == "internal"` (or no SSO providers), the username form is shown without the hidden class. If `"sso"` or unset (and providers exist), the username form gets a `d-none` class initially, revealed by clicking the toggle.

**JavaScript requirement**: The inline-expand toggle (FR-006) requires minimal JavaScript to toggle the `d-none` class — approximately 3 lines. No framework required.

**Files**:
- `server/core/templates/login.html` — restructure with SSO section
- `server/core/templates/login_base.html` — no changes required

---

### Finding 7: `?next=` Parameter Preservation (FR-007)

**Decision**: For the SSO initiation path, store the `next` parameter in `COOKIE_NEXT_REDIRECT` (same as the existing flow in `view_index_get`). The existing `AuthState::Success` handling already reads and honours this cookie.

**Rationale**: `view_index_get` already writes `COOKIE_NEXT_REDIRECT` when `?next=<path>` is present. The `view_sso_initiate_get` handler receives `next` from its query string and should write the same cookie before redirecting. The existing post-auth redirect machinery then handles it transparently.

**No changes needed to**: `view_login_step` success branch, redirect URL construction.

---

### Finding 8: Constitution Check

**Principle I (Ethics)**: No personal data leakage — provider names displayed on login page are configured by admins, not user data. ✅

**Principle III (Correct & Simple)**:
- Tests required for: provider listing, SSO initiation flow, preference cookie read/write, template rendering with 0/1/N providers
- Integration tests must use real `netidmd` via `server/testkit`

**Principle IV (Clippy)**:
- `Vec<SsoProviderInfo>` in `LoginDisplayCtx` must not trigger unused-field warnings
- `AuthStep::InitOAuth2Provider` variant must be matched exhaustively or with `_` in all existing match arms

**Principle V (Security)**:
- `view_sso_initiate_get` must validate that `provider_name` matches a known provider before initiating (prevents auth session creation for unknown names)
- `?next=` must use existing relative-path validation (already in `view_index_get`)
- OAuth2 `state` parameter generation must remain in the existing crypto path (not replaced)
