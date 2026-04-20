# Data Model: SSO Login Choice UX

**Branch**: `005-sso-login-choice`
**Phase**: 1 — Design

## Display Entities (in-memory only, no schema changes for P1/P2)

### SsoProviderInfo

A read-only view of an OAuth2 client provider for use in the login page template. Constructed from `OAuth2ClientProvider` at login page render time. No persistence.

```rust
pub struct SsoProviderInfo {
    /// Internal name used in the URL: GET /ui/sso/<name>
    pub name: String,
    /// Human-readable button label. Defaults to `name` if no DisplayName is set.
    pub display_name: String,
    /// Optional branding image URI (P3 — requires DL20 schema attribute).
    pub logo_uri: Option<Url>,
}
```

**Derivation from `OAuth2ClientProvider`**:
- `name` ← `OAuth2ClientProvider.name`
- `display_name` ← `OAuth2ClientProvider.display_name` (new field, loaded from `Attribute::DisplayName`, fallback to `name`)
- `logo_uri` ← `OAuth2ClientProvider.logo_uri` (P3, new field, loaded from `Attribute::OAuth2ClientLogoUri`)

---

### OAuth2ClientProvider — Extended Fields

Two new fields added to the existing `OAuth2ClientProvider` struct in `server/lib/src/idm/oauth2_client.rs`:

| Field | Type | Source Attribute | Required |
|-------|------|-----------------|----------|
| `display_name` | `String` | `Attribute::DisplayName` (fallback: `name`) | Always present |
| `logo_uri` | `Option<Url>` | `Attribute::OAuth2ClientLogoUri` (P3) | Optional |

No database migration required for `display_name` — `Attribute::DisplayName` already exists in the schema and can be set on any entry.

---

### LoginDisplayCtx — Extended Field

One new field added to `LoginDisplayCtx` in `server/core/src/https/views/login.rs`:

```rust
pub struct LoginDisplayCtx {
    pub domain_info: DomainInfoRead,
    pub reauth: Option<Reauth>,
    pub oauth2: Option<Oauth2Ctx>,      // existing — used for "access X" banner
    pub error: Option<LoginError>,
    // NEW ↓
    pub available_sso_providers: Vec<SsoProviderInfo>,
}
```

**Population**: `view_index_get` calls `state.qe_r_ref.list_sso_providers()` and sets this field. All other login handlers that construct `LoginDisplayCtx` without a provider list set it to `Vec::new()`.

---

## Auth Step Extension

```rust
// proto/src/v1/auth.rs
pub enum AuthStep {
    Init { username: String, issue: AuthIssueSession, privileged: bool },
    Begin(AuthMech),
    Cred(AuthCredential),
    // NEW ↓
    InitOAuth2Provider {
        provider_name: String,
        issue: AuthIssueSession,
    },
}
```

**Auth session state for provider-initiated flow**: On `InitOAuth2Provider`, the auth server creates an auth session with no pre-bound user account (`account: None`). The `CredHandlerOAuth2Client` resolves the account from OAuth2 identity claims during callback processing using `find_and_link_account_by_email`.

---

## Schema Changes (P3 only)

### New Attribute: `oauth2_client_logo_uri`

| Property | Value |
|---------|-------|
| Name | `oauth2_client_logo_uri` |
| Type | `Url` (single-value) |
| UUID | `00000000-0000-0000-0000-ffff00000248` |
| Description | Optional logo image URI for the OAuth2 client provider login button |
| Applied to | `EntryClass::OAuth2Client` (via `systemmay`) |
| Migration | DL20 |

---

## Cookie Model

### `COOKIE_AUTH_METHOD_PREF` (new, P2)

| Property | Value |
|---------|-------|
| Name | `auth_method_pref` |
| Type | unsigned session cookie |
| Values | `"internal"` or `"sso"` |
| Written | On `AuthState::Success` in `view_login_step` — set to `"internal"` if auth used password/TOTP/passkey; set to `"sso"` if auth completed via OAuth2 provider |
| Read | In `view_index_get` — if `"internal"`, `available_sso_providers` is ignored for initial render (form shown expanded) |
| Lifetime | Session (no `Max-Age`) — cleared on browser close |

**Existing related cookies** (unchanged):
- `COOKIE_USERNAME` — remember-me username
- `COOKIE_NEXT_REDIRECT` — post-login redirect path
- `COOKIE_BEARER_TOKEN` — auth session bearer token
