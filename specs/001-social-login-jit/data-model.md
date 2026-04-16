# Data Model: Social Login with JIT Provisioning

**Branch**: `001-social-login-jit` | **Date**: 2026-04-16

---

## Existing Entities (Extended)

### OAuth2ClientProvider (extended)

**Location**: `server/lib/src/idm/oauth2_client.rs`

Existing fields (unchanged):
```rust
name: String
uuid: Uuid
client_id: String
client_basic_secret: String
client_redirect_uri: Url
request_scopes: BTreeSet<String>
authorisation_endpoint: Url
token_endpoint: Url
```

New fields added:
```rust
userinfo_endpoint: Option<Url>        // For non-OIDC providers (GitHub)
jit_provisioning: bool                // Default: false
claim_map: HashMap<KanidmAttr, String> // Maps local attr → provider claim name
```

**DB Attributes (DL15 — new, all systemmay on OAuth2Client class)**:

| Rust constant | DB name | Syntax | Notes |
|---|---|---|---|
| `ATTR_OAUTH2_USERINFO_ENDPOINT` | `oauth2_userinfo_endpoint` | Url | GitHub: `https://api.github.com/user` |
| `ATTR_OAUTH2_JIT_PROVISIONING` | `oauth2_jit_provisioning` | Boolean | Absent = false |
| `ATTR_OAUTH2_CLAIM_MAP_NAME` | `oauth2_claim_map_name` | Utf8String | e.g. `"login"` for GitHub |
| `ATTR_OAUTH2_CLAIM_MAP_DISPLAYNAME` | `oauth2_claim_map_displayname` | Utf8String | e.g. `"name"` |
| `ATTR_OAUTH2_CLAIM_MAP_EMAIL` | `oauth2_claim_map_email` | Utf8String | e.g. `"email"` |

---

### CredHandlerOAuth2Client (extended)

**Location**: `server/lib/src/idm/authsession/handler_oauth2_client.rs`

Existing fields (unchanged):
```rust
provider_id: Uuid
provider_name: String
user_id: String
user_cred_id: Uuid
request_scopes: BTreeSet<String>
client_id: String
client_basic_secret: String
client_redirect_url: Url
authorisation_endpoint: Url
token_endpoint: Url
pkce_secret: PkceS256Secret
csrf_state: String
```

New fields added:
```rust
userinfo_endpoint: Option<Url>
jit_provisioning: bool
claim_map: HashMap<KanidmAttr, String>
```

---

## New Entities

### ExternalUserClaims

**Location**: `server/lib/src/idm/authsession/handler_oauth2_client.rs` (new struct)

```rust
pub struct ExternalUserClaims {
    pub sub: String,                        // Stable provider user ID (required)
    pub email: Option<String>,              // May be None (e.g. GitHub private email)
    pub email_verified: Option<bool>,       // OIDC providers only
    pub display_name: Option<String>,       // From `name` claim
    pub username_hint: Option<String>,      // From `login` (GitHub) or email local-part (Google)
}
```

**Validation rules**:
- `sub` MUST be non-empty. If empty or missing, return `CredState::Denied`.
- All other fields are optional. Missing fields do not block provisioning.
- `sub` combined with `provider_uuid` MUST be globally unique (enforced by DB lookup before provisioning).

---

### CredState::ProvisioningRequired (new variant)

**Location**: `server/lib/src/idm/authsession/mod.rs` (new variant on existing enum)

```rust
enum CredState {
    Success { auth_type, cred_id, ext_session_metadata },
    Continue(Box<NonEmpty<AuthAllowed>>),
    External(AuthExternal),
    Denied(&'static str),
    // NEW:
    ProvisioningRequired {
        provider_uuid: Uuid,
        claims: ExternalUserClaims,
    },
}
```

**State transitions**:
- `ProvisioningRequired` → (after successful `jit_provision_oauth2_account()`) → re-enter auth as existing account → `Success`
- `ProvisioningRequired` → (if provider has `jit_provisioning: false`) → `Denied`

---

### AuthState::ProvisioningRequired (new variant)

**Location**: `server/lib/src/idm/authsession/mod.rs` (new variant on external-facing enum)

```rust
// Existing external-facing AuthState (inferred from codebase context)
pub enum AuthState {
    Success(UserAuthToken),
    Continue(Vec<AuthAllowed>),
    Denied(String),
    // NEW:
    ProvisioningRequired {
        provider_uuid: Uuid,
        claims: ExternalUserClaims,
    },
}
```

---

### OAuth2ProvisionCookie

**Location**: `server/core/src/https/views/login.rs` (new cookie, serialized as signed JSON)

Cookie name: `COOKIE_OAUTH2_PROVISION_REQ`

```rust
// Serialized into the signed cookie value
struct OAuth2ProvisionCookie {
    provider_uuid: Uuid,
    claims: ExternalUserClaims,
    expires_at: i64,          // Unix timestamp, 10 minutes from creation
}
```

**Properties**:
- Signed with server's existing cookie signing key (same as `COOKIE_OAUTH2_REQ`)
- HTTP-only, SameSite=Strict, Secure
- TTL: 10 minutes
- Cleared after successful account creation or on login restart

---

## Entity Relationships

```
OAuth2ClientProvider (1) ──────────────── (0..*) OAuth2AccountCredential
    │                                              │
    │ provider_uuid                                │ provider + user_id
    ▼                                              ▼
ExternalUserClaims ──── JIT path ────► Kanidm Account Entry
                                        (classes: Object, Account, Person, OAuth2Account)
                                        attrs: name, displayName, mail (optional)
                                               oauth2AccountProvider
                                               oauth2AccountUniqueUserId
                                               oauth2AccountCredentialUuid
```

---

## State Transition: First-Time Social Login

```
OAuth2 callback received
        │
        ▼
validate_access_token_response()
        │
        ├─ Extract claims (Google: id_token JWT / GitHub: userinfo API call)
        │
        ├─ claims.sub empty? → CredState::Denied
        │
        ▼
find_account_by_oauth2_provider_and_user_id(provider_uuid, sub)
        │
        ├─ Account found → CredState::Success (normal login)
        │
        └─ Account not found
                │
                ├─ jit_provisioning == false → CredState::Denied
                │
                └─ jit_provisioning == true → CredState::ProvisioningRequired { provider_uuid, claims }
                        │
                        ▼
              AuthState::ProvisioningRequired
                        │
                        ▼
              Store in COOKIE_OAUTH2_PROVISION_REQ
              Redirect to GET /ui/login/provision
                        │
                        ▼
              User reviews + edits username → POST /ui/login/provision
                        │
                        ▼
              jit_provision_oauth2_account(provider_uuid, claims, desired_name)
                        │
                        ├─ Name collision → suggest alternate → re-render
                        │
                        └─ Success → new account UUID
                                │
                                ▼
                        Re-enter auth with new account UUID → issue_uat() → redirect
```

---

## Accounts Created by JIT Provisioning

Entry classes: `Object`, `Account`, `Person`, `OAuth2Account`

| Attribute | Source | Required |
|---|---|---|
| `name` (iname) | Derived from claims + collision handling | Yes |
| `displayName` | `ExternalUserClaims.display_name` or fallback to `name` | Yes |
| `mail` | `ExternalUserClaims.email` | No |
| `oauth2AccountProvider` | `provider_uuid` | Yes |
| `oauth2AccountUniqueUserId` | `ExternalUserClaims.sub` | Yes |
| `oauth2AccountCredentialUuid` | `Uuid::new_v4()` | Yes |

**Uniqueness invariant**: `(oauth2AccountProvider, oauth2AccountUniqueUserId)` pair MUST be unique across all accounts. Enforced by lookup before creation.
