# Data Model: Generic OIDC Upstream Connector

## Entity: OAuth2ClientProvider (extended)

The existing `OAuth2ClientProvider` struct in `server/lib/src/idm/oauth2_client.rs` gains two new optional fields.

### New Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuer` | `Option<Url>` | No | OIDC issuer URL. If set, this provider was configured via OIDC discovery. Used for provenance and display. |
| `jwks_uri` | `Option<Url>` | No | JWKS endpoint URL. If set, `id_token` JWTs are cryptographically verified against these keys. If absent, existing unverified decode behaviour applies (backward compatibility for GitHub/Google). |

### Existing Fields (unchanged)

| Field | Type | Description |
|-------|------|-------------|
| `name` | `String` | Provider name (spn) |
| `display_name` | `String` | Human-readable name for SSO button |
| `uuid` | `Uuid` | Entry UUID |
| `client_id` | `String` | OAuth2 client ID |
| `client_basic_secret` | `String` | OAuth2 client secret |
| `client_redirect_uri` | `Url` | Callback URL (derived from base URL) |
| `request_scopes` | `BTreeSet<String>` | Scopes to request (default: `openid profile email`) |
| `authorisation_endpoint` | `Url` | Provider's authorization endpoint |
| `token_endpoint` | `Url` | Provider's token endpoint |
| `userinfo_endpoint` | `Option<Url>` | Provider's userinfo endpoint (optional) |
| `jit_provisioning` | `bool` | Whether to auto-create accounts |
| `email_link_accounts` | `bool` | Whether to link by email |
| `logo_uri` | `Option<Url>` | Provider logo for SSO button |
| `claim_map` | `BTreeMap<Attribute, String>` | Custom claim name mappings |

---

## Schema Attributes (DL21)

### `Attribute::OAuth2Issuer`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff00000249` |
| Syntax | `SyntaxType::Url` |
| Multivalue | `false` |
| Schema class | `systemmay` on `EntryClass::OAuth2Client` |
| Description | OIDC issuer URL — the base URL used to discover this provider's endpoints. |

### `Attribute::OAuth2JwksUri`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff0000024a` |
| Syntax | `SyntaxType::Url` |
| Multivalue | `false` |
| Schema class | `systemmay` on `EntryClass::OAuth2Client` |
| Description | JWKS URI for verifying id_token signatures from this provider. |

---

## Transient: OidcDiscoveryDocument

Not stored. Fetched at provider creation time by the SDK client from `<issuer>/.well-known/openid-configuration`. Fields used:

| JSON field | Maps to entry attribute |
|------------|------------------------|
| `issuer` | `Attribute::OAuth2Issuer` |
| `authorization_endpoint` | `Attribute::OAuth2AuthorisationEndpoint` |
| `token_endpoint` | `Attribute::OAuth2TokenEndpoint` |
| `userinfo_endpoint` | `Attribute::OAuth2UserinfoEndpoint` (optional) |
| `jwks_uri` | `Attribute::OAuth2JwksUri` |

### Validation Rules

- `issuer` in the discovery document MUST match the issuer URL used to fetch it (OIDC spec requirement).
- `authorization_endpoint` and `token_endpoint` are REQUIRED in the discovery document; absent either → creation error.
- `jwks_uri` is REQUIRED for JWKS-based id_token verification; if absent, `jwks_uri` is not stored and unverified decode applies.

---

## Transient: JWKS Cache (in server/core)

Not persisted. Per-request in-memory state during the JWKS verification continuation.

| Field | Type | Description |
|-------|------|-------------|
| `keys` | `JwkKeySet` | Deserialized JWKS response from `jwks_uri` |
| Key rotation retry | — | If `kid` not found in first fetch, one retry is performed |

---

## Auth Continuation Messages (new)

### `AuthExternal::OAuth2JwksRequest` (new variant in `authentication.rs`)

Signals `server/core` to fetch JWKS and verify the id_token.

| Field | Type | Description |
|-------|------|-------------|
| `jwks_url` | `Url` | Provider's JWKS endpoint |
| `id_token` | `String` | Raw JWT string from token response |
| `access_token` | `String` | Bearer token for userinfo fallback if needed |

### `AuthCredential::OAuth2JwksTokenResponse` (new variant in `authentication.rs`)

Carries OIDC claims extracted from the verified id_token back to the handler.

| Field | Type | Description |
|-------|------|-------------|
| `claims_body` | `String` | JSON string of id_token claims, suitable for `claims_from_oidc_json` |

---

## Migration: DL21

Extends the DL20 `OAuth2Client` schema class to add the two new `systemmay` attributes.

### `SCHEMA_CLASS_OAUTH2_CLIENT_DL21`

Replaces `SCHEMA_CLASS_OAUTH2_CLIENT_DL20`. Extended `systemmay`:
```
OAuth2ClientLogoUri   (from DL20)
OAuth2Issuer          (new, DL21)
OAuth2JwksUri         (new, DL21)
```
