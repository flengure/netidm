# Contract: OIDC Authentication Flow

## Login Flow (OIDC provider with id_token + jwks_uri)

```
Browser                server/core              server/lib                External OIDC Provider
  |                        |                        |                              |
  |-- GET /ui/sso/:name -->|                        |                              |
  |                        |-- handle_auth(InitOAuth2Provider) -->                 |
  |                        |<-- External(OAuth2AuthorisationRequest) --            |
  |<-- 302 to provider ----|                        |                              |
  |                                                 |                              |
  |-- GET /ui/login/oauth2_landing?code=X&state=Y ->|                              |
  |                        |-- handle_auth(OAuth2AuthorisationResponse) -->        |
  |                        |<-- External(OAuth2AccessTokenRequest) --              |
  |                        |-- POST <token_endpoint>?code=X... --------------------->
  |                        |<-- { access_token, id_token } ----------------------|
  |                        |-- handle_auth(OAuth2AccessTokenResponse) -->         |
  |                        |                        |                              |
  |                        |  [id_token present, jwks_uri set]                    |
  |                        |<-- External(OAuth2JwksRequest { jwks_url, id_token }) |
  |                        |-- GET <jwks_uri> ---------------------------------------->
  |                        |<-- JwkKeySet ----------------------------------------|
  |                        |   [verify id_token signature + expiry]               |
  |                        |-- handle_auth(OAuth2JwksTokenResponse { claims }) --> |
  |                        |<-- Success(token) --                                  |
  |<-- 302 /ui/ + cookie --|                        |                              |
```

## Login Flow (OIDC provider without id_token — fallback to userinfo)

Same as above until token exchange. When `id_token` is absent but `userinfo_endpoint` is set:
```
  |                        |<-- External(OAuth2UserinfoRequest { userinfo_url, access_token })
  |                        |-- GET <userinfo_url> + Bearer <access_token> ----------->
  |                        |<-- { sub, email, name, ... } -------------------------|
  |                        |-- handle_auth(OAuth2UserinfoResponse { body }) -->    |
  |                        |<-- Success(token) --                                  |
```

## Error Paths

| Condition | Handler response | User sees |
|-----------|-----------------|-----------|
| JWKS fetch fails | auth loop returns `OperationError` | "Authentication failed" |
| `kid` not in JWKS (first attempt) | retry with fresh JWKS fetch | (transparent) |
| `kid` not in JWKS (second attempt) | `CredState::Denied` | "Authentication failed" |
| Invalid signature | `CredState::Denied` | "Authentication failed" |
| Token expired | `CredState::Denied` | "Authentication failed" |
| Missing `sub` claim | `CredState::Denied` | "Authentication failed" |

## JWKS Key Selection Logic

1. Parse `id_token` → extract `kid` from header (may be absent)
2. Fetch `JwkKeySet` from `jwks_uri`
3. If `kid` present: find matching key by `kid` field
4. If `kid` absent: use first key with matching algorithm (`alg`)
5. If no matching key found: re-fetch JWKS (key rotation scenario), retry once
6. Build verifier based on algorithm: `ES256` → `JwsEs256Verifier`, `RS256` → `JwsRs256Verifier`
7. Algorithms other than ES256/RS256 → `CredState::Denied` with logged warning

## Claims Extraction (`claims_from_oidc_json`)

Input: JSON body of the verified id_token claims.

| JSON field | Mapped to | Notes |
|------------|-----------|-------|
| `sub` | `ExternalUserClaims::sub` | Required; absent → `None` from function → `CredState::Denied` |
| `email` (or claim_map override) | `ExternalUserClaims::email` | Optional |
| `email_verified` | `ExternalUserClaims::email_verified` | Optional bool |
| `name` (or claim_map override) | `ExternalUserClaims::display_name` | Optional |
| `preferred_username` (or claim_map Name override) | `ExternalUserClaims::username_hint` | Optional; falls back to local-part of email |
