# Quickstart: OIDC Connector Test Scenarios

## Integration Test Setup

Tests run against a real in-process netidmd instance via `server/testkit`. No mocks.

The external OIDC provider is simulated by a test helper that:
1. Generates a real ES256 or RS256 key pair (using `compact_jwt` key generation)
2. Serves a mock OIDC discovery document at a local endpoint
3. Signs real `id_token` JWTs with the generated key
4. Exposes the public key as a JWKS endpoint

---

## Scenario 1: Provider Created via Discovery

**Setup**: Mock OIDC server with valid discovery document.

**Action**:
```rust
let result = client.idm_oauth2_client_create_oidc(
    "test-oidc",
    "https://mock-oidc.test",
    "client-id",
    "client-secret",
).await;
```

**Verify**:
- `result` is `Ok(())`
- Provider entry exists with `name = "test-oidc"`
- `OAuth2AuthorisationEndpoint` matches discovery document's `authorization_endpoint`
- `OAuth2TokenEndpoint` matches discovery document's `token_endpoint`
- `OAuth2Issuer` matches `"https://mock-oidc.test"`
- `OAuth2JwksUri` matches discovery document's `jwks_uri`

---

## Scenario 2: Full Login Flow — ES256 id_token

**Setup**: Provider created in Scenario 1. Test user JIT-provisioned.

**Action**: Simulate complete auth flow:
1. `InitOAuth2Provider` → get auth URL
2. Skip actual redirect (test); synthesise `code` + `state`
3. `OAuth2AuthorisationResponse { code, state }` → token exchange
4. Mock token endpoint returns `{ access_token, id_token: <ES256 JWT signed by test key> }`
5. `OAuth2AccessTokenResponse` → expect `AuthExternal::OAuth2JwksRequest`
6. Fetch JWKS from mock endpoint → `JwkKeySet`
7. Verify id_token → `OidcToken`
8. `OAuth2JwksTokenResponse { claims_body }` → expect `AuthState::Success` (after JIT provision confirm)

**Verify**:
- `AuthState::Success` returned
- JIT-provisioned account exists with correct email and display_name
- `OAuth2AccountUniqueUserId` matches `sub` from id_token

---

## Scenario 3: Invalid Signature Rejected

**Setup**: Provider from Scenario 1. Different key pair generates the id_token.

**Action**: Complete auth flow with id_token signed by a different key.

**Verify**:
- JWKS verification returns error
- `AuthState::Denied` returned
- No account provisioned

---

## Scenario 4: Key Rotation — Unknown kid, Retry Succeeds

**Setup**: Provider configured with JWKS endpoint. First JWKS fetch returns old keys. After refresh, new key is present.

**Action**: Complete auth flow with id_token signed by the new key (not in first JWKS response).

**Verify**:
- First verification attempt fails (kid not found)
- JWKS is re-fetched
- Second attempt succeeds
- `AuthState::Success` returned

---

## Scenario 5: Expired Token Rejected

**Setup**: Provider from Scenario 1. id_token with `exp` in the past.

**Verify**: `AuthState::Denied` returned.

---

## Scenario 6: Existing GitHub Provider Unaffected

**Setup**: Create GitHub provider (no `issuer`, no `jwks_uri`).

**Action**: Complete GitHub auth flow with `id_token` absent (GitHub doesn't return one).

**Verify**:
- Fallback to userinfo endpoint used (existing behaviour)
- No regression from DL21 migration
- Provider loads correctly without `issuer`/`jwks_uri` fields

---

## Scenario 7: Discovery Failure Cases

**Action A**: `create_oidc` with issuer URL that returns 404.
**Verify**: `ClientError` with message about unreachable discovery document.

**Action B**: `create_oidc` where discovery doc missing `authorization_endpoint`.
**Verify**: `ClientError` with specific missing-field message.

**Action C**: `create_oidc` where discovery doc `issuer` field doesn't match provided issuer.
**Verify**: `ClientError` with issuer mismatch message.

---

## Scenario 8: CLI Round-Trip

```sh
# Create
netidm system oauth2-client create-oidc \
  --name my-okta --issuer https://mock.test \
  --client-id id --client-secret sec

# List (verify appears)
netidm system oauth2-client list

# Delete
netidm system oauth2-client delete my-okta

# List again (verify gone)
netidm system oauth2-client list
```
