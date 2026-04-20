# Research: Generic OIDC Upstream Connector

## Decision 1: Where OIDC Discovery Happens

**Decision**: Discovery (`<issuer>/.well-known/openid-configuration`) runs in `libs/client/src/oauth.rs` (the SDK client layer), not in `server/lib` or `server/core`.

**Rationale**: `server/lib` has no `reqwest` dependency and should stay that way — it is pure in-process IDM logic. `libs/client` is an HTTP client; it already makes outbound HTTP calls and is the right place to pre-resolve provider endpoints before creating the entry. This means:
- The client calls `idm_oauth2_client_create_oidc(name, issuer, client_id, client_secret)`
- Internally fetches `<issuer>/.well-known/openid-configuration`
- Extracts `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `issuer`
- Builds an `Entry` with all fields populated and POSTs to `/v1/oauth2/_client`

**Alternatives considered**:
- Discovery in `server/core` HTTP handler: possible, but adds latency to the admin API path and requires error-handling for provider unavailability at server startup
- Discovery in `server/lib` write transaction: requires adding `reqwest` to `server/lib`, which would break the clean separation of storage from networking

## Decision 2: JWKS Token Verification Architecture

**Decision**: JWKS fetch and `id_token` cryptographic verification happen in `server/core/src/https/views/login.rs`, using the existing `AuthExternal` continuation pattern. A new `AuthExternal::OAuth2JwksRequest` variant signals `server/core` to fetch JWKS and verify the token. Claims are passed back via a new `AuthCredential::OAuth2JwksTokenResponse { claims_body: String }`.

**Rationale**: This follows the identical pattern already in use for `OAuth2UserinfoRequest`. The `server/lib` auth session handler signals what external resource it needs; `server/core` fetches it and continues the loop. This keeps `server/lib` network-free and `compact_jwt` usage isolated to where the verification keys are fetched.

**Verified API** (`compact_jwt` 0.5.6, already in workspace):
```rust
// Verification flow:
let unverified = OidcUnverified::from_str(id_token)?;     // parse
let kid = unverified.kid();                                // extract key ID for lookup
let alg = unverified.alg();                               // ES256 or RS256
// find matching Jwk in fetched JwkKeySet
let verified = match alg {
    JwaAlg::ES256 => JwsEs256Verifier::try_from(&jwk)?.verify(&unverified)?,
    JwaAlg::RS256 => JwsRs256Verifier::try_from(&jwk)?.verify(&unverified)?,
    _ => return Err(...),
};
let token = verified.verify_exp(now_secs)?;               // check expiry → OidcToken
```
This pattern is already used in `server/lib/src/idm/oauth2.rs` tests (`validate_id_token`).

**Alternatives considered**:
- Add `reqwest` to `server/lib` and do JWKS fetch in the handler: breaks architectural isolation, reqwest is async and handler code is synchronous
- Cache JWKS in `IdmServer` state at startup: requires background refresh logic and adds complexity; the continuation pattern is simpler and already proven

## Decision 3: id_token Claim Extraction After Verification

**Decision**: Add `claims_from_oidc_json` to `handler_oauth2_client.rs`. This is distinct from the existing `claims_from_userinfo_json` (which uses `id` for sub, specific to GitHub) and `claims_from_id_token` (which decodes without verification). The new function reads standard OIDC claims: `sub`, `email`, `email_verified`, `name`/`preferred_username`.

**Rationale**: GitHub's userinfo uses `id` (numeric) as the subject; OIDC standard uses `sub` (string). Reusing `claims_from_userinfo_json` would require adding a `sub` fallback which changes existing GitHub behaviour. A dedicated function is cleaner and safer.

**Alternatives considered**:
- Modify `claims_from_userinfo_json` to try `id` then `sub`: changes existing behaviour for GitHub providers, risk of regression
- Pass `OidcToken` struct directly across the auth boundary: would require `compact_jwt` dependency in `server/lib` for a type that is currently only used in `server/lib`'s own OAuth2 server implementation

## Decision 4: New Schema Attributes (DL21)

**Decision**: Introduce two new URL-type schema attributes in a DL21 migration:
- `Attribute::OAuth2Issuer` — UUID `00000000-0000-0000-0000-ffff00000249` — stores the OIDC issuer URL for provenance and re-discovery
- `Attribute::OAuth2JwksUri` — UUID `00000000-0000-0000-0000-ffff0000024a` — stores the discovered JWKS endpoint for token verification

Both are `systemmay` (optional, single-value) on `EntryClass::OAuth2Client`.

**Rationale**: A dedicated DL migration is required per the constitution. Storing `jwks_uri` separately avoids re-fetching the discovery document on every server startup. Storing `issuer` gives operators visibility into which OIDC provider is connected and enables future re-discovery (e.g., provider endpoint rotation).

**Next available UUID**: `ffff00000249` (last used: `ffff00000248` for `OAuth2ClientLogoUri` in DL20).

**Alternatives considered**:
- Reuse `OAuth2AuthorisationEndpoint` with a sentinel for the issuer: conflates two different concepts, breaks error messages
- Derive `jwks_uri` from `issuer` at runtime: requires an outbound HTTP call at startup for every provider, fragile if provider is temporarily unreachable

## Decision 5: Backward Compatibility

**Decision**: Existing providers (GitHub, Google) with no `issuer` field continue to work exactly as before. The `jwks_uri` field, if absent, causes the id_token to be decoded without verification (existing behaviour). If set, verification is performed. No breaking changes.

**Rationale**: Operators with existing GitHub/Google providers must not be required to re-create them. The feature is additive — OIDC providers use the new attributes, existing providers do not.

## Decision 6: No New External Crate Dependencies

**Decision**: Zero new crate dependencies. `compact_jwt` (already in workspace) provides `OidcUnverified`, `JwkKeySet`, `Jwk`, `JwsEs256Verifier`, `JwsRs256Verifier`. `reqwest` is already in `server/core` and `libs/client`. `serde_json` is already present.

**Rationale**: Constitution principle III (keep it simple). Adding a crate for something already available inflates the dependency tree unnecessarily.
