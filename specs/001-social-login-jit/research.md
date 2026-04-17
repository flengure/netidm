# Research: Social Login with JIT Provisioning

**Branch**: `001-social-login-jit` | **Date**: 2026-04-16

---

## Decision 1: Claim Extraction Path Per Provider

**Decision**: Two distinct extraction paths — never conflated.

- **Google** (OIDC-compliant): The token endpoint response includes an `id_token` field that is a signed JWT. Decode and verify the JWT signature against Google's published JWKS. Extract standard OIDC claims: `sub`, `email`, `email_verified`, `name`.
- **GitHub** (non-OIDC): No `id_token` in the token response. Call `https://api.github.com/user` with the `Authorization: Bearer <access_token>` header. Parse the JSON response for `id` (integer → string = sub), `login` (username), `name` (display name), `email` (may be null).

**Rationale**: GitHub does not implement OIDC. Attempting to parse a JWT that isn't there would fail silently. The two paths are cleanly separated in `validate_access_token_response()` by whether `id_token` is present in the token response.

**Alternatives considered**: A single unified userinfo-endpoint path for both providers (call userinfo for Google too). Rejected because Google's signed `id_token` provides stronger security guarantees than a plain HTTP call.

---

## Decision 2: GitHub — No Email Address

**Decision**: Two-step email fetch with graceful fallback.

1. After fetching `https://api.github.com/user`, if `email` is null, make a second request to `https://api.github.com/user/emails` (requires `user:email` scope already in required scopes).
2. From the returned list, select the entry where `primary: true` and `verified: true`.
3. If still no verified primary email exists, proceed with account creation — email field on the Netidm account is left empty. Account creation is NOT blocked by missing email.

**Rationale**: Many legitimate GitHub users keep their email private. Blocking provisioning on missing email would exclude them. Email is informational at creation time per spec assumption.

**Alternatives considered**: Block provisioning if no email found. Rejected — disproportionate, violates the Netidm "humans first" principle.

---

## Decision 3: Username Collision Handling

**Decision**: Numeric suffix up to 100 attempts, then UUID fragment.

1. Derive candidate username from provider claims: GitHub → `login` field; Google → local part of `email` (before `@`), normalized to valid iname characters (lowercase, alphanumeric + hyphens, max 64 chars).
2. Check for collision with existing `name` attribute.
3. If collision: append `_2`, `_3`, … `_100`.
4. If all 100 suffixed candidates are taken (extreme edge case): use first 8 chars of the provider `sub` value as suffix (e.g. `alice_a1b2c3d4`).
5. The confirmation page (US3) always shows the proposed username before account creation, so the user can override the derived name.

**Rationale**: Purely numeric suffixes are conventional and predictable. The confirmation page is the primary UX safety valve — auto-resolution just ensures the confirmation page always loads with a valid proposed name.

**Alternatives considered**: Use a UUID-based name by default and force the user to choose. Rejected — poor UX, users should see a recognizable name.

---

## Decision 4: `sub` Already Linked to a Different Account

**Decision**: Hard deny with a clear error message. No silent re-linking.

If `find_account_by_oauth2_provider_and_user_id(provider_uuid, sub)` returns an account, but that account is NOT the one the current session would map to (impossible in initial flow — this is a guard for future re-link scenarios), return `OperationError::AccessDenied`. Surface to user as: "This external identity is already linked to another account. Please contact your administrator."

For the initial JIT flow: this guard is also the duplicate-prevention mechanism. If a user with the same provider+sub already exists, they are logged in to the existing account — no new account is created.

**Rationale**: Silent re-linking would allow an attacker who gains temporary access to a provider account to hijack a Netidm account. Hard deny + admin contact is the safe default.

**Alternatives considered**: Allow re-linking via an explicit admin operation. Agreed as the correct future path but out of scope for v1.

---

## Decision 5: Abandoned Confirmation Page

**Decision**: Short-lived signed cookie (`COOKIE_OAUTH2_PROVISION_REQ`) with 10-minute TTL.

- Claims from the provider are serialized, signed (same mechanism as `COOKIE_OAUTH2_REQ`), and stored in a cookie named `COOKIE_OAUTH2_PROVISION_REQ` when redirecting to `/ui/login/provision`.
- If the user abandons (closes browser, navigates away, lets cookie expire): the cookie expires, the provider token expires independently on the provider side. No Netidm state is left behind since the account was never created.
- If the user returns within 10 minutes: the cookie is still valid, the confirmation page re-renders with the same proposed details (idempotent).
- If the provider access token has expired when the user submits confirmation: the submission still succeeds — the access token is not re-validated at confirmation time. The claims were already extracted and stored in the cookie.

**Rationale**: The 10-minute window matches typical user interaction time. No server-side session state needed for the confirmation page — cookie-only approach keeps the provisioning flow stateless.

**Alternatives considered**: Store claims server-side in a Redis/in-memory store. Rejected — Netidm has no such store, and the cookie approach already exists for `COOKIE_OAUTH2_REQ`.

---

## Decision 6: Invalid / Expired Provider Token

**Decision**: Surface as `CredState::Denied` with a provider-specific message. User must restart login.

- Token validation errors from the provider (HTTP 401, malformed JWT, signature mismatch) during `validate_access_token_response()` → return `CredState::Denied("Provider token validation failed. Please try again.")`.
- Userinfo endpoint network errors (timeout, 5xx) → return `CredState::Denied("Unable to retrieve your identity from the provider. Please try again.")`.
- In both cases, the existing auth session is terminated. The user sees the login page again with the error.

**Rationale**: Partial auth states are dangerous. A clean deny-and-restart is simpler and more secure than retry logic inside the auth session.

**Alternatives considered**: Retry the userinfo endpoint once before denying. Rejected — adds latency to the already time-sensitive auth path and masks provider-side problems.

---

## Decision 7: Provider Removed / Disabled Mid-Session

**Decision**: Existing sessions survive; new logins fail cleanly.

- Sessions already issued (UserAuthToken + bearer cookie) are independent of the provider configuration. They are not revoked when a provider is removed.
- New login attempts via a removed provider: `reload_oauth2_client_providers()` will have removed it from `IdmServer.oauth2_client_providers`. The auth session initialization at line 1219 of `authsession/mod.rs` checks `asd.oauth2_client_provider` — if the provider is gone, no `CredHandler::OAuth2Trust` is pushed, and the auth flow returns `AuthState::Denied`.
- Existing sessions expire naturally per their configured lifetime.

**Rationale**: Revoking all active sessions when a provider is disabled would be a high-impact destructive action (logging out all social-login users). The provider removal should be a deliberate admin operation; if immediate revocation is needed, the admin can use the existing session revocation tooling.

**Alternatives considered**: Revoke all sessions linked to the removed provider on provider deletion. Agreed as a future enhancement but out of scope for v1.

---

## Decision 8: New `CredState` Variant vs. Extending `Success`

**Decision**: Add `CredState::ProvisioningRequired { provider_uuid: Uuid, claims: ExternalUserClaims }` as a new variant.

The current `CredState` enum has:
```
Success { auth_type, cred_id, ext_session_metadata }
Continue(...)
External(...)
Denied(...)
```
A `ProvisioningRequired` state is semantically distinct from `Success` (no account exists yet) and from `Denied` (provisioning is allowed, just pending). A new variant is the correct Rust approach.

**Rationale**: Stuffing provisioning state into `Success` with a sentinel `cred_id` would be confusing and error-prone. A new variant makes the type system enforce the invariant that a `ProvisioningRequired` state never issues a UAT.

---

## Decision 9: Schema Migration Level

**Decision**: Create DL15 under `server/lib/src/migration_data/dl15/`.

Current highest level is DL14 (`server/lib/src/migration_data/dl14/`). New attributes added to `OAuth2Client` schema class (`systemmay`):

| Attribute constant | DB name | Type | Purpose |
|---|---|---|---|
| `ATTR_OAUTH2_USERINFO_ENDPOINT` | `oauth2_userinfo_endpoint` | Url | Userinfo endpoint for non-OIDC providers |
| `ATTR_OAUTH2_JIT_PROVISIONING` | `oauth2_jit_provisioning` | Boolean | Enable JIT provisioning for this provider |
| `ATTR_OAUTH2_CLAIM_MAP_DISPLAYNAME` | `oauth2_claim_map_displayname` | Utf8 | Provider claim name → Netidm display name |
| `ATTR_OAUTH2_CLAIM_MAP_EMAIL` | `oauth2_claim_map_email` | Utf8 | Provider claim name → Netidm email |
| `ATTR_OAUTH2_CLAIM_MAP_NAME` | `oauth2_claim_map_name` | Utf8 | Provider claim name → Netidm iname (username) |

**Rationale**: All new attributes are optional (`systemmay`) on the existing `OAuth2Client` class. No migration of existing data is required — existing providers simply lack these attributes and therefore have JIT disabled by default.

---

## Decision 10: Account Lookup Implementation

**Decision**: Use `internal_search_impersonate_resolve_entry_ref_uuid` (or equivalent internal search) with a compound filter.

```
filter_all!(f_and!([
    f_eq(Attribute::OAuth2AccountProvider, PartialValue::Refer(provider_uuid)),
    f_eq(Attribute::OAuth2AccountUniqueUserId, PartialValue::Utf8(sub.to_string())),
]))
```

This runs as an internal (server-privileged) search, bypassing access controls — appropriate because this is a server-initiated lookup during authentication, not a user-initiated query.

**Rationale**: The two attributes together form a compound unique identifier. Neither alone is sufficient (the same `sub` string could exist for different providers; the same provider could have many users).
