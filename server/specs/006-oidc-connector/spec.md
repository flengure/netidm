# Feature Specification: Generic OIDC Upstream Connector

**Feature Branch**: `006-oidc-connector`
**Created**: 2026-04-18
**Status**: Draft
**Input**: User description: "Generic OIDC upstream connector — any OIDC-compliant issuer (Okta, Auth0, Keycloak) as upstream IdP via discovery URL, extending OAuth2ClientProvider"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Connect Any OIDC Provider via Discovery URL (Priority: P1)

As a system administrator, I want to add any OIDC-compliant identity provider (Okta, Auth0, Keycloak, or any self-hosted OIDC server) as a federated login source by supplying only the issuer URL, so that users of that provider can authenticate into netidm without manual endpoint configuration.

**Why this priority**: This is the core value of the feature — replacing the need to know each provider's individual endpoints. Admins point at a discovery URL and the system auto-populates the rest.

**Independent Test**: Can be fully tested by creating an OIDC provider entry with only an `issuer` URL, verifying the system fetches `.well-known/openid-configuration`, stores the discovered endpoints, and a test user can complete an OAuth2 login flow end-to-end.

**Acceptance Scenarios**:

1. **Given** an admin provides a valid `issuer` URL (e.g., `https://dev-xxx.okta.com`), **When** the provider is created, **Then** the system fetches `<issuer>/.well-known/openid-configuration`, extracts `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, and `jwks_uri`, and stores them.
2. **Given** the issuer URL returns a valid OIDC discovery document, **When** a user initiates login with this provider, **Then** they are redirected to the discovered `authorization_endpoint` with correct OAuth2 parameters.
3. **Given** the issuer URL is unreachable or returns an invalid document, **When** the admin attempts to create the provider, **Then** the system returns a clear error describing what went wrong.
4. **Given** a provider created via discovery, **When** the discovery document changes (e.g., key rotation), **Then** the system re-fetches JWKS when token validation fails, rather than caching stale keys forever.

---

### User Story 2 - Validate ID Tokens via JWKS (Priority: P2)

As a system administrator, I want tokens returned from OIDC providers to be validated cryptographically against the provider's published JWKS, so that forged or tampered tokens are rejected.

**Why this priority**: Currently the system uses only the userinfo endpoint to fetch identity. For OIDC providers that return `id_token` in the token response, JWKS-based validation is the standard verification path and is required for providers that don't expose a userinfo endpoint.

**Independent Test**: Can be tested by configuring a provider that returns an `id_token`, verifying the system fetches the JWKS URI, validates the token signature, and rejects a token with an invalid signature.

**Acceptance Scenarios**:

1. **Given** a token exchange returns an `id_token`, **When** the system processes the callback, **Then** it fetches the JWKS from the discovered `jwks_uri` and verifies the token's signature.
2. **Given** a valid `id_token` signature, **When** claims are extracted, **Then** the system uses `id_token` claims (sub, email, name, groups) rather than falling back to userinfo.
3. **Given** an `id_token` with an invalid or unknown signing key, **When** validation is attempted, **Then** the system rejects the token with an authentication error.
4. **Given** the provider rotates its signing keys, **When** a token signed with the new key arrives, **Then** the system re-fetches JWKS and retries validation once before failing.

---

### User Story 3 - Manage OIDC Providers via CLI (Priority: P3)

As a system administrator, I want CLI commands to create, list, update, and delete OIDC provider entries, so that I can manage federated identity sources without editing config files.

**Why this priority**: The existing OAuth2 client management has CLI support; the OIDC connector needs equivalent commands. This is a usability concern rather than a functional blocker — the system works without it, but operational management requires it.

**Independent Test**: Can be tested by running `netidm system oidc-client create --name my-okta --issuer https://... --client-id xxx --client-secret yyy` and verifying the provider appears in `list` output and is usable for login.

**Acceptance Scenarios**:

1. **Given** valid issuer, client ID, and client secret, **When** `netidm system oidc-client create` is run, **Then** the provider is created and discovery is performed at creation time.
2. **Given** an existing OIDC provider, **When** `netidm system oidc-client list` is run, **Then** all configured OIDC providers are shown with their issuer URL and name.
3. **Given** an existing OIDC provider, **When** `netidm system oidc-client delete --name <name>` is run, **Then** the provider is removed and login attempts via that provider fail gracefully.

---

### Edge Cases

- What happens when the discovery document is missing required fields (`authorization_endpoint`, `token_endpoint`)?
- How does the system handle an issuer URL that returns HTTP 200 but is not a valid OIDC discovery document?
- What if the `jwks_uri` is unreachable at token validation time?
- How are providers with identical issuer URLs but different client IDs handled (should be allowed)?
- What if the `id_token` is absent from the token response — should the system fall back to the userinfo endpoint?
- How does claim mapping interact with OIDC discovery — should discovered claim names be mappable?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST accept an `issuer` URL as the primary configuration input for an OIDC provider and auto-discover all required endpoints via `<issuer>/.well-known/openid-configuration`.
- **FR-002**: System MUST store the discovered `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, and `jwks_uri` from the OIDC discovery document.
- **FR-003**: System MUST validate `id_token` JWTs returned during the token exchange against the provider's JWKS when an `id_token` is present.
- **FR-004**: System MUST fall back to the userinfo endpoint for identity claims when no `id_token` is present in the token response.
- **FR-005**: System MUST re-fetch JWKS on key-not-found errors to support provider key rotation without requiring administrator intervention.
- **FR-006**: System MUST reject token responses with invalid signatures or expired claims and return a clear authentication failure.
- **FR-007**: System MUST support the existing claim mapping capability (`OAuth2ClaimMapName`, `OAuth2ClaimMapDisplayname`, `OAuth2ClaimMapEmail`) for OIDC-discovered providers.
- **FR-008**: System MUST support JIT provisioning and email-based account linking for OIDC-discovered providers, consistent with existing OAuth2 client behaviour.
- **FR-009**: System MUST expose the OIDC provider in the SSO login button list (same as existing OAuth2 providers).
- **FR-010**: Administrators MUST be able to create, list, and delete OIDC provider entries via the CLI.

### Key Entities

- **OidcProvider** (extends `OAuth2ClientProvider`): An OIDC upstream IdP. Key attributes: `issuer` (URL), `client_id`, `client_secret`, `authorization_endpoint` (discovered), `token_endpoint` (discovered), `userinfo_endpoint` (discovered, optional), `jwks_uri` (discovered), plus inherited claim maps, JIT flag, email-link flag.
- **OidcDiscoveryDocument**: Transient struct representing the parsed `.well-known/openid-configuration` response; not stored directly — its fields are persisted onto the provider entry.
- **JwksCache**: Transient in-memory structure mapping `kid` → public key; fetched from `jwks_uri` and refreshed on unknown key ID.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An administrator can federate a new OIDC provider from zero to working login in under 5 minutes, providing only the issuer URL, client ID, and client secret.
- **SC-002**: A user can log in via an OIDC-connected provider with the same end-to-end experience as the existing GitHub/Google connectors.
- **SC-003**: Tokens with invalid signatures are rejected 100% of the time; valid tokens from any standard OIDC issuer are accepted without per-provider customisation.
- **SC-004**: Provider key rotation (new `kid` in JWKS) is handled transparently without administrator action within one authentication attempt.
- **SC-005**: All existing OAuth2 provider tests continue to pass after the generic OIDC connector is introduced (no regressions).

## Assumptions

- The existing `OAuth2ClientProvider` struct and its authentication session handler are the correct extension points — the OIDC connector adds an optional `issuer` field; if set, discovery auto-populates the endpoint fields.
- Providers configured with an explicit `issuer` field are treated as OIDC providers; providers without it retain the existing explicit-endpoint behaviour (backward compatibility).
- JWKS keys are cached per-provider in memory for the lifetime of the server process; a full process restart also re-fetches JWKS.
- Scopes default to `openid profile email` when not explicitly specified by the administrator.
- PKCE is used for all OIDC flows (same as existing OAuth2 clients).
- The `redirect_uri` follows the existing pattern (`<base_url>/oauth2/callback/<provider_name>`).
- No new external crates are required — JWT validation reuses the existing `compact_jwt` or equivalent already present in the codebase.
- Mobile/native app OIDC flows (device flow, etc.) are out of scope for this feature.
