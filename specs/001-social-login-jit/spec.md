# Feature Specification: Social Login with JIT Provisioning

**Feature Branch**: `001-social-login-jit`
**Created**: 2026-04-16
**Status**: Draft
**Input**: User description: "Social Login with JIT Provisioning — Add GitHub and Google as social login providers to Netidm, with Just-In-Time account provisioning on first login."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - First-Time Social Login (Priority: P1)

A new user who has never logged into Netidm visits an application that delegates authentication to Netidm. They click "Sign in with GitHub" (or Google), are redirected to the provider, authenticate successfully, and are automatically given a Netidm account — without any prior admin setup for that individual. They are then logged in and redirected back to the application, all within a single login flow.

**Why this priority**: This is the core value proposition. Without automatic provisioning on first login, the feature has no value — admins would still need to pre-create accounts, which is the current broken experience.

**Independent Test**: Can be fully tested by configuring a Netidm OAuth2 provider with JIT enabled and logging in as a brand-new user — no prior account creation needed. Delivers a working end-to-end social login flow.

**Acceptance Scenarios**:

1. **Given** a Netidm instance with GitHub configured as a social login provider and JIT provisioning enabled, **When** a user with no existing Netidm account authenticates via GitHub for the first time, **Then** a new Netidm account is created automatically and the user is logged in.
2. **Given** a Netidm instance with JIT provisioning disabled, **When** a user with no existing account authenticates via a social provider, **Then** login is denied with a clear error message and no account is created.
3. **Given** a user who has already logged in via GitHub, **When** they authenticate via GitHub again, **Then** they are logged into their existing account (no duplicate account is created).

---

### User Story 2 - Admin Configures a Social Provider (Priority: P2)

A Netidm administrator wants to enable GitHub or Google as a login option. They use the Netidm CLI to register the provider (supplying client ID and secret), enable JIT provisioning, and optionally map provider claims to Netidm account fields. No code changes or restarts are required.

**Why this priority**: Without administrator tooling, the feature cannot be deployed. This story enables the feature to be turned on and configured for an organisation.

**Independent Test**: Can be tested by running CLI commands to create a GitHub/Google provider configuration, then verifying the provider appears in Netidm and the login UI shows the provider option.

**Acceptance Scenarios**:

1. **Given** a Netidm administrator with appropriate permissions, **When** they run `netidm system oauth2-client create-github <name> <client_id> <client_secret>`, **Then** a GitHub provider is registered with correct default endpoints and required scopes.
2. **Given** a registered social provider, **When** the admin runs `netidm system oauth2-client enable-jit-provisioning <name>`, **Then** JIT provisioning is enabled for that provider and new users can be auto-provisioned on first login.
3. **Given** a registered social provider, **When** the admin maps a claim (`set-claim-map <name> displayname name`), **Then** the user's display name on their Netidm account is populated from the provider's `name` claim on first login.

---

### User Story 3 - New Account Review Before Activation (Priority: P3)

A new user authenticating via a social provider for the first time is shown a confirmation page before their Netidm account is created. The page displays the proposed username, display name, and email derived from the provider's claims. The user can edit the proposed username before confirming. Only after confirmation is the account created.

**Why this priority**: Provides user control and reduces unwanted account names. However, the core provisioning flow (User Story 1) can work with auto-derived names, so this is an enhancement.

**Independent Test**: Can be tested by triggering a first-time social login and verifying the confirmation page appears with pre-filled fields, that the username is editable, and that submitting creates the account with the chosen username.

**Acceptance Scenarios**:

1. **Given** a first-time social login where JIT provisioning is enabled, **When** the provider returns user claims, **Then** a confirmation page is shown with the proposed username, display name, and email before account creation.
2. **Given** the confirmation page is displayed, **When** the user edits the proposed username and confirms, **Then** the account is created with the user-chosen username.
3. **Given** the confirmation page is displayed, **When** the proposed username is already taken, **Then** an alternate username is suggested (e.g. with numeric suffix) and the user is prompted to confirm or change it.

---

### Edge Cases

- What happens when the provider returns no email address (e.g. GitHub with private email settings)?
- What happens when the derived username collides with an existing Netidm account name?
- What happens when the provider's user ID (`sub`) is already linked to a different Netidm account?
- What happens when the user cancels or abandons the confirmation page mid-flow?
- What happens when the access token or id_token from the provider is invalid or expired?
- What happens when the provider is removed/disabled while a user session is in progress?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST allow administrators to register GitHub as a social login provider by supplying a client ID, client secret, and a provider name; default endpoints and required scopes MUST be pre-filled.
- **FR-002**: The system MUST allow administrators to register Google as a social login provider by supplying a client ID, client secret, and a provider name; default endpoints and required scopes MUST be pre-filled.
- **FR-003**: Administrators MUST be able to enable or disable JIT provisioning per social provider independently.
- **FR-004**: Administrators MUST be able to map provider-supplied identity claims (e.g. name, email, username) to Netidm account fields on a per-provider basis.
- **FR-005**: When a user authenticates via a social provider for the first time and JIT provisioning is enabled, the system MUST automatically create a Netidm account for that user without administrator intervention.
- **FR-006**: The system MUST extract identity claims from the provider: for OIDC-compliant providers (Google) via the signed identity token; for non-OIDC providers (GitHub) via the provider's user-info endpoint using the granted access token.
- **FR-007**: Each social provider MUST be associated with a unique identifier per user (a stable subject identifier from the provider), and subsequent logins MUST resolve to the same Netidm account using this identifier.
- **FR-008**: When JIT provisioning is disabled for a provider and no existing linked account is found, the system MUST deny login and display a clear, user-friendly error message.
- **FR-009**: When a first-time social login triggers account creation, the system MUST present the user with a confirmation page showing the proposed account details (username, display name, email) before the account is created.
- **FR-010**: The confirmation page MUST allow the user to edit the proposed username before confirming account creation.
- **FR-011**: If the derived username conflicts with an existing account, the system MUST automatically suggest an alternative username (e.g. appending a numeric suffix).
- **FR-012**: After successful account creation and confirmation, the system MUST log the user in and redirect them to their original destination without requiring a second authentication.
- **FR-013**: The system MUST prevent duplicate account creation if a user authenticates again with the same provider subject identifier.
- **FR-014**: All administrator configuration of social providers MUST be available via the Netidm CLI.

### Key Entities *(include if feature involves data)*

- **Social Provider Configuration**: Represents a configured external identity provider. Attributes: name, provider type (GitHub/Google), client ID, client secret (stored securely), authorization endpoint, token endpoint, userinfo endpoint, required scopes, JIT provisioning enabled flag, claim mappings.
- **Provider Claim Mapping**: Maps a provider claim name (e.g. `name`) to a Netidm account attribute (e.g. display name). Belongs to a Social Provider Configuration.
- **Linked Provider Identity**: Links a Netidm account to an external provider. Attributes: provider reference, stable provider subject identifier, credential UUID. Ensures a user can be looked up by provider + subject on subsequent logins.
- **Netidm Account**: The automatically-provisioned user account. Attributes derived from provider claims: username (iname), display name, email. Created only once per unique provider subject identifier.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A brand-new user can complete social login and have a Netidm account created within the same login flow, with no prior administrator action for that specific user.
- **SC-002**: An administrator can fully configure a GitHub or Google social provider (registration, JIT enablement, claim mapping) using only CLI commands, completing the setup in under 5 minutes.
- **SC-003**: A returning user who previously logged in via a social provider is recognised and logged into their existing account on subsequent logins — no duplicate accounts are created across 100% of repeat login attempts.
- **SC-004**: When JIT provisioning is disabled, 100% of first-time social login attempts are denied with an informative error; no accounts are created.
- **SC-005**: The username confirmation page is shown to 100% of first-time social login users before account creation, giving them the opportunity to review and adjust their proposed username.
- **SC-006**: Username conflicts are automatically resolved with a suggested alternative in 100% of cases — no first-time login fails solely due to a name collision.

## Assumptions

- JIT provisioning is opt-in per provider: it must be explicitly enabled by an administrator; new providers default to JIT disabled.
- Only GitHub and Google are supported as social login providers in v1; the underlying mechanism is extensible but additional providers are out of scope.
- A single Netidm account can only be linked to one external provider identity at a time in v1 (no multi-provider linking or email-based account merging).
- Profile data from the provider (display name, email) is used only at account creation time; subsequent changes at the provider are not synced back to Netidm.
- Email is treated as informational at provisioning time; a provider returning no email does not block account creation, but the email field on the Netidm account will be empty.
- The administrator performing provider configuration holds the appropriate Netidm administrative role.
- Netidm's existing session and redirect handling is reused after account creation; no new session infrastructure is required.
- Deprovisioning (account removal when a provider account is deleted or unlinked) is out of scope for v1.
