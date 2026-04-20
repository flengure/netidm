# Feature Specification: OAuth2 Email-Based Account Linking

**Feature Branch**: `003-oauth2-email-linking`
**Created**: 2026-04-17
**Status**: Draft

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Admin Enables Email Linking on a Provider (Priority: P1)

An administrator configures an OAuth2 provider (e.g. Google) and enables `oauth2_email_link_accounts` on it. From that point on, social logins via that provider will attempt email-based account linking. A separate global setting `oauth2_email_link_accounts` on the domain object can enable it for all providers at once, with per-provider settings overriding the global default.

**Why this priority**: Without this, email linking is either always-on (unsafe for providers the admin doesn't trust) or always-off. The admin must be able to choose which providers are trusted for email-based linking.

**Independent Test**: Can be fully tested by toggling the setting on/off on a provider and confirming linking behaviour changes accordingly, without affecting other providers.

**Acceptance Scenarios**:

1. **Given** `oauth2_email_link_accounts = false` globally and `oauth2_email_link_accounts = true` on the Google provider, **When** a user logs in via Google with a matching verified email, **Then** linking occurs.
2. **Given** `oauth2_email_link_accounts = true` globally and `oauth2_email_link_accounts = false` on the GitHub provider, **When** a user logs in via GitHub, **Then** no email linking occurs for that provider.
3. **Given** `oauth2_email_link_accounts = true` globally and no per-provider override, **When** a user logs in via any provider, **Then** email linking is attempted for all of them.

---

### User Story 2 - Existing User Links via Social Login (Priority: P1)

An administrator has pre-provisioned a local account for Alice (`alice@company.com`) with a password. Alice later tries to sign in using "Login with Google." Her Google account's verified email matches her local account's mail attribute. The system silently links her Google identity to her existing account and logs her in — no duplicate account is created.

**Why this priority**: This is the core feature. Without it, every pre-provisioned user who tries social login gets a duplicate orphaned account, breaking the identity model.

**Independent Test**: Can be fully tested by creating a local account with a known email, then completing a GitHub/Google OAuth2 flow with a matching verified email, and confirming only one account exists in the directory afterwards.

**Acceptance Scenarios**:

1. **Given** a local Person account exists with `mail = alice@example.com`, **When** Alice completes Google OAuth2 login with verified email `alice@example.com`, **Then** she is logged in as the existing account and the OAuth2 identity is permanently linked to it.
2. **Given** the same local account already linked to Google, **When** Alice logs in with Google again, **Then** the existing `(provider, sub)` lookup succeeds and she logs in normally without re-triggering the email match.
3. **Given** a local Person account exists with `mail = alice@example.com`, **When** Alice completes GitHub OAuth2 login with verified primary email `alice@example.com`, **Then** she is logged in as the existing account and the link is established.

---

### User Story 2 - Unverified Email Does Not Auto-Link (Priority: P1)

A user logs in via a provider that returns an unverified email. The system must not auto-link to any existing local account, falling through to normal JIT provisioning (creating a new account) to prevent account takeover.

**Why this priority**: Security requirement — auto-linking on unverified emails would allow an attacker to claim ownership of any account whose email they know.

**Independent Test**: Can be tested by simulating a provider response with `email_verified: false` and a matching local email, confirming no link is made and JIT proceeds normally.

**Acceptance Scenarios**:

1. **Given** a local account with `mail = victim@example.com`, **When** an OAuth2 login arrives with email `victim@example.com` but `email_verified = false`, **Then** no linking occurs and JIT provisioning runs instead.
2. **Given** a GitHub login where the primary email is not publicly visible (returns null), **When** no verified email is available, **Then** JIT provisioning proceeds without attempting email-match linking.

---

### User Story 4 - No Local Match Falls Through to JIT (Priority: P2)

A new user with no pre-existing local account logs in via Google or GitHub. No local account matches their email. The system falls through to normal JIT provisioning behaviour — creating a new account — unchanged from existing behaviour.

**Why this priority**: Preserves existing JIT provisioning functionality; email linking is additive and must not break it.

**Independent Test**: Can be tested by completing a social login with an email that has no matching local account, confirming a new account is created normally.

**Acceptance Scenarios**:

1. **Given** no local account exists with the provider's verified email, **When** a user completes social login, **Then** JIT provisioning creates a new account as before.
2. **Given** JIT provisioning is disabled on the OAuth2 client, **When** no local account matches the email, **Then** login fails with the same error as without this feature.

---

### Edge Cases

- What happens when multiple local accounts share the same email? The system must not link and should fall through to JIT (or fail gracefully), not pick arbitrarily.
- What happens when the local account found by email already has a different OAuth2 provider linked? The system must not overwrite the existing link.
- What happens when the local account found by email is locked, expired, or disabled? Linking must not bypass account state checks — the login should fail as it would for any disabled account.
- What happens when the provider returns an email but the local account's mail attribute is a secondary (non-primary) address? Matching should use the primary mail attribute only.
- What happens when two providers return the same verified email for the same user? The first successful link wins; subsequent providers cannot re-link.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: A global domain-level setting `oauth2_email_link_accounts` (boolean, default: off) MUST control whether email-based linking is attempted for all OAuth2 providers.
- **FR-002**: Each OAuth2 provider MUST support a per-provider `oauth2_email_link_accounts` (boolean) setting that overrides the global default when set.
- **FR-003**: Email linking MUST only be attempted when the effective setting (per-provider if set, otherwise global) is enabled for that provider.
- **FR-004**: System MUST search for an existing local Person account by verified email before attempting JIT provisioning, when linking is enabled.
- **FR-005**: System MUST only attempt email-based linking when the provider confirms the email is verified (`email_verified = true` for OIDC; primary email from GitHub userinfo is treated as verified).
- **FR-006**: System MUST permanently link the OAuth2 identity to the matched local account on first successful email match.
- **FR-007**: System MUST log in the user as the existing account (not create a new one) when a verified email match is found and linking succeeds.
- **FR-008**: System MUST fall through to normal JIT provisioning behaviour when no local account matches the verified email.
- **FR-009**: System MUST NOT link when the email is absent or unverified.
- **FR-010**: System MUST NOT link when the matched local account already has a different OAuth2 provider linked to it.
- **FR-011**: System MUST NOT link when more than one local account matches the verified email (ambiguous match).
- **FR-012**: After linking, subsequent logins from the same provider MUST use the existing `(provider, sub)` lookup — email matching runs only once per provider identity.
- **FR-013**: Account state (locked, expired, disabled) MUST be enforced after linking — linking does not grant access to disabled accounts.

### Key Entities

- **Local Person Account**: An existing directory entry with classes `Object + Account + Person`, carrying a `mail` (primary email) attribute and no current OAuth2 link.
- **OAuth2 Provider**: An `OAuth2Client` entry with JIT provisioning enabled and a configured userinfo or OIDC endpoint.
- **ExternalUserClaims**: The set of claims returned by the provider — includes `sub`, `email`, `email_verified`, `display_name`, `username_hint`.
- **OAuth2 Link**: The three attributes written onto a Person entry to permanently associate it with a provider identity: `OAuth2AccountProvider`, `OAuth2AccountUniqueUserId`, `OAuth2AccountCredentialUuid`.
- **Global Email Link Setting**: A boolean attribute on the domain object controlling the default email-linking behaviour across all providers.
- **Per-Provider Email Link Setting**: A boolean attribute on an individual `OAuth2Client` entry that overrides the global setting for that provider only.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An administrator can enable or disable email linking globally or per-provider without restarting the server.
- **SC-002**: A pre-provisioned user with a matching verified email can complete social login without a duplicate account being created, in under 3 seconds end-to-end.
- **SC-003**: Zero duplicate accounts are created for users whose provider email exactly matches an existing local account's primary email, when linking is enabled.
- **SC-004**: Social login with an unverified or absent email produces no email-match attempt — existing JIT or failure behaviour is preserved identically.
- **SC-005**: After the first successful link, all subsequent logins from the same provider use the fast `(provider, sub)` path with no email lookup overhead.
- **SC-006**: No existing account can be linked to a new provider if it is already linked to another provider — the attempt is rejected and the original link is preserved.

## Assumptions

- GitHub's primary email returned by the userinfo endpoint is treated as verified (GitHub verifies email addresses before allowing them to be set as primary).
- Only the primary `mail` attribute is used for matching — secondary/alias emails are out of scope for v1.
- The linking operation is atomic — if the write to the existing account fails, no link is established and login fails cleanly.
- Admins can manually set the OAuth2 link attributes on a Person entry via the existing admin API (this feature does not need a separate admin linking endpoint).
- This feature applies only to Person accounts — ServiceAccounts cannot be linked to social providers.
- JIT provisioning must be enabled on the OAuth2 client for email-matching to activate; if JIT is disabled, the feature does not apply.
- The global `oauth2_email_link_accounts` defaults to off — admins must explicitly enable it, either globally or per-provider.
- Per-provider setting takes precedence over global: if per-provider is explicitly set (true or false), the global value is ignored for that provider.
