# Feature Specification: SSO Login Choice UX

**Feature Branch**: `005-sso-login-choice`
**Created**: 2026-04-18
**Status**: Draft
**Input**: SSO login choice UX — replace username-first login with SSO/internal choice landing page

## User Scenarios & Testing *(mandatory)*

### User Story 1 — SSO-first landing page (Priority: P1)

A visitor arrives at the login page. Instead of immediately seeing a username field, they see a list of configured SSO provider buttons (e.g. "Sign in with GitHub", "Sign in with Google") prominently at the top, followed by a clear divider and an option labelled "Use internal authentication" that reveals the existing username/password flow.

If no SSO providers are configured, the page falls back to the current username-first layout with no visible change.

**Why this priority**: This is the primary UX change. Most users in a modern deployment will use SSO. Showing SSO options first reduces clicks and friction for the majority path.

**Independent Test**: Load the login page with at least one OAuth2 client provider configured — SSO buttons must appear above the internal auth option. Load it with zero providers — the page must look identical to the current login page.

**Acceptance Scenarios**:

1. **Given** one or more SSO providers are configured, **When** a user navigates to the login page, **Then** one button per provider is shown at the top, each labelled with the provider name, before any username input field is visible.
2. **Given** no SSO providers are configured, **When** a user navigates to the login page, **Then** only the existing username form is shown — no SSO section, no divider.
3. **Given** the SSO-first landing page is shown, **When** the user clicks "Use internal authentication", **Then** the username/password form becomes visible without a full page reload.
4. **Given** the SSO-first landing page is shown, **When** the user clicks a provider button, **Then** the browser is redirected to that provider's authorisation URL to begin the OAuth2 flow.

---

### User Story 2 — Remembered internal auth preference (Priority: P2)

A user who regularly uses internal authentication (username + password) does not want to click "Use internal authentication" on every visit. If they previously completed a login via internal auth, the login page should open with the internal auth form already expanded on their next visit.

**Why this priority**: Reduces friction for power users and admins who always use internal auth. Without this, they need an extra click every single time.

**Independent Test**: Complete a login via internal auth, then navigate to the login page again — the username form should be immediately visible without clicking the divider.

**Acceptance Scenarios**:

1. **Given** a user has previously logged in using internal authentication on this browser, **When** they navigate to the login page, **Then** the username form is shown expanded by default, with SSO options still accessible above.
2. **Given** a user has previously logged in using an SSO provider, **When** they navigate to the login page, **Then** the SSO-first layout is shown (provider buttons first, internal auth collapsed).

---

### User Story 3 — SSO button branding (Priority: P3)

Each SSO provider button displays the provider's display name. If the provider has a logo/image configured, the logo appears on the button. This gives users visual confirmation of which identity provider they are choosing.

**Why this priority**: Pure polish — functional without it, but branding increases user confidence and reduces mis-clicks between multiple similar-looking providers.

**Independent Test**: Configure a provider with a display name and a logo — verify the logo appears on the button. Configure a provider without a logo — verify the button still renders correctly with just the name.

**Acceptance Scenarios**:

1. **Given** a provider has a display name configured, **When** the login page is shown, **Then** the button label uses the provider display name (not the internal name/slug).
2. **Given** a provider has a logo image configured, **When** the login page is shown, **Then** the provider's logo is displayed on the button.
3. **Given** a provider has no logo configured, **When** the login page is shown, **Then** the button renders with text only — no broken image placeholder.

---

### Edge Cases

- What if a provider is configured but currently unreachable? The button still appears — the error surfaces only after the user clicks and the OAuth2 redirect fails.
- What if only one SSO provider is configured? Show one button — no special single-provider auto-redirect behaviour in v1.
- What if the user navigates to `/ui/login?next=<url>`? The `next` parameter must be preserved through both the SSO redirect flow and the internal auth flow.
- What happens on mobile viewports? Buttons stack vertically; minimum touch target size maintained.
- What if more than 5 providers are configured? All are listed — no pagination or truncation in v1.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The login page MUST display one button per configured OAuth2 client provider when at least one provider exists, positioned above the internal authentication option.
- **FR-002**: Each provider button MUST be labelled with the provider's display name; if no display name is set, the provider's internal name is used as a fallback.
- **FR-003**: Each provider button MUST initiate the OAuth2 authorisation redirect for that provider when clicked.
- **FR-004**: The login page MUST display a clearly labelled action ("Use internal authentication") that reveals the existing username/password form.
- **FR-005**: When no OAuth2 client providers are configured, the login page MUST display only the existing username/password form — the SSO section and divider MUST NOT appear.
- **FR-006**: The internal authentication form MUST be revealed without a full page navigation (inline expand).
- **FR-007**: The `?next=<url>` query parameter MUST be preserved and honoured regardless of whether the user chooses SSO or internal authentication.
- **FR-008**: If a provider has a logo/image configured, the logo MUST be displayed on the provider's button.
- **FR-009**: The login page MUST remain fully functional on mobile viewports with no horizontal overflow.
- **FR-010**: Users who most recently authenticated via internal auth MUST see the internal auth form expanded by default on subsequent visits to the login page on the same browser.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A user with one or more SSO providers configured can initiate an SSO login in 1 click from the login landing page (previously required typing a username first).
- **SC-002**: The login page load time increases by no more than 50ms compared to the current login page (provider list is derived from already-available server state — no additional network calls at render time).
- **SC-003**: 100% of existing internal authentication flows continue to work without regression — username/password, TOTP, passkey, and backup code paths are unaffected.
- **SC-004**: The SSO section renders zero elements when zero providers are configured — verified by automated test.
- **SC-005**: The `?next=<url>` redirect is honoured correctly in both the SSO path and the internal auth path.

## Assumptions

- SSO providers in scope are the OAuth2 client providers already implemented (`OAuth2ClientProvider`). No new provider type is introduced by this feature.
- The existing login templates use Bootstrap — button and divider styling will reuse the same design system already in place.
- Provider display names and optional logo images are already stored in the `OAuth2ClientProvider` schema; no new database fields or migrations are required.
- The "Use internal authentication" toggle state is persisted client-side (short-lived browser cookie or local storage) — no server-side state is needed.
- The SSO button click initiates the same OAuth2 redirect that currently happens after the user types their username and the server resolves an OAuth2 provider — the redirect URL construction logic is reused, not rewritten.
- This feature is web UI only; the API and CLI are unaffected.
- The list of providers available on the login page is those configured as OAuth2 client providers in the system — there is no separate "show on login page" toggle in v1.
