# Feature Specification: RP-Initiated Logout (PR-RP-LOGOUT)

**Feature Branch**: `009-rp-logout`
**Created**: 2026-04-21
**Status**: Draft
**Input**: User description: "PR-RP-LOGOUT — RP-initiated logout across netidm's OAuth2/OIDC and SAML surfaces, so downstream apps can terminate a user's netidm session and cascade that logout across the trust chain. Adds OIDC end_session_endpoint (RP-Initiated Logout 1.0), OIDC Back-Channel Logout 1.0, and SAML Single Logout (SLO). New configuration attributes for post-logout redirect URI allowlists, back-channel logout endpoints, and SAML SLO service URLs; admin CLI and client SDK to manage them. PR #2 of the 17-PR dex-parity roadmap. Dex is the parity anchor; where dex is silent (notably SAML SLO), the OIDC/SAML specs are the fallback."

## Clarifications

### Session 2026-04-21

- Q: When an OIDC end-session request identifies a session via the ID token hint, does netidm terminate only that session, or every active netidm session for that user? → A: Only the single session named by the ID token hint's session claim (dex/OIDC default). A separate netidm-owned surface — exposed to both the end user as self-service and to administrators — terminates every active session for a given user when that is what is wanted; this surface is NOT reachable from a relying-party logout request.
- Q: How does netidm deliver back-channel logout tokens to registered relying-party endpoints when a session ends? → A: A durable queue persisted in the entry database. When a session ends, one delivery record per registered endpoint is enqueued. A background worker attempts each delivery with a bounded per-request timeout and a bounded overall retry budget using exponential backoff, surviving netidm restart. Administrators can list pending, succeeded, and permanently-failed deliveries via CLI. This is an intentional netidm extension beyond dex's fire-and-forget model — chosen for operational visibility and resilience.
- Q: How does a SAML `<LogoutRequest>` identify the session(s) to terminate at netidm? → A: Spec-strict SAML 2.0 Single Logout behaviour. If `<SessionIndex>` is present, netidm terminates the single session matching (NameID, SessionIndex). If `<SessionIndex>` is absent, netidm terminates every session the NameID principal holds at THAT specific SP — not the user's sessions at other SPs and not their OIDC/netidm-web sessions. A per-SP session index is maintained to make the "absent" case tractable without scanning all sessions.
- Q: Where does netidm host the OIDC end-session endpoint — per-client or global? → A: Both. A per-client endpoint at `/oauth2/openid/:rs_name/end_session_endpoint` is the primary shape and is what each client's discovery document advertises (matches netidm's existing per-client authorize/discovery routing). A global endpoint at `/oauth2/openid/end_session_endpoint` is also hosted as a fallback; it derives the client from the ID token hint's audience claim. Both routes share the same handler and semantics.
- Q: Does this PR add `<SessionIndex>` emission to the SAML IdP auth path, and what happens to existing active SAML sessions? → A: This PR adds `<SessionIndex>` emission to the SAML IdP auth response so every new SAML session carries one, AND runs a migration that backfills synthetic `<SessionIndex>` values for all currently-active SAML sessions at the time the migration lands. Both new and pre-existing active sessions are therefore addressable by a specific-session `<LogoutRequest>` from the moment the feature ships.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A downstream app logs a user out of netidm (Priority: P1)

A user is signed in to both a downstream relying-party application (for example, a dashboard or wiki) and to netidm. The user clicks "Log out" in the downstream app. The app redirects the user's browser to netidm's logout endpoint, presenting the OIDC ID token the user originally received. Netidm verifies the token, ends the user's netidm session, revokes the refresh tokens that app held for this user, and either returns the browser to an app-provided post-logout page or shows a confirmation page if no redirect was supplied or allowed.

**Why this priority**: This is the primary capability the feature exists to deliver. Without it, downstream apps cannot terminate a user's session at netidm at all — a user who logs out of the app remains signed in at netidm and will be silently re-authenticated on the next visit. P1.

**Independent Test**: A test that drives a dummy OAuth2 client through a full login-then-logout flow can verify the user's netidm session cookie is cleared, the refresh tokens associated with that app are revoked, and the browser ends at the correct post-logout destination. No other user stories need to be implemented for this to be testable.

**Acceptance Scenarios**:

1. **Given** a user is signed in to netidm and was issued an ID token by a registered app, **When** the app redirects the browser to netidm's logout endpoint with that ID token and a registered post-logout redirect URI, **Then** the user's netidm session ends, the app's refresh tokens for that user are revoked, and the browser is redirected to the supplied URI with any `state` parameter echoed back.
2. **Given** a logout request arrives without an ID token, **When** netidm handles it, **Then** the user's netidm session still ends but the browser lands on a netidm-owned confirmation page rather than being redirected anywhere.
3. **Given** a logout request supplies a post-logout redirect URI that is not on the app's registered allowlist, **When** netidm handles it, **Then** netidm ends the session but ignores the redirect and shows the confirmation page; the unregistered URI is never visited.
4. **Given** an expired or cryptographically invalid ID token is presented, **When** netidm handles the request, **Then** the session is ended and the confirmation page is shown; no redirect occurs even if a URI was supplied.
5. **Given** netidm's OpenID discovery document, **When** a relying party reads it, **Then** the logout endpoint is advertised alongside the existing authorisation and token endpoints.

---

### User Story 2 - Administrator registers where logouts are allowed to redirect (Priority: P1)

A netidm administrator configuring a new downstream app must tell netidm which URIs that app is permitted to name as its post-logout destination. Without a registered allowlist entry, logout still works but the user cannot be redirected back to the app — they see netidm's confirmation page instead.

**Why this priority**: No allowlist entry means no end-to-end logout UX for the app. Every app that expects to use the feature needs this step, so US1 is only meaningful once administrators can register these entries. P1 alongside US1.

**Independent Test**: The administrator runs the CLI verbs to add, list, and remove post-logout redirect URIs on a test app entry; changes persist across restarts and appear in subsequent listings. No end-user interaction is required.

**Acceptance Scenarios**:

1. **Given** a registered app has no post-logout redirect URIs, **When** the administrator adds one, **Then** the URI appears in a subsequent list command and is accepted by the logout endpoint on the next flow.
2. **Given** a registered app already has one or more post-logout redirect URIs, **When** the administrator adds another, **Then** all entries coexist and any of them is accepted by the logout endpoint.
3. **Given** a post-logout redirect URI is configured, **When** the administrator removes it, **Then** a subsequent logout request naming that URI falls through to the confirmation page.
4. **Given** a malformed URI is supplied (not a valid absolute URL), **When** the administrator runs the add command, **Then** the command fails with a clear error and storage is unchanged.

---

### User Story 3 - Other apps learn about a logout without the user visiting them (Priority: P2)

When a user ends a session at netidm — whether by clicking logout in one app, or because netidm itself terminated the session (expiry, admin revoke) — other apps that minted tokens against the same session can be informed, so they can invalidate their own local sessions without waiting for the user to visit them. An administrator registers a back-channel logout endpoint for each app that wants to receive these notifications; netidm sends a signed logout token to each registered endpoint when the session ends.

**Why this priority**: Without this, a user who logs out of app A remains "logged in" at app B until app B's own session expires, even though their netidm session has ended. For single-sign-on deployments with multiple tenant apps (the common netidm-dex use case), this is the difference between a user hitting logout once and actually being signed out everywhere vs. hitting logout once and still being signed in most places. P2 — valuable but the core logout flow in US1 can ship and be used without it.

**Independent Test**: A test that wires up a dummy HTTP endpoint as an app's back-channel logout receiver can assert that when a session ends (via US1, or by directly invoking session termination), the dummy receiver receives a signed logout token whose claims identify the user, the session, netidm as the issuer, and the receiving app as the audience.

**Acceptance Scenarios**:

1. **Given** an app has a back-channel logout endpoint registered and a user has an active session that produced tokens for that app, **When** the user logs out via US1, **Then** the endpoint receives a POST carrying a signed logout token identifying the user and the session.
2. **Given** two apps each have back-channel logout endpoints registered, **When** a session associated with both ends, **Then** both endpoints receive logout tokens, each addressed to its respective app.
3. **Given** netidm's OpenID discovery document, **When** a relying party reads it, **Then** the document advertises that back-channel logout is supported and that it includes a session identifier.
4. **Given** an app has no back-channel logout endpoint registered, **When** a session ends, **Then** netidm performs no back-channel delivery for that app and the session termination succeeds regardless.
5. **Given** a registered back-channel endpoint returns an error or cannot be reached, **When** netidm attempts delivery, **Then** the session still ends successfully at netidm and the failure is logged; the session is never held open because of a back-channel delivery problem.

---

### User Story 4 - SAML service providers log their users out of netidm (Priority: P2)

A SAML service provider that federates to netidm as its identity provider needs a way to terminate the netidm session when the user logs out at the SP. The SP sends netidm a signed `<LogoutRequest>`; netidm verifies the signature, ends the user's netidm session, and returns a signed `<LogoutResponse>`.

**Why this priority**: SAML deployments are less common in typical netidm use than OIDC, and most operators can tolerate SAML SP sessions outliving the netidm session for a little longer. But any deployment that federates a SAML SP expects SLO to exist per the SAML spec. P2 — not gating US1, but needed for SAML feature-completeness.

**Independent Test**: A test can submit a signed `<LogoutRequest>` to netidm's SAML SLO endpoint for a test SP and assert netidm ends the session, returns a signed `<LogoutResponse>`, and reflects the SLO endpoints in its published IdP metadata. No browser is strictly required for the SOAP binding; the HTTP-Redirect binding adds the browser round-trip.

**Acceptance Scenarios**:

1. **Given** a SAML SP has an SLO service URL registered on its netidm entry and the user has one active SAML session with that SP, **When** the SP sends a signed `<LogoutRequest>` via the SOAP binding carrying the session's `<SessionIndex>`, **Then** netidm ends only that one session and returns a signed `<LogoutResponse>` with a success status.
2. **Given** a user has two active SAML sessions with the same SP, **When** the SP sends a signed `<LogoutRequest>` with no `<SessionIndex>`, **Then** netidm ends both sessions at that SP, leaves untouched any sessions the user holds at other SPs or OIDC RPs, and returns a signed `<LogoutResponse>` with a success status.
3. **Given** a SAML SP sends a `<LogoutRequest>` via the HTTP-Redirect binding, **When** netidm handles it, **Then** behaviour matches the SOAP case and the browser lands on a netidm-rendered confirmation page (or the SP-supplied relay state, if present).
4. **Given** a `<LogoutRequest>` arrives with an invalid or missing signature, **When** netidm handles it, **Then** no session is ended and a signed `<LogoutResponse>` with a failure status is returned.
5. **Given** netidm publishes its SAML IdP metadata, **When** an SP reads it, **Then** the SLO service endpoints appear alongside the existing single-sign-on endpoints.
6. **Given** a SAML session was created before this feature's migration landed, **When** the SP sends a `<LogoutRequest>` carrying the backfilled `<SessionIndex>`, **Then** netidm correlates and ends that one session exactly as it would for a session created after the migration.

---

### User Story 5 - User or administrator ends every session a user has at once (Priority: P3)

A user who notices their account has been used on a forgotten or compromised device needs a way to kill every active netidm session they hold, not just the one in front of them. An administrator responding to a potential account compromise needs the same capability on behalf of any user. This surface is intentionally separate from the OIDC end-session endpoint — relying parties cannot escalate a single-session logout into a global one.

**Why this priority**: The core RP-initiated logout flows (US1–US4) deliver the parity feature. This capability is an adjacent safety net that composes with them cleanly but is not required for the parity target. P3 — ships in this PR because the decision converged here, but the implementation load is small and orthogonal to the rest.

**Independent Test**: With a test user having N active sessions and some of those sessions having minted tokens for RPs with back-channel endpoints registered, invoke the all-sessions termination surface as that user (self-service path) and separately as an administrator (admin path). Assert every session ends and that the registered back-channel endpoints fire once per applicable session.

**Acceptance Scenarios**:

1. **Given** a user has three active netidm sessions, **When** the user invokes the all-sessions logout surface as themselves, **Then** all three sessions are terminated and any in-scope refresh tokens are revoked.
2. **Given** a user has multiple active sessions, some of which produced tokens for RPs with back-channel endpoints registered, **When** all-sessions logout runs, **Then** each affected back-channel endpoint receives a logout token per ended session (one per session, not one per user).
3. **Given** a netidm administrator needs to force-terminate another user's sessions, **When** the administrator invokes the all-sessions surface naming that user, **Then** the user's sessions are all ended with the same guarantees as the self-service path.
4. **Given** an OIDC relying party sends a standard end-session request, **When** netidm handles it, **Then** only the single session named by the ID token hint is terminated — the relying-party-facing surface never triggers all-sessions behaviour.

---

### Edge Cases

- **Session already ended.** A logout arrives for a session that is already terminated (another tab, refresh expired, admin revoked). Netidm treats this as success — the confirmation page is shown (or the registered redirect is honoured) and no back-channel delivery is repeated for the already-gone session.
- **Logout for a different user.** An ID token naming user A is presented while the browser's netidm cookie is for user B. Netidm ends the session identified by the ID token's session claim (not the browser cookie); if no matching session is found, behaviour matches "session already ended".
- **Multiple sessions per user.** A single user has multiple active netidm sessions (e.g., laptop and phone). A logout request naming one session terminates only that session; the user's other sessions remain active, and their refresh tokens and back-channel endpoints are untouched.
- **Back-channel endpoint is slow or hangs.** Netidm does not block the user's browser waiting for back-channel delivery; deliveries are handled by a background worker and each attempt is bounded by a per-request timeout.
- **Back-channel endpoint is permanently broken.** Delivery attempts are subject to a bounded retry budget with exponential backoff; after exhaustion, the delivery record is marked permanently failed and stops retrying. The session stays ended regardless.
- **Netidm restarts with pending deliveries.** Delivery records that were pending at shutdown survive the restart and are picked up by the worker on next boot; no pending delivery is lost.
- **Allowlist URI contains a wildcard or query string.** Only exact matches are allowed — no partial or prefix matching, no query-string wildcards. An administrator who needs multiple URIs registers multiple entries.
- **SAML LogoutRequest for an unknown SP.** The request is rejected with a failure response; no session is touched.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Netidm MUST expose OIDC RP-Initiated Logout 1.0 logout endpoints at two routes sharing one handler: a per-client route scoped to each registered client (which each client's discovery document advertises as `end_session_endpoint`), and a global fallback route not tied to any specific client (which derives the target client from the ID token hint's audience claim). Both routes MUST implement identical semantics.
- **FR-002**: The logout endpoint MUST accept the standard parameters (ID token hint, post-logout redirect URI, state, client identifier, logout hint, UI locales) and behave as follows when the ID token hint identifies a valid session: end ONLY the single netidm session named by the token's session claim (other sessions for the same user remain active), revoke the refresh tokens held by the identified app for that user that were issued against the ended session, and either redirect to a post-logout URI registered on the app (echoing `state`) or render a netidm-owned confirmation page.
- **FR-003**: When the ID token hint is missing, expired, unverifiable, or names an unknown session, the endpoint MUST still end any session implied by the request context (e.g., the browser's current netidm session if one is present) and render the confirmation page without performing any redirect.
- **FR-004**: A post-logout redirect URI supplied in a logout request MUST only be honoured if it matches an entry on the named app's registered allowlist exactly; otherwise the request falls through to the confirmation page.
- **FR-005**: Administrators MUST be able to add, list, and remove post-logout redirect URIs on an OAuth2 app entry via CLI and client SDK, with changes persisted in the netidm entry database.
- **FR-006**: Netidm MUST support OpenID Connect Back-Channel Logout 1.0: when a session terminates (through FR-002, FR-003, netidm-initiated session expiry, or an administrator revoke), netidm MUST send a signed logout token to every registered back-channel logout endpoint owned by an app that minted tokens against that session.
- **FR-007**: Logout tokens MUST be JWTs whose claims identify the user (subject), the session (session identifier), netidm (issuer), and the receiving app (audience), and carry the back-channel logout event indicator and a unique JWT identifier per the specification.
- **FR-008**: Administrators MUST be able to set and clear a back-channel logout endpoint URL on an OAuth2 app entry via CLI and client SDK.
- **FR-009**: Back-channel delivery MUST NOT block the user's browser logout — the session ends and the logout response returns whether delivery succeeds, fails, or has not yet been attempted. Each delivery MUST be persisted as a record in the entry database at the moment the session ends so that pending deliveries survive netidm restart. A background worker MUST attempt each pending delivery with a bounded per-request timeout and a bounded overall retry budget using exponential backoff; on success the record is marked delivered, and on budget exhaustion the record is marked permanently failed. Administrators MUST be able to list pending, succeeded, and permanently-failed delivery records via CLI.
- **FR-010**: Netidm's OpenID discovery document MUST advertise that back-channel logout is supported and that logout tokens include a session identifier.
- **FR-011**: Netidm MUST expose SAML Single Logout endpoints over both the SOAP binding and the HTTP-Redirect binding on any SAML SP entry, accept a signed `<LogoutRequest>` from the SP, terminate the session(s) identified per FR-011a, and return a signed `<LogoutResponse>`.
- **FR-011a**: A `<LogoutRequest>` carrying a `<SessionIndex>` MUST terminate only the single session matching the (NameID, SessionIndex) pair at the originating SP. A `<LogoutRequest>` with no `<SessionIndex>` MUST terminate every session the NameID principal currently holds at THAT specific SP — and no other sessions the user has at other SPs, at OIDC relying parties, or in netidm's web UI. To make the no-SessionIndex case tractable, netidm MUST maintain a per-SP session index that lists the active SAML sessions at each SP.
- **FR-011b**: Netidm MUST include a `<SessionIndex>` value, unique per session, in the `<AuthnStatement>` of every SAML IdP authentication response issued on or after this feature ships. The value MUST be retained on the session record so inbound `<LogoutRequest>` messages can correlate.
- **FR-011c**: The schema migration that lands this feature MUST backfill a synthetic, unique `<SessionIndex>` value onto every currently-active SAML session entry so that, from the moment the feature is live, every SAML session is addressable by a single-session `<LogoutRequest>`. Backfilled values have the same shape as newly-issued ones and live in the same per-SP session index.
- **FR-012**: A SAML `<LogoutRequest>` with a missing or invalid signature MUST NOT end any session; netidm MUST respond with a signed `<LogoutResponse>` carrying a failure status.
- **FR-013**: Netidm's published SAML IdP metadata MUST list the SLO service endpoints alongside the existing SSO endpoints.
- **FR-014**: Administrators MUST be able to set and clear the SLO service URL on a SAML SP entry via CLI and client SDK.
- **FR-015**: Any end-of-session path (OIDC end-session, SAML SLO, netidm-initiated expiry, admin revoke) MUST converge on a single internal session-termination routine that ends the netidm session, revokes the in-scope refresh tokens, and triggers back-channel logout delivery — there must be no termination path that skips these steps.
- **FR-016**: Configuration attributes added by this feature MUST be covered by access-control entries so that only administrators (and no ordinary users) can read or modify them.
- **FR-017**: Netidm MUST expose an all-sessions termination surface, accessible both to an end user acting on their own account (self-service) and to an administrator acting on another user's account, that terminates every active netidm session held by the target user. This surface MUST route every session termination through the same internal routine named in FR-015 (so refresh-token revocation and back-channel delivery fire per session), and MUST NOT be reachable from any relying-party logout request.

### Key Entities

- **OAuth2 App (relying party)**: an entry in netidm representing a registered OpenID Connect client. Gains two new configuration facets: an allowlist of permitted post-logout redirect URIs, and an optional back-channel logout endpoint URL.
- **SAML Service Provider**: an entry in netidm representing a registered SAML SP. Gains one new configuration facet: the SP's SLO service URL.
- **Session**: an active authenticated session for a user at netidm. Termination of a session triggers refresh-token revocation for apps that minted tokens against that session and back-channel logout delivery to registered endpoints.
- **Logout Token**: a signed JSON Web Token minted by netidm and delivered to a relying party's back-channel logout endpoint when a session ends. Conveys the user, the session identifier, the issuer, the audience, and the back-channel logout event indicator.
- **Back-channel Delivery Record**: a persisted record of one pending, succeeded, or permanently-failed logout-token delivery, enqueued at session termination. Holds the target endpoint, the logout token payload, attempt history, and terminal status. Administrators can list and inspect these records.
- **Post-logout redirect URI allowlist entry**: a single URI that an administrator has declared is permitted to be named as a logout destination for a given app.
- **Per-SP Session Index entry**: a record linking a SAML service provider and a (NameID, SessionIndex) tuple to the netidm session produced by the most recent authentication at that SP. Populated on SAML auth, consulted on inbound `<LogoutRequest>`, and cleaned up on session termination.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of OIDC logout flows initiated by a registered relying party with a valid ID token hint result in the user's netidm session ending and the browser arriving at the relying party's registered post-logout destination.
- **SC-002**: 0% of OIDC logout flows with an unregistered post-logout redirect URI result in the browser being redirected to that URI; all such flows end at the netidm confirmation page.
- **SC-003**: When a user's session ends, every registered back-channel logout endpoint for apps that minted tokens against that session receives a logout-token POST at least once, within the retry budget, as long as the endpoint is reachable at some point during that window.
- **SC-004**: A back-channel logout endpoint that is unreachable for the entire retry budget does NOT prevent the user's netidm session from ending or the browser logout from completing; the delivery record is marked permanently failed and is visible to administrators via CLI.
- **SC-005**: 100% of SAML SLO requests carrying a valid signature from a registered SP end the matching session(s) per the SessionIndex rule and receive a signed success response; 0% of requests with an invalid or absent signature end any session.
- **SC-006**: Published discovery/metadata documents advertise every logout endpoint added by this feature — an external relying party can discover them without consulting netidm documentation or source.
- **SC-007**: Administrators can register a new relying party's logout configuration (post-logout URIs, back-channel endpoint, SAML SLO URL) end-to-end via the CLI without touching the database or restarting netidm.
- **SC-008**: Back-channel deliveries that were pending when netidm was restarted resume from the database-persisted record and complete or fail-out per the normal retry budget — no deliveries are silently dropped by a restart.
- **SC-009**: From the moment the migration lands, 100% of currently-active SAML sessions are addressable by a single-session `<LogoutRequest>` carrying the session's `<SessionIndex>` — no active session is left in a state where only the "no SessionIndex" fall-through branch can reach it.

## Assumptions

- Netidm's existing session cookie, refresh-token, and SAML assertion infrastructure are reused; this feature adds termination paths and configuration, not a new session implementation.
- Dex (the parity anchor for this roadmap) implements OIDC RP-Initiated Logout and Back-Channel Logout; it does not currently implement SAML SLO. For SAML SLO, the SAML 2.0 Single Logout Profile is the reference.
- "Exact parity with dex" for OIDC means: same discovery claims, same request parameter handling, same logout-token claim set, same error semantics. Idiomatic Rust internals are not required to mirror dex's Go code line-for-line.
- Back-channel delivery durability is an intentional netidm extension beyond dex's fire-and-forget model — dex does not persist or retry back-channel deliveries. This is chosen for operational visibility and resilience and is flagged as a netidm extension of the dex feature set (comparable to how PR-LINKBY extends dex's account linking).
- SAML single-logout behaviour follows the SAML 2.0 Single Logout Profile where dex is silent. The per-SP session index is netidm-specific state needed to implement the profile's "no SessionIndex" branch without scanning all sessions.
- Netidm's SAML IdP did not emit `<SessionIndex>` before this feature; this PR introduces emission on all new SAML auth responses and a one-time migration that backfills a synthetic `<SessionIndex>` onto every currently-active SAML session so no active session is left unaddressable by SLO.
- Front-channel SLO (browser iframe-based logout propagation) is out of scope; dex does not ship it. Session-management via OP-iframe + postMessage is also out of scope.
- Device authorization flow logout is out of scope; device flow is a separate PR later in the roadmap.
- Existing OpenID discovery, OAuth2 admin endpoints, and SAML IdP metadata surfaces continue to live at the same external paths they live at today — this feature adds entries to those surfaces, it does not move them.
- The netidm entry database gains new attributes and access-control entries via a schema migration consistent with how previous features (e.g., PR-GROUPS-PIPELINE) extended the schema.
- Release notes for this feature are drafted at tag time, not mid-cycle.
