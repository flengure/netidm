# Feature Specification: GitHub Upstream Connector (PR-CONNECTOR-GITHUB)

**Feature Branch**: `012-github-connector`  
**Created**: 2026-04-21  
**Status**: Draft  
**Input**: User description: "PR-CONNECTOR-GITHUB — first concrete connector against the `RefreshableConnector` trait introduced by PR-REFRESH-CLAIMS. PR #4 of the 17-PR dex-parity roadmap. Exact-parity port of dex's `connector/github/github.go` — same OAuth2 scopes, same API endpoints, same group-claim shape, same config-surface semantics. Where dex has behaviour that the broader OAuth2/GitHub API specs don't mandate, follow dex. Introduces DL28 with per-connector config attrs, a `GitHubConnector` that implements `RefreshableConnector`, admin CLI + SDK verbs for GitHub-specific config, and connector registration at `IdmServer::start`. GitHub App auth, other connectors, and PAT ingestion are out of scope."

## Clarifications

### Session 2026-04-21

- Q: When a GitHub user completes the flow and no matching netidm Person exists, does the connector auto-provision (JIT) or require a pre-existing Person? → A: Admin-configurable per connector via a new `allow_jit_provisioning` (bool) attribute. When `true`, first-time users without a matching Person get a fresh one provisioned; when `false`, they are rejected with an operator-guided error. Defaults to `false` (conservative).
- Q: Should the connector support restricting login to specific GitHub teams (access gate), not just scoping which teams contribute groups? → A: Yes. A new optional multi-value attribute `OAuth2ClientGithubAllowedTeams` is the ACCESS GATE — when non-empty, a login succeeds only if the user's GitHub team memberships intersect the list. It is distinct from `OAuth2ClientGithubOrgFilter`, which is the GROUP-MAPPING FILTER (controls which teams contribute to the groups claim, but never rejects a login). Both can be set independently.
- Q: How does the connector link a GitHub user to an existing netidm Person when verified email is unavailable, and what about users with no verified emails at all? → A: Four-step fallback chain. (1) If a verified email matches an existing Person's email → link by email. (2) Else if a Person already has this GitHub numeric ID stored as its upstream-subject-for-this-connector → link by ID (stable across GitHub username changes). (3) Else if a Person has the GitHub login stored as its upstream-subject → link by login (less stable; for legacy cases). (4) Else: if `allow_jit_provisioning` is `true` → provision; otherwise → reject. Users with no verified emails can still authenticate via steps 2–4; the Person's email field is simply left empty (or untouched for linked Persons).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - End user logs in via GitHub, groups flow through (Priority: P1)

Alice is a member of the `platform` team in the `acme` GitHub org. Her netidm administrator has configured a GitHub connector pointing at `github.com`, loaded the OAuth app's `client_id` and `client_secret`, and mapped `acme:platform` → netidm group `platform-admin` via the existing `OAuth2GroupMapping` table (PR-GROUPS-PIPELINE). Alice visits a downstream relying party that delegates authentication to netidm, picks "Log in with GitHub", is redirected to GitHub, consents, and lands back on the RP with a netidm session.

**Why this priority**: This is the single reason the PR exists. Every downstream RP netidm serves (Portainer, Grafana, reverse-proxy auth, etc.) is blocked on users being able to authenticate through GitHub. No user flow completes without this.

**Independent Test**: `netidmd_testkit` with a mock GitHub HTTP server in-process. Drive a full authorization-code flow: click login → mock GitHub returns a code → netidm exchanges it → netidm fetches `/user`, `/user/emails`, `/user/orgs`, `/user/teams` from the mock → asserts a netidm Person exists for the GitHub user and holds `platform-admin` in their memberOf via the PR-GROUPS-PIPELINE reconciler.

**Acceptance Scenarios**:

1. **Given** Alice is a member of `acme:platform` on GitHub and the connector has `acme:platform → platform-admin` in its mapping, **When** she completes the login flow, **Then** her netidm Person entry has `platform-admin` in its memberOf and the groups claim in her outgoing netidm session token contains `platform-admin`.
2. **Given** Alice's GitHub account has a verified email `alice@acme.com` and an unverified email `alice@personal.example`, **When** she completes the login flow, **Then** her netidm Person entry's email is `alice@acme.com` (verified emails are strictly preferred over unverified).
3. **Given** Alice is in two teams — `acme:platform` and `acme:audit` — and both are mapped in the connector, **When** she completes the login flow, **Then** both mapped netidm groups appear in her memberOf and the groups claim.
4. **Given** Alice is a member of an org that has no teams mapped to netidm groups, **When** she completes the login flow, **Then** her login succeeds and her netidm memberOf contains no mapped groups from that org (empty-but-valid session, no upstream-side rejection).

---

### User Story 2 - Admin gates login by team membership (Priority: P2)

Bob runs netidm for a company where only members of the `acme:employees` GitHub team should be able to log in through netidm — contractors and external collaborators who happen to be in other `acme` teams must not. He configures `OAuth2ClientGithubAllowedTeams = ["acme:employees"]`. A GitHub user who is in `acme:employees` (possibly with other teams) can log in; a user who is in `acme` but only in `acme:contractors` is rejected at the login boundary, before any Person provisioning or group mapping runs.

**Why this priority**: Team-level access gating is the most common "who is allowed to use our netidm" policy in organisations that already use GitHub teams to model employment status or entitlement. Without this, admins have to rely on downstream RPs each enforcing "is this user in a specific group" post-login, which scales badly and leaks accounts into netidm that should never have existed.

**Independent Test**: Configure `OAuth2ClientGithubAllowedTeams = ["acme:employees"]`. Drive a login for a user in `acme:employees` → succeeds. Drive a login for a user in `acme:contractors` only → rejected with a visible error page (no Person provisioned, no session minted, no group-mapping reconciler invoked).

**Acceptance Scenarios**:

1. **Given** `OAuth2ClientGithubAllowedTeams = ["acme:employees"]` and Alice is in `acme:employees` + `acme:oncall`, **When** she logs in, **Then** login succeeds and her full team set feeds the downstream group-mapping path.
2. **Given** `OAuth2ClientGithubAllowedTeams = ["acme:employees"]` and Bob is in `acme:contractors` but NOT in `acme:employees`, **When** he attempts to log in, **Then** the login is rejected BEFORE any Person is provisioned and BEFORE any JIT/link-by-email logic runs. No upstream-synced markers are written.
3. **Given** `OAuth2ClientGithubAllowedTeams = []` (empty), **When** any authenticated GitHub user attempts to log in, **Then** the access gate is off and the flow continues through the rest of the policy chain (JIT / link-by-email / org-filter).
4. **Given** both `OAuth2ClientGithubAllowedTeams` and `OAuth2ClientGithubOrgFilter` are set on the same connector entry, **When** any user logs in, **Then** the access gate (allowed-teams) applies FIRST — a user not in any allowed team is rejected regardless of which orgs they belong to.

---

### User Story 3 - Admin controls JIT provisioning (Priority: P2)

Carol runs two netidm deployments. Her production deployment has `allow_jit_provisioning = false`: every netidm Person is pre-provisioned by an admin via the CLI, and GitHub login only LINKS existing Persons to their GitHub identity. Her dev deployment has `allow_jit_provisioning = true`: any employee with a corporate GitHub account can log in and netidm auto-creates the Person on first sight.

**Why this priority**: The JIT toggle is the difference between "GitHub is an identity provider that can create netidm accounts" (dev / research orgs) and "GitHub is an authentication front for pre-provisioned accounts" (production / compliance-sensitive orgs). Both postures are legitimate; the admin must be able to choose explicitly.

**Independent Test**: With `allow_jit_provisioning = false` and no Person matching the logging-in GitHub user, assert the login is rejected with a clear "contact your administrator" message. Flip to `true`, reattempt the login, assert a new Person is provisioned and the login completes.

**Acceptance Scenarios**:

1. **Given** `allow_jit_provisioning = false` and no Person matches the GitHub user's verified email, ID, or login, **When** the user attempts to log in, **Then** the login is rejected with an operator-guided error page and no Person is created.
2. **Given** `allow_jit_provisioning = true` and no Person matches the GitHub user, **When** the user attempts to log in, **Then** a new Person is provisioned (netidm name derived from the GitHub login, display name + verified email populated where available) and the login completes normally.
3. **Given** a Person already exists that matches the GitHub user via the linking chain (verified email, stored GitHub ID, or stored GitHub login), **When** the user logs in, **Then** the existing Person is used regardless of the `allow_jit_provisioning` flag. JIT only applies when no match exists at all.

---

### User Story 4 - Admin restricts group mapping to a whitelist of GitHub orgs (Priority: P2)

David runs netidm for a company that uses three GitHub orgs; users often hold team memberships across all three, but only the `acme` org's teams should contribute to the netidm groups claim (the other orgs are used for open-source collaboration and shouldn't inform internal authorisation). He configures `OAuth2ClientGithubOrgFilter = ["acme"]`. Users can still log in if they're in any allowed team (per User Story 2); only teams in the listed orgs feed the group-mapping reconciler.

**Why this priority**: Even when everyone who can log in is legitimate, their FULL multi-org team membership is often too noisy to reflect in netidm. The org-filter is the group-mapping-scoping lever. Separating it from the access-gate (US2) gives admins fine-grained control: "anyone on our team can log in (US2), but only our org's teams affect their roles (US4)."

**Independent Test**: Configure `OAuth2ClientGithubOrgFilter = ["acme"]` AND `OAuth2ClientGithubAllowedTeams = []` (access gate off). Drive a login for a user who is in `acme:platform` AND `external:contractor`. Assert login succeeds; assert the netidm session's groups claim contains only the `acme`-derived groups; the `external:contractor` membership is silently dropped at the group-mapping stage.

**Acceptance Scenarios**:

1. **Given** `OAuth2ClientGithubOrgFilter = ["acme"]` and Alice is in `acme:platform` + `external:audit`, **When** she logs in, **Then** only `acme:platform` passes through the filter into the mapping reconciler (the `external:audit` team is silently dropped from group-claim contribution — login still succeeds).
2. **Given** `OAuth2ClientGithubOrgFilter = []` (empty), **When** Alice logs in, **Then** every team she belongs to feeds the group-mapping reconciler (no filter applied).
3. **Given** the org-filter excludes every org the user is in, **When** the user logs in, **Then** login SUCCEEDS (the org-filter is NOT an access gate — see User Story 2 for that role) but the outgoing session carries no upstream-synced groups for this connector.

---

### User Story 5 - Admin points the connector at GitHub Enterprise (Priority: P2)

Carol's company runs GitHub Enterprise at `https://github.acme.internal`. She configures a netidm connector with `host = https://github.acme.internal`. All OAuth2 and API calls route to that host instead of `github.com` / `api.github.com`.

**Why this priority**: Enterprise deployments are a core netidm use case. Hard-coding `github.com` would make the connector unusable for them. Dex supports this out of the box — matching that is part of the "exact parity" goal.

**Independent Test**: Configure the connector with a custom host pointing at the mock GitHub server. Drive a login. Assert all upstream HTTP calls landed on the configured host (no stray `api.github.com` requests).

**Acceptance Scenarios**:

1. **Given** the connector has `host = https://github.acme.internal`, **When** Alice logs in, **Then** all OAuth2 authorize/token and REST userinfo/teams requests are sent to that host (specifically, authorize at `<host>/login/oauth/authorize`, token at `<host>/login/oauth/access_token`, REST at `<host>/api/v3/...`).
2. **Given** the connector has no host configured, **When** Alice logs in, **Then** upstream requests default to `github.com` (authorize + token) and `api.github.com` (REST).

---

### User Story 6 - Refresh re-fetches team membership (Priority: P2)

The same Alice from US1. A week after her initial login, her downstream RP's access token expires. The RP presents netidm's refresh token to `/oauth2/token` with `grant_type=refresh_token`. Meanwhile, her GitHub admin has removed her from `acme:platform`. The next access token netidm mints must reflect that removal.

**Why this priority**: PR-REFRESH-CLAIMS introduced the `RefreshableConnector` trait precisely so this refresh-time re-fetch could happen; having no concrete connector implement it would leave the feature untested in production. This story is what closes the loop between the two PRs.

**Independent Test**: Drive a US1 login. Mutate the mock GitHub server to remove Alice from `acme:platform`. Exchange the refresh token. Assert the new access token's groups claim no longer contains `platform-admin`, the Person entry's upstream-synced markers for the connector are updated accordingly, and the `refresh_claims.groups_changed` span is emitted (per PR-REFRESH-CLAIMS FR-013).

**Acceptance Scenarios**:

1. **Given** Alice's netidm session was minted through the GitHub connector and she's been removed from `acme:platform` on GitHub, **When** the RP exchanges the refresh token, **Then** the new access token's groups claim does not contain `platform-admin`.
2. **Given** the stored GitHub access token has expired AND the stored refresh token is still valid, **When** the RP exchanges netidm's refresh token, **Then** the connector transparently refreshes the GitHub access token against GitHub's token endpoint before calling the team APIs.
3. **Given** Alice has revoked the OAuth app on GitHub (so both access and refresh tokens are invalid), **When** the RP exchanges netidm's refresh token, **Then** the netidm token endpoint returns `invalid_grant` and forces the RP to restart authentication (per PR-REFRESH-CLAIMS FR-003).
4. **Given** GitHub's API is unreachable, **When** the RP exchanges netidm's refresh token, **Then** the netidm token endpoint returns `invalid_grant` (fail-closed per PR-REFRESH-CLAIMS FR-003).

---

### Edge Cases

- **User belongs to no mapped teams on first login**: the login succeeds, the Person is provisioned (JIT per existing netidm OAuth2 client-provider semantics), and the outgoing session carries no groups claim beyond any locally-granted memberships. Zero-team users are valid.
- **User's `login` (handle) changes between sessions**: GitHub IDs are stable even if usernames change. The connector MUST use the stable numeric ID as the subject identifier, never the mutable `login`. A changed login does NOT create a new netidm Person — it MUST resolve to the existing one via the stored ID.
- **GitHub returns a paginated teams response**: the connector MUST follow the `Link: <...>; rel="next"` header through every page. A user in 200 teams must see all 200 reflected in netidm (bounded only by the hard limit defined below).
- **GitHub returns a 4xx from the team API mid-flow** (e.g. the OAuth app's scope was revoked while the user was still authorised): treat as a login failure, surface a human-readable error page, do NOT provision a partial Person with missing groups.
- **GitHub rate-limits (403 with `X-RateLimit-Remaining: 0`)**: treat as a refresh failure on the refresh path (`ConnectorRefreshError::UpstreamRejected(403)`). On the login path, treat as a login failure with a dedicated error message pointing operators at the rate-limit headers.
- **A team is renamed on GitHub between sessions**: the connector identifies teams by `org-slug:team-slug`. A renamed slug produces a different mapping key — the PR-GROUPS-PIPELINE reconciler will drop the old marker and add the new one on the next login/refresh cycle. Admins who rely on stable mapping should configure `teamNameField = slug` (default).
- **Email collision on JIT provisioning**: the same verified email is shared by a pre-existing netidm Person and the freshly authenticating GitHub account. Existing netidm behaviour for provider-initiated-login collision applies (PR-LINKBY logic from `003-oauth2-email-linking`) — this PR does not change collision resolution, only the connector that triggers it.
- **Connector entry's `client_secret` has been rotated on GitHub but not yet updated in netidm**: the code exchange returns `invalid_client`; the user sees a failed-login page; the connector does NOT quietly proceed.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST provide a GitHub connector that handles the OAuth2 authorization-code flow against `github.com` (default) or a configured GitHub Enterprise host, using the scopes necessary to fetch userinfo, primary verified email, and org/team membership.
- **FR-002**: After a successful authorization-code exchange, the system MUST fetch (a) the user's profile, (b) the user's verified email list, and (c) the user's org + team membership. Only verified emails count for Person provisioning/linking.
- **FR-003**: The system MUST use the user's stable numeric GitHub ID — NOT the mutable `login` handle — as the upstream subject identifier written to the session's upstream-refresh state. A changed `login` MUST resolve to the same netidm Person on the next login.
- **FR-004**: The system MUST translate GitHub team membership into upstream group names of the form `org-slug:team-slug`, then run those names through the connector entry's existing `OAuth2GroupMapping` table (PR-GROUPS-PIPELINE) to produce the netidm group UUID set. The existing `reconcile_upstream_memberships` helper MUST be reused — no parallel reconciliation.
- **FR-005**: The connector MUST honour an optional admin-configured org allowlist (`OAuth2ClientGithubOrgFilter`, multi-value). When non-empty, teams from orgs outside the allowlist MUST be silently dropped before reaching the mapping reconciler. The org allowlist is strictly a GROUP-MAPPING FILTER — a user whose orgs do not intersect the allowlist still succeeds in logging in (subject to FR-005a's access gate); their outgoing session simply carries no upstream-synced groups for this connector. This is distinct from FR-005a (access gate) to give admins independent levers.
- **FR-005a**: The connector MUST honour an optional admin-configured team-based access gate (`OAuth2ClientGithubAllowedTeams`, multi-value, each entry in `org-slug:team-slug` form). When non-empty, a login MUST succeed only if the user's set of GitHub team memberships intersects the allowed-teams list. When the intersection is empty, the login MUST be rejected BEFORE any Person provisioning, linking, or group-mapping logic runs — no upstream-synced markers are written, no session is minted, no JIT provisioning is attempted. An empty or absent `OAuth2ClientGithubAllowedTeams` attribute means the access gate is off. The access gate applies FIRST, before the org-filter (FR-005) and before the linking chain (FR-013a).
- **FR-006**: The connector MUST honour an optional admin-configured team-name-rendering policy: `slug` (default), `name`, or `both`. The policy affects the upstream-group-name string fed to the mapping reconciler.
- **FR-007**: The connector MUST honour an optional admin-configured preferred-email-domain: if set, and the user has multiple verified emails, pick the first verified email whose domain matches; fall back to the primary-marked verified email otherwise. If unset, use the primary-marked verified email.
- **FR-008**: The connector MUST implement the `RefreshableConnector` trait defined by PR-REFRESH-CLAIMS. On refresh, it MUST re-fetch the user's team membership from GitHub using the stored session state, run the fresh set through the mapping reconciler (via the preflight diff the refresh handler already performs), and return the refreshed claims or an appropriate `ConnectorRefreshError`.
- **FR-009**: On refresh, if the stored GitHub access token has expired AND a stored refresh token is present, the connector MUST silently exchange the refresh token for a new access token before calling the team APIs. Any failure of that exchange MUST map to `ConnectorRefreshError::TokenRevoked`.
- **FR-010**: On refresh, a returned GitHub user ID that differs from the session's originally-stored ID MUST map to `ConnectorRefreshError::TokenRevoked`. (This is a defence against a compromised connector returning someone else's identity — enforced at the refresh call site per PR-REFRESH-CLAIMS R2.)
- **FR-011**: The connector MUST handle paginated GitHub responses (`Link: <next>` header) on the teams endpoint up to a bounded page count (e.g. 50 pages of 100 teams — 5000 memberships). Users in excess of the bound see the first N pages; operators see a warning log. This cap prevents a malicious or misconfigured GitHub account from consuming unbounded memory.
- **FR-012**: GitHub API error responses MUST translate to the correct `ConnectorRefreshError` variant on the refresh path and to a human-readable failure page on the login path. Specifically: 4xx → `UpstreamRejected(status)` / failed-login; 5xx → `Network(...)` / failed-login; parsing errors → `Serialization(...)` / failed-login; anything else → `Other(...)` / failed-login.
- **FR-013**: The connector MUST NOT write unverified GitHub emails into netidm. A user whose email list contains only unverified entries is permitted to authenticate (provided FR-005a's access gate and FR-013a's linking chain clear them); the Person's email field MUST be left empty in that case, or left untouched for an already-linked Person. This is an intentional divergence from dex (which rejects such users) — motivated by the netidm principle that GitHub IDs / logins are sufficiently stable identifiers in their own right and do not require an email to exist.
- **FR-013a**: The connector MUST resolve a first-time GitHub login to an existing or new netidm Person via a four-step fallback chain, evaluated in order: (1) if the user has at least one verified email AND a Person exists whose email matches → link to that Person; (2) else if a Person exists whose stored upstream-subject-for-this-connector equals the GitHub numeric ID → link to that Person; (3) else if a Person exists whose stored upstream-subject-for-this-connector equals the GitHub login → link to that Person; (4) else: if `OAuth2ClientGithubAllowJitProvisioning` is `true` → provision a new Person (netidm name derived from the GitHub login, display name + verified email populated where available); if the flag is `false` → reject the login with an operator-guided error. Each successful step MUST persist both the numeric ID AND the current GitHub login on the resulting Person as its upstream-subject-for-this-connector (the numeric ID is authoritative for future identity-chain matches; the login is a human-readable fallback kept in sync on every login).
- **FR-014**: Admins MUST be able to configure every connector parameter (provider-kind selector, host, org-filter, allowed-teams, team-name-field, load-all-groups flag, preferred-email-domain, allow-jit-provisioning, client-id, client-secret, group-mapping) via the existing OAuth2 admin CLI + client SDK, without needing direct DB modifications. New CLI verbs MUST follow the shape established by PR-GROUPS-PIPELINE's admin verbs.
- **FR-015**: At netidmd boot, the system MUST scan all `OAuth2Client` entries, identify those whose provider-kind attribute is `"github"`, and register a concrete `GitHubConnector` instance for each one against the `ConnectorRegistry` introduced by PR-REFRESH-CLAIMS. Changes to the connector entry's config require a netidmd restart to take effect (same semantics as the existing OIDC connector).
- **FR-016**: The connector MUST NOT change the existing netidm OAuth2 callback URL, token endpoint path, or any externally-visible HTTP surface.
- **FR-017**: The connector MUST honour a per-connector admin flag `OAuth2ClientGithubAllowJitProvisioning` (bool, default `false`) controlling whether a first-time GitHub user with no match from FR-013a steps 1–3 is auto-provisioned (step 4) or rejected. The default is `false` (most conservative — pre-provision required) to match the netidm constitution's §V Security-by-Hierarchy preference for Elimination over Administrative Controls. Admins explicitly opting into JIT for their deployment accept the "any GitHub account at our configured host can create a netidm account" surface area.

### Key Entities *(include if feature involves data)*

- **`OAuth2Client` (extended, DL28)**: existing entity. Gains eight new optional attributes that configure a GitHub connector specifically when `OAuth2ClientProviderKind == "github"`:
  - `OAuth2ClientGithubHost` (URL, single) — default `https://github.com`.
  - `OAuth2ClientGithubOrgFilter` (utf8, multi) — group-mapping filter (FR-005). Empty = no filter.
  - `OAuth2ClientGithubAllowedTeams` (utf8, multi, `org-slug:team-slug`) — access gate (FR-005a). Empty = gate off.
  - `OAuth2ClientGithubTeamNameField` (iutf8, single, enum `slug`/`name`/`both`) — default `slug`.
  - `OAuth2ClientGithubLoadAllGroups` (bool, single) — default `false`.
  - `OAuth2ClientGithubPreferredEmailDomain` (iutf8, single) — optional.
  - `OAuth2ClientGithubAllowJitProvisioning` (bool, single) — default `false` (FR-017).
  All additions are optional with documented defaults; pre-DL28 entries continue to behave as before.
- **`OAuth2ClientProviderKind`**: discriminator attribute selecting the concrete connector implementation. This PR introduces value `"github"`; the absence of the attribute means `"generic-oidc"` (backwards compatibility with the existing PR-OIDC-CONNECTOR path).
- **`GitHubConnector` (in-memory)**: process-local connector instance registered in `ConnectorRegistry` at boot. Holds host, org filter, team-name-field policy, load-all-groups flag, preferred-email-domain, and HTTP-client configuration. Does NOT persist any state — its inputs come from the OAuth2Client entry at boot, and its per-session state flows through the opaque blob defined by PR-REFRESH-CLAIMS FR-009.
- **Upstream-session state blob (opaque, per-session)**: connector-owned serialisation of the GitHub access token, (optional) refresh token, the stored user ID, and the access-token expiry. Stored verbatim by netidm core per PR-REFRESH-CLAIMS; interpreted only by the `GitHubConnector`. Size bound: a few kB (two opaque tokens plus metadata).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An end user with a configured GitHub connector can complete a "log in with GitHub" flow in under 10 seconds wall-clock time (bounded by GitHub's own response latency plus netidm-internal processing under 500 ms).
- **SC-002**: Team membership changes on GitHub flow into downstream RP tokens within one refresh cycle — consistent with PR-REFRESH-CLAIMS SC-001 — for 100% of connector-bound sessions.
- **SC-003**: A user who is in 50 teams sees all 50 mapped groups in their session (pagination works end-to-end). A user who is in excess of the FR-011 page-count cap sees the first N pages and the deployment logs a warning.
- **SC-004**: An admin can stand up a new GitHub connector end-to-end (GitHub-side OAuth app creation, netidm-side connector config, test login) in under 15 minutes following the connector documentation.
- **SC-005**: GitHub Enterprise deployments route 100% of upstream HTTP calls to the configured host; zero leakage to `github.com` or `api.github.com` when a custom host is set.
- **SC-006**: The connector's HTTP footprint per login is bounded — no more than 1 authorization redirect, 1 token exchange, and 4 REST calls (`/user`, `/user/emails`, `/user/orgs`, `/user/teams` — pagination counted separately). Each refresh is bounded by 3 REST calls (`/user/orgs`, `/user/teams`, plus at most 1 token refresh).

## Assumptions

- **PR-GROUPS-PIPELINE (DL25) is deployed and on main** — group-mapping storage, the locally-managed vs upstream-synced tagging, and the `reconcile_upstream_memberships` helper all already exist. This PR is the second consumer of that plumbing (after the refresh path from PR-REFRESH-CLAIMS).
- **PR-REFRESH-CLAIMS (DL27) is on main** — the `RefreshableConnector` trait, `ConnectorRegistry`, and per-session upstream-refresh-state blob machinery are all landed. The trait shape is frozen; this PR is its first concrete implementation.
- **PR-REFRESH-CLAIMS tests (branch `011-refresh-claims-tests`) are in-flight in parallel** — this PR does not block on them. The trait is not going to change.
- **Onboarding default is conservative**: `allow_jit_provisioning` defaults to `false` — every new deployment requires admins to either pre-provision Persons or explicitly flip the flag. This avoids the "anyone with a GitHub account at our configured host can create an account here" surface area by default.
- **The OAuth app's `client_secret` is stored encrypted** via the existing netidm key-provider infrastructure (same pattern PR-OIDC-CONNECTOR established).
- **Release notes are hand-written at tag time** — this PR does not touch `RELEASE_NOTES.md`.
- **Other connectors (Generic-OIDC, Google, Microsoft, ...) ride the same trait interface** — this PR validates the trait shape. If it needs adjustment, the adjustment lands here and propagates back to PR-REFRESH-CLAIMS; subsequent connector PRs (#5+) inherit the final shape.
- **Test coverage uses an in-process mock GitHub server** (`wiremock` or equivalent) rather than hitting real GitHub. `cargo test` must remain self-contained per constitution §III.
- **GitHub App authentication is out of scope** — this PR uses the OAuth App flow only, matching dex. A separate future PR could add GitHub App support if netidm grows a use case.
- **Secrets posture**: at no point does the connector log or persist the user's GitHub access or refresh token in plaintext outside the opaque session-state blob that netidm stores (which sits in the same MVCC store as other credentials, with the same ACP gates).
