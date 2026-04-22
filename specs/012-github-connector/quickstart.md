# Quickstart: GitHub Upstream Connector (PR-CONNECTOR-GITHUB)

Operator-facing test scenarios. Each maps to one user story and the acceptance scenarios inside it. Each scenario is reproducible on a fresh DL28 database with nothing but netidmd and an in-process mock GitHub server (see `spawn_mock_github_server()` in `netidmd_testkit`).

## Prerequisites

- netidmd built from this branch, running at DL28.
- `netidm` CLI configured.
- An `OAuth2Client` entry in the netidm DB configured as:
  ```
  name = "corp-github"
  OAuth2ClientProviderKind = "github"
  OAuth2ClientGithubHost = https://github.com        # or the mock server URL in tests
  OAuth2ClientGithubAllowJitProvisioning = false     # default
  client_id, client_secret             = <OAuth app values from github.com/settings/developers>
  ```
- A group-mapping table on the same entry, populated via PR-GROUPS-PIPELINE CLI:
  ```
  acme:platform → <netidm-uuid-of-platform-admin>
  acme:audit    → <netidm-uuid-of-audit-readers>
  ```
- For integration tests, `spawn_mock_github_server()` returns a handle that pre-registers Alice as GitHub user `id=42, login=alice` in teams `acme:platform` and `acme:audit`.

---

## Scenario 1 (US1): End user logs in, teams map to groups

**Given** Alice (GitHub user `id=42, login=alice`) is in `acme:platform` + `acme:audit`, the connector is configured with default settings (no access gate, no org filter), and a netidm Person exists with the verified email `alice@acme.com` (same as her GitHub primary verified email).

**When** she visits the downstream RP, picks "Log in with GitHub", consents at GitHub, and is redirected back:

**Then**:
- She is linked to the existing Person (step 1 of the linking chain — verified email match).
- The Person entry is updated with `OAuth2AccountProvider = <connector-uuid>`, `OAuth2AccountUniqueUserId = "42"` (and a second record with `"alice"`).
- Upstream-synced markers are added on her Person for `platform-admin` and `audit-readers`.
- Her outgoing netidm session's `groups` claim contains `platform-admin` and `audit-readers`.

**Test**: `test_github_login_links_by_email_and_maps_teams_to_groups` — drives all the above against the mock.

---

## Scenario 2 (US2): Team-based access gate rejects disallowed user

**Given** the connector is configured with `OAuth2ClientGithubAllowedTeams = ["acme:employees"]`. Bob is a GitHub user in `acme:contractors` + `acme:external` — but NOT in `acme:employees`.

**When** Bob attempts to log in:

**Then**:
- The authorize/code-exchange/fetch steps succeed.
- Immediately after the fetch, the access-gate check finds `{contractors, external} ∩ {employees} = ∅`.
- Login is rejected with an operator-guided error page: "Your GitHub account does not have permission to access this system."
- No Person is provisioned. No linking-chain step runs. No `OAuth2AccountProvider` record is written. No Oauth2Session row is created. No group-mapping reconciliation occurs.

**Test**: `test_github_login_rejected_by_team_access_gate`. Also tests the positive case (Bob added to `acme:employees` → subsequent login succeeds).

---

## Scenario 3 (US3): JIT provisioning toggle

**Given** the connector is configured with `OAuth2ClientGithubAllowJitProvisioning = false` (default). Carol is a GitHub user (`id=100, login=carol`) with no matching netidm Person via email/ID/login.

**When** Carol attempts to log in:

**Then (Part A — JIT off)**:
- The 4-step linking chain is evaluated.
- Steps 1, 2, 3 all miss (no email match, no ID match, no login match).
- Step 4 sees `allow_jit_provisioning = false` → rejected.
- Error page: "No netidm account is provisioned for your GitHub user. Please contact your administrator."
- No Person is created.

**Given (Part B)** the admin runs `netidm oauth2 set-allow-jit-provisioning corp-github true` and restarts netidmd (config is read at boot).

**When** Carol attempts to log in a second time:

**Then (Part B — JIT on)**:
- Same linking-chain misses through step 3.
- Step 4 sees `allow_jit_provisioning = true` → provisions a new Person with `name = "carol"`, display name from GitHub, email from her verified emails, linked to the connector with `OAuth2AccountUniqueUserId = "100"` and `"carol"`.
- Login succeeds; subsequent sessions for Carol resolve via step 2 (ID match) without JIT.

**Test**: `test_github_jit_provisioning_toggle_respects_admin_flag` — exercises both halves.

---

## Scenario 4 (US4): Org filter silently drops out-of-org teams from groups

**Given** the connector is configured with `OAuth2ClientGithubOrgFilter = ["acme"]` and `OAuth2ClientGithubAllowedTeams = []` (access gate off). Dave is in `acme:platform` + `external:contractor`. The group-mapping table includes entries for both orgs' teams.

**When** Dave logs in:

**Then**:
- Login succeeds (no access gate rejection).
- Only `acme:platform` reaches the group-mapping reconciler.
- Dave's outgoing session's `groups` claim contains `platform-admin` but NOT the `external`-derived group.
- His Person's `OAuth2UpstreamSyncedGroup` markers reflect only the `acme`-scoped groups.

**Negative variant (same config, Dave in ONLY `external:contractor`)**:
- Login SUCCEEDS (org filter is NOT an access gate per FR-005).
- His session carries no upstream-synced groups for this connector.

**Test**: `test_github_org_filter_narrows_group_mapping_without_rejecting_login`.

---

## Scenario 5 (US5): GitHub Enterprise

**Given** the connector is configured with `OAuth2ClientGithubHost = https://github.acme.internal` (mock server URL in tests).

**When** any user logs in:

**Then**:
- The authorize URL is `https://github.acme.internal/login/oauth/authorize`.
- The code exchange hits `https://github.acme.internal/login/oauth/access_token`.
- The REST calls hit `https://github.acme.internal/api/v3/user`, `/user/emails`, `/user/orgs`, `/user/teams`.
- Zero requests land on `github.com` or `api.github.com`.

**Test**: `test_github_enterprise_host_routing` — mock server instrumented to record request URLs; assert none outside the configured host.

---

## Scenario 6 (US6): Refresh re-fetches team membership

**Given** Alice from Scenario 1. Her session was minted through the GitHub connector and includes `platform-admin` in her groups claim.

**When**:
1. The mock GitHub server mutates: `set_teams(42, [])` (Alice is no longer in any team).
2. Alice's downstream RP exchanges the refresh token against netidm's `/oauth2/token` with `grant_type=refresh_token`.

**Then**:
- The refresh handler finds `Oauth2Session::upstream_connector = Some(<github-connector-uuid>)` and dispatches to `GitHubConnector::refresh`.
- The connector re-fetches `/user/orgs` + `/user/teams` against the mock (now returning `[]`).
- The new `RefreshOutcome::claims.groups` is empty (for this connector's contribution).
- The preflight diff at the refresh handler (PR-REFRESH-CLAIMS FR-010) sees desired `{}` vs existing `{platform-admin, audit-readers}` → reconciles, removes the upstream-synced markers, emits one `refresh_claims.groups_changed` span with `groups_removed = [platform-admin, audit-readers]`.
- The new access token's `groups` claim no longer contains those two groups.
- Alice's Person entry shows no upstream-synced markers for this connector (locally-managed memberships untouched per FR-004).

**Negative variants**:
- Mock set to `fail_next(500)` → refresh returns `ConnectorRefreshError::Network(...)` → netidm token endpoint responds `invalid_grant`.
- Mock set to `fail_next(401)` → refresh returns `ConnectorRefreshError::TokenRevoked` → netidm token endpoint responds `invalid_grant`.
- Mock returns a user with `id=99` (mismatch vs session's stored `id=42`) → subject-consistency check trips at the refresh call site → `invalid_grant`.

**Test**: `test_github_refresh_reflects_upstream_team_mutation` + three parameterised failure-mode tests.

---

## How to run from integration tests

| Scenario | Test name (proposed) |
|---|---|
| 1 | `test_github_login_links_by_email_and_maps_teams_to_groups` |
| 2 | `test_github_login_rejected_by_team_access_gate` |
| 3 | `test_github_jit_provisioning_toggle_respects_admin_flag` |
| 4 | `test_github_org_filter_narrows_group_mapping_without_rejecting_login` |
| 5 | `test_github_enterprise_host_routing` |
| 6 | `test_github_refresh_reflects_upstream_team_mutation` |

All six live in `server/testkit/tests/testkit/github_connector_test.rs` and use `netidmd_testkit::spawn_mock_github_server()` to control the upstream between requests.

## How to run manually on a live netidmd

1. Register an OAuth app at `https://github.com/settings/developers` with the netidm callback URL.
2. On the netidm side:
   ```bash
   netidm oauth2 basic-create corp-github "Corp GitHub" https://netidm.corp.example
   netidm oauth2 set-provider-kind corp-github github
   netidm oauth2 github set-host corp-github https://github.com
   # Optional: tighten access
   netidm oauth2 github add-allowed-team corp-github acme:employees
   netidm oauth2 github add-org-filter corp-github acme
   # Optional: JIT
   netidm oauth2 github set-allow-jit-provisioning corp-github true
   # Group mapping (inherited from PR-GROUPS-PIPELINE)
   netidm oauth2 client-add-group-mapping corp-github acme:platform <uuid-of-platform-admin>
   ```
3. Restart netidmd so the connector-registry picks up the new entry.
4. Visit a downstream RP and click "Log in with GitHub".
