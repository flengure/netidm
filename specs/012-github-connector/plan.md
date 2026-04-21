# Implementation Plan: GitHub Upstream Connector (PR-CONNECTOR-GITHUB)

**Branch**: `012-github-connector` | **Date**: 2026-04-21 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/012-github-connector/spec.md`

## Summary

Port dex's `connector/github/github.go` to netidm as the first concrete implementation of the `RefreshableConnector` trait introduced by PR-REFRESH-CLAIMS (DL27). A GitHub OAuth app acts as the upstream identity provider; netidm exchanges the authorisation code against GitHub's token endpoint, fetches profile + verified-emails + team membership, applies a team-based access gate (new), an org-scoped group-mapping filter (existing pattern), and either links the user to an existing Person (via verified email, stored GitHub numeric ID, or stored GitHub login) or JIT-provisions one (when the admin has explicitly enabled provisioning). On every refresh-token exchange thereafter, the refresh path already landed by PR-REFRESH-CLAIMS dispatches to this connector to re-fetch the user's current team set; changes propagate into the next access token's `groups` claim within one refresh cycle.

Scope-wise this PR is entirely additive — DL28 introduces a new `OAuth2ClientProviderKind` discriminator attribute plus seven GitHub-specific config attrs on `EntryClass::OAuth2Client`; existing pre-DL28 entries (absent provider-kind) continue to behave as `"generic-oidc"` via PR-OIDC-CONNECTOR's path. No change to the external HTTP surface (FR-016). The only new HTTP traffic is outbound GitHub REST (max 4 REST calls per login, max 3 per refresh).

## Technical Context

**Language/Version**: Rust stable (see `rust-toolchain.toml`)
**Primary Dependencies**: Existing — `netidmd_lib` (MVCC entry DB, DL migration framework, `RefreshableConnector` trait + `ConnectorRegistry` from PR-REFRESH-CLAIMS, `reconcile_upstream_memberships` + `OAuth2GroupMapping` from PR-GROUPS-PIPELINE), `netidm_proto` (Attribute / EntryClass / constants), `reqwest` (already in `server/core`; use for outbound GitHub REST), `serde` + `serde_json` (already in tree — for GitHub response deserialisation + opaque session-state blob serialisation), `async-trait` (already added in PR-REFRESH-CLAIMS), `url`, `hashbrown`. No new workspace deps.
**New Dependencies**: None for production code. Phase 0 chooses between using existing `wiremock` dev-dep (if present) vs hand-rolled `axum` mock for the GitHub-server stub in integration tests.
**Storage**: Netidm MVCC entry database. DL28 migration adds:
- One new discriminator attribute `OAuth2ClientProviderKind` (iutf8, single-value) on `EntryClass::OAuth2Client`. Values used in this PR: `"github"`. Absence = `"generic-oidc"` (backwards compatibility with PR-OIDC-CONNECTOR).
- Seven GitHub-specific config attributes on `EntryClass::OAuth2Client` (all optional, documented defaults): `OAuth2ClientGithubHost` (URL), `OAuth2ClientGithubOrgFilter` (utf8, multi), `OAuth2ClientGithubAllowedTeams` (utf8, multi), `OAuth2ClientGithubTeamNameField` (iutf8, single, enum `slug`/`name`/`both`), `OAuth2ClientGithubLoadAllGroups` (bool, single), `OAuth2ClientGithubPreferredEmailDomain` (iutf8, single), `OAuth2ClientGithubAllowJitProvisioning` (bool, single).
- DL28 ACP extensions: the existing OAuth2 admin ACPs gain read/write on the new attributes. No new entry class, no new ACP entity.
- Connector-persistent session-state blob reuses the existing `Oauth2Session::upstream_refresh_state` (`Option<Vec<u8>>`) field landed by PR-REFRESH-CLAIMS (FR-009). Connector-owned JSON format.

**Testing**: `cargo test` via `server/testkit` integration infrastructure (real in-process netidmd) plus a mock GitHub server spun up inside the test process — `wiremock` crate if available, hand-rolled `axum` mock otherwise. Unit tests co-located in `idm/github_connector.rs` module; integration tests in `server/testkit/tests/testkit/github_connector_test.rs` (new file).
**Target Platform**: Linux server (same as rest of netidm).
**Project Type**: Library + HTTP service (tri-crate touches: `server/lib`, possibly `libs/client` + `tools/cli` for admin verbs; `server/core` unchanged — the connector registry hook already exists on `IdmServer` as of PR-REFRESH-CLAIMS).
**Performance Goals**:
- Login path: bounded at 1 authorize redirect + 1 token exchange + 4 REST calls (`/user`, `/user/emails`, `/user/orgs`, `/user/teams`) + pagination. End-to-end wall-clock under 10 s per SC-001; netidm-internal overhead on top of GitHub's own latency under 500 ms.
- Refresh path: bounded at 3 REST calls (`/user/orgs`, `/user/teams`, plus at most 1 token refresh). Latency contract inherited from PR-REFRESH-CLAIMS SC-005 (≤20% tail-latency overhead).
- HTTP client: shared `reqwest::Client` per connector instance with 10 s per-call timeout, `User-Agent: netidm/<version> (connector-github)` header, HTTPS only.

**Constraints**:
- Doc comments on every new `pub` item per constitution §Documentation Standards.
- `cargo clippy -- -D warnings` must remain clean (§IV).
- `cargo test` (default features) must pass — no `--all-features`.
- `cargo test` must NOT hit the real GitHub API (§III Correct & Simple — `git clone && cargo test` must work on a clean checkout with no external services). Mock GitHub server runs in-process.
- Opaque session-state blob MUST NOT include plaintext anywhere accessible from logs (the existing MVCC encryption of the entry itself is sufficient; connector code must not log the blob contents).
- The `GitHubConnector` trait impl dispatches over the trait object; per-login state is constructed from the opaque blob at call time, not cached across calls.
- Pagination cap: 50 pages × 100 teams = 5000 team memberships per user. Exceeding this emits a `warn!` log and returns the first 5000 (FR-011).
- GitHub's numeric user ID (`id` field from `GET /user`, an `i64`) is the stable subject identifier; never the `login` handle (which is mutable).

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Ethics & Human Rights | PASS | No new PII fields beyond what GitHub already exposes. Stored upstream-subject is the GitHub numeric ID (stable, admin-visible via existing Person-read ACPs). Users retain self-control: revoking the OAuth app on GitHub invalidates all refresh tokens (FR-009 → `ConnectorRefreshError::TokenRevoked`); netidm-side revocation via existing session-termination paths still works. Name fields remain case-sensitive UTF-8 — GitHub logins propagated as-is. |
| II. Humans First | PASS | `allow_jit_provisioning` defaults to `false` (safest). Team-based access gate (FR-005a) rejects disallowed users BEFORE any Person entry is written — users who shouldn't have accounts never get ghost entries. Admin CLI accepts client entries by name or UUID. Login-path failure pages are human-readable and tell the user what to do (contact admin, re-link, etc.). |
| III. Correct & Simple | PASS | `cargo test` remains self-contained — mock GitHub runs in-process. No new runtime dependency. No new storage engine. The `GitHubConnector` struct fits on one page; the trait impl on another. |
| IV. Clippy & Zero Warnings | PASS | No `#[allow(...)]` planned. `hashbrown::HashSet` used for team-set intersections. `async_trait` already in workspace deps. |
| V. Security by Hierarchy | PASS | **Elimination**: access gate (FR-005a) rejects unauthorised users before any state is written. **Substitution**: link-by-ID instead of link-by-login where both are known. **Engineering Control**: connector registry is immutable-at-boot; adding a connector requires restart. **Administrative Control**: failure-mode logs include connector UUID + user UUID for post-mortem; RP sees only `invalid_grant`. |
| Security Standards | PASS | FR-005a denies on validation failure — no partial-auth states. Secrets: connector log path does NOT include the opaque session-state blob, GitHub tokens, or client secret. Post-logout revocation works via existing session-termination (PR-RP-LOGOUT). |
| Documentation Standards | REQUIRED | Doc comments on every new `pub` item: `GitHubConnector` struct + methods, `GitHubConfig`, `GitHubSessionState` (opaque blob type), all new `Attribute::*` variants, new CLI opts, new client SDK methods. `# Errors` on every `Result`-returning `pub fn` added. `# Examples` on `GitHubConnector::from_entry`. |
| Testing Standards | REQUIRED | Unit tests for (a) GitHub response parsers against captured fixtures, (b) team-name-field rendering, (c) orgs-filter semantics, (d) allowed-teams access-gate intersection, (e) preferred-email-domain selection, (f) linking-chain step ordering, (g) `RefreshableConnector::refresh` happy + each `ConnectorRefreshError` variant, (h) pagination via mock `Link` header. Integration test (testkit + mock GitHub): drive US1 end-to-end + demonstrate US2/US3/US4/US5/US6. |
| DL Migration | REQUIRED | DL28 migration introduced; round-trip test asserts (a) an existing DL27 DB with OAuth2Client entries upgrades cleanly, (b) new attributes default to `None` / empty on existing entries, (c) new config writes round-trip through the DL28 serializer. |

No constitution violations. No Complexity Tracking entries required.

## Project Structure

### Documentation (this feature)

```text
specs/012-github-connector/
├── plan.md              # This file
├── research.md          # Phase 0 design decisions + dex parity notes
├── data-model.md        # Phase 1 entity model (DL28 attributes + in-memory connector)
├── quickstart.md        # Phase 1 operator scenarios (1 per user story)
├── contracts/
│   ├── github-api.md            # Which GitHub REST endpoints we consume + request/response shapes
│   └── connector-dispatch.md    # How the callback routes by OAuth2ClientProviderKind
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Generated by /speckit.tasks
```

### Source Code Changes

```text
proto/src/
├── attribute.rs                                # + OAuth2ClientProviderKind,
│                                                 + OAuth2ClientGithubHost,
│                                                 + OAuth2ClientGithubOrgFilter,
│                                                 + OAuth2ClientGithubAllowedTeams,
│                                                 + OAuth2ClientGithubTeamNameField,
│                                                 + OAuth2ClientGithubLoadAllGroups,
│                                                 + OAuth2ClientGithubPreferredEmailDomain,
│                                                 + OAuth2ClientGithubAllowJitProvisioning
└── constants.rs                                # + ATTR_* const strings (one per new attribute)

server/lib/src/
├── constants/
│   ├── mod.rs                                  # DOMAIN_LEVEL_28; bump TGT/MAX; PREVIOUS follows
│   └── uuids.rs                                # UUID_SCHEMA_ATTR_* (8 new UUIDs)
├── idm/
│   ├── github_connector.rs                     # NEW: GitHubConnector struct, GitHubConfig
│   │                                                    parsed from OAuth2Client entry at boot,
│   │                                                    GitHubSessionState (opaque blob),
│   │                                                    RefreshableConnector impl,
│   │                                                    GitHub REST client + pagination helper,
│   │                                                    access-gate + org-filter semantics,
│   │                                                    linking-chain implementation,
│   │                                                    unit tests with captured fixtures
│   ├── oauth2_connector.rs                     # no changes — trait + registry stay unchanged
│   ├── authsession/
│   │   └── provider_initiated.rs               # dispatch on OAuth2ClientProviderKind:
│   │                                                    "github" → github_connector;
│   │                                                    absent/"generic-oidc" → existing OIDC path
│   └── server.rs                               # IdmServer::start — scan OAuth2Client entries
│                                                  with ProviderKind = "github", build a
│                                                  GitHubConnector per entry, register in
│                                                  connector_registry
├── server/
│   └── migrations.rs                           # migrate_domain_27_to_28 phase;
│                                                 round-trip test
└── migration_data/dl28/
    ├── mod.rs                                  # NEW: phase_1_schema_attrs, phase_7_acp_updates
    ├── schema.rs                               # + 8 new SCHEMA_ATTR_* statics
    └── access.rs                               # + IDM_ACP_OAUTH2_MANAGE_DL28 (extends DL26
                                                  OAuth2 admin ACP with the 8 new attrs)

libs/client/src/oauth.rs                        # + 9 client SDK methods (set-provider-kind +
                                                  the 7 GitHub-specific attrs + set-group-mapping
                                                  pass-through wrapping); mirror the shape of
                                                  idm_oauth2_client_set_backchannel_logout_uri
                                                  from PR-RP-LOGOUT

tools/cli/src/
├── opt/netidm.rs                               # + OAuth2Opt::SetProviderKind +
│                                                 + OAuth2Opt::GitHub subcommand tree:
│                                                 SetHost / AddOrgFilter / RemoveOrgFilter /
│                                                 AddAllowedTeam / RemoveAllowedTeam /
│                                                 SetTeamNameField / SetLoadAllGroups /
│                                                 SetPreferredEmailDomain /
│                                                 SetAllowJitProvisioning + Clear- siblings
└── cli/oauth2.rs                               # + handlers for the new CLI verbs

server/testkit/
├── src/lib.rs                                  # + spawn_mock_github_server() helper + fixture
│                                                  JSON literals; pub-reachable so integration
│                                                  tests can configure the mock
└── tests/testkit/
    └── github_connector_test.rs                # NEW: integration tests — one per user story
                                                  driving the full HTTP login/refresh flow
                                                  against the in-process mock GitHub
```

**Structure Decision**: Single new connector module in `server/lib/src/idm/github_connector.rs` (sibling to `oauth2.rs`, `oauth2_connector.rs`) — matches the structural precedent set by PR-REFRESH-CLAIMS. The dispatch hook in `authsession/provider_initiated.rs` branches on the discriminator attribute so later connectors (#5 Generic-OIDC, #6 Google, #7 Microsoft, ...) each add a sibling module and a new match arm without touching this connector's code. Zero new external HTTP paths (FR-016).

## Complexity Tracking

No constitution violations, no extra complexity to justify.

## Phases

### Phase 0: Research (research.md)

1. **Dex parity review — `connector/github/github.go`**
   - Read dex's implementation and document behavioural quirks the spec doesn't explicitly anchor: pagination defaults, `Accept` header values, error-response parsing, rate-limit handling.
   - Note any dex behaviour that's a workaround for a GitHub-specific quirk; inherit those workarounds.
   - Diverge only where the spec explicitly does (no-verified-email handling per FR-013; team-based access gate per FR-005a, which dex does not have as a first-class concept).
2. **Linking-chain infrastructure**
   - Does netidm already persist `upstream_subject_per_connector` on Person entries? (PR-LINKBY's `003-oauth2-email-linking` likely defined this.)
   - If yes, reuse the attribute and its lookup index.
   - If no, define how the GitHub connector stores the `(connector_uuid, github_id, github_login)` tuple. Options: a new multi-value attribute on `Person`, or extend an existing OAuth2-subject-indexed attribute from PR-LINKBY.
3. **Provider-initiated callback dispatch**
   - Locate the existing OIDC-connector callback handler (PR-OIDC-CONNECTOR `006-oidc-connector`).
   - Decide: (a) add a `match kind` branch at the top of that handler, or (b) add a new route + handler for `kind = "github"`.
   - **Tentative decision**: (a) — single callback URL + inner dispatch keeps the external contract stable (FR-016 — zero new HTTP paths).
4. **Mock GitHub server — `wiremock` vs hand-rolled `axum`**
   - Check workspace `Cargo.toml` for existing `wiremock` dev-dependency.
   - If present, reuse. If absent: choose between adding `wiremock` as a dev-dep vs hand-rolling an `axum` mock (precedent: PR-RP-LOGOUT's `spawn_bcl_receiver`).
   - **Tentative decision**: hand-rolled `axum` mock — zero new dependencies, matches the testkit idiom, GitHub's API surface is narrow enough.
5. **Team-pagination cap justification**
   - Dex has no documented cap. GitHub's `/user/teams` supports up to 100 per page.
   - Argue for a conservative 50-page cap = 5000 teams per user — orders of magnitude beyond any real-world deployment while still bounding memory.
   - Document the `warn!` emitted when exceeded.
6. **Connector registration hook at boot**
   - Identify the hook on `IdmServer::start` (added by PR-REFRESH-CLAIMS for `connector_registry`).
   - Document the pattern: enumerate OAuth2Client entries with `OAuth2ClientProviderKind = "github"` → build `GitHubConnector::from_entry(entry)` → `registry.register(entry.uuid, Arc::new(connector))`.
7. **Opaque session-state blob format**
   - Serde struct: `github_id: i64`, `github_login: String`, `github_access_token: String`, `github_refresh_token: Option<String>`, `access_token_expires_at: Option<OffsetDateTime>`, `format_version: u8`.
   - Stored via PR-REFRESH-CLAIMS's `Oauth2Session::upstream_refresh_state: Option<Vec<u8>>`. JSON-encoded then UTF-8 bytes.
   - `format_version = 1` at ship; bumping doesn't require a DL migration (netidm core treats the blob as opaque bytes).
8. **GitHub API `Accept` / `User-Agent` conventions**
   - `Accept: application/vnd.github+json` plus `X-GitHub-Api-Version: 2022-11-28` for GHE.
   - `User-Agent: netidm/<version> (connector-github)` — required by GitHub; missing UA triggers 403.

**Output**: `specs/012-github-connector/research.md` with eight decisions in Decision / Rationale / Alternatives-considered format.

### Phase 1: Design & Contracts

1. **Entity model** → `specs/012-github-connector/data-model.md`:
   - `OAuth2Client` extension — 8 new attributes with types, defaults, invariants.
   - `GitHubConfig` (new, in-memory) — parsed connector configuration built from an `OAuth2Client` entry at `IdmServer::start`; immutable.
   - `GitHubSessionState` (new, serde struct) — the opaque blob stored in `Oauth2Session::upstream_refresh_state`.
   - `GithubUserProfile`, `GithubEmail`, `GithubOrg`, `GithubTeam` (new, serde deserialise targets) — minimal fields; tolerant to GitHub adding new fields.
   - Invariants: `github_id` is stable; `login` is mutable; access gate runs before linking; linking writes both id and current login to the Person.
2. **Interface contracts** → `specs/012-github-connector/contracts/`:
   - `github-api.md` — documented REST surface we consume: `/user`, `/user/emails`, `/user/orgs`, `/user/teams`, `/login/oauth/access_token`. For each: method, required scopes, relevant response fields, pagination handling, recognised error responses.
   - `connector-dispatch.md` — how the provider-initiated callback selects the connector: read `OAuth2ClientProviderKind` from the entry; dispatch to the corresponding module. Includes the rejection-path diagram for the team-based access gate.
3. **Quickstart scenarios** → `specs/012-github-connector/quickstart.md`:
   - Scenario 1 (US1): End user happy path — login + teams → groups.
   - Scenario 2 (US2): Team access gate — disallowed user rejected.
   - Scenario 3 (US3): JIT toggle — `false` rejects unknown user; `true` provisions.
   - Scenario 4 (US4): Org filter — out-of-org teams silently dropped from groups.
   - Scenario 5 (US5): GitHub Enterprise — all calls route to configured host.
   - Scenario 6 (US6): Refresh-time re-fetch reflects upstream team changes.
4. **Agent context update**: run `.specify/scripts/bash/update-agent-context.sh claude`.

**Output**: data-model.md, two contracts/* files, quickstart.md, updated CLAUDE.md.
