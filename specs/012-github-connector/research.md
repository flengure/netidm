# Research: GitHub Upstream Connector (PR-CONNECTOR-GITHUB)

Phase 0 research — resolves the eight items flagged in `plan.md` before Phase 1 design begins. Each decision is recorded as Decision / Rationale / Alternatives considered.

## R1. Dex parity — behavioural quirks to inherit

**Decision**: Inherit the following dex-specific behaviours verbatim:
- **Pagination**: request 100 items per page (`?per_page=100`), follow `Link: <...>; rel="next"` header until absent. Hard-cap at 50 pages (FR-011) — dex has no cap, but we bound ours to prevent unbounded memory on pathological accounts.
- **Accept header**: `application/vnd.github+json` (modern GitHub JSON). Dex previously used `application/vnd.github.v3+json`; we use the newer form GitHub recommends as of 2022.
- **`X-GitHub-Api-Version: 2022-11-28`** on every request (required for newer endpoints on GHE; harmless on public GitHub).
- **Token endpoint `Accept: application/json`**: GitHub's default is `application/x-www-form-urlencoded` response — we override to get JSON.
- **`/user/emails` response field to select**: match `primary: true, verified: true` first; if none, any `verified: true`. Preferred-email-domain (FR-007) applies as a soft preference AFTER verification.
- **Teams endpoint error suppression**: on 404 from a specific `/orgs/{org}/teams/{team}/members/{user}` check, treat as "not a member" rather than "upstream error" (dex does this because the GitHub API returns 404 when the user isn't a team member).

**Diverge from dex** on exactly two points, both driven by the spec's Clarifications:
- No-verified-email handling (FR-013): dex rejects; netidm permits via the ID/login fallback. Motivated by FR-013a's 4-step linking chain.
- Team-based access gate (FR-005a): dex has no first-class concept of "reject login if user isn't in these specific teams" — only a looser "required orgs" setting. netidm adds a stricter team-level gate that runs before all other logic.

**Rationale**: Exact parity is the default so deployments migrating from dex have predictable behaviour. The two divergences are explicit features netidm wants that dex doesn't express cleanly.

**Alternatives considered**:
- Exact 1:1 dex parity including reject-on-no-verified-email. Rejected — user explicitly asked for the more permissive behaviour ("link by github name or id whichever is unique").
- Skip the 50-page cap. Rejected — unbounded memory on a pathological user (e.g. compromised account invited to 10,000 teams) is a DoS surface.

## R2. Linking-chain infrastructure

**Decision**: Reuse the existing PR-LINKBY infrastructure for per-connector upstream-subject storage. The `Attribute::OAuth2AccountProvider` + `Attribute::OAuth2AccountUniqueUserId` attributes already exist on Person entries (added in DL24 as part of `003-oauth2-email-linking`) and support the equivalent of `LinkBy::Id`. The GitHub connector stores `github_id.to_string()` as the `OAuth2AccountUniqueUserId` and the connector UUID as `OAuth2AccountProvider`; a second row per Person carries `github_login` as the `OAuth2AccountUniqueUserId` of a parallel link-record so we can look up by login when the numeric ID isn't known yet.

The 4-step linking chain (FR-013a) is NOT implemented via the existing `find_and_link_account(LinkBy::...)` dispatch, which is single-strategy. The GitHub connector implements its own chain internally:
1. `internal_search` for a Person with a verified email matching any of the user's GitHub verified emails.
2. Else `internal_search` for a Person with `(OAuth2AccountProvider = connector_uuid, OAuth2AccountUniqueUserId = github_id_as_string)`.
3. Else `internal_search` for a Person with `(OAuth2AccountProvider = connector_uuid, OAuth2AccountUniqueUserId = github_login)`.
4. Else: JIT if `allow_jit_provisioning`, else reject.

On any successful step 1–3, the Person is updated to carry BOTH link records (ID and login) so a later rename on GitHub still resolves. Step 4's JIT provisioning also writes both records.

**Rationale**: No new schema needed. The existing (provider, unique-user-id) tuple semantics fits. Chain is internal to the GitHub connector — matching dex's architecture where each connector owns its linking logic.

**Alternatives considered**:
- Add a new `LinkBy::EmailThenId` variant to the existing dispatch. Rejected — turns a generic single-strategy knob into a strategy-specific one, which is awkward for other connectors that might not want the same chain.
- New schema attribute `Attribute::GithubLinkSubject` with explicit tuple-of-id-and-login. Rejected — redundant with the existing pattern.

## R3. Provider-initiated callback dispatch

**Decision**: The existing OAuth2 callback handler in `server/core/src/https/views/login.rs` (or equivalent; PR-OIDC-CONNECTOR added it) dispatches on `OAuth2ClientProviderKind` at the top of the handler. A match arm for `"github"` routes to `github_connector::handle_callback(entry, code, state)`; the default / `"generic-oidc"` path remains untouched.

No new HTTP route. The callback URL stays at its DL24+ path so every connector shares one endpoint (FR-016).

**Rationale**: Single callback URL is the external contract — OAuth apps configured on the GitHub side register this URL once, and every downstream connector rides it. Inner dispatch is cheap (single string comparison on an already-loaded entry).

**Alternatives considered**:
- Per-connector HTTP route (`/oauth2/callback/github`). Rejected — changes the external contract; every OAuth app would need its redirect URI updated on migration to a new connector.
- Dispatch on an enum rather than a string. Rejected — the DL discriminator is inherently a string for forward-compat with connectors that haven't been written yet.

## R4. Mock GitHub server for integration tests

**Decision**: Hand-rolled `axum` mock server in `server/testkit/src/lib.rs`, exported as `pub fn spawn_mock_github_server() -> MockGithub`. No `wiremock` dep (workspace doesn't carry one; adding a dev-dep to match one connector is heavier than rolling ~100 lines of `axum` routes). The mock exposes `set_user(...)`, `set_teams(...)`, `set_orgs(...)`, `fail_next(status)` hooks so tests can drive any scenario without editing fixture JSON at runtime.

**Rationale**: Matches the existing testkit idiom (PR-RP-LOGOUT's `spawn_bcl_receiver` is the precedent). Zero new dependencies. Fast to start / tear down between tests.

**Alternatives considered**:
- `wiremock` crate. Rejected — one-dep-per-connector doesn't scale well; we'll have 14 connector mocks eventually.
- Fixture-file-based static server. Rejected — tests need to mutate state between requests (e.g. "change the team set mid-test to exercise the refresh path"), which fixture files don't support cleanly.

## R5. Team-pagination cap justification

**Decision**: Hard cap at 50 pages × 100 teams-per-page = 5000 team memberships per user. Exceeding emits a `warn!` log with the user's GitHub ID + the truncation count and returns the first 5000 teams. The cap is global (not per-connector-configurable) for this PR.

**Rationale**: 5000 teams is orders of magnitude beyond any real organisational structure. The largest public GitHub orgs peak at ~500 teams; a single user belonging to 5000 would indicate either a bot account or a compromised credential. Cutting off at that point gives the deployment a self-protection lever.

**Alternatives considered**:
- No cap (match dex). Rejected — unbounded memory under pathological input.
- Lower cap (say, 500). Rejected — cuts too close to real-world usage at large orgs.
- Per-connector admin override. Rejected — adds a config surface for an edge case; the default is safe and can be revisited if operational experience surfaces a need.

## R6. Connector registration hook at boot

**Decision**: Add a new step to `IdmServer::start` (or whatever the startup routine is — located by Phase 1 implementation work) that runs AFTER the initial DB read-through and BEFORE the server starts accepting requests. The step:

```rust
let entries = qs_read.internal_search(filter!(f_and!([
    f_eq(Attribute::Class, EntryClass::OAuth2Client.into()),
    f_eq(Attribute::OAuth2ClientProviderKind, PartialValue::new_iutf8("github")),
])))?;
for entry in entries {
    let config = GitHubConfig::from_entry(&entry)?;
    let connector = Arc::new(GitHubConnector::new(config));
    idm_server.connector_registry().register(entry.uuid(), connector);
}
```

Changes to connector config require a netidmd restart to take effect. This matches the existing OIDC-connector pattern (PR-OIDC-CONNECTOR cache: boot-time read, immutable at runtime).

**Rationale**: Restart semantics match netidm's broader posture on configuration reloads — simple, predictable, no mid-flight config drift. Admins who need to rotate a connector client-secret already expect a restart for similar reasons.

**Alternatives considered**:
- Hot-reload on entry change. Rejected — would require a watcher on the `OAuth2Client` entries, mid-flight HTTP-client replacement, and race-window management. Out of scope for this PR; can be added later if demanded.
- Lazy per-request registration. Rejected — per-request config parsing is slow and invites invalid connectors to break individual logins rather than failing fast at boot.

## R7. Opaque session-state blob format

**Decision**: Serde struct `GitHubSessionState` with these fields:
```rust
#[derive(Serialize, Deserialize)]
struct GitHubSessionState {
    format_version: u8,              // 1 at ship; never 0
    github_id: i64,                  // stable subject identifier
    github_login: String,            // captured at mint time; may be stale on refresh
    access_token: String,            // opaque GitHub token
    refresh_token: Option<String>,   // present when GitHub OAuth app uses refresh
    access_token_expires_at: Option<OffsetDateTime>,  // None = no expiry known
}
```
Encoded as JSON → UTF-8 bytes → stored as the opaque blob via PR-REFRESH-CLAIMS's `Oauth2Session::upstream_refresh_state: Option<Vec<u8>>`. Netidm core sees only opaque bytes; only the `GitHubConnector` parses.

`format_version = 1` at ship. Future connector versions bump this field and implement a forward migration inside the connector; no DL migration needed because the blob format is connector-internal.

**Rationale**: Matches PR-REFRESH-CLAIMS R1 (opaque-bytes discipline). `format_version` gives the connector a private-upgrade lever.

**Alternatives considered**:
- Typed tuple variant per-connector in core. Rejected per PR-REFRESH-CLAIMS research — breaks the opaque-bytes contract.
- Omit `format_version`. Rejected — without it, a future blob-format change is indistinguishable from a corrupt legacy entry; mandatory version tag makes future compatibility easier.

## R8. GitHub API `Accept` / `User-Agent` conventions

**Decision**:
- Every outbound request carries `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, and `User-Agent: netidm/<crate-version> (connector-github)`.
- The token endpoint specifically also carries `Accept: application/json` (overrides GitHub's default urlencoded response).
- Authorization header is `Bearer <token>` for REST calls, `Basic <client_id:client_secret>` for the token endpoint.

**Rationale**: GitHub documentation requires the User-Agent on every request — missing it triggers 403. The version pin (`2022-11-28`) gives us stable semantics on GHE (where older API versions still work). The `vnd.github+json` Accept is the recommended modern form.

**Alternatives considered**:
- Minimal headers (no `Accept`, no `X-GitHub-Api-Version`). Rejected — GitHub would fall back to legacy defaults that may change.
- Use the crate's `semver` version in the User-Agent. Decided against for now — `env!("CARGO_PKG_VERSION")` is fine but a hand-pinned `"netidm/1.0"` or similar might be more stable for rate-limit key purposes on GitHub's side. Phase 1 implementation may refine this; the contract is "netidm/ + version + ( + connector-github + )".
