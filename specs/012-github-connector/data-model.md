# Data Model: GitHub Upstream Connector (PR-CONNECTOR-GITHUB)

Phase 1 artifact. Enumerates the entities this PR introduces or extends, the DL28 schema additions, the in-memory connector shape, and the opaque session-state blob format.

## Entity: `OAuth2Client` (extended, DL28)

Existing entry class. DL28 adds one discriminator attribute + seven GitHub-specific config attributes. All additions are **optional** — pre-DL28 entries decode unchanged.

| Attribute | Introduced | Cardinality | Type | Default | Description |
|---|---|---|---|---|---|
| `OAuth2ClientProviderKind` | **DL28 NEW** | single, optional | `Iutf8` | `"generic-oidc"` when absent | Discriminator selecting the concrete connector impl. This PR ships `"github"`; PR-OIDC-CONNECTOR's entries continue to work unchanged because absence defaults to `"generic-oidc"`. |
| `OAuth2ClientGithubHost` | **DL28 NEW** | single, optional | `Utf8` URL | `https://github.com` | Base host for OAuth2 authorize/token. REST calls derive from this as `<host>` for `github.com` or `<host>/api/v3` for GHE. |
| `OAuth2ClientGithubOrgFilter` | **DL28 NEW** | multi, optional | `Utf8` | `[]` = no filter | Group-mapping filter (FR-005). Teams from orgs outside this list are silently dropped from the group-mapping stage; login is NOT rejected. |
| `OAuth2ClientGithubAllowedTeams` | **DL28 NEW** | multi, optional | `Utf8` (form `org-slug:team-slug`) | `[]` = gate off | Access gate (FR-005a). Non-empty requires the user's GitHub team set to intersect this list; empty intersection → login rejected BEFORE any provisioning. |
| `OAuth2ClientGithubTeamNameField` | **DL28 NEW** | single, optional | `Iutf8` enum `slug` \| `name` \| `both` | `slug` | Format of the upstream group name fed to the mapping reconciler (FR-006). |
| `OAuth2ClientGithubLoadAllGroups` | **DL28 NEW** | single, optional | `Boolean` | `false` | When `true`, users' plain org memberships (without team scoping) also feed the group-mapping reconciler, in addition to their team memberships. |
| `OAuth2ClientGithubPreferredEmailDomain` | **DL28 NEW** | single, optional | `Iutf8` | `None` | Preferred domain (e.g. `"acme.com"`); selects the first verified email matching this domain over the primary-marked one (FR-007). |
| `OAuth2ClientGithubAllowJitProvisioning` | **DL28 NEW** | single, optional | `Boolean` | `false` | When `true`, a first-time GitHub user with no match from the linking chain is auto-provisioned (FR-017). Conservative default — admins opt in explicitly. |

**Invariants** (enforced at schema validation + at connector-build time):
- `OAuth2ClientGithubTeamNameField` MUST be one of `slug`, `name`, `both`. Other values → rejected at modify-time.
- `OAuth2ClientGithubAllowedTeams` entries MUST contain exactly one `:` separator — `org:team` format. Malformed entries → rejected at modify-time.
- `OAuth2ClientGithubHost` MUST parse as an absolute `https://` URL. HTTP or non-URL → rejected at modify-time.
- `OAuth2ClientGithubPreferredEmailDomain` MUST be a bare DNS domain (no `@`, no scheme, no path). Enforced at modify-time.
- `OAuth2ClientGithubOrgFilter` entries are treated case-insensitively (GitHub org slugs are case-insensitive at the API level). Stored lowercased.
- All eight new attributes are ACP-gated via the existing OAuth2-admin ACP, extended by DL28 to include them.

---

## Entity: `Person` (extended use, no schema change)

The GitHub connector reuses PR-LINKBY's existing (DL24) attributes on the Person entry for the upstream-subject linking chain:

| Attribute | Usage from this PR |
|---|---|
| `OAuth2AccountProvider` | Stores the UUID of the GitHub connector entry that linked this Person. |
| `OAuth2AccountUniqueUserId` | Stores **two** records per connector for the same user: (a) `github_id` as a string, (b) the current `github_login`. This lets linking-chain step 2 match by ID and step 3 match by login. Both records share the same `OAuth2AccountProvider` value (same connector). |
| Existing email attributes | Used by linking-chain step 1 (verified-email match) — no new behaviour. |

**No new schema** on Person. DL28 does not touch the Person class.

---

## Entity: `GitHubConfig` (new, in-memory)

Parsed configuration built from an `OAuth2Client` entry at `IdmServer::start`; immutable for the lifetime of the process.

```rust
pub struct GitHubConfig {
    /// UUID of the OAuth2Client entry this config was built from.
    /// Registered with `ConnectorRegistry::register(entry_uuid, ...)`.
    pub entry_uuid: Uuid,
    /// Parsed host — `https://github.com` by default, or the GHE host.
    pub host: Url,
    /// Derived REST base — `https://api.github.com` for github.com,
    /// `<host>/api/v3` for GHE.
    pub api_base: Url,
    pub client_id: String,
    /// Read via netidm's existing key-provider infrastructure, not stored plaintext here.
    pub client_secret: SecretString,
    /// Lowercased; may be empty.
    pub org_filter: HashSet<String>,
    /// Lowercased; may be empty.
    pub allowed_teams: HashSet<String>,
    pub team_name_field: TeamNameField,
    pub load_all_groups: bool,
    pub preferred_email_domain: Option<String>,
    pub allow_jit_provisioning: bool,
    /// Shared across all refresh calls — reused connection pool.
    pub http: reqwest::Client,
}

pub enum TeamNameField {
    Slug,
    Name,
    Both,
}
```

**Invariants**:
- `org_filter` + `allowed_teams` normalised to lowercase at construction time; GitHub slugs are case-insensitive.
- `client_secret` wrapped in `secrecy::SecretString` (or equivalent) so accidental `Debug` printing doesn't leak it. Confirm at Phase 1 implementation which secret-wrapping type netidm uses elsewhere.
- `http` client is built once per config with the standard headers (`Accept`, `User-Agent`, `X-GitHub-Api-Version` — see R8) baked in via `default_headers`.

---

## Entity: `GitHubSessionState` (new, serde struct)

The opaque per-session blob stored in `Oauth2Session::upstream_refresh_state: Option<Vec<u8>>` (PR-REFRESH-CLAIMS FR-009). Netidm core treats this as bytes; only the `GitHubConnector` deserialises.

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
struct GitHubSessionState {
    /// Blob format version. `1` at ship. Future connector versions
    /// can bump this and implement a forward migration without a DL bump.
    format_version: u8,
    /// GitHub's stable numeric user ID. NEVER the mutable `login`.
    github_id: i64,
    /// GitHub login AT THE TIME OF THE MINT. May be stale on refresh — the
    /// refresh path updates this on every success.
    github_login: String,
    /// Upstream access token, used as `Authorization: Bearer <...>` on REST.
    access_token: String,
    /// Present when the OAuth app issued a refresh token.
    refresh_token: Option<String>,
    /// Absolute time the access token is known to expire. `None` when the
    /// GitHub response didn't include an `expires_in`.
    access_token_expires_at: Option<OffsetDateTime>,
}
```

**Invariants**:
- `format_version` MUST equal the connector's current expected version on deserialise. Mismatch → `ConnectorRefreshError::Serialization(...)` → `Oauth2Error::InvalidGrant`.
- `github_id > 0` — GitHub never issues id `0`; a zero value indicates corruption.
- `github_login` may be updated between blob-writes (it's stored for human-readable fallback lookups only; `github_id` is authoritative).
- The blob is a few hundred bytes to a few kB in typical cases; hard-capped at 64 KiB by `ValueSetOauth2Session`'s size limit.

---

## Entity: GitHub REST response types (new, serde deserialise targets)

Minimal shape for the four REST endpoints we consume. Each is tolerant of GitHub adding fields (uses the default `serde(deny_unknown_fields = false)`).

```rust
#[derive(Deserialize)]
struct GithubUserProfile {
    id: i64,
    login: String,
    name: Option<String>,
    /// Public email — NOT authoritative; only `GET /user/emails` is.
    /// Captured for logging, not for Person-email.
    email: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[derive(Deserialize)]
struct GithubOrg {
    login: String,
}

#[derive(Deserialize)]
struct GithubTeam {
    slug: String,
    name: String,
    organization: GithubOrg,
}
```

---

## Entity: `GitHubConnector` (new, trait impl)

Thin struct over `GitHubConfig` that implements `RefreshableConnector` (PR-REFRESH-CLAIMS). Per-call state is constructed from the opaque blob at call time; no mutable state on the connector.

```rust
pub struct GitHubConnector {
    config: GitHubConfig,
}

#[async_trait]
impl RefreshableConnector for GitHubConnector {
    async fn refresh(
        &self,
        session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> { /* … */ }
}
```

**Invariants**:
- `refresh()` is the only method the trait exposes; all login-path helpers are on this struct as `pub(crate)` methods invoked from `authsession/provider_initiated.rs`, not through the trait.
- No interior mutability — every refresh call parses the blob fresh, talks to GitHub, returns a `RefreshOutcome`, and lets the caller persist the updated state.

---

## State transitions: login path (one-shot diagram)

```
user clicks "Log in with GitHub"
    │
    ▼
netidm redirects to <host>/login/oauth/authorize (code-flow start)
    │
    ▼ (user consents at GitHub)
GitHub redirects to netidm callback URL with ?code=...&state=...
    │
    ▼
Callback handler reads the OAuth2Client entry; dispatches on OAuth2ClientProviderKind
    │
    ├── "github" → GitHubConnector::handle_callback(code, state)
    │       │
    │       ▼
    │   code exchange at <host>/login/oauth/access_token
    │       │  (on failure → rendered error page, no Person touched)
    │       ▼
    │   GET /user          → profile (id, login)
    │   GET /user/emails   → verified emails
    │   GET /user/orgs     → org list (paginated)
    │   GET /user/teams    → team list (paginated, capped at 5000)
    │       │  (any 4xx/5xx → rendered error page, no Person touched)
    │       ▼
    │   apply OAuth2ClientGithubAllowedTeams access gate (FR-005a)
    │       │  (no intersection → rejected with error page; RETURN)
    │       ▼
    │   apply OAuth2ClientGithubOrgFilter group filter (FR-005)
    │       │  (produces the set of upstream team names that will feed the reconciler)
    │       ▼
    │   run 4-step linking chain (FR-013a)
    │       ├── step 1: verified-email match         → link, mint
    │       ├── step 2: github_id match on Person    → link, mint
    │       ├── step 3: github_login match on Person → link, mint
    │       └── step 4: if allow_jit → provision, link, mint
    │                   else         → reject with error page
    │       ▼
    │   persist GitHubSessionState as opaque blob on the new OAuth2Session
    │       ▼
    │   call reconcile_upstream_memberships with the filtered team names
    │       ▼
    │   redirect to the RP with the netidm session cookie set
    │
    └── "generic-oidc" / absent → existing OIDC path (PR-OIDC-CONNECTOR, unchanged)
```

**Key invariants** on this diagram:
- Access gate (FR-005a) runs FIRST after the GitHub fetches. A rejected user never reaches any Person-provisioning code.
- Org filter (FR-005) runs SECOND; it only narrows the group-mapping input.
- Linking chain (FR-013a) runs AFTER the filters. Every step that succeeds persists BOTH the numeric ID and the current login to the Person, so future refreshes resolve by the stable identifier regardless of which step matched this time.

## State transitions: refresh path

Inherited from PR-REFRESH-CLAIMS diagram — this connector contributes only the `refresh()` implementation. Key specifics:
- The connector extracts the opaque blob, calls `GET /user/orgs` + `GET /user/teams` with the stored access token (refreshing it first if expired and a `refresh_token` is present).
- Returns `RefreshOutcome { claims: new, new_session_state: Some(updated_blob) }` — the blob is rotated to capture a potentially-refreshed access token + the latest login.
- `outcome.claims.sub = github_id.to_string()` — matches the session's originally-stored sub at the call site (subject-consistency check).

---

## Relationships (summary)

- `OAuth2Client` ←1:1→ `GitHubConnector` (by entry UUID, registered in `ConnectorRegistry` at boot, absent when `OAuth2ClientProviderKind != "github"`).
- `OAuth2Client` ←*:1→ `Person` via the upstream-linking chain (FR-013a writes `(OAuth2AccountProvider = connector_uuid, OAuth2AccountUniqueUserId = ...)` on the Person).
- `Person` ←1:*→ `Oauth2Session` (existing).
- `Oauth2Session` ←1:0..1→ `GitHubSessionState` via the opaque `upstream_refresh_state` blob (new as of DL27, populated on GitHub-bound sessions).
- `GitHubConnector` ←1:0..1→ `reqwest::Client` (embedded; shared across all calls on this connector instance).
