//! GitHub upstream connector (PR-CONNECTOR-GITHUB, DL28).
//!
//! This module is the concrete implementation of the [`RefreshableConnector`]
//! trait for GitHub / GitHub Enterprise. Providers whose `OAuth2Client`
//! entry carries `oauth2_client_provider_kind = "github"` are dispatched
//! here at callback time, bypassing the generic OIDC code-exchange /
//! userinfo / JWKS path that pre-DL28 providers still use.
//!
//! ## Status
//!
//! This is the **T011 scaffold**: it defines the types the rest of the PR
//! builds on — `GitHubConfig`, `GitHubSessionState`, the REST response
//! shapes, `TeamNameField`, and the `GitHubConnector` struct. Behaviour
//! (code exchange, user / emails / orgs / teams fetch, the four-step
//! linking chain, the `RefreshableConnector` impl) lands in T012–T017,
//! T023–T034 per `specs/012-github-connector/tasks.md`.
//!
//! Until the implementation lands, [`GITHUB_CONNECTOR_STUB_MSG`] is the
//! user-visible message rendered by the T009 authsession short-circuit
//! for Github providers.
//!
//! ## Dispatch contract (FR-016)
//!
//! Absence of `oauth2_client_provider_kind` on an `OAuth2Client` entry, or
//! an unrecognised value, both resolve to
//! [`crate::idm::oauth2_client::ProviderKind::GenericOidc`] in
//! `reload_oauth2_client_providers` — so pre-DL28 providers decode
//! byte-identically to DL27 and never reach this module.
//!
//! [`RefreshableConnector`]: crate::idm::oauth2_connector::RefreshableConnector

use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

/// User-visible message rendered in place of the OAuth2 auth flow when a
/// provider is configured with `provider_kind = "github"` under the T009
/// stub. Replaced in T013 once [`GitHubConnector::handle_callback`] lands.
///
/// Kept short so it fits inside the existing `CredState::Denied(&'static str)`
/// arm without a string-lifetime shim.
pub const GITHUB_CONNECTOR_STUB_MSG: &str =
    "GitHub upstream connector is not yet available on this build";

/// Current `GitHubSessionState::format_version` this connector writes and
/// accepts. Future versions bump this and implement a forward migration
/// inside the connector; no DL migration needed because the blob is
/// connector-internal.
pub const GITHUB_SESSION_STATE_FORMAT_VERSION: u8 = 1;

/// Rendering policy for an upstream GitHub team name fed to the group-
/// mapping reconciler (FR-006). Mirrors dex's `teamNameField`.
///
/// The default, [`TeamNameField::Slug`], is stable across human-readable
/// renames on GitHub. [`TeamNameField::Name`] follows the display name.
/// [`TeamNameField::Both`] emits both strings so either one can match the
/// mapping table — useful for migrations from dex deployments configured
/// either way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TeamNameField {
    /// `org-slug:team-slug`. Default — stable across renames.
    #[default]
    Slug,
    /// `org-slug:team-name` — human-readable, follows renames.
    Name,
    /// Emit both `:slug` and `:name` forms.
    Both,
}

impl TeamNameField {
    /// Canonical string form for storage in the
    /// `oauth2_client_github_team_name_field` attribute.
    pub fn as_str(self) -> &'static str {
        match self {
            TeamNameField::Slug => "slug",
            TeamNameField::Name => "name",
            TeamNameField::Both => "both",
        }
    }

    /// Strict parse. Returns `None` for garbage so CLI input validation can
    /// reject unknown values at modify time rather than silently defaulting.
    pub fn from_str_strict(s: &str) -> Option<Self> {
        match s {
            "slug" => Some(TeamNameField::Slug),
            "name" => Some(TeamNameField::Name),
            "both" => Some(TeamNameField::Both),
            _ => None,
        }
    }
}

/// Parsed GitHub connector configuration — one per `OAuth2Client` entry
/// with `oauth2_client_provider_kind = "github"`. Built once at
/// `IdmServer::start` and registered with the
/// [`crate::idm::oauth2_connector::ConnectorRegistry`]; immutable for
/// the lifetime of the process (config changes require a netidmd
/// restart, per research.md R6).
#[derive(Clone, Debug)]
pub struct GitHubConfig {
    /// UUID of the `OAuth2Client` entry this config was built from.
    /// Registered as the lookup key in the `ConnectorRegistry`.
    pub entry_uuid: Uuid,
    /// OAuth2 host — `https://github.com` by default, or the GHE host.
    /// Used for `/login/oauth/authorize` + `/login/oauth/access_token`.
    pub host: Url,
    /// REST base derived from [`Self::host`]: `https://api.github.com` for
    /// `github.com`, or `<host>/api/v3` for GHE.
    pub api_base: Url,
    /// GitHub OAuth app's client ID.
    pub client_id: String,
    /// GitHub OAuth app's client secret. Stored as a plain `String` —
    /// netidm keeps secrets out of `Debug` via per-field `#[debug(skip)]`
    /// rather than a type-level wrapper (matches the rest of the
    /// codebase; see research.md R0 note on `SecretString`).
    pub client_secret: String,
    /// Lowercased org slugs whose teams contribute to the group-mapping
    /// reconciler. Empty = no filter (FR-005).
    pub org_filter: HashSet<String>,
    /// Lowercased `org:team` entries that gate login (FR-005a). Empty =
    /// gate off.
    pub allowed_teams: HashSet<String>,
    /// Team-name rendering policy passed to the reconciler (FR-006).
    pub team_name_field: TeamNameField,
    /// When `true`, plain org memberships (without team scoping) also
    /// feed the group-mapping reconciler.
    pub load_all_groups: bool,
    /// Preferred email domain (FR-007). Bare DNS domain, no scheme, no
    /// `@`.
    pub preferred_email_domain: Option<String>,
    /// When `true`, first-time GitHub users with no match from the
    /// linking chain are auto-provisioned (FR-017). Conservative default
    /// is `false`.
    pub allow_jit_provisioning: bool,
    /// Shared across all outbound calls on this connector instance —
    /// reused connection pool. Built once with the standard GitHub
    /// headers (`Accept`, `User-Agent`, `X-GitHub-Api-Version`) baked
    /// in via `default_headers`.
    pub http: reqwest::Client,
}

/// Opaque per-session blob persisted as bytes in
/// `Oauth2Session::upstream_refresh_state` (PR-REFRESH-CLAIMS FR-009).
/// Netidm core treats this as opaque; only [`GitHubConnector`] serialises
/// and deserialises.
///
/// Encoded as JSON → UTF-8 bytes. `format_version` lets the connector
/// bump blob layout without a DL migration.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GitHubSessionState {
    /// Blob format version. [`GITHUB_SESSION_STATE_FORMAT_VERSION`] at
    /// ship. A deserialise with a different value MUST return
    /// `ConnectorRefreshError::Serialization` so the call site maps to
    /// `Oauth2Error::InvalidGrant`.
    pub format_version: u8,
    /// GitHub's stable numeric user ID. NEVER the mutable `login`.
    pub github_id: i64,
    /// GitHub login AT THE TIME OF THE MINT. May be stale on refresh —
    /// the refresh path updates this on every success.
    pub github_login: String,
    /// Upstream access token, used as `Authorization: Bearer <...>` on
    /// REST calls.
    pub access_token: String,
    /// Present when the OAuth app issued a refresh token.
    pub refresh_token: Option<String>,
    /// Absolute instant the access token is known to expire. `None` when
    /// the `access_token` response didn't include `expires_in`.
    pub access_token_expires_at: Option<OffsetDateTime>,
}

/// `GET /user` response. Other fields GitHub returns are tolerated but
/// unused; only `id` and `login` drive the connector's linking chain
/// (plus `name` for JIT display names).
#[derive(Deserialize, Debug, Clone)]
pub struct GithubUserProfile {
    /// Stable numeric user id — the connector's authoritative subject.
    pub id: i64,
    /// Current login (mutable; users can rename).
    pub login: String,
    /// Human-readable display name. `None` for users who never set one.
    pub name: Option<String>,
    /// Public profile email, NOT authoritative — only `GET /user/emails`
    /// surfaces the verified set. Captured here so logs show what GitHub
    /// returned but never written to a Person.
    pub email: Option<String>,
}

/// One entry from `GET /user/emails`.
#[derive(Deserialize, Debug, Clone)]
pub struct GithubEmail {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
}

/// Org slug — extracted from `GET /user/orgs` and from
/// `GithubTeam::organization`.
#[derive(Deserialize, Debug, Clone)]
pub struct GithubOrg {
    pub login: String,
}

/// One entry from `GET /user/teams`. Only `slug`, `name`, and
/// `organization.login` are consumed; other GitHub fields (description,
/// privacy, etc.) are tolerated but unused.
#[derive(Deserialize, Debug, Clone)]
pub struct GithubTeam {
    pub slug: String,
    pub name: String,
    pub organization: GithubOrg,
}

/// GitHub upstream connector. Thin wrapper over [`GitHubConfig`] that
/// owns the HTTP client and implements
/// [`RefreshableConnector`](crate::idm::oauth2_connector::RefreshableConnector).
///
/// Stateless at instance level — every refresh call parses the opaque
/// session-state blob fresh, talks to GitHub, and returns a
/// `RefreshOutcome`. No interior mutability.
#[derive(Clone, Debug)]
pub struct GitHubConnector {
    config: GitHubConfig,
}

impl GitHubConnector {
    /// Build a fresh connector from an already-parsed [`GitHubConfig`].
    /// Used at `IdmServer::start` after `GitHubConfig::from_entry` (see
    /// T012) parses the DL28 attributes off the `OAuth2Client` entry.
    pub fn new(config: GitHubConfig) -> Self {
        Self { config }
    }

    /// Read-only accessor for the parsed config. Tests inspect this to
    /// assert parse behaviour without touching private fields.
    pub fn config(&self) -> &GitHubConfig {
        &self.config
    }
}
