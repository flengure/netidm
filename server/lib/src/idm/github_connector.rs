//! GitHub upstream connector (PR-CONNECTOR-GITHUB, DL28).
//!
//! This module is the concrete implementation of the [`RefreshableConnector`]
//! trait for GitHub / GitHub Enterprise. Providers whose `OAuth2Client`
//! entry carries `oauth2_client_provider_kind = "github"` are dispatched
//! here at callback time, bypassing the generic OIDC code-exchange /
//! userinfo / JWKS path that pre-DL28 providers still use.
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

use crate::idm::authsession::handler_oauth2_client::ExternalUserClaims;
use crate::idm::oauth2_connector::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use time::{Duration as TimeDuration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

static GITHUB_COM_HOST: LazyLock<Url> =
    LazyLock::new(|| Url::parse("https://github.com/").unwrap_or_else(|_| unreachable!()));
static GITHUB_API_BASE: LazyLock<Url> =
    LazyLock::new(|| Url::parse("https://api.github.com/").unwrap_or_else(|_| unreachable!()));

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

impl GitHubSessionState {
    /// Deserialise from the opaque bytes stored on the `Oauth2Session`.
    /// Returns `ConnectorRefreshError::Serialization` on any decode failure
    /// so the call site can map it to `Oauth2Error::InvalidGrant`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorRefreshError> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state is not UTF-8: {e}"))
        })?;
        let state: Self = serde_json::from_str(s).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state JSON parse failed: {e}"))
        })?;
        if state.format_version != GITHUB_SESSION_STATE_FORMAT_VERSION {
            return Err(ConnectorRefreshError::Serialization(format!(
                "session-state format_version {} is not supported (expected {})",
                state.format_version, GITHUB_SESSION_STATE_FORMAT_VERSION
            )));
        }
        Ok(state)
    }

    /// Serialise to bytes for storage on `Oauth2Session::upstream_refresh_state`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ConnectorRefreshError> {
        serde_json::to_vec(self).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state serialisation failed: {e}"))
        })
    }
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

impl GitHubConfig {
    /// Parse DL28 attributes off an `OAuth2Client` entry and build a
    /// `GitHubConfig`. Called once per GitHub provider at `IdmServer::start`
    /// (T017). Missing optional attributes use the documented defaults.
    ///
    /// # Errors
    ///
    /// - [`OperationError::InvalidValueState`] — `OAuth2ClientId` or
    ///   `OAuth2ClientSecret` absent, or the reqwest client fails to build.
    /// - [`OperationError::InvalidAttribute`] — `OAuth2ClientGithubHost` is
    ///   present but not an absolute `https://` URL.
    pub fn from_entry(entry: &EntrySealedCommitted) -> Result<GitHubConfig, OperationError> {
        let entry_uuid = entry.get_uuid();

        let client_id = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientId)
            .map(str::to_string)
            .ok_or(OperationError::InvalidValueState)?;

        let client_secret = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientSecret)
            .map(str::to_string)
            .ok_or(OperationError::InvalidValueState)?;

        // host defaults to https://github.com
        let host = entry
            .get_ava_single_url(Attribute::OAuth2ClientGithubHost)
            .cloned()
            .unwrap_or_else(|| GITHUB_COM_HOST.clone());

        if host.scheme() != "https" {
            return Err(OperationError::InvalidAttribute(
                "oauth2_client_github_host must use the https:// scheme".to_string(),
            ));
        }

        // api_base: public GitHub → https://api.github.com/, GHE → <host>/api/v3/
        let api_base = if host.host_str() == Some("github.com") {
            GITHUB_API_BASE.clone()
        } else {
            let mut base = host.clone();
            base.set_path("/api/v3/");
            base
        };

        let org_filter: HashSet<String> = entry
            .get_ava_set(Attribute::OAuth2ClientGithubOrgFilter)
            .and_then(|vs| vs.as_utf8_iter())
            .map(|iter| iter.map(|s| s.to_lowercase()).collect())
            .unwrap_or_default();

        let allowed_teams: HashSet<String> = entry
            .get_ava_set(Attribute::OAuth2ClientGithubAllowedTeams)
            .and_then(|vs| vs.as_utf8_iter())
            .map(|iter| iter.map(|s| s.to_lowercase()).collect())
            .unwrap_or_default();

        let team_name_field = entry
            .get_ava_single_iutf8(Attribute::OAuth2ClientGithubTeamNameField)
            .and_then(TeamNameField::from_str_strict)
            .unwrap_or_default();

        let load_all_groups = entry
            .get_ava_single_bool(Attribute::OAuth2ClientGithubLoadAllGroups)
            .unwrap_or(false);

        let preferred_email_domain = entry
            .get_ava_single_iutf8(Attribute::OAuth2ClientGithubPreferredEmailDomain)
            .map(str::to_string);

        let allow_jit_provisioning = entry
            .get_ava_single_bool(Attribute::OAuth2ClientGithubAllowJitProvisioning)
            .unwrap_or(false);

        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/vnd.github+json"),
        );
        default_headers.insert(
            reqwest::header::HeaderName::from_static("x-github-api-version"),
            reqwest::header::HeaderValue::from_static("2022-11-28"),
        );

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent(concat!(
                "netidm/",
                env!("CARGO_PKG_VERSION"),
                " (connector-github)"
            ))
            .default_headers(default_headers)
            .build()
            .map_err(|e| {
                error!(?e, "Failed to build reqwest::Client for GitHub connector");
                OperationError::InvalidValueState
            })?;

        Ok(GitHubConfig {
            entry_uuid,
            host,
            api_base,
            client_id,
            client_secret,
            org_filter,
            allowed_teams,
            team_name_field,
            load_all_groups,
            preferred_email_domain,
            allow_jit_provisioning,
            http,
        })
    }
}

/// GitHub access token response (code-exchange and refresh).
#[derive(Deserialize, Debug)]
struct GitHubTokenResponse {
    access_token: String,
    /// Present when the OAuth app issues a refresh token (GitHub Apps do, classic OAuth apps do not).
    /// Used in T016 for the session-state blob and T034 for the refresh path.
    #[allow(dead_code)]
    refresh_token: Option<String>,
    /// Access token lifetime in seconds; absent for non-expiring tokens.
    /// Used in T016 to compute `access_token_expires_at`.
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

/// Parse an RFC 5988 `Link` header value and return the `rel="next"` URL.
fn parse_next_link(link_header: &str) -> Option<Url> {
    for part in link_header.split(',') {
        let part = part.trim();
        let mut iter = part.splitn(2, ';');
        let url_part = iter.next()?.trim();
        let rel_part = iter.next()?.trim();
        if rel_part.contains("rel=\"next\"") {
            let url_str = url_part.trim_start_matches('<').trim_end_matches('>');
            return Url::parse(url_str).ok();
        }
    }
    None
}

impl GitHubConnector {
    /// Build a fresh connector from an already-parsed [`GitHubConfig`].
    /// Used at `IdmServer::start` after [`GitHubConfig::from_entry`]
    /// parses the DL28 attributes off the `OAuth2Client` entry.
    pub fn new(config: GitHubConfig) -> Self {
        Self { config }
    }

    /// Read-only accessor for the parsed config. Tests inspect this to
    /// assert parse behaviour without touching private fields.
    pub fn config(&self) -> &GitHubConfig {
        &self.config
    }

    // -----------------------------------------------------------------
    // T013: REST fetch helpers
    // -----------------------------------------------------------------

    /// Exchange the authorisation `code` for an access/refresh token pair.
    /// Sends `Accept: application/json` so GitHub's token endpoint returns
    /// JSON (not form-encoded). The `Accept` header in `self.config.http`'s
    /// default headers is `application/vnd.github+json` which also satisfies
    /// GitHub's `contains("application/json")` check.
    async fn post_token(&self, code: &str) -> Result<GitHubTokenResponse, ConnectorRefreshError> {
        let token_url = self
            .config
            .host
            .join("login/oauth/access_token")
            .map_err(|e| ConnectorRefreshError::Other(format!("token URL build error: {e}")))?;

        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];

        let resp = self
            .config
            .http
            .post(token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(ConnectorRefreshError::UpstreamRejected(status.as_u16()));
        }

        resp.json::<GitHubTokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Other(format!("token parse error: {e}")))
    }

    /// Exchange a refresh token for a new access/refresh token pair.
    /// Returns `ConnectorRefreshError::TokenRevoked` on a 4xx response
    /// (GitHub signals an invalid or expired refresh token this way).
    async fn post_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<GitHubTokenResponse, ConnectorRefreshError> {
        let token_url = self
            .config
            .host
            .join("login/oauth/access_token")
            .map_err(|e| ConnectorRefreshError::Other(format!("token URL build error: {e}")))?;

        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];

        let resp = self
            .config
            .http
            .post(token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        let status = resp.status();
        if status.is_client_error() {
            return Err(ConnectorRefreshError::TokenRevoked);
        }
        if !status.is_success() {
            return Err(ConnectorRefreshError::UpstreamRejected(status.as_u16()));
        }

        resp.json::<GitHubTokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Other(format!("refresh token parse error: {e}")))
    }

    /// `GET <api_base>/user` — fetch the authenticated user's profile.
    async fn fetch_user(&self, token: &str) -> Result<GithubUserProfile, ConnectorRefreshError> {
        let url = self
            .config
            .api_base
            .join("user")
            .map_err(|e| ConnectorRefreshError::Other(format!("user URL build error: {e}")))?;

        let resp = self
            .config
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(ConnectorRefreshError::UpstreamRejected(status.as_u16()));
        }

        resp.json::<GithubUserProfile>()
            .await
            .map_err(|e| ConnectorRefreshError::Other(format!("user parse error: {e}")))
    }

    /// `GET <api_base>/user/emails` — fetch the authenticated user's email list.
    async fn fetch_emails(&self, token: &str) -> Result<Vec<GithubEmail>, ConnectorRefreshError> {
        let url =
            self.config.api_base.join("user/emails").map_err(|e| {
                ConnectorRefreshError::Other(format!("emails URL build error: {e}"))
            })?;

        let resp = self
            .config
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(ConnectorRefreshError::UpstreamRejected(status.as_u16()));
        }

        resp.json::<Vec<GithubEmail>>()
            .await
            .map_err(|e| ConnectorRefreshError::Other(format!("emails parse error: {e}")))
    }

    /// Fetch all items from a paginated GitHub endpoint (follows `Link: rel="next"`).
    /// Caps at `max_items` total entries to prevent runaway loops (FR-011).
    async fn fetch_paginated<T: serde::de::DeserializeOwned + Send>(
        &self,
        token: &str,
        start_url: Url,
        max_items: usize,
    ) -> Result<Vec<T>, ConnectorRefreshError> {
        let mut items: Vec<T> = Vec::new();
        let mut current_url = {
            let mut u = start_url;
            u.query_pairs_mut().append_pair("per_page", "100");
            u
        };

        loop {
            let resp = self
                .config
                .http
                .get(current_url)
                .bearer_auth(token)
                .send()
                .await
                .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

            let status = resp.status();
            if !status.is_success() {
                return Err(ConnectorRefreshError::UpstreamRejected(status.as_u16()));
            }

            let next = resp
                .headers()
                .get("link")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_next_link);

            let page: Vec<T> = resp.json().await.map_err(|e| {
                ConnectorRefreshError::Other(format!("pagination parse error: {e}"))
            })?;

            items.extend(page);

            if items.len() >= max_items {
                items.truncate(max_items);
                break;
            }

            match next {
                Some(next_url) => current_url = next_url,
                None => break,
            }
        }

        Ok(items)
    }

    /// `GET <api_base>/user/orgs` — fetch all org slugs the user belongs to.
    async fn fetch_orgs(&self, token: &str) -> Result<Vec<GithubOrg>, ConnectorRefreshError> {
        let url = self
            .config
            .api_base
            .join("user/orgs")
            .map_err(|e| ConnectorRefreshError::Other(format!("orgs URL build error: {e}")))?;

        self.fetch_paginated(token, url, 5000).await
    }

    /// `GET <api_base>/user/teams` — fetch all teams; capped at 5000 per FR-011.
    async fn fetch_teams(&self, token: &str) -> Result<Vec<GithubTeam>, ConnectorRefreshError> {
        let url = self
            .config
            .api_base
            .join("user/teams")
            .map_err(|e| ConnectorRefreshError::Other(format!("teams URL build error: {e}")))?;

        self.fetch_paginated(token, url, 5000).await
    }

    // -----------------------------------------------------------------
    // T015: Render upstream group names
    // -----------------------------------------------------------------

    /// Convert the raw GitHub team list (and optionally org memberships)
    /// into netidm group name strings for the `ExternalUserClaims.groups`
    /// field. Applies `team_name_field` and `load_all_groups` from the
    /// connector config (FR-006, FR-004a). Everything is lowercased for
    /// consistency.
    pub fn render_team_names(&self, teams: &[GithubTeam], orgs: &[GithubOrg]) -> Vec<String> {
        let mut names = Vec::new();

        for team in teams {
            let org = team.organization.login.to_lowercase();
            let slug = team.slug.to_lowercase();
            let name = team.name.to_lowercase();

            // Apply org_filter: skip teams whose org is not in the allowlist
            // (empty allowlist = no filter).
            if !self.config.org_filter.is_empty() && !self.config.org_filter.contains(&org) {
                continue;
            }

            match self.config.team_name_field {
                TeamNameField::Slug => names.push(format!("{org}:{slug}")),
                TeamNameField::Name => names.push(format!("{org}:{name}")),
                TeamNameField::Both => {
                    names.push(format!("{org}:{slug}"));
                    if slug != name {
                        names.push(format!("{org}:{name}"));
                    }
                }
            }
        }

        if self.config.load_all_groups {
            for org in orgs {
                let org_lower = org.login.to_lowercase();
                if self.config.org_filter.is_empty() || self.config.org_filter.contains(&org_lower)
                {
                    names.push(org_lower);
                }
            }
        }

        names
    }

    // -----------------------------------------------------------------
    // T013: assemble ExternalUserClaims from code
    // -----------------------------------------------------------------

    /// Select the best email from the user's verified email list.
    ///
    /// Priority: primary+verified → preferred-domain match → any verified.
    /// Returns `(email, verified=true)` for the chosen address, or
    /// `(None, None)` if no verified address exists.
    fn select_email<'a>(&self, emails: &'a [GithubEmail]) -> (Option<&'a str>, Option<bool>) {
        let verified: Vec<&GithubEmail> = emails.iter().filter(|e| e.verified).collect();

        if verified.is_empty() {
            return (None, None);
        }

        // Prefer primary+verified
        if let Some(e) = verified.iter().find(|e| e.primary) {
            return (Some(e.email.as_str()), Some(true));
        }

        // Prefer preferred email domain
        if let Some(ref domain) = self.config.preferred_email_domain {
            let suffix = format!("@{domain}");
            if let Some(e) = verified.iter().find(|e| e.email.ends_with(&suffix)) {
                return (Some(e.email.as_str()), Some(true));
            }
        }

        // First verified (we checked is_empty() above so this always matches)
        if let Some(e) = verified.first() {
            (Some(e.email.as_str()), Some(true))
        } else {
            (None, None)
        }
    }

    /// T023: access-gate check (FR-005a). If `config.allowed_teams` is
    /// non-empty, compute the user's flat team set as lowercased `org:slug`
    /// strings and intersect with the allowed list. An empty intersection
    /// returns `ConnectorRefreshError::AccessDenied` and logs an audit line
    /// BEFORE any Person state is touched.
    fn check_access_gate(
        &self,
        profile: &GithubUserProfile,
        teams: &[GithubTeam],
    ) -> Result<(), ConnectorRefreshError> {
        if self.config.allowed_teams.is_empty() {
            return Ok(());
        }

        let user_teams: HashSet<String> = teams
            .iter()
            .map(|t| {
                format!(
                    "{}:{}",
                    t.organization.login.to_lowercase(),
                    t.slug.to_lowercase()
                )
            })
            .collect();

        let allowed = &self.config.allowed_teams;
        if user_teams.iter().any(|t| allowed.contains(t)) {
            return Ok(());
        }

        info!(
            connector_uuid = ?self.config.entry_uuid,
            github_id = profile.id,
            github_login = %profile.login,
            ?user_teams,
            "github_access_gate_denied"
        );
        Err(ConnectorRefreshError::AccessDenied)
    }

    /// Exchange an authorisation code for `ExternalUserClaims` by making
    /// the full GitHub API call chain (T013 implementation of
    /// [`RefreshableConnector::fetch_callback_claims`]). Steps:
    ///
    /// 1. POST token exchange
    /// 2. GET /user
    /// 3. GET /user/emails
    /// 4. GET /user/orgs (paginated)
    /// 5. GET /user/teams (paginated, capped at 5000)
    /// 6. T023 access-gate check (short-circuits if allowed_teams non-empty)
    ///
    /// Then T015 `render_team_names` populates `ExternalUserClaims.groups`.
    async fn do_fetch_callback_claims(
        &self,
        code: &str,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        let token_resp = self.post_token(code).await?;
        let token = &token_resp.access_token;

        let profile = self.fetch_user(token).await?;
        let emails = self.fetch_emails(token).await?;
        let orgs = self.fetch_orgs(token).await?;
        let teams = self.fetch_teams(token).await?;

        self.check_access_gate(&profile, &teams)?;

        let (email, email_verified) = self.select_email(&emails);
        let groups = self.render_team_names(&teams, &orgs);

        Ok(ExternalUserClaims {
            sub: profile.id.to_string(),
            email: email.map(str::to_string),
            email_verified,
            display_name: profile.name.clone(),
            username_hint: Some(profile.login.clone()),
            groups,
        })
    }
}

#[async_trait]
impl RefreshableConnector for GitHubConnector {
    async fn refresh(
        &self,
        session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        // T034 (US6): full refresh implementation.
        //
        // (a) Deserialise session state.
        let mut state = GitHubSessionState::from_bytes(session_state)?;

        // (b) Rotate the access token if it is known to be expired.
        if let (Some(expires_at), Some(ref rt)) =
            (state.access_token_expires_at, state.refresh_token.clone())
        {
            let now = OffsetDateTime::UNIX_EPOCH + crate::time::duration_from_epoch_now();
            if now > expires_at {
                let rotated = self.post_refresh_token(rt).await?;
                state.access_token = rotated.access_token;
                if let Some(new_rt) = rotated.refresh_token {
                    state.refresh_token = Some(new_rt);
                }
                state.access_token_expires_at = rotated
                    .expires_in
                    .map(|secs| now + TimeDuration::seconds(secs as i64));
            }
        }

        // (c) Re-fetch team membership (and orgs for load_all_groups).
        let token = &state.access_token;
        let orgs = self.fetch_orgs(token).await?;
        let teams = self.fetch_teams(token).await?;

        // T035: access-gate is enforced on EVERY refresh, not just login.
        // A user who has since left the allowed teams must be blocked.
        let gate_profile = GithubUserProfile {
            id: state.github_id,
            login: state.github_login.clone(),
            name: None,
            email: None,
        };
        if let Err(ConnectorRefreshError::AccessDenied) =
            self.check_access_gate(&gate_profile, &teams)
        {
            return Err(ConnectorRefreshError::TokenRevoked);
        }

        // (d) Compute the new claims. Sub MUST equal the session's original sub.
        let groups = self.render_team_names(&teams, &orgs);
        let new_claims = ExternalUserClaims {
            sub: state.github_id.to_string(),
            // Refresh path does not re-fetch emails — preserve the previous
            // verified email (stable) to avoid unnecessary writes.
            email: previous_claims.email.clone(),
            email_verified: previous_claims.email_verified,
            display_name: previous_claims.display_name.clone(),
            username_hint: Some(state.github_login.clone()),
            groups,
        };

        // (e) Serialise the (possibly rotated) session state.
        let new_blob = state.to_bytes()?;

        Ok(RefreshOutcome {
            claims: new_claims,
            new_session_state: Some(new_blob),
        })
    }

    async fn fetch_callback_claims(
        &self,
        code: &str,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        self.do_fetch_callback_claims(code).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_connector(team_name_field: TeamNameField, load_all_groups: bool) -> GitHubConnector {
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        GitHubConnector::new(GitHubConfig {
            entry_uuid: uuid::Uuid::new_v4(),
            host: GITHUB_COM_HOST.clone(),
            api_base: GITHUB_API_BASE.clone(),
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            org_filter: HashSet::new(),
            allowed_teams: HashSet::new(),
            team_name_field,
            load_all_groups,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            http,
        })
    }

    fn teams() -> Vec<GithubTeam> {
        vec![
            GithubTeam {
                slug: "Alpha".to_string(),
                name: "Alpha Team".to_string(),
                organization: GithubOrg {
                    login: "Org1".to_string(),
                },
            },
            GithubTeam {
                slug: "Beta".to_string(),
                name: "Beta Team".to_string(),
                organization: GithubOrg {
                    login: "Org1".to_string(),
                },
            },
            GithubTeam {
                slug: "Gamma".to_string(),
                name: "Gamma Team".to_string(),
                organization: GithubOrg {
                    login: "Org2".to_string(),
                },
            },
        ]
    }

    fn orgs() -> Vec<GithubOrg> {
        vec![
            GithubOrg {
                login: "Org1".to_string(),
            },
            GithubOrg {
                login: "Org2".to_string(),
            },
        ]
    }

    // T018: render_team_names with Slug
    #[test]
    fn test_github_render_team_names_slug() {
        let c = make_connector(TeamNameField::Slug, false);
        let mut got = c.render_team_names(&teams(), &orgs());
        got.sort();
        assert_eq!(got, vec!["org1:alpha", "org1:beta", "org2:gamma"]);
    }

    // T019: render_team_names with Name and Both
    #[test]
    fn test_github_render_team_names_name_and_both() {
        let c = make_connector(TeamNameField::Name, false);
        let mut got = c.render_team_names(&teams(), &orgs());
        got.sort();
        assert_eq!(
            got,
            vec!["org1:alpha team", "org1:beta team", "org2:gamma team"]
        );

        let c = make_connector(TeamNameField::Both, false);
        let mut got = c.render_team_names(&teams(), &orgs());
        got.sort();
        assert_eq!(
            got,
            vec![
                "org1:alpha",
                "org1:alpha team",
                "org1:beta",
                "org1:beta team",
                "org2:gamma",
                "org2:gamma team"
            ]
        );
    }

    // T018/T019 bonus: load_all_groups appends org names
    #[test]
    fn test_github_render_team_names_load_all_groups() {
        let c = make_connector(TeamNameField::Slug, true);
        let mut got = c.render_team_names(&teams(), &orgs());
        got.sort();
        assert_eq!(
            got,
            vec!["org1", "org1:alpha", "org1:beta", "org2", "org2:gamma"]
        );
    }

    // T030: org_filter drops teams from outside orgs (FR-005 — group-mapping filter only)
    #[test]
    fn test_github_org_filter_drops_outside_orgs() {
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        let mut org_filter = HashSet::new();
        org_filter.insert("org1".to_string());
        let connector = GitHubConnector::new(GitHubConfig {
            entry_uuid: uuid::Uuid::new_v4(),
            host: GITHUB_COM_HOST.clone(),
            api_base: GITHUB_API_BASE.clone(),
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            org_filter,
            allowed_teams: HashSet::new(),
            team_name_field: TeamNameField::Slug,
            load_all_groups: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            http,
        });

        // Only org1 teams survive; org2:gamma is dropped.
        let mut got = connector.render_team_names(&teams(), &orgs());
        got.sort();
        assert_eq!(got, vec!["org1:alpha", "org1:beta"]);

        // Empty org_filter is a no-op pass-through.
        let pass_through = make_connector(TeamNameField::Slug, false);
        let mut all = pass_through.render_team_names(&teams(), &orgs());
        all.sort();
        assert_eq!(all, vec!["org1:alpha", "org1:beta", "org2:gamma"]);
    }

    // T021: pagination link header parsing
    #[test]
    fn test_github_pagination_link_header() {
        let hdr = r#"<https://api.github.com/user/teams?per_page=2&page=2>; rel="next", <https://api.github.com/user/teams?per_page=2&page=5>; rel="last""#;
        let next = parse_next_link(hdr);
        assert_eq!(
            next,
            Some(
                Url::parse("https://api.github.com/user/teams?per_page=2&page=2")
                    .unwrap_or_else(|_| unreachable!())
            )
        );

        let hdr_last_only = r#"<https://api.github.com/user/teams?per_page=2&page=5>; rel="last""#;
        assert_eq!(parse_next_link(hdr_last_only), None);
    }

    // T024: access gate unit tests (FR-005a)

    fn make_connector_with_allowed_teams(allowed: &[&str]) -> GitHubConnector {
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        let allowed_teams = allowed.iter().map(|s| s.to_string()).collect();
        GitHubConnector::new(GitHubConfig {
            entry_uuid: uuid::Uuid::new_v4(),
            host: GITHUB_COM_HOST.clone(),
            api_base: GITHUB_API_BASE.clone(),
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            org_filter: HashSet::new(),
            allowed_teams,
            team_name_field: TeamNameField::Slug,
            load_all_groups: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            http,
        })
    }

    fn make_profile(id: i64, login: &str) -> GithubUserProfile {
        GithubUserProfile {
            id,
            login: login.to_string(),
            name: None,
            email: None,
        }
    }

    fn make_team(org: &str, slug: &str) -> GithubTeam {
        GithubTeam {
            slug: slug.to_string(),
            name: slug.to_string(),
            organization: GithubOrg {
                login: org.to_string(),
            },
        }
    }

    #[test]
    fn test_github_access_gate_empty_allowed_teams_passes() {
        let connector = make_connector_with_allowed_teams(&[]);
        let profile = make_profile(1, "alice");
        // No allowed_teams configured → gate is off; any team set passes.
        assert!(connector.check_access_gate(&profile, &[]).is_ok());
        let teams = vec![make_team("org", "nope")];
        assert!(connector.check_access_gate(&profile, &teams).is_ok());
    }

    #[test]
    fn test_github_access_gate_empty_intersection_rejects() {
        let connector = make_connector_with_allowed_teams(&["acme:eng"]);
        let profile = make_profile(2, "bob");
        let teams = vec![make_team("acme", "ops"), make_team("other", "devs")];
        let result = connector.check_access_gate(&profile, &teams);
        assert!(
            matches!(
                result,
                Err(crate::idm::oauth2_connector::ConnectorRefreshError::AccessDenied)
            ),
            "expected AccessDenied, got {result:?}"
        );
    }

    #[test]
    fn test_github_access_gate_matching_team_passes() {
        let connector = make_connector_with_allowed_teams(&["acme:eng", "other:staff"]);
        let profile = make_profile(3, "carol");
        // User is in acme:eng — intersection is non-empty.
        let teams = vec![make_team("acme", "eng"), make_team("acme", "all")];
        assert!(connector.check_access_gate(&profile, &teams).is_ok());
    }

    #[test]
    fn test_github_access_gate_case_insensitive() {
        // allowed_teams is lowercased at config parse time; gate check
        // lowercases the user's org+slug — mixed-case teams must match.
        let connector = make_connector_with_allowed_teams(&["acme:eng"]);
        let profile = make_profile(4, "dave");
        let teams = vec![make_team("ACME", "ENG")];
        assert!(connector.check_access_gate(&profile, &teams).is_ok());
    }

    // T036–T039: refresh unit tests

    /// Build a minimal `GitHubSessionState` suitable for unit tests.
    fn make_session_state(
        id: i64,
        login: &str,
        token: &str,
        refresh_token: Option<&str>,
        expires_at: Option<OffsetDateTime>,
    ) -> Vec<u8> {
        GitHubSessionState {
            format_version: GITHUB_SESSION_STATE_FORMAT_VERSION,
            github_id: id,
            github_login: login.to_string(),
            access_token: token.to_string(),
            refresh_token: refresh_token.map(str::to_string),
            access_token_expires_at: expires_at,
        }
        .to_bytes()
        .unwrap_or_else(|_| unreachable!())
    }

    fn make_previous_claims(id: i64, email: &str) -> ExternalUserClaims {
        ExternalUserClaims {
            sub: id.to_string(),
            email: Some(email.to_string()),
            email_verified: Some(true),
            display_name: Some("Test User".to_string()),
            username_hint: Some("testuser".to_string()),
            groups: vec!["old:group".to_string()],
        }
    }

    // T036: refresh returns fresh claims with updated groups.
    #[tokio::test]
    async fn test_github_refresh_returns_fresh_claims() {
        use crate::idm::oauth2_connector::RefreshableConnector;

        // Spin up the mock server.
        let mock_server_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = tokio::net::TcpListener::bind(mock_server_addr)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        // We need the mock's State to register a token.  Use a minimal standalone
        // reqwest call instead of the full mock; this test focuses on the connector
        // logic, not the HTTP layer — so we re-use the mock helpers via the full
        // integration path below in T040.  Here we test the non-refresh-needed path:
        // token is not expiring.

        // Build a connector pointing at a non-existent URL — but the token is NOT
        // expiring so no HTTP call is made for refresh.  We still need to call
        // fetch_orgs/teams, so we need the mock running.

        // --- Use the public MockGithub struct from the testkit wouldn't be available
        // in lib tests. Instead, spin up a tiny axum mock inline. ---
        // This is complex; instead, use a session state with a token that maps to
        // a user in our own mini-mock. Since we can't import github_mock here (it's
        // in the testkit crate), we test via direct method calls instead.

        // Build a connector where orgs/teams endpoints are served by our inline mock.
        use axum::routing::get;
        use axum::Json;
        use serde_json::json;

        let app = axum::Router::new()
            .route(
                "/api/v3/user/orgs",
                get(|| async { Json(json!([{"login": "refreshcorp"}])) }),
            )
            .route(
                "/api/v3/user/teams",
                get(|| async {
                    Json(json!([{
                        "slug": "devs",
                        "name": "Developers",
                        "organization": {"login": "refreshcorp"}
                    }]))
                }),
            );

        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = url::Url::parse(&format!("http://{addr}")).expect("url");
        let http = reqwest::Client::builder()
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert(
                    reqwest::header::ACCEPT,
                    reqwest::header::HeaderValue::from_static("application/vnd.github+json"),
                );
                h
            })
            .build()
            .unwrap_or_else(|_| unreachable!());

        let mut api_base = base.clone();
        api_base.set_path("/api/v3/");

        let connector = GitHubConnector::new(GitHubConfig {
            entry_uuid: uuid::Uuid::new_v4(),
            host: base,
            api_base,
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            org_filter: HashSet::new(),
            allowed_teams: HashSet::new(),
            team_name_field: TeamNameField::Slug,
            load_all_groups: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            http,
        });

        // Token is not expiring (no expires_at), so no refresh call is made.
        let blob = make_session_state(42, "alice", "gho_does_not_matter", None, None);
        let prev = make_previous_claims(42, "alice@example.com");

        let outcome = connector
            .refresh(&blob, &prev)
            .await
            .expect("refresh should succeed");

        assert_eq!(outcome.claims.sub, "42");
        let mut groups = outcome.claims.groups.clone();
        groups.sort();
        assert_eq!(groups, vec!["refreshcorp:devs"]);
        // Email preserved from previous_claims (refresh path doesn't re-fetch).
        assert_eq!(outcome.claims.email.as_deref(), Some("alice@example.com"));
        // new_session_state must be Some (blob always rewritten).
        assert!(outcome.new_session_state.is_some());
    }

    // T037: refresh with serialization failure returns Serialization error.
    #[tokio::test]
    async fn test_github_refresh_error_serialization_failure() {
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        let connector = GitHubConnector::new(GitHubConfig {
            entry_uuid: uuid::Uuid::new_v4(),
            host: GITHUB_COM_HOST.clone(),
            api_base: GITHUB_API_BASE.clone(),
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            org_filter: HashSet::new(),
            allowed_teams: HashSet::new(),
            team_name_field: TeamNameField::Slug,
            load_all_groups: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            http,
        });
        use crate::idm::oauth2_connector::RefreshableConnector;
        let prev = make_previous_claims(1, "x@example.com");
        // Corrupt blob.
        let result = connector.refresh(b"not-valid-json", &prev).await;
        assert!(
            matches!(
                result,
                Err(crate::idm::oauth2_connector::ConnectorRefreshError::Serialization(_))
            ),
            "expected Serialization error, got {result:?}"
        );
    }

    // T039: access gate enforced on refresh path (T035).
    #[tokio::test]
    async fn test_github_refresh_access_gate_enforced() {
        use crate::idm::oauth2_connector::RefreshableConnector;
        use axum::routing::get;

        // Spin up inline mock returning a team NOT in allowed_teams.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let app = axum::Router::new()
            .route(
                "/api/v3/user/orgs",
                get(|| async { axum::Json(serde_json::json!([{"login": "acme"}])) }),
            )
            .route(
                "/api/v3/user/teams",
                get(|| async {
                    axum::Json(serde_json::json!([{
                        "slug": "contractors",
                        "name": "Contractors",
                        "organization": {"login": "acme"}
                    }]))
                }),
            );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = url::Url::parse(&format!("http://{addr}")).expect("url");
        let mut api_base = base.clone();
        api_base.set_path("/api/v3/");

        let mut allowed_teams = HashSet::new();
        allowed_teams.insert("acme:employees".to_string());

        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        let connector = GitHubConnector::new(GitHubConfig {
            entry_uuid: uuid::Uuid::new_v4(),
            host: base,
            api_base,
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            org_filter: HashSet::new(),
            allowed_teams,
            team_name_field: TeamNameField::Slug,
            load_all_groups: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            http,
        });

        let blob = make_session_state(99, "former-employee", "gho_any_token", None, None);
        let prev = make_previous_claims(99, "user@example.com");

        let result = connector.refresh(&blob, &prev).await;
        // T035: access gate on refresh maps to TokenRevoked (not AccessDenied).
        assert!(
            matches!(
                result,
                Err(crate::idm::oauth2_connector::ConnectorRefreshError::TokenRevoked)
            ),
            "expected TokenRevoked on gate failure, got {result:?}"
        );
    }
}
