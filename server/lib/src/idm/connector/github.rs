//! GitHub upstream connector.
//!
//! Full port of dex's `connector/github/github.go`.
//! Implements [`CallbackConnector`], [`RefreshConnector`], and the
//! legacy [`RefreshableConnector`] (backward-compat — to be removed).
//!
//! Main public types:
//! - [`Config`]  — parsed connector configuration (dex: `githubConnector` fields)
//! - [`Org`]     — per-org access filter (dex: `Org`)
//! - [`Conn`]    — connector implementation (dex: `*githubConnector`)
//! - [`ConnectorData`] — opaque session state blob (dex: `connectorData`)

use crate::idm::authsession::handler_connector::ExternalUserClaims;
use crate::idm::connector::traits::{
    CallbackConnector, CallbackParams, Connector as ConnectorTrait, ConnectorError,
    ConnectorIdentity, ConnectorRefreshError, RefreshConnector, RefreshOutcome,
    RefreshableConnector, Scopes,
};
use crate::prelude::*;
use async_trait::async_trait;
use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use time::{Duration as TimeDuration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants (mirrors dex's package-level consts)
// ---------------------------------------------------------------------------

static COM_HOST: LazyLock<Url> =
    LazyLock::new(|| Url::parse("https://github.com/").unwrap_or_else(|_| unreachable!()));
const SCOPE_EMAIL: &str = "user:email";
const SCOPE_ORGS: &str = "read:org";
const GITHUB_API_VERSION: &str = "2022-11-28";

/// Format version for the [`ConnectorData`] blob. Bump when the serialised
/// layout changes; add forward-migration logic in [`ConnectorData::from_bytes`].
pub const FORMAT_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Config-level types
// ---------------------------------------------------------------------------

/// Rendering policy for an upstream GitHub team name fed to the group-mapping
/// reconciler. Mirrors dex's `teamNameField` string option.
///
/// Default is [`TeamNameField::Name`] (display name), matching dex.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TeamNameField {
    /// Human-readable display name (e.g. `"Engineering"`). Dex default.
    #[default]
    Name,
    /// URL-stable slug (e.g. `"engineering"`). Stable across renames.
    Slug,
    /// Emit both the name and the slug as separate group strings.
    Both,
}

impl TeamNameField {
    pub fn as_str(self) -> &'static str {
        match self {
            TeamNameField::Name => "name",
            TeamNameField::Slug => "slug",
            TeamNameField::Both => "both",
        }
    }

    /// Parse. Empty string → `Name` (dex's default). Returns `None` for
    /// unknown values so the call site can reject them at schema-write time.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "name" | "" => Some(TeamNameField::Name),
            "slug" => Some(TeamNameField::Slug),
            "both" => Some(TeamNameField::Both),
            _ => None,
        }
    }
}

/// Per-org access filter. Users must belong to at least one configured org.
/// When `teams` is non-empty, the user must also be in at least one of those
/// teams within that org.
///
/// Mirrors dex's `Org` struct exactly.
#[derive(Clone, Debug)]
pub struct Org {
    /// GitHub organization name (not slug).
    pub name: String,
    /// Specific teams within the org. Empty = any team (or just org membership).
    pub teams: Vec<String>,
}

// ---------------------------------------------------------------------------
// Connector configuration (mirrors dex's githubConnector fields)
// ---------------------------------------------------------------------------

/// Parsed GitHub connector configuration built from a `Connector` entry.
///
/// Mirrors dex's `githubConnector` struct. Built once at `IdmServer::start`
/// and registered with [`crate::idm::connector::traits::ConnectorRegistry`].
#[derive(Clone, Debug)]
pub struct Config {
    /// UUID of the `Connector` entry. Registry lookup key.
    pub entry_uuid: Uuid,
    /// Registered OAuth callback URL. Dex: `redirectURI`.
    pub redirect_uri: Url,
    /// GitHub OAuth App client ID. Dex: `clientID`.
    pub client_id: String,
    /// GitHub OAuth App client secret. Dex: `clientSecret`.
    pub client_secret: String,
    /// Per-org access filters. Dex: `orgs []Org`.
    pub orgs: Vec<Org>,
    /// GitHub Enterprise hostname (no scheme, no path). Dex: `hostName`.
    pub host_name: Option<String>,
    /// Path to root CA PEM for custom TLS. Dex: `rootCA`.
    pub root_ca: Option<String>,
    /// Team name rendering policy. Dex: `teamNameField`.
    pub team_name_field: TeamNameField,
    /// Load all org+team memberships when no orgs are configured. Dex: `loadAllGroups`.
    pub load_all_groups: bool,
    /// Use login string as `user_id` instead of numeric ID. Dex: `useLoginAsID`.
    pub use_login_as_id: bool,
    /// Preferred email domain for selection (e.g. `"github.com"`). Dex: `preferredEmailDomain`.
    pub preferred_email_domain: Option<String>,
    /// JIT-provisioning of new local accounts on first login. Netidm extension.
    pub allow_jit_provisioning: bool,
    /// Derived OAuth2 authorization base URL (github.com or GHE).
    pub host: Url,
    /// Derived REST API base URL string. Dex: `apiURL`.
    pub api_url: String,
    /// Shared HTTP client with `Accept`, `User-Agent`, and API version headers baked in.
    pub http: reqwest::Client,
    // Backward-compat: mapped from legacy schema attributes into `orgs` above.
    // Kept for `render_team_names` (old group-mapping path) until that path is migrated.
    pub org_filter: HashSet<String>,
    pub allowed_teams: HashSet<String>,
}

// ---------------------------------------------------------------------------
// Opaque session blob (mirrors dex's connectorData)
// ---------------------------------------------------------------------------

/// Opaque per-session state serialized into `ConnectorIdentity.connector_data`.
/// Mirrors dex's `connectorData` struct, extended with GitHub Apps token rotation
/// fields and a format-version stamp for forward migration.
///
/// JSON field names use camelCase to match dex's original Go json tags.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectorData {
    /// GitHub access token. Dex: `accessToken`.
    #[serde(rename = "accessToken")]
    pub access_token: String,
    /// GitHub Apps refresh token (absent for classic OAuth Apps). Netidm extension.
    #[serde(rename = "refreshToken", skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// When the access token expires. Absent for non-expiring tokens. Netidm extension.
    #[serde(
        rename = "accessTokenExpiresAt",
        skip_serializing_if = "Option::is_none",
        with = "optional_offset_dt",
        default
    )]
    pub access_token_expires_at: Option<OffsetDateTime>,
    /// Stable numeric GitHub user ID. Netidm extension for refresh sub-consistency check.
    #[serde(rename = "githubId", skip_serializing_if = "Option::is_none")]
    pub github_id: Option<i64>,
    /// GitHub login at mint time. Netidm extension.
    #[serde(rename = "githubLogin", skip_serializing_if = "Option::is_none")]
    pub github_login: Option<String>,
    /// Blob format version. Netidm extension.
    #[serde(rename = "v", default)]
    pub format_version: u8,
}

// serde helper for Option<OffsetDateTime> as Unix seconds
mod optional_offset_dt {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(v: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(dt) => dt.unix_timestamp().serialize(s),
            None => unreachable!("skip_serializing_if guards this"),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        let ts = i64::deserialize(d)?;
        OffsetDateTime::from_unix_timestamp(ts)
            .map(Some)
            .map_err(serde::de::Error::custom)
    }
}

impl ConnectorData {
    /// Deserialise from the opaque bytes on `Oauth2Session`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorRefreshError> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state is not UTF-8: {e}"))
        })?;
        let state: Self = serde_json::from_str(s).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state JSON parse failed: {e}"))
        })?;
        if state.format_version != FORMAT_VERSION {
            return Err(ConnectorRefreshError::Serialization(format!(
                "session-state format_version {} not supported (expected {})",
                state.format_version, FORMAT_VERSION
            )));
        }
        Ok(state)
    }

    /// Serialise to bytes for `Oauth2Session::upstream_refresh_state`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ConnectorRefreshError> {
        serde_json::to_vec(self).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state serialisation failed: {e}"))
        })
    }
}

// ---------------------------------------------------------------------------
// HTTP API response types (private — mirrors dex's unexported structs)
// ---------------------------------------------------------------------------

/// `GET /user` response. Dex: `user` struct.
#[derive(Deserialize, Debug, Clone)]
struct User {
    id: i64,
    login: String,
    name: Option<String>,
    /// Public profile email — may be empty; `user_email()` fills this in.
    #[serde(default)]
    email: String,
}

/// One entry from `GET /user/emails`. Dex: `userEmail` struct.
#[derive(Deserialize, Debug, Clone)]
struct UserEmail {
    email: String,
    verified: bool,
    primary: bool,
    #[serde(default)]
    #[allow(dead_code)]
    visibility: String,
}

/// One entry from `GET /user/teams`. Dex: `team` struct.
#[derive(Deserialize, Debug, Clone)]
struct Team {
    name: String,
    #[serde(rename = "organization")]
    org: OrgEntry,
    slug: String,
}

/// Org field embedded in [`Team`] and used in `GET /user/orgs`. Dex: `org` struct.
#[derive(Deserialize, Debug, Clone)]
struct OrgEntry {
    login: String,
}

/// GitHub token endpoint response.
#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    refresh_token: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

// ---------------------------------------------------------------------------
// Connector implementation
// ---------------------------------------------------------------------------

/// GitHub connector implementation. Thin wrapper over [`Config`].
///
/// Mirrors dex's private `*githubConnector`. Made `pub` so the testkit can
/// construct one directly; production code always goes through [`Config::from_entry`].
#[derive(Clone, Debug)]
pub struct Conn {
    config: Config,
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

impl Config {
    /// Parse DL28+ attributes off a `Connector` entry and build a `Config`.
    /// Called once per GitHub provider at `IdmServer::start`.
    pub fn from_entry(
        entry: &EntrySealedCommitted,
        redirect_uri: Url,
    ) -> Result<Config, OperationError> {
        let entry_uuid = entry.get_uuid();

        let client_id = entry
            .get_ava_single_utf8(Attribute::ConnectorId)
            .map(str::to_string)
            .ok_or(OperationError::InvalidValueState)?;

        let client_secret = entry
            .get_ava_single_utf8(Attribute::ConnectorSecret)
            .map(str::to_string)
            .ok_or(OperationError::InvalidValueState)?;

        let host = entry
            .get_ava_single_url(Attribute::ConnectorGithubHost)
            .cloned()
            .unwrap_or_else(|| COM_HOST.clone());

        if host.scheme() != "https" {
            return Err(OperationError::InvalidAttribute(
                "connector_github_host must use the https:// scheme".to_string(),
            ));
        }

        let host_name: Option<String> = if host.host_str() == Some("github.com") {
            None
        } else {
            host.host_str().map(str::to_string)
        };

        let api_url = if host_name.is_none() {
            "https://api.github.com".to_string()
        } else {
            format!("https://{}/api/v3", host.host_str().unwrap_or(""))
        };

        let org_filter: HashSet<String> = entry
            .get_ava_set(Attribute::ConnectorGithubOrgFilter)
            .and_then(|vs| vs.as_utf8_iter())
            .map(|iter| iter.map(|s| s.to_lowercase()).collect())
            .unwrap_or_default();

        let allowed_teams: HashSet<String> = entry
            .get_ava_set(Attribute::ConnectorGithubAllowedTeams)
            .and_then(|vs| vs.as_utf8_iter())
            .map(|iter| iter.map(|s| s.to_lowercase()).collect())
            .unwrap_or_default();

        // Build dex-style orgs from legacy schema attrs.
        // org_filter → Org { name, teams: [] } (any team counts)
        // allowed_teams → Org { name, teams: [..] } (specific teams)
        let mut org_map: std::collections::BTreeMap<String, Vec<String>> =
            org_filter.iter().map(|o| (o.clone(), Vec::new())).collect();
        for team_str in &allowed_teams {
            if let Some((org, team)) = team_str.split_once(':') {
                org_map
                    .entry(org.to_string())
                    .or_default()
                    .push(team.to_string());
            }
        }
        let orgs: Vec<Org> = org_map
            .into_iter()
            .map(|(name, teams)| Org { name, teams })
            .collect();

        let team_name_field = entry
            .get_ava_single_iutf8(Attribute::ConnectorGithubTeamNameField)
            .and_then(TeamNameField::parse)
            .unwrap_or_default();

        let load_all_groups = entry
            .get_ava_single_bool(Attribute::ConnectorGithubLoadAllGroups)
            .unwrap_or(false);

        let use_login_as_id = entry
            .get_ava_single_bool(Attribute::ConnectorGithubUseLoginAsId)
            .unwrap_or(false);

        let preferred_email_domain = entry
            .get_ava_single_iutf8(Attribute::ConnectorGithubPreferredEmailDomain)
            .map(str::to_string);

        let allow_jit_provisioning = entry
            .get_ava_single_bool(Attribute::ConnectorGithubAllowJitProvisioning)
            .unwrap_or(false);

        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/vnd.github+json"),
        );
        default_headers.insert(
            reqwest::header::HeaderName::from_static("x-github-api-version"),
            reqwest::header::HeaderValue::from_static(GITHUB_API_VERSION),
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

        Ok(Config {
            entry_uuid,
            redirect_uri,
            client_id,
            client_secret,
            orgs,
            host_name,
            root_ca: None,
            team_name_field,
            load_all_groups,
            use_login_as_id,
            preferred_email_domain,
            allow_jit_provisioning,
            host,
            api_url,
            http,
            org_filter,
            allowed_teams,
        })
    }
}

// ---------------------------------------------------------------------------
// Pagination helper
// ---------------------------------------------------------------------------

/// Parse an RFC 5988 `Link` header and return the `rel="next"` URL.
/// Mirrors dex's `reNext` regex approach.
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

// ---------------------------------------------------------------------------
// Connector methods (mirrors dex's githubConnector methods)
// ---------------------------------------------------------------------------

impl Conn {
    /// Build a connector from a parsed [`Config`].
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Read-only config accessor. Tests inspect this to assert parse behaviour.
    pub fn config(&self) -> &Config {
        &self.config
    }

    // -----------------------------------------------------------------
    // groupsRequired — mirrors dex's groupsRequired
    // -----------------------------------------------------------------

    /// `true` when the `read:org` scope must be requested.
    /// Dex: `groupsRequired(groupScope bool) bool`.
    fn groups_required(&self, group_scope: bool) -> bool {
        !self.config.orgs.is_empty() || group_scope
    }

    // -----------------------------------------------------------------
    // teamGroupClaims — mirrors dex's teamGroupClaims
    // -----------------------------------------------------------------

    /// Return the group claim strings for a single team.
    /// Does NOT prefix with org name — callers add that via [`format_team_name`].
    /// Dex: `teamGroupClaims(t team) []string`.
    fn team_group_claims(&self, t: &Team) -> Vec<String> {
        match self.config.team_name_field {
            TeamNameField::Both => vec![t.name.clone(), t.slug.clone()],
            TeamNameField::Slug => vec![t.slug.clone()],
            TeamNameField::Name => vec![t.name.clone()],
        }
    }

    // -----------------------------------------------------------------
    // HTTP helpers
    // -----------------------------------------------------------------

    /// Perform a GET request and deserialize the JSON response.
    /// Returns the `rel="next"` pagination URL if present.
    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        url: &str,
    ) -> Result<(T, Option<String>), ConnectorError> {
        let resp = self
            .config
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            warn!(github_status = %status, github_body = %body, "GitHub GET {url} failed");
            return Err(ConnectorError::UpstreamRejected(status.as_u16()));
        }

        let next = resp
            .headers()
            .get("link")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_next_link)
            .map(|u| u.to_string());

        let value = resp
            .json::<T>()
            .await
            .map_err(|e| ConnectorError::Parse(format!("JSON parse error: {e}")))?;

        Ok((value, next))
    }

    /// Fetch all pages of a paginated JSON array endpoint.
    async fn get_paginated<T: serde::de::DeserializeOwned + Send>(
        &self,
        token: &str,
        start_url: &str,
        max_items: usize,
    ) -> Result<Vec<T>, ConnectorError> {
        let mut items: Vec<T> = Vec::new();
        let first_url = if start_url.contains('?') {
            format!("{start_url}&per_page=100")
        } else {
            format!("{start_url}?per_page=100")
        };
        let mut current_url = first_url;

        loop {
            let resp = self
                .config
                .http
                .get(&current_url)
                .bearer_auth(token)
                .send()
                .await
                .map_err(|e| ConnectorError::Network(e.to_string()))?;

            let status = resp.status();
            if !status.is_success() {
                return Err(ConnectorError::UpstreamRejected(status.as_u16()));
            }

            let next = resp
                .headers()
                .get("link")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_next_link)
                .map(|u| u.to_string());

            let page: Vec<T> = resp
                .json()
                .await
                .map_err(|e| ConnectorError::Parse(format!("pagination parse error: {e}")))?;

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

    /// Exchange an authorization code for tokens.
    async fn post_token(&self, code: &str) -> Result<TokenResponse, ConnectorError> {
        let token_url = format!("{}login/oauth/access_token", self.config.host.as_str());
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("redirect_uri", self.config.redirect_uri.as_str()),
        ];

        let resp = self
            .config
            .http
            .post(&token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|e| ConnectorError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            warn!(github_status = %status, github_body = %body, "GitHub token exchange failed");
            return Err(ConnectorError::UpstreamRejected(status.as_u16()));
        }

        resp.json::<TokenResponse>()
            .await
            .map_err(|e| ConnectorError::Other(format!("token parse error: {e}")))
    }

    /// Exchange a refresh token for a new token pair.
    async fn post_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, ConnectorRefreshError> {
        let token_url = format!("{}login/oauth/access_token", self.config.host.as_str());
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];

        let resp = self
            .config
            .http
            .post(&token_url)
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

        resp.json::<TokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Other(format!("refresh token parse error: {e}")))
    }

    // -----------------------------------------------------------------
    // user — mirrors dex's user()
    // -----------------------------------------------------------------

    /// `GET /user` — fetch profile; if email is empty or preferredEmailDomain
    /// is set, also fetch private email list via [`user_email`].
    /// Dex: `user(ctx, client) (user, error)`.
    async fn user(&self, token: &str) -> Result<User, ConnectorError> {
        let url = format!("{}/user", self.config.api_url);
        let (mut u, _): (User, _) = self.get(token, &url).await?;

        if u.email.is_empty() || self.config.preferred_email_domain.is_some() {
            u.email = self.user_email(token).await?;
        }
        Ok(u)
    }

    // -----------------------------------------------------------------
    // userEmail — mirrors dex's userEmail()
    // -----------------------------------------------------------------

    /// `GET /user/emails` — return the preferred/primary verified email.
    /// Returns the `preferredEmailDomain` match first, then primary+verified,
    /// then errors if none found.
    /// Dex: `userEmail(ctx, client) (string, error)`.
    async fn user_email(&self, token: &str) -> Result<String, ConnectorError> {
        let mut primary_email: Option<UserEmail> = None;
        let mut preferred_emails: Vec<UserEmail> = Vec::new();

        let mut api_url = format!("{}/user/emails", self.config.api_url);
        loop {
            let resp = self
                .config
                .http
                .get(&api_url)
                .bearer_auth(token)
                .send()
                .await
                .map_err(|e| ConnectorError::Network(e.to_string()))?;

            let status = resp.status();
            if !status.is_success() {
                return Err(ConnectorError::UpstreamRejected(status.as_u16()));
            }

            let next = resp
                .headers()
                .get("link")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_next_link)
                .map(|u| u.to_string());

            let emails: Vec<UserEmail> = resp
                .json()
                .await
                .map_err(|e| ConnectorError::Parse(format!("email parse error: {e}")))?;

            for mut email in emails {
                // GitHub Enterprise: treat all emails as verified (GHE has no email verification).
                if self.config.host_name.is_some() {
                    email.verified = true;
                }

                if email.verified && email.primary {
                    primary_email = Some(email.clone());
                }

                if self.config.preferred_email_domain.is_some() && email.verified {
                    if let Some((_, domain_part)) = email.email.split_once('@') {
                        if self.is_preferred_email_domain(domain_part) {
                            preferred_emails.push(email);
                        }
                    }
                }
            }

            match next {
                Some(next_url) => api_url = next_url,
                None => break,
            }
        }

        if let Some(e) = preferred_emails.into_iter().next() {
            return Ok(e.email);
        }
        if let Some(e) = primary_email {
            return Ok(e.email);
        }
        Err(ConnectorError::Other(
            "github: user has no verified, primary email or preferred-domain email".to_string(),
        ))
    }

    // -----------------------------------------------------------------
    // isPreferredEmailDomain — mirrors dex's isPreferredEmailDomain()
    // -----------------------------------------------------------------

    /// Check whether a domain matches the configured `preferred_email_domain`.
    /// Supports wildcard prefix (`*.example.com`).
    /// Dex: `isPreferredEmailDomain(domain string) bool`.
    fn is_preferred_email_domain(&self, domain: &str) -> bool {
        let Some(preferred) = self.config.preferred_email_domain.as_deref() else {
            return false;
        };
        if domain == preferred {
            return true;
        }
        let preferred_parts: Vec<&str> = preferred.split('.').collect();
        let domain_parts: Vec<&str> = domain.split('.').collect();
        if preferred_parts.len() != domain_parts.len() {
            return false;
        }
        for (p, d) in preferred_parts.iter().zip(domain_parts.iter()) {
            if *p != "*" && p != d {
                return false;
            }
        }
        true
    }

    // -----------------------------------------------------------------
    // userInOrg — mirrors dex's userInOrg()
    // -----------------------------------------------------------------

    /// Check whether `user_name` is a member of `org_name`.
    /// `GET /orgs/{org}/members/{user}` — 204 = member, 302/404 = not member.
    /// Dex: `userInOrg(ctx, client, userName, orgName string) (bool, error)`.
    async fn user_in_org(
        &self,
        token: &str,
        user_name: &str,
        org_name: &str,
    ) -> Result<bool, ConnectorError> {
        let url = format!(
            "{}/orgs/{}/members/{}",
            self.config.api_url, org_name, user_name
        );

        let resp = self
            .config
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorError::Network(e.to_string()))?;

        match resp.status().as_u16() {
            204 => Ok(true),
            302 | 404 => {
                info!(
                    connector_uuid = ?self.config.entry_uuid,
                    user = user_name,
                    org = org_name,
                    "user not in org or app not authorized to read org data"
                );
                Ok(false)
            }
            other => Err(ConnectorError::UpstreamRejected(other)),
        }
    }

    // -----------------------------------------------------------------
    // teamsForOrg — mirrors dex's teamsForOrg()
    // -----------------------------------------------------------------

    /// Fetch all team claims for teams the user belongs to within `org_name`.
    /// Iterates all user teams and filters by org; calls [`team_group_claims`]
    /// (returns bare name/slug without org prefix — callers add that).
    /// Dex: `teamsForOrg(ctx, client, orgName string) ([]string, error)`.
    async fn teams_for_org(
        &self,
        token: &str,
        org_name: &str,
    ) -> Result<Vec<String>, ConnectorError> {
        let api_url = format!("{}/user/teams", self.config.api_url);
        let teams: Vec<Team> = self.get_paginated(token, &api_url, 5000).await?;

        let mut groups: Vec<String> = Vec::new();
        for t in &teams {
            if t.org.login == org_name {
                groups.extend(self.team_group_claims(t));
            }
        }
        Ok(groups)
    }

    // -----------------------------------------------------------------
    // userOrgs — mirrors dex's userOrgs()
    // -----------------------------------------------------------------

    /// `GET /user/orgs` — return all org login names the user belongs to.
    /// Dex: `userOrgs(ctx, client) ([]string, error)`.
    async fn user_orgs(&self, token: &str) -> Result<Vec<String>, ConnectorError> {
        let api_url = format!("{}/user/orgs", self.config.api_url);
        let orgs: Vec<OrgEntry> = self.get_paginated(token, &api_url, 5000).await?;
        Ok(orgs.into_iter().map(|o| o.login).collect())
    }

    // -----------------------------------------------------------------
    // userOrgTeams — mirrors dex's userOrgTeams()
    // -----------------------------------------------------------------

    /// `GET /user/teams` — return a map of `org_login → [team_claims]`.
    /// Dex: `userOrgTeams(ctx, client) (map[string][]string, error)`.
    async fn user_org_teams(
        &self,
        token: &str,
    ) -> Result<HashMap<String, Vec<String>>, ConnectorError> {
        let api_url = format!("{}/user/teams", self.config.api_url);
        let teams: Vec<Team> = self.get_paginated(token, &api_url, 5000).await?;

        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for t in &teams {
            groups
                .entry(t.org.login.clone())
                .or_default()
                .extend(self.team_group_claims(t));
        }
        Ok(groups)
    }

    // -----------------------------------------------------------------
    // userGroups — mirrors dex's userGroups()
    // -----------------------------------------------------------------

    /// Return all group strings when `loadAllGroups` is set and no orgs are
    /// configured: org names + `org:team` strings for every membership.
    /// Dex: `userGroups(ctx, client) ([]string, error)`.
    async fn user_groups(&self, token: &str) -> Result<Vec<String>, ConnectorError> {
        let orgs = self.user_orgs(token).await?;
        let org_teams = self.user_org_teams(token).await?;

        let mut groups: Vec<String> = Vec::new();
        for o in &orgs {
            groups.push(o.clone());
            if let Some(teams) = org_teams.get(o) {
                for t in teams {
                    groups.push(format_team_name(o, t));
                }
            }
        }
        Ok(groups)
    }

    // -----------------------------------------------------------------
    // groupsForOrgs — mirrors dex's groupsForOrgs()
    // -----------------------------------------------------------------

    /// Enforce org/team constraints and return group strings.
    ///
    /// For each configured org: check membership, then collect matching team
    /// claims. User is authorized if they are a member of at least one org
    /// (either with no team restriction, or with matching teams).
    /// Returns `UserNotInRequiredGroups` if they match no org at all.
    /// Dex: `groupsForOrgs(ctx, client, userName string) ([]string, error)`.
    async fn groups_for_orgs(
        &self,
        token: &str,
        user_name: &str,
    ) -> Result<Vec<String>, ConnectorError> {
        let mut groups: Vec<String> = Vec::new();
        let mut in_org_no_teams = false;

        for org in &self.config.orgs {
            let in_org = self.user_in_org(token, user_name, &org.name).await?;
            if !in_org {
                continue;
            }

            let mut teams = self.teams_for_org(token, &org.name).await?;

            if org.teams.is_empty() {
                in_org_no_teams = true;
            } else {
                // Filter to configured teams only (pkg/groups.Filter equivalent).
                let allowed: HashSet<&str> = org.teams.iter().map(|s| s.as_str()).collect();
                teams.retain(|t| allowed.contains(t.as_str()));
                if teams.is_empty() {
                    info!(
                        connector_uuid = ?self.config.entry_uuid,
                        user = user_name,
                        org = org.name,
                        "user in org but no matching teams"
                    );
                }
            }

            for team_name in teams {
                groups.push(format_team_name(&org.name, &team_name));
            }
        }

        if in_org_no_teams || !groups.is_empty() {
            return Ok(groups);
        }

        Err(ConnectorError::UserNotInRequiredGroups {
            user_id: user_name.to_string(),
            groups: self.config.orgs.iter().map(|o| o.name.clone()).collect(),
        })
    }

    // -----------------------------------------------------------------
    // getGroups — mirrors dex's getGroups()
    // -----------------------------------------------------------------

    /// Retrieve group strings for the authenticated user, applying the
    /// configured access policy.
    /// Dex: `getGroups(ctx, client, groupScope bool, userLogin string) ([]string, error)`.
    async fn get_groups(
        &self,
        token: &str,
        group_scope: bool,
        user_login: &str,
    ) -> Result<Vec<String>, ConnectorError> {
        if !self.config.orgs.is_empty() {
            return self.groups_for_orgs(token, user_login).await;
        }
        if group_scope && self.config.load_all_groups {
            return self.user_groups(token).await;
        }
        Ok(Vec::new())
    }

    // -----------------------------------------------------------------
    // Legacy helpers kept for the RefreshableConnector path
    // -----------------------------------------------------------------

    fn select_email<'a>(&self, emails: &'a [UserEmail]) -> (Option<&'a str>, Option<bool>) {
        let verified: Vec<&UserEmail> = emails.iter().filter(|e| e.verified).collect();
        if verified.is_empty() {
            return (None, None);
        }
        if let Some(e) = verified.iter().find(|e| e.primary) {
            return (Some(e.email.as_str()), Some(true));
        }
        if let Some(ref domain) = self.config.preferred_email_domain {
            let suffix = format!("@{domain}");
            if let Some(e) = verified.iter().find(|e| e.email.ends_with(&suffix)) {
                return (Some(e.email.as_str()), Some(true));
            }
        }
        verified
            .first()
            .map(|e| (Some(e.email.as_str()), Some(true)))
            .unwrap_or((None, None))
    }

    /// Render group name strings from team list and org list, applying
    /// `org_filter` and `team_name_field`. Legacy path for `RefreshableConnector`.
    fn render_team_names(&self, teams: &[Team], orgs: &[OrgEntry]) -> Vec<String> {
        let mut names = Vec::new();
        for t in teams {
            let org = t.org.login.to_lowercase();
            let slug = t.slug.to_lowercase();
            let name = t.name.to_lowercase();

            if !self.config.org_filter.is_empty() && !self.config.org_filter.contains(&org) {
                continue;
            }

            match self.config.team_name_field {
                TeamNameField::Name => names.push(format!("{org}:{name}")),
                TeamNameField::Slug => names.push(format!("{org}:{slug}")),
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

    fn check_access_gate(
        &self,
        profile: &User,
        teams: &[Team],
    ) -> Result<(), ConnectorRefreshError> {
        if self.config.allowed_teams.is_empty() {
            return Ok(());
        }
        let user_teams: HashSet<String> = teams
            .iter()
            .map(|t| format!("{}:{}", t.org.login.to_lowercase(), t.slug.to_lowercase()))
            .collect();
        if user_teams
            .iter()
            .any(|t| self.config.allowed_teams.contains(t))
        {
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

    async fn fetch_emails(&self, token: &str) -> Result<Vec<UserEmail>, ConnectorRefreshError> {
        let url = format!("{}/user/emails", self.config.api_url);
        let resp = self
            .config
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            warn!(github_status = %status, github_body = %body, "GitHub GET /user/emails failed");
            return Err(ConnectorRefreshError::UpstreamRejected(status.as_u16()));
        }
        resp.json::<Vec<UserEmail>>()
            .await
            .map_err(|e| ConnectorRefreshError::Other(format!("emails parse error: {e}")))
    }

    async fn fetch_paginated_legacy<T: serde::de::DeserializeOwned + Send>(
        &self,
        token: &str,
        start_url: Url,
        max_items: usize,
    ) -> Result<Vec<T>, ConnectorRefreshError> {
        let mut items: Vec<T> = Vec::new();
        let mut current_url = {
            let mut u = start_url;
            u.query_pairs_mut().append_pair("per_page", "100");
            u.to_string()
        };
        loop {
            let resp = self
                .config
                .http
                .get(&current_url)
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
                .and_then(parse_next_link)
                .map(|u| u.to_string());
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

    async fn fetch_orgs_legacy(&self, token: &str) -> Result<Vec<OrgEntry>, ConnectorRefreshError> {
        let url = format!("{}/user/orgs", self.config.api_url);
        let url = Url::parse(&url).map_err(|e| ConnectorRefreshError::Other(e.to_string()))?;
        self.fetch_paginated_legacy(token, url, 5000).await
    }

    async fn fetch_teams_legacy(&self, token: &str) -> Result<Vec<Team>, ConnectorRefreshError> {
        let url = format!("{}/user/teams", self.config.api_url);
        let url = Url::parse(&url).map_err(|e| ConnectorRefreshError::Other(e.to_string()))?;
        self.fetch_paginated_legacy(token, url, 5000).await
    }

    async fn fetch_user_legacy(&self, token: &str) -> Result<User, ConnectorRefreshError> {
        let url = format!("{}/user", self.config.api_url);
        let resp = self
            .config
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            warn!(github_status = %status, github_body = %body, "GitHub GET /user failed");
            return Err(ConnectorRefreshError::UpstreamRejected(status.as_u16()));
        }
        resp.json::<User>()
            .await
            .map_err(|e| ConnectorRefreshError::Other(format!("user parse error: {e}")))
    }

    /// Full code-exchange → claims pipeline for the legacy `RefreshableConnector` path.
    async fn do_fetch_callback_claims(
        &self,
        code: &str,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        let token_resp = self
            .post_token(code)
            .await
            .map_err(|e| ConnectorRefreshError::Other(e.to_string()))?;
        let token = &token_resp.access_token;

        let profile = self.fetch_user_legacy(token).await?;
        let emails = self.fetch_emails(token).await?;

        let orgs = match self.fetch_orgs_legacy(token).await {
            Ok(orgs) => orgs,
            Err(ConnectorRefreshError::UpstreamRejected(403 | 404)) => {
                warn!("GitHub /user/orgs 403/404 — no org memberships");
                Vec::new()
            }
            Err(e) => return Err(e),
        };
        let teams = match self.fetch_teams_legacy(token).await {
            Ok(teams) => teams,
            Err(ConnectorRefreshError::UpstreamRejected(403 | 404)) => {
                warn!("GitHub /user/teams 403/404 — no team memberships");
                Vec::new()
            }
            Err(e) => return Err(e),
        };

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

// ---------------------------------------------------------------------------
// formatTeamName — mirrors dex's package-level formatTeamName()
// ---------------------------------------------------------------------------

/// Return a unique team name prefixed with the org. Dex: `formatTeamName`.
pub fn format_team_name(org: &str, team: &str) -> String {
    format!("{org}:{team}")
}

// ---------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------

impl ConnectorTrait for Conn {}

#[async_trait]
impl CallbackConnector for Conn {
    /// Build the GitHub OAuth2 authorization URL.
    /// Returns the URL and an empty `conn_data` blob (GitHub doesn't use state blobs).
    /// Dex: `LoginURL(scopes, callbackURL, state string) (string, []byte, error)`.
    fn login_url(
        &self,
        s: &Scopes,
        callback_url: &str,
        state: &str,
    ) -> Result<(String, Vec<u8>), ConnectorError> {
        if callback_url != self.config.redirect_uri.as_str() {
            return Err(ConnectorError::Other(format!(
                "expected callback URL {:?} did not match the URL in the config {:?}",
                self.config.redirect_uri.as_str(),
                callback_url,
            )));
        }

        let mut scope = SCOPE_EMAIL.to_string();
        if self.groups_required(s.groups) {
            scope.push(' ');
            scope.push_str(SCOPE_ORGS);
        }

        let auth_url = if let Some(ref hn) = self.config.host_name {
            format!("https://{hn}/login/oauth/authorize")
        } else {
            "https://github.com/login/oauth/authorize".to_string()
        };

        let mut url = Url::parse(&auth_url)
            .map_err(|e| ConnectorError::Other(format!("auth URL build error: {e}")))?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", self.config.redirect_uri.as_str())
            .append_pair("scope", &scope)
            .append_pair("state", state);

        Ok((url.to_string(), Vec::new()))
    }

    /// Exchange the authorization code and return a [`ConnectorIdentity`].
    /// Dex: `HandleCallback(s, connData, r) (Identity, error)`.
    async fn handle_callback(
        &self,
        s: &Scopes,
        _conn_data: &[u8],
        params: &CallbackParams,
    ) -> Result<ConnectorIdentity, ConnectorError> {
        if let Some(ref err) = params.error {
            return Err(ConnectorError::Other(format!("upstream error: {err}")));
        }

        let code = params
            .code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| ConnectorError::Other("missing authorization code".to_string()))?;

        let token_resp = self.post_token(code).await?;
        let token = &token_resp.access_token;

        let user_profile = self.user(token).await?;

        let username = user_profile
            .name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| user_profile.login.clone());

        let user_id = if self.config.use_login_as_id {
            user_profile.login.clone()
        } else {
            user_profile.id.to_string()
        };

        let mut identity = ConnectorIdentity {
            user_id,
            username,
            preferred_username: user_profile.login.clone(),
            email: user_profile.email.clone(),
            email_verified: true,
            groups: Vec::new(),
            connector_data: None,
        };

        if self.groups_required(s.groups) {
            identity.groups = self
                .get_groups(token, s.groups, &user_profile.login)
                .await?;
        }

        if s.offline_access {
            let data = ConnectorData {
                access_token: token.clone(),
                refresh_token: token_resp.refresh_token.clone(),
                access_token_expires_at: token_resp.expires_in.map(|secs| {
                    OffsetDateTime::UNIX_EPOCH
                        + crate::time::duration_from_epoch_now()
                        + TimeDuration::seconds(secs as i64)
                }),
                github_id: Some(user_profile.id),
                github_login: Some(user_profile.login),
                format_version: FORMAT_VERSION,
            };
            identity.connector_data = data.to_bytes().map(Some).unwrap_or(None);
        }

        Ok(identity)
    }
}

#[async_trait]
impl RefreshConnector for Conn {
    /// Re-fetch user info using the stored access token.
    /// Dex: `Refresh(ctx, s, identity Identity) (Identity, error)`.
    async fn refresh(
        &self,
        s: &Scopes,
        mut identity: ConnectorIdentity,
    ) -> Result<ConnectorIdentity, ConnectorError> {
        let conn_data_bytes = identity
            .connector_data
            .as_deref()
            .filter(|b| !b.is_empty())
            .ok_or_else(|| ConnectorError::Other("no upstream access token found".to_string()))?;

        let mut data = serde_json::from_slice::<ConnectorData>(conn_data_bytes)
            .map_err(|e| ConnectorError::Parse(format!("unmarshal access token: {e}")))?;

        // Rotate the access token if it has expired (GitHub Apps).
        if let (Some(expires_at), Some(ref rt)) =
            (data.access_token_expires_at, data.refresh_token.clone())
        {
            let now = OffsetDateTime::UNIX_EPOCH + crate::time::duration_from_epoch_now();
            if now > expires_at {
                let rotated = self
                    .post_refresh_token(rt)
                    .await
                    .map_err(|e| ConnectorError::Other(e.to_string()))?;
                data.access_token = rotated.access_token;
                if let Some(new_rt) = rotated.refresh_token {
                    data.refresh_token = Some(new_rt);
                }
                data.access_token_expires_at = rotated
                    .expires_in
                    .map(|secs| now + TimeDuration::seconds(secs as i64));
            }
        }

        let token = &data.access_token;
        let user_profile = self.user(token).await?;

        let username = user_profile
            .name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| user_profile.login.clone());

        identity.username = username;
        identity.preferred_username = user_profile.login.clone();
        identity.email = user_profile.email.clone();

        if self.groups_required(s.groups) {
            identity.groups = self
                .get_groups(token, s.groups, &user_profile.login)
                .await?;
        }

        data.github_login = Some(user_profile.login);
        identity.connector_data = data.to_bytes().ok();

        Ok(identity)
    }
}

// ---------------------------------------------------------------------------
// Legacy RefreshableConnector (backward-compat — will be removed)
// ---------------------------------------------------------------------------

#[async_trait]
impl RefreshableConnector for Conn {
    async fn refresh(
        &self,
        session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        let mut state = ConnectorData::from_bytes(session_state)?;

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

        let token = &state.access_token;
        let orgs = self.fetch_orgs_legacy(token).await?;
        let teams = self.fetch_teams_legacy(token).await?;

        let gate_profile = User {
            id: state.github_id.unwrap_or(0),
            login: state.github_login.clone().unwrap_or_default(),
            name: None,
            email: String::new(),
        };
        if let Err(ConnectorRefreshError::AccessDenied) =
            self.check_access_gate(&gate_profile, &teams)
        {
            return Err(ConnectorRefreshError::TokenRevoked);
        }

        let groups = self.render_team_names(&teams, &orgs);
        let new_claims = ExternalUserClaims {
            sub: state
                .github_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| previous_claims.sub.clone()),
            email: previous_claims.email.clone(),
            email_verified: previous_claims.email_verified,
            display_name: previous_claims.display_name.clone(),
            username_hint: state
                .github_login
                .clone()
                .or_else(|| previous_claims.username_hint.clone()),
            groups,
        };

        state.github_login = state
            .github_login
            .or_else(|| previous_claims.username_hint.clone());
        let new_blob = state.to_bytes()?;

        Ok(RefreshOutcome {
            claims: new_claims,
            new_session_state: Some(new_blob),
        })
    }

    async fn fetch_callback_claims(
        &self,
        code: &str,
        _code_verifier: Option<&str>,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        self.do_fetch_callback_claims(code).await
    }

    fn allow_jit_provisioning(&self) -> bool {
        self.config.allow_jit_provisioning
    }
}

// ---------------------------------------------------------------------------
// Account linking + JIT provisioning
// ---------------------------------------------------------------------------

/// 4-step GitHub account linking chain (T014 / FR-013a).
///
/// Runs steps in order, returning on the first match:
/// 1. Stable numeric ID match (already linked — no write needed).
/// 2. Verified-email match — first-time link.
/// 3. Login-string match — upgrade stored link to numeric ID.
/// 4. JIT provision — create a new `Person` when `allow_jit_provisioning` is true.
pub fn link_or_provision_chain(
    qs_write: &mut crate::server::QueryServerWriteTransaction,
    provider_uuid: Uuid,
    claims: &ExternalUserClaims,
    allow_jit_provisioning: bool,
) -> Result<Option<Uuid>, crate::prelude::OperationError> {
    use crate::prelude::*;

    // Step 1: stable numeric ID match.
    {
        let mut matches = qs_write.internal_search(filter!(f_and!([
            f_eq(
                Attribute::OAuth2AccountProvider,
                PartialValue::Refer(provider_uuid)
            ),
            f_eq(
                Attribute::OAuth2AccountUniqueUserId,
                PartialValue::new_utf8s(&claims.sub)
            ),
            f_eq(Attribute::Class, EntryClass::Person.into()),
        ])))?;
        if let Some(entry) = matches.pop() {
            return Ok(Some(entry.get_uuid()));
        }
    }

    // Step 2: verified email match.
    if claims.email_verified == Some(true) {
        if let Some(ref email) = claims.email {
            let mut matches = qs_write.internal_search(filter!(f_and!([
                f_eq(Attribute::Mail, PartialValue::EmailAddress(email.clone())),
                f_eq(Attribute::Class, EntryClass::Person.into()),
            ])))?;
            if let Some(entry) = matches.pop() {
                let target = entry.get_uuid();
                let cred_id = Uuid::new_v4();
                qs_write
                    .internal_modify(
                        &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target))),
                        &ModifyList::new_list(vec![
                            Modify::Present(Attribute::Class, EntryClass::OAuth2Account.to_value()),
                            Modify::Present(
                                Attribute::OAuth2AccountProvider,
                                Value::Refer(provider_uuid),
                            ),
                            Modify::Present(
                                Attribute::OAuth2AccountUniqueUserId,
                                Value::new_utf8s(&claims.sub),
                            ),
                            Modify::Present(
                                Attribute::OAuth2AccountCredentialUuid,
                                Value::Uuid(cred_id),
                            ),
                        ]),
                    )
                    .map_err(|e| {
                        admin_error!(?e, "github link chain step 2 modify failed");
                        e
                    })?;
                return Ok(Some(target));
            }
        }
    }

    // Step 3: login-string match — upgrade to numeric ID.
    if let Some(ref login) = claims.username_hint {
        let mut matches = qs_write.internal_search(filter!(f_and!([
            f_eq(
                Attribute::OAuth2AccountProvider,
                PartialValue::Refer(provider_uuid)
            ),
            f_eq(
                Attribute::OAuth2AccountUniqueUserId,
                PartialValue::new_utf8s(login)
            ),
            f_eq(Attribute::Class, EntryClass::Person.into()),
        ])))?;
        if let Some(entry) = matches.pop() {
            let target = entry.get_uuid();
            qs_write
                .internal_modify(
                    &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target))),
                    &ModifyList::new_list(vec![
                        Modify::Purged(Attribute::OAuth2AccountUniqueUserId),
                        Modify::Present(
                            Attribute::OAuth2AccountUniqueUserId,
                            Value::new_utf8s(&claims.sub),
                        ),
                    ]),
                )
                .map_err(|e| {
                    admin_error!(?e, "github link chain step 3 upgrade modify failed");
                    e
                })?;
            return Ok(Some(target));
        }
    }

    // Step 4: JIT provision.
    if !allow_jit_provisioning {
        return Ok(None);
    }

    let desired_name = derive_username(qs_write, claims)?;
    let display_name = claims
        .display_name
        .clone()
        .unwrap_or_else(|| desired_name.clone());
    let person_uuid = Uuid::new_v4();
    let cred_id = Uuid::new_v4();

    let mut entry: Entry<EntryInit, EntryNew> = Entry::new();
    entry.add_ava(Attribute::Class, EntryClass::Object.to_value());
    entry.add_ava(Attribute::Class, EntryClass::Account.to_value());
    entry.add_ava(Attribute::Class, EntryClass::Person.to_value());
    entry.add_ava(Attribute::Class, EntryClass::OAuth2Account.to_value());
    entry.add_ava(Attribute::Uuid, Value::Uuid(person_uuid));
    entry.add_ava(Attribute::Name, Value::new_iname(&desired_name));
    entry.add_ava(Attribute::DisplayName, Value::new_utf8s(&display_name));
    entry.add_ava(
        Attribute::OAuth2AccountProvider,
        Value::Refer(provider_uuid),
    );
    entry.add_ava(
        Attribute::OAuth2AccountUniqueUserId,
        Value::new_utf8s(&claims.sub),
    );
    entry.add_ava(Attribute::OAuth2AccountCredentialUuid, Value::Uuid(cred_id));
    if let Some(ref email) = claims.email {
        entry.add_ava(Attribute::Mail, Value::EmailAddress(email.clone(), true));
    }

    qs_write.internal_create(vec![entry]).map_err(|e| {
        admin_error!(?e, "github link chain step 4 JIT provision create failed");
        e
    })?;

    Ok(Some(person_uuid))
}

/// Derive a collision-free netidm username from GitHub claims.
fn derive_username(
    qs_write: &mut crate::server::QueryServerWriteTransaction,
    claims: &ExternalUserClaims,
) -> Result<String, crate::prelude::OperationError> {
    use crate::prelude::*;

    let base = claims
        .username_hint
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            claims
                .email
                .as_deref()
                .and_then(|e| e.split('@').next())
                .filter(|s| !s.is_empty())
        })
        .map(|s| {
            let n: String = s
                .to_lowercase()
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .collect();
            if n.starts_with(|c: char| c.is_ascii_digit()) {
                format!("u{n}")
            } else {
                n
            }
        })
        .unwrap_or_else(|| {
            let frag: String = claims
                .sub
                .chars()
                .filter(|c| c.is_alphanumeric())
                .take(8)
                .collect::<String>()
                .to_lowercase();
            if frag.starts_with(|c: char| c.is_ascii_digit()) {
                format!("u{frag}")
            } else {
                frag
            }
        });

    let mut name_is_free = |name: &str| -> Result<bool, OperationError> {
        qs_write
            .internal_search(filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname(name)
            )))
            .map(|res| res.is_empty())
    };

    if name_is_free(&base)? {
        return Ok(base);
    }
    for suffix in 2u32..=100 {
        let candidate = format!("{base}_{suffix}");
        if name_is_free(&candidate)? {
            return Ok(candidate);
        }
    }
    Err(OperationError::InvalidAttribute(format!(
        "No available username derived from GitHub hint '{base}' (tried _2 through _100)"
    )))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_connector(team_name_field: TeamNameField, load_all_groups: bool) -> Conn {
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        Conn::new(Config {
            entry_uuid: uuid::Uuid::new_v4(),
            host: COM_HOST.clone(),
            api_url: "https://api.github.com".to_string(),
            host_name: None,
            root_ca: None,
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            orgs: Vec::new(),
            org_filter: HashSet::new(),
            allowed_teams: HashSet::new(),
            team_name_field,
            load_all_groups,
            use_login_as_id: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
                .expect("test redirect_uri"),
            http,
        })
    }

    fn teams() -> Vec<Team> {
        vec![
            Team {
                slug: "Alpha".to_string(),
                name: "Alpha Team".to_string(),
                org: OrgEntry {
                    login: "Org1".to_string(),
                },
            },
            Team {
                slug: "Beta".to_string(),
                name: "Beta Team".to_string(),
                org: OrgEntry {
                    login: "Org1".to_string(),
                },
            },
            Team {
                slug: "Gamma".to_string(),
                name: "Gamma Team".to_string(),
                org: OrgEntry {
                    login: "Org2".to_string(),
                },
            },
        ]
    }

    fn orgs() -> Vec<OrgEntry> {
        vec![
            OrgEntry {
                login: "Org1".to_string(),
            },
            OrgEntry {
                login: "Org2".to_string(),
            },
        ]
    }

    #[test]
    fn test_render_team_names_name() {
        let c = make_connector(TeamNameField::Name, false);
        let mut got = c.render_team_names(&teams(), &orgs());
        got.sort();
        assert_eq!(
            got,
            vec!["org1:alpha team", "org1:beta team", "org2:gamma team"]
        );
    }

    #[test]
    fn test_render_team_names_slug() {
        let c = make_connector(TeamNameField::Slug, false);
        let mut got = c.render_team_names(&teams(), &orgs());
        got.sort();
        assert_eq!(got, vec!["org1:alpha", "org1:beta", "org2:gamma"]);
    }

    #[test]
    fn test_render_team_names_both() {
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

    #[test]
    fn test_render_team_names_load_all_groups() {
        let c = make_connector(TeamNameField::Slug, true);
        let mut got = c.render_team_names(&teams(), &orgs());
        got.sort();
        assert_eq!(
            got,
            vec!["org1", "org1:alpha", "org1:beta", "org2", "org2:gamma"]
        );
    }

    #[test]
    fn test_org_filter_drops_outside_orgs() {
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        let mut org_filter = HashSet::new();
        org_filter.insert("org1".to_string());
        let connector = Conn::new(Config {
            entry_uuid: uuid::Uuid::new_v4(),
            host: COM_HOST.clone(),
            api_url: "https://api.github.com".to_string(),
            host_name: None,
            root_ca: None,
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            orgs: Vec::new(),
            org_filter,
            allowed_teams: HashSet::new(),
            team_name_field: TeamNameField::Slug,
            load_all_groups: false,
            use_login_as_id: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
                .expect("test redirect_uri"),
            http,
        });
        let mut got = connector.render_team_names(&teams(), &orgs());
        got.sort();
        assert_eq!(got, vec!["org1:alpha", "org1:beta"]);

        let pass_through = make_connector(TeamNameField::Slug, false);
        let mut all = pass_through.render_team_names(&teams(), &orgs());
        all.sort();
        assert_eq!(all, vec!["org1:alpha", "org1:beta", "org2:gamma"]);
    }

    #[test]
    fn test_pagination_link_header() {
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

    #[test]
    fn test_team_group_claims_name_default() {
        let c = make_connector(TeamNameField::Name, false);
        let t = Team {
            slug: "eng".to_string(),
            name: "Engineering".to_string(),
            org: OrgEntry {
                login: "acme".to_string(),
            },
        };
        assert_eq!(c.team_group_claims(&t), vec!["Engineering"]);
    }

    #[test]
    fn test_team_group_claims_slug() {
        let c = make_connector(TeamNameField::Slug, false);
        let t = Team {
            slug: "eng".to_string(),
            name: "Engineering".to_string(),
            org: OrgEntry {
                login: "acme".to_string(),
            },
        };
        assert_eq!(c.team_group_claims(&t), vec!["eng"]);
    }

    #[test]
    fn test_team_group_claims_both() {
        let c = make_connector(TeamNameField::Both, false);
        let t = Team {
            slug: "eng".to_string(),
            name: "Engineering".to_string(),
            org: OrgEntry {
                login: "acme".to_string(),
            },
        };
        assert_eq!(c.team_group_claims(&t), vec!["Engineering", "eng"]);
    }

    #[test]
    fn test_format_team_name() {
        assert_eq!(format_team_name("acme", "eng"), "acme:eng");
    }

    #[test]
    fn test_is_preferred_email_domain_exact() {
        let c = make_connector(TeamNameField::Name, false);
        let mut c = c;
        c.config.preferred_email_domain = Some("example.com".to_string());
        assert!(c.is_preferred_email_domain("example.com"));
        assert!(!c.is_preferred_email_domain("other.com"));
    }

    #[test]
    fn test_is_preferred_email_domain_wildcard() {
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        let c = Conn::new(Config {
            entry_uuid: uuid::Uuid::new_v4(),
            host: COM_HOST.clone(),
            api_url: "https://api.github.com".to_string(),
            host_name: None,
            root_ca: None,
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            orgs: Vec::new(),
            org_filter: HashSet::new(),
            allowed_teams: HashSet::new(),
            team_name_field: TeamNameField::Name,
            load_all_groups: false,
            use_login_as_id: false,
            preferred_email_domain: Some("*.example.com".to_string()),
            allow_jit_provisioning: false,
            redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
                .expect("test redirect_uri"),
            http,
        });
        assert!(c.is_preferred_email_domain("sub.example.com"));
        assert!(!c.is_preferred_email_domain("example.com"));
        assert!(!c.is_preferred_email_domain("other.com"));
    }

    #[test]
    fn test_groups_required() {
        let c = make_connector(TeamNameField::Name, false);
        assert!(!c.groups_required(false));
        assert!(c.groups_required(true));
    }

    #[test]
    fn test_groups_required_with_orgs() {
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        let c = Conn::new(Config {
            entry_uuid: uuid::Uuid::new_v4(),
            host: COM_HOST.clone(),
            api_url: "https://api.github.com".to_string(),
            host_name: None,
            root_ca: None,
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            orgs: vec![Org {
                name: "acme".to_string(),
                teams: Vec::new(),
            }],
            org_filter: HashSet::new(),
            allowed_teams: HashSet::new(),
            team_name_field: TeamNameField::Name,
            load_all_groups: false,
            use_login_as_id: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
                .expect("test redirect_uri"),
            http,
        });
        assert!(c.groups_required(false));
    }

    fn make_connector_with_allowed_teams(allowed: &[&str]) -> Conn {
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        let allowed_teams = allowed.iter().map(|s| s.to_string()).collect();
        Conn::new(Config {
            entry_uuid: uuid::Uuid::new_v4(),
            host: COM_HOST.clone(),
            api_url: "https://api.github.com".to_string(),
            host_name: None,
            root_ca: None,
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            orgs: Vec::new(),
            org_filter: HashSet::new(),
            allowed_teams,
            team_name_field: TeamNameField::Name,
            load_all_groups: false,
            use_login_as_id: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
                .expect("test redirect_uri"),
            http,
        })
    }

    fn make_profile(id: i64, login: &str) -> User {
        User {
            id,
            login: login.to_string(),
            name: None,
            email: String::new(),
        }
    }

    fn make_team(org: &str, slug: &str) -> Team {
        Team {
            slug: slug.to_string(),
            name: slug.to_string(),
            org: OrgEntry {
                login: org.to_string(),
            },
        }
    }

    #[test]
    fn test_access_gate_empty_allowed_teams_passes() {
        let connector = make_connector_with_allowed_teams(&[]);
        let profile = make_profile(1, "alice");
        assert!(connector.check_access_gate(&profile, &[]).is_ok());
        let teams = vec![make_team("org", "nope")];
        assert!(connector.check_access_gate(&profile, &teams).is_ok());
    }

    #[test]
    fn test_access_gate_empty_intersection_rejects() {
        let connector = make_connector_with_allowed_teams(&["acme:eng"]);
        let profile = make_profile(2, "bob");
        let teams = vec![make_team("acme", "ops"), make_team("other", "devs")];
        let result = connector.check_access_gate(&profile, &teams);
        assert!(
            matches!(
                result,
                Err(crate::idm::connector::traits::ConnectorRefreshError::AccessDenied)
            ),
            "expected AccessDenied, got {result:?}"
        );
    }

    #[test]
    fn test_access_gate_matching_team_passes() {
        let connector = make_connector_with_allowed_teams(&["acme:eng", "other:staff"]);
        let profile = make_profile(3, "carol");
        let teams = vec![make_team("acme", "eng"), make_team("acme", "all")];
        assert!(connector.check_access_gate(&profile, &teams).is_ok());
    }

    #[test]
    fn test_access_gate_case_insensitive() {
        let connector = make_connector_with_allowed_teams(&["acme:eng"]);
        let profile = make_profile(4, "dave");
        let teams = vec![make_team("ACME", "ENG")];
        assert!(connector.check_access_gate(&profile, &teams).is_ok());
    }

    fn make_session_state(
        id: i64,
        login: &str,
        token: &str,
        refresh_token: Option<&str>,
        expires_at: Option<OffsetDateTime>,
    ) -> Vec<u8> {
        ConnectorData {
            format_version: FORMAT_VERSION,
            access_token: token.to_string(),
            refresh_token: refresh_token.map(str::to_string),
            access_token_expires_at: expires_at,
            github_id: Some(id),
            github_login: Some(login.to_string()),
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

    #[tokio::test]
    async fn test_refresh_returns_fresh_claims() {
        use crate::idm::connector::traits::RefreshableConnector;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

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

        let api_url = format!("{}api/v3", base.as_str());

        let connector = Conn::new(Config {
            entry_uuid: uuid::Uuid::new_v4(),
            host: base,
            api_url,
            host_name: None,
            root_ca: None,
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            orgs: Vec::new(),
            org_filter: HashSet::new(),
            allowed_teams: HashSet::new(),
            team_name_field: TeamNameField::Slug,
            load_all_groups: false,
            use_login_as_id: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
                .expect("test redirect_uri"),
            http,
        });

        let blob = make_session_state(42, "alice", "gho_does_not_matter", None, None);
        let prev = make_previous_claims(42, "alice@example.com");

        let outcome = RefreshableConnector::refresh(&connector, &blob, &prev)
            .await
            .expect("refresh should succeed");

        assert_eq!(outcome.claims.sub, "42");
        let mut groups = outcome.claims.groups.clone();
        groups.sort();
        assert_eq!(groups, vec!["refreshcorp:devs"]);
        assert_eq!(outcome.claims.email.as_deref(), Some("alice@example.com"));
        assert!(outcome.new_session_state.is_some());
    }

    #[tokio::test]
    async fn test_refresh_error_serialization_failure() {
        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        let connector = Conn::new(Config {
            entry_uuid: uuid::Uuid::new_v4(),
            host: COM_HOST.clone(),
            api_url: "https://api.github.com".to_string(),
            host_name: None,
            root_ca: None,
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            orgs: Vec::new(),
            org_filter: HashSet::new(),
            allowed_teams: HashSet::new(),
            team_name_field: TeamNameField::Name,
            load_all_groups: false,
            use_login_as_id: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
                .expect("test redirect_uri"),
            http,
        });
        use crate::idm::connector::traits::RefreshableConnector;
        let prev = make_previous_claims(1, "x@example.com");
        let result = RefreshableConnector::refresh(&connector, b"not-valid-json", &prev).await;
        assert!(
            matches!(
                result,
                Err(crate::idm::connector::traits::ConnectorRefreshError::Serialization(_))
            ),
            "expected Serialization error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_refresh_access_gate_enforced() {
        use crate::idm::connector::traits::RefreshableConnector;
        use axum::routing::get;

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
        let api_url = format!("{}api/v3", base.as_str());

        let mut allowed_teams = HashSet::new();
        allowed_teams.insert("acme:employees".to_string());

        let http = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| unreachable!());
        let connector = Conn::new(Config {
            entry_uuid: uuid::Uuid::new_v4(),
            host: base,
            api_url,
            host_name: None,
            root_ca: None,
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            orgs: Vec::new(),
            org_filter: HashSet::new(),
            allowed_teams,
            team_name_field: TeamNameField::Name,
            load_all_groups: false,
            use_login_as_id: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
                .expect("test redirect_uri"),
            http,
        });

        let blob = make_session_state(99, "former-employee", "gho_any_token", None, None);
        let prev = make_previous_claims(99, "user@example.com");

        let result = RefreshableConnector::refresh(&connector, &blob, &prev).await;
        assert!(
            matches!(
                result,
                Err(crate::idm::connector::traits::ConnectorRefreshError::TokenRevoked)
            ),
            "expected TokenRevoked on gate failure, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_refresh_rotates_access_token_when_expired() {
        use crate::idm::connector::traits::RefreshableConnector;
        use axum::routing::{get, post};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                axum::Router::new()
                    .route(
                        "/login/oauth/access_token",
                        post(|| async {
                            axum::Json(serde_json::json!({
                                "access_token": "gho_new_access_token",
                                "token_type": "bearer",
                                "refresh_token": "ghr_new_refresh_token",
                                "expires_in": 3600
                            }))
                        }),
                    )
                    .route(
                        "/api/v3/user/orgs",
                        get(|| async { axum::Json(serde_json::json!([])) }),
                    )
                    .route(
                        "/api/v3/user/teams",
                        get(|| async { axum::Json(serde_json::json!([])) }),
                    ),
            )
            .await;
        });

        let base = url::Url::parse(&format!("http://{addr}")).expect("url");
        let api_url = format!("{}api/v3", base.as_str());

        let connector = Conn::new(Config {
            entry_uuid: Uuid::new_v4(),
            host: base,
            api_url,
            host_name: None,
            root_ca: None,
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            orgs: Vec::new(),
            org_filter: HashSet::new(),
            allowed_teams: HashSet::new(),
            team_name_field: TeamNameField::Name,
            load_all_groups: false,
            use_login_as_id: false,
            preferred_email_domain: None,
            allow_jit_provisioning: false,
            redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
                .expect("test redirect_uri"),
            http: reqwest::Client::builder()
                .build()
                .unwrap_or_else(|_| unreachable!()),
        });

        let expired_at = OffsetDateTime::UNIX_EPOCH + TimeDuration::seconds(1_000_000_000);
        let blob = make_session_state(
            7,
            "bob",
            "gho_old_access_token",
            Some("ghr_old_refresh_token"),
            Some(expired_at),
        );
        let prev = make_previous_claims(7, "bob@example.com");

        let outcome = RefreshableConnector::refresh(&connector, &blob, &prev)
            .await
            .expect("refresh should succeed");

        let new_state = ConnectorData::from_bytes(
            &outcome
                .new_session_state
                .expect("new_session_state should be Some"),
        )
        .expect("parse new session state");

        assert_eq!(new_state.access_token, "gho_new_access_token");
        assert_eq!(
            new_state.refresh_token.as_deref(),
            Some("ghr_new_refresh_token")
        );
    }

    #[tokio::test]
    async fn test_refresh_error_variants() {
        use crate::idm::connector::traits::{ConnectorRefreshError, RefreshableConnector};
        use axum::routing::get;

        let make_conn = |addr: std::net::SocketAddr| -> Conn {
            let base = url::Url::parse(&format!("http://{addr}")).expect("url");
            let api_url = format!("{}api/v3", base.as_str());
            Conn::new(Config {
                entry_uuid: Uuid::new_v4(),
                host: base,
                api_url,
                host_name: None,
                root_ca: None,
                client_id: "t".to_string(),
                client_secret: "t".to_string(),
                orgs: Vec::new(),
                org_filter: HashSet::new(),
                allowed_teams: HashSet::new(),
                team_name_field: TeamNameField::Name,
                load_all_groups: false,
                use_login_as_id: false,
                preferred_email_domain: None,
                allow_jit_provisioning: false,
                redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
                    .expect("test redirect_uri"),
                http: reqwest::Client::builder()
                    .build()
                    .unwrap_or_else(|_| unreachable!()),
            })
        };

        let blob = make_session_state(1, "user", "gho_tok", None, None);
        let prev = make_previous_claims(1, "user@example.com");

        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(async move {
                let _ = axum::serve(
                    listener,
                    axum::Router::new().route(
                        "/api/v3/user/orgs",
                        get(|| async { (axum::http::StatusCode::UNAUTHORIZED, "") }),
                    ),
                )
                .await;
            });
            let result = RefreshableConnector::refresh(&make_conn(addr), &blob, &prev).await;
            assert!(
                matches!(result, Err(ConnectorRefreshError::UpstreamRejected(401))),
                "401 from orgs should be UpstreamRejected(401), got {result:?}"
            );
        }

        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(async move {
                let _ = axum::serve(
                    listener,
                    axum::Router::new()
                        .route(
                            "/api/v3/user/orgs",
                            get(|| async { axum::Json(serde_json::json!([])) }),
                        )
                        .route(
                            "/api/v3/user/teams",
                            get(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "") }),
                        ),
                )
                .await;
            });
            let result = RefreshableConnector::refresh(&make_conn(addr), &blob, &prev).await;
            assert!(
                matches!(result, Err(ConnectorRefreshError::UpstreamRejected(500))),
                "500 from teams should be UpstreamRejected(500), got {result:?}"
            );
        }

        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(async move {
                let _ = axum::serve(
                    listener,
                    axum::Router::new()
                        .route("/api/v3/user/orgs", get(|| async { "not-valid-json" })),
                )
                .await;
            });
            let result = RefreshableConnector::refresh(&make_conn(addr), &blob, &prev).await;
            assert!(
                matches!(result, Err(ConnectorRefreshError::Other(_))),
                "malformed JSON should be Other, got {result:?}"
            );
        }
    }

    #[idm_test]
    async fn test_linking_chain_step_1_email(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = std::time::Duration::from_secs(6000);
        let provider_uuid = UUID_DOMAIN_INFO;
        let person_uuid = Uuid::new_v4();

        let mut pw = idms.proxy_write(ct).await.expect("proxy_write");
        let entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Uuid, Value::Uuid(person_uuid)),
            (Attribute::Name, Value::new_iname("alice")),
            (Attribute::DisplayName, Value::new_utf8s("Alice")),
            (
                Attribute::Mail,
                Value::EmailAddress("alice@example.com".to_string(), true)
            )
        );
        pw.qs_write
            .internal_create(vec![entry])
            .expect("create person");
        pw.commit().expect("commit");

        let claims = ExternalUserClaims {
            sub: "99".to_string(),
            email: Some("alice@example.com".to_string()),
            email_verified: Some(true),
            display_name: Some("Alice".to_string()),
            username_hint: Some("alice-gh".to_string()),
            groups: vec![],
        };
        let mut pw = idms.proxy_write(ct).await.expect("proxy_write");
        let result = link_or_provision_chain(&mut pw.qs_write, provider_uuid, &claims, false)
            .expect("chain should not error");

        assert_eq!(
            result,
            Some(person_uuid),
            "step 1 should return the seeded person"
        );

        let entry = pw
            .qs_write
            .internal_search_uuid(person_uuid)
            .expect("search seeded person");
        assert!(
            entry.attribute_equality(
                Attribute::OAuth2AccountUniqueUserId,
                &PartialValue::new_utf8s("99")
            ),
            "numeric GitHub ID should be written as UniqueUserId"
        );
        pw.commit().expect("commit");
    }

    #[idm_test]
    async fn test_jit_disabled_rejects_unknown_user(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = std::time::Duration::from_secs(6000);
        let provider_uuid = Uuid::new_v4();

        let claims = ExternalUserClaims {
            sub: "999".to_string(),
            email: Some("ghost@example.com".to_string()),
            email_verified: Some(true),
            display_name: None,
            username_hint: Some("ghost-user".to_string()),
            groups: vec![],
        };

        let mut pw = idms.proxy_write(ct).await.expect("proxy_write");
        let result = link_or_provision_chain(&mut pw.qs_write, provider_uuid, &claims, false)
            .expect("chain should not error");

        assert_eq!(
            result, None,
            "JIT disabled and no match should return Ok(None)"
        );
        pw.commit().expect("commit");
    }
}
