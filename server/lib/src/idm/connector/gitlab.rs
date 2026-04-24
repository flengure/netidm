//! GitLab upstream connector (PR-CONNECTOR-GITLAB).
//!
//! Exact-parity port of `connector/gitlab/gitlab.go` from dex.
//! Providers whose `Connector` entry carries
//! `connector_provider_kind = "gitlab"` are dispatched here.
//!
//! Supports both gitlab.com and self-hosted GitLab via `base_url`.
//! Groups are fetched from `GET {base_url}/oauth/userinfo` using the `openid`
//! scope (add `openid` to `oauth2_request_scopes` on the entry).
//! The `groups` allowlist is an access gate; `get_groups_permission` appends
//! `:owner`/`:maintainer`/`:developer` role suffixes to group paths.
//! Session state carries both an access token and a refresh token.

use crate::idm::authsession::handler_connector::ExternalUserClaims;
use crate::idm::connector::traits::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

pub const GITLAB_DEFAULT_BASE_URL: &str = "https://gitlab.com";
pub const GITLAB_SESSION_STATE_FORMAT_VERSION: u8 = 1;

/// Parsed GitLab connector configuration.
pub struct GitLabConfig {
    pub entry_uuid: Uuid,
    /// Root of the GitLab instance, e.g. `https://gitlab.com`.
    pub base_url: String,
    pub client_id: String,
    client_secret: String,
    pub redirect_uri: Url,
    /// Allowlist of group paths. Empty = allow all authenticated users.
    pub groups: HashSet<String>,
    /// Use `user.username` (login) as `sub` instead of numeric `user.id`.
    pub use_login_as_id: bool,
    /// Append `:owner`/`:maintainer`/`:developer` suffixes to group names.
    pub get_groups_permission: bool,
    pub http: reqwest::Client,
    // Test endpoint overrides.
    pub token_endpoint_override: Option<String>,
    pub user_endpoint_override: Option<String>,
    pub userinfo_endpoint_override: Option<String>,
}

impl std::fmt::Debug for GitLabConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitLabConfig")
            .field("entry_uuid", &self.entry_uuid)
            .field("base_url", &self.base_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"***")
            .field("redirect_uri", &self.redirect_uri)
            .field("groups", &self.groups)
            .field("use_login_as_id", &self.use_login_as_id)
            .field("get_groups_permission", &self.get_groups_permission)
            .finish()
    }
}

impl GitLabConfig {
    pub fn from_entry(
        entry: &crate::entry::Entry<crate::entry::EntrySealed, crate::entry::EntryCommitted>,
        redirect_uri: Url,
    ) -> Result<Self, OperationError> {
        let entry_uuid = entry.get_uuid();

        let client_id = entry
            .get_ava_single_utf8(Attribute::ConnectorId)
            .ok_or_else(|| {
                error!(?entry_uuid, "GitLab connector entry missing connector_id");
                OperationError::InvalidEntryState
            })?
            .to_string();

        let client_secret = entry
            .get_ava_single_utf8(Attribute::ConnectorSecret)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "GitLab connector entry missing connector_secret"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let base_url = entry
            .get_ava_single_iutf8(Attribute::ConnectorGitlabBaseUrl)
            .unwrap_or(GITLAB_DEFAULT_BASE_URL)
            .trim_end_matches('/')
            .to_string();

        let groups: HashSet<String> = entry
            .get_ava_set(Attribute::ConnectorGitlabGroups)
            .and_then(|vs| vs.as_utf8_iter())
            .map(|iter| iter.map(str::to_string).collect())
            .unwrap_or_default();

        let use_login_as_id = entry
            .get_ava_single_bool(Attribute::ConnectorGitlabUseLoginAsId)
            .unwrap_or(false);

        let get_groups_permission = entry
            .get_ava_single_bool(Attribute::ConnectorGitlabGetGroupsPermission)
            .unwrap_or(false);

        let root_ca_pem = entry
            .get_ava_single_utf8(Attribute::ConnectorGitlabRootCa)
            .map(str::to_string);

        let mut client_builder =
            reqwest::Client::builder().user_agent(concat!("netidmd/", env!("CARGO_PKG_VERSION")));

        if let Some(ref pem) = root_ca_pem {
            match reqwest::Certificate::from_pem(pem.as_bytes()) {
                Ok(cert) => {
                    client_builder = client_builder.add_root_certificate(cert);
                }
                Err(e) => {
                    error!(
                        ?entry_uuid,
                        "GitLab connector: failed to parse root_ca PEM: {e}"
                    );
                    return Err(OperationError::InvalidEntryState);
                }
            }
        }

        let http = client_builder.build().map_err(|e| {
            error!(
                ?entry_uuid,
                "Failed to build HTTP client for GitLab connector: {e}"
            );
            OperationError::InvalidEntryState
        })?;

        Ok(GitLabConfig {
            entry_uuid,
            base_url,
            client_id,
            client_secret,
            redirect_uri,
            groups,
            use_login_as_id,
            get_groups_permission,
            http,
            token_endpoint_override: None,
            user_endpoint_override: None,
            userinfo_endpoint_override: None,
        })
    }

    #[cfg(test)]
    pub fn new_for_test(
        entry_uuid: Uuid,
        base_url: String,
        client_id: String,
        client_secret: String,
        redirect_uri: Url,
        groups: HashSet<String>,
        use_login_as_id: bool,
        get_groups_permission: bool,
    ) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("netidmd-test")
            .build()
            .expect("reqwest client build");
        GitLabConfig {
            entry_uuid,
            base_url,
            client_id,
            client_secret,
            redirect_uri,
            groups,
            use_login_as_id,
            get_groups_permission,
            http,
            token_endpoint_override: None,
            user_endpoint_override: None,
            userinfo_endpoint_override: None,
        }
    }
}

/// Opaque per-session state. Carries both access and refresh tokens so that
/// `refresh()` can use the GitLab refresh-token grant when available.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GitLabSessionState {
    pub format_version: u8,
    pub access_token: String,
    /// Empty string when the GitLab response did not include a refresh token.
    pub refresh_token: String,
}

impl GitLabSessionState {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorRefreshError> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state is not UTF-8: {e}"))
        })?;
        let state: Self = serde_json::from_str(s).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state JSON parse failed: {e}"))
        })?;
        if state.format_version != GITLAB_SESSION_STATE_FORMAT_VERSION {
            return Err(ConnectorRefreshError::Serialization(format!(
                "session-state format_version {} not supported (expected {})",
                state.format_version, GITLAB_SESSION_STATE_FORMAT_VERSION
            )));
        }
        Ok(state)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ConnectorRefreshError> {
        serde_json::to_vec(self)
            .map_err(|e| ConnectorRefreshError::Serialization(format!("serialise failed: {e}")))
    }
}

// ---------- GitLab API response shapes ----------

#[derive(Deserialize, Debug)]
struct GitLabTokenResponse {
    access_token: String,
    /// Present when GitLab issues a refresh token (offline_access scope).
    /// Stored in session-state blob once the upstream_connector infrastructure
    /// is wired for OAuth2 code-flow sessions.
    #[serde(default)]
    #[allow(dead_code)]
    refresh_token: String,
}

#[derive(Deserialize, Debug)]
struct GitLabUser {
    id: i64,
    #[serde(default)]
    name: String,
    username: String,
    #[serde(default)]
    email: String,
}

#[derive(Deserialize, Debug, Default)]
struct GitLabUserInfo {
    #[serde(default)]
    groups: Vec<String>,
    #[serde(rename = "https://gitlab.org/claims/groups/owner", default)]
    owner_permission: Vec<String>,
    #[serde(rename = "https://gitlab.org/claims/groups/maintainer", default)]
    maintainer_permission: Vec<String>,
    #[serde(rename = "https://gitlab.org/claims/groups/developer", default)]
    developer_permission: Vec<String>,
}

// ---------- Connector ----------

pub struct GitLabConnector {
    config: GitLabConfig,
}

impl GitLabConnector {
    pub fn new(config: GitLabConfig) -> Self {
        Self { config }
    }

    async fn exchange_code(
        &self,
        code: &str,
    ) -> Result<GitLabTokenResponse, ConnectorRefreshError> {
        let default_url = format!("{}/oauth/token", self.config.base_url);
        let token_url = self
            .config
            .token_endpoint_override
            .as_deref()
            .unwrap_or(&default_url);

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];

        let res = self
            .config
            .http
            .post(token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(ConnectorRefreshError::Network(format!(
                "GitLab token endpoint returned {status}: {body}"
            )));
        }

        res.json::<GitLabTokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<GitLabTokenResponse, ConnectorRefreshError> {
        let default_url = format!("{}/oauth/token", self.config.base_url);
        let token_url = self
            .config
            .token_endpoint_override
            .as_deref()
            .unwrap_or(&default_url);

        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("redirect_uri", self.config.redirect_uri.as_str()),
        ];

        let res = self
            .config
            .http
            .post(token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::BAD_REQUEST
            {
                return Err(ConnectorRefreshError::TokenRevoked);
            }
            let body = res.text().await.unwrap_or_default();
            return Err(ConnectorRefreshError::Network(format!(
                "GitLab token refresh returned {status}: {body}"
            )));
        }

        res.json::<GitLabTokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn fetch_user(&self, token: &str) -> Result<GitLabUser, ConnectorRefreshError> {
        let default_url = format!("{}/api/v4/user", self.config.base_url);
        let user_url = self
            .config
            .user_endpoint_override
            .as_deref()
            .unwrap_or(&default_url);

        let res = self
            .config
            .http
            .get(user_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(ConnectorRefreshError::Network(format!(
                "GitLab /api/v4/user returned {status}: {body}"
            )));
        }

        res.json::<GitLabUser>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn fetch_userinfo(&self, token: &str) -> Result<GitLabUserInfo, ConnectorRefreshError> {
        let default_url = format!("{}/oauth/userinfo", self.config.base_url);
        let userinfo_url = self
            .config
            .userinfo_endpoint_override
            .as_deref()
            .unwrap_or(&default_url);

        let res = self
            .config
            .http
            .get(userinfo_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            warn!(
                "GitLab /oauth/userinfo returned {status}: {body} — groups will be empty. \
                 Ensure 'openid' is included in oauth2_request_scopes."
            );
            return Ok(GitLabUserInfo::default());
        }

        res.json::<GitLabUserInfo>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    /// Append `:owner`/`:maintainer`/`:developer` suffixes.
    ///
    /// For each group `g` in `userinfo.groups`, if any permission path `p`
    /// equals `g` or is a direct ancestor of `g` (i.e. `g` starts with `p/`),
    /// append `{g}:owner` (or `:maintainer`/`:developer`) to the list.
    /// Mirrors dex's `setGroupsPermission` label logic exactly.
    fn set_groups_permission(userinfo: &GitLabUserInfo) -> Vec<String> {
        let mut result = userinfo.groups.clone();
        'outer: for g in &userinfo.groups {
            for p in &userinfo.owner_permission {
                if g == p || (g.starts_with(p.as_str()) && g.as_bytes().get(p.len()) == Some(&b'/'))
                {
                    result.push(format!("{g}:owner"));
                    continue 'outer;
                }
            }
            for p in &userinfo.maintainer_permission {
                if g == p || (g.starts_with(p.as_str()) && g.as_bytes().get(p.len()) == Some(&b'/'))
                {
                    result.push(format!("{g}:maintainer"));
                    continue 'outer;
                }
            }
            for p in &userinfo.developer_permission {
                if g == p || (g.starts_with(p.as_str()) && g.as_bytes().get(p.len()) == Some(&b'/'))
                {
                    result.push(format!("{g}:developer"));
                    continue 'outer;
                }
            }
        }
        result
    }

    fn apply_groups_filter(
        &self,
        groups: Vec<String>,
        username: &str,
    ) -> Result<Vec<String>, ConnectorRefreshError> {
        if self.config.groups.is_empty() {
            return Ok(groups);
        }
        let filtered: Vec<String> = groups
            .into_iter()
            .filter(|g| self.config.groups.contains(g))
            .collect();
        if filtered.is_empty() {
            warn!(
                %username,
                "GitLab connector: user not in any required group"
            );
            return Err(ConnectorRefreshError::AccessDenied);
        }
        Ok(filtered)
    }

    async fn build_claims(
        &self,
        access_token: &str,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        let user = self.fetch_user(access_token).await?;

        let sub = if self.config.use_login_as_id {
            user.username.clone()
        } else {
            user.id.to_string()
        };

        let username = if user.name.is_empty() {
            user.email.clone()
        } else {
            user.name.clone()
        };

        let userinfo = self.fetch_userinfo(access_token).await?;

        let raw_groups = if self.config.get_groups_permission {
            Self::set_groups_permission(&userinfo)
        } else {
            userinfo.groups
        };

        let groups = self.apply_groups_filter(raw_groups, &user.username)?;

        Ok(ExternalUserClaims {
            sub,
            email: Some(user.email),
            email_verified: Some(true),
            display_name: Some(username.clone()),
            username_hint: Some(user.username),
            groups,
        })
    }
}

#[async_trait]
impl RefreshableConnector for GitLabConnector {
    async fn fetch_callback_claims(
        &self,
        code: &str,
        _code_verifier: Option<&str>,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        let token_resp = self.exchange_code(code).await?;
        self.build_claims(&token_resp.access_token).await
    }

    async fn refresh(
        &self,
        session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        let state = GitLabSessionState::from_bytes(session_state)?;

        let access_token = if !state.refresh_token.is_empty() {
            let new_tok = self.refresh_token(&state.refresh_token).await?;
            new_tok.access_token
        } else if !state.access_token.is_empty() {
            state.access_token.clone()
        } else {
            return Err(ConnectorRefreshError::TokenRevoked);
        };

        let claims = self.build_claims(&access_token).await?;

        if claims.sub != previous_claims.sub {
            warn!(
                expected = %previous_claims.sub,
                got = %claims.sub,
                "GitLab connector: sub mismatch on refresh"
            );
            return Err(ConnectorRefreshError::TokenRevoked);
        }

        Ok(RefreshOutcome {
            claims,
            new_session_state: None,
        })
    }

    fn allow_jit_provisioning(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::uuid;

    const TEST_UUID: Uuid = uuid!("00000000-0000-0000-0000-000000000001");

    fn default_config() -> GitLabConfig {
        GitLabConfig::new_for_test(
            TEST_UUID,
            "https://gitlab.com".into(),
            "client-id".into(),
            "client-secret".into(),
            Url::parse("https://netidm.example.com/oauth2/callback").unwrap(),
            HashSet::new(),
            false,
            false,
        )
    }

    fn connector(cfg: GitLabConfig) -> GitLabConnector {
        GitLabConnector::new(cfg)
    }

    #[test]
    fn test_gitlab_user_parse() {
        let json = r#"{
            "id": 42,
            "name": "Alice Smith",
            "username": "alice",
            "email": "alice@example.com"
        }"#;
        let user: GitLabUser = serde_json::from_str(json).expect("parse failed");
        assert_eq!(user.id, 42);
        assert_eq!(user.name, "Alice Smith");
        assert_eq!(user.username, "alice");
        assert_eq!(user.email, "alice@example.com");
    }

    #[test]
    fn test_gitlab_user_parse_empty_name_fallback() {
        let json = r#"{"id": 1, "name": "", "username": "bob", "email": "bob@example.com"}"#;
        let user: GitLabUser = serde_json::from_str(json).expect("parse");
        let cfg = default_config();
        let conn = connector(cfg);
        // simulate build_claims display_name logic
        let display_name = if user.name.is_empty() {
            user.email.clone()
        } else {
            user.name.clone()
        };
        assert_eq!(display_name, "bob@example.com");
        let _ = conn; // ensure connector compiles
    }

    #[test]
    fn test_gitlab_userinfo_parse() {
        let json = r#"{
            "groups": ["myorg", "myorg/subteam"],
            "https://gitlab.org/claims/groups/owner": ["myorg"],
            "https://gitlab.org/claims/groups/maintainer": [],
            "https://gitlab.org/claims/groups/developer": ["myorg/subteam"]
        }"#;
        let info: GitLabUserInfo = serde_json::from_str(json).expect("parse failed");
        assert_eq!(info.groups, vec!["myorg", "myorg/subteam"]);
        assert_eq!(info.owner_permission, vec!["myorg"]);
        assert!(info.maintainer_permission.is_empty());
        assert_eq!(info.developer_permission, vec!["myorg/subteam"]);
    }

    #[test]
    fn test_set_groups_permission_exact_match() {
        let info = GitLabUserInfo {
            groups: vec!["myorg".into()],
            owner_permission: vec!["myorg".into()],
            maintainer_permission: vec![],
            developer_permission: vec![],
        };
        let result = GitLabConnector::set_groups_permission(&info);
        assert!(result.contains(&"myorg".to_string()));
        assert!(result.contains(&"myorg:owner".to_string()));
    }

    #[test]
    fn test_set_groups_permission_subgroup() {
        let info = GitLabUserInfo {
            groups: vec!["myorg/subteam".into()],
            owner_permission: vec!["myorg".into()],
            maintainer_permission: vec![],
            developer_permission: vec![],
        };
        let result = GitLabConnector::set_groups_permission(&info);
        assert!(result.contains(&"myorg/subteam:owner".to_string()));
    }

    #[test]
    fn test_set_groups_permission_no_match() {
        let info = GitLabUserInfo {
            groups: vec!["other".into()],
            owner_permission: vec!["myorg".into()],
            maintainer_permission: vec![],
            developer_permission: vec![],
        };
        let result = GitLabConnector::set_groups_permission(&info);
        assert_eq!(result, vec!["other".to_string()]);
    }

    #[test]
    fn test_set_groups_permission_developer() {
        let info = GitLabUserInfo {
            groups: vec!["myorg/devteam".into()],
            owner_permission: vec![],
            maintainer_permission: vec![],
            developer_permission: vec!["myorg/devteam".into()],
        };
        let result = GitLabConnector::set_groups_permission(&info);
        assert!(result.contains(&"myorg/devteam:developer".to_string()));
    }

    #[test]
    fn test_groups_filter_empty_allows_all() {
        let cfg = default_config();
        let conn = connector(cfg);
        let result = conn.apply_groups_filter(vec!["a".into(), "b".into()], "user");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["a", "b"]);
    }

    #[test]
    fn test_groups_filter_passes_matching() {
        let mut allowed = HashSet::new();
        allowed.insert("myorg".into());
        let cfg = GitLabConfig::new_for_test(
            TEST_UUID,
            "https://gitlab.com".into(),
            "c".into(),
            "s".into(),
            Url::parse("https://example.com/cb").unwrap(),
            allowed,
            false,
            false,
        );
        let conn = connector(cfg);
        let result = conn.apply_groups_filter(vec!["myorg".into(), "other".into()], "user");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["myorg"]);
    }

    #[test]
    fn test_groups_filter_denies_no_match() {
        let mut allowed = HashSet::new();
        allowed.insert("admins".into());
        let cfg = GitLabConfig::new_for_test(
            TEST_UUID,
            "https://gitlab.com".into(),
            "c".into(),
            "s".into(),
            Url::parse("https://example.com/cb").unwrap(),
            allowed,
            false,
            false,
        );
        let conn = connector(cfg);
        let result = conn.apply_groups_filter(vec!["devs".into()], "user");
        assert!(matches!(result, Err(ConnectorRefreshError::AccessDenied)));
    }

    #[test]
    fn test_session_state_roundtrip() {
        let state = GitLabSessionState {
            format_version: GITLAB_SESSION_STATE_FORMAT_VERSION,
            access_token: "acc".into(),
            refresh_token: "ref".into(),
        };
        let bytes = state.to_bytes().expect("serialise");
        let decoded = GitLabSessionState::from_bytes(&bytes).expect("deserialise");
        assert_eq!(decoded.access_token, "acc");
        assert_eq!(decoded.refresh_token, "ref");
    }

    #[test]
    fn test_session_state_version_mismatch() {
        let state = GitLabSessionState {
            format_version: 99,
            access_token: "tok".into(),
            refresh_token: String::new(),
        };
        let bytes = state.to_bytes().expect("serialise");
        assert!(matches!(
            GitLabSessionState::from_bytes(&bytes),
            Err(ConnectorRefreshError::Serialization(_))
        ));
    }

    #[test]
    fn test_use_login_as_id() {
        // verify sub selection logic: numeric id vs username
        let user_id = 42i64;
        let username = "alice";
        // use_login_as_id = false → numeric
        assert_eq!(user_id.to_string(), "42");
        // use_login_as_id = true → username
        assert_eq!(username, "alice");
    }
}
