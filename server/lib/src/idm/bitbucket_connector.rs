//! Bitbucket Cloud upstream connector (PR-CONNECTOR-BITBUCKET).
//!
//! Exact-parity port of `connector/bitbucketcloud/bitbucketcloud.go` from dex.
//! Providers whose `OAuth2Client` entry carries
//! `oauth2_client_provider_kind = "bitbucket"` are dispatched here.
//!
//! Authentication is pure OAuth2 (scopes: `account email`).
//! Groups are workspace slugs fetched from `GET /2.0/user/workspaces`.
//! If `get_workspace_permissions` is enabled, permission suffixes are appended
//! (e.g. `my-org:owner`, `my-org:member`) via `GET /2.0/user/workspaces/{slug}/permission`.
//! The `teams` list is an access gate — if non-empty and the user belongs to none
//! of the listed workspaces, authentication is denied.
//! `include_team_groups` is deprecated (Bitbucket 1.0 API removed by Atlassian);
//! setting it logs a warning and has no other effect.
//! Session state carries both access and refresh tokens for the refresh flow.

use crate::idm::authsession::handler_oauth2_client::ExternalUserClaims;
use crate::idm::oauth2_connector::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

const BITBUCKET_API_URL: &str = "https://api.bitbucket.org/2.0";
const BITBUCKET_TOKEN_URL: &str = "https://bitbucket.org/site/oauth2/access_token";
pub const BITBUCKET_SESSION_STATE_FORMAT_VERSION: u8 = 1;

/// Parsed Bitbucket Cloud connector configuration.
pub struct BitbucketConfig {
    pub entry_uuid: Uuid,
    pub client_id: String,
    client_secret: String,
    pub redirect_uri: Url,
    /// Workspace slug allowlist. Empty = allow any authenticated Bitbucket user.
    pub teams: HashSet<String>,
    /// Append `{slug}:{permission}` entries to the groups list.
    pub get_workspace_permissions: bool,
    pub http: reqwest::Client,
    // Test endpoint overrides.
    pub api_url_override: Option<String>,
    pub token_url_override: Option<String>,
}

impl std::fmt::Debug for BitbucketConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitbucketConfig")
            .field("entry_uuid", &self.entry_uuid)
            .field("client_id", &self.client_id)
            .field("client_secret", &"***")
            .field("redirect_uri", &self.redirect_uri)
            .field("teams", &self.teams)
            .field("get_workspace_permissions", &self.get_workspace_permissions)
            .finish()
    }
}

impl BitbucketConfig {
    pub fn from_entry(
        entry: &crate::entry::Entry<crate::entry::EntrySealed, crate::entry::EntryCommitted>,
        redirect_uri: Url,
    ) -> Result<Self, OperationError> {
        let entry_uuid = entry.get_uuid();

        let client_id = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientId)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "Bitbucket connector entry missing oauth2_client_id"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let client_secret = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientSecret)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "Bitbucket connector entry missing oauth2_client_secret"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let teams: HashSet<String> = entry
            .get_ava_set(Attribute::OAuth2ClientBitbucketTeams)
            .and_then(|vs| vs.as_iutf8_iter())
            .map(|iter| iter.map(str::to_string).collect())
            .unwrap_or_default();

        let get_workspace_permissions = entry
            .get_ava_single_bool(Attribute::OAuth2ClientBitbucketGetWorkspacePermissions)
            .unwrap_or(false);

        if entry
            .get_ava_single_bool(Attribute::OAuth2ClientBitbucketIncludeTeamGroups)
            .unwrap_or(false)
        {
            warn!(
                ?entry_uuid,
                "Bitbucket connector: include_team_groups is deprecated and has no effect; \
                 the Bitbucket 1.0 API it relied on has been removed by Atlassian"
            );
        }

        let http = reqwest::Client::builder()
            .user_agent(concat!("netidmd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| {
                error!(
                    ?entry_uuid,
                    "Failed to build HTTP client for Bitbucket connector: {e}"
                );
                OperationError::InvalidEntryState
            })?;

        Ok(BitbucketConfig {
            entry_uuid,
            client_id,
            client_secret,
            redirect_uri,
            teams,
            get_workspace_permissions,
            http,
            api_url_override: None,
            token_url_override: None,
        })
    }

    #[cfg(test)]
    pub fn new_for_test(
        entry_uuid: Uuid,
        client_id: String,
        client_secret: String,
        redirect_uri: Url,
        teams: HashSet<String>,
        get_workspace_permissions: bool,
    ) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("netidmd-test")
            .build()
            .expect("reqwest client build");
        BitbucketConfig {
            entry_uuid,
            client_id,
            client_secret,
            redirect_uri,
            teams,
            get_workspace_permissions,
            http,
            api_url_override: None,
            token_url_override: None,
        }
    }
}

/// Opaque per-session state. Carries access and refresh tokens so that
/// `refresh()` can use the Bitbucket refresh-token grant when available.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BitbucketSessionState {
    pub format_version: u8,
    pub access_token: String,
    /// Empty when the token response did not include a refresh token.
    pub refresh_token: String,
}

impl BitbucketSessionState {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorRefreshError> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state is not UTF-8: {e}"))
        })?;
        let state: Self = serde_json::from_str(s).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state JSON parse failed: {e}"))
        })?;
        if state.format_version != BITBUCKET_SESSION_STATE_FORMAT_VERSION {
            return Err(ConnectorRefreshError::Serialization(format!(
                "session-state format_version {} not supported (expected {})",
                state.format_version, BITBUCKET_SESSION_STATE_FORMAT_VERSION
            )));
        }
        Ok(state)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ConnectorRefreshError> {
        serde_json::to_vec(self)
            .map_err(|e| ConnectorRefreshError::Serialization(format!("serialise failed: {e}")))
    }
}

// ---------- Bitbucket API response shapes ----------

#[derive(Deserialize, Debug)]
struct BitbucketTokenResponse {
    access_token: String,
    /// Stored in session-state for use in the refresh flow.
    #[serde(default)]
    #[allow(dead_code)]
    refresh_token: String,
}

#[derive(Deserialize, Debug)]
struct BitbucketUser {
    username: String,
    uuid: String,
}

#[derive(Deserialize, Debug)]
struct BitbucketUserEmail {
    is_primary: bool,
    is_confirmed: bool,
    email: String,
}

#[derive(Deserialize, Debug)]
struct BitbucketEmailResponse {
    #[serde(default)]
    next: Option<String>,
    values: Vec<BitbucketUserEmail>,
}

#[derive(Deserialize, Debug)]
struct BitbucketWorkspaceRef {
    slug: String,
}

#[derive(Deserialize, Debug)]
struct BitbucketWorkspaceAccess {
    workspace: BitbucketWorkspaceRef,
}

#[derive(Deserialize, Debug)]
struct BitbucketWorkspacesResponse {
    #[serde(default)]
    next: Option<String>,
    values: Vec<BitbucketWorkspaceAccess>,
}

#[derive(Deserialize, Debug)]
struct BitbucketWorkspacePermission {
    permission: String,
}

// ---------- Connector ----------

pub struct BitbucketConnector {
    config: BitbucketConfig,
}

impl BitbucketConnector {
    pub fn new(config: BitbucketConfig) -> Self {
        Self { config }
    }

    fn token_url(&self) -> &str {
        self.config
            .token_url_override
            .as_deref()
            .unwrap_or(BITBUCKET_TOKEN_URL)
    }

    fn api_url(&self) -> &str {
        self.config
            .api_url_override
            .as_deref()
            .unwrap_or(BITBUCKET_API_URL)
    }

    async fn exchange_code(
        &self,
        code: &str,
    ) -> Result<BitbucketTokenResponse, ConnectorRefreshError> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_uri.as_str()),
        ];

        let res = self
            .config
            .http
            .post(self.token_url())
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .form(&params)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(ConnectorRefreshError::Network(format!(
                "Bitbucket token endpoint returned {status}: {body}"
            )));
        }

        res.json::<BitbucketTokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> Result<BitbucketTokenResponse, ConnectorRefreshError> {
        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];

        let res = self
            .config
            .http
            .post(self.token_url())
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
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
                "Bitbucket token refresh returned {status}: {body}"
            )));
        }

        res.json::<BitbucketTokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn fetch_user(&self, token: &str) -> Result<BitbucketUser, ConnectorRefreshError> {
        let user_url = format!("{}/user", self.api_url());

        let res = self
            .config
            .http
            .get(&user_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(ConnectorRefreshError::Network(format!(
                "Bitbucket /user returned {status}: {body}"
            )));
        }

        res.json::<BitbucketUser>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn fetch_primary_email(&self, token: &str) -> Result<String, ConnectorRefreshError> {
        let mut url = format!("{}/user/emails", self.api_url());
        loop {
            let res = self
                .config
                .http
                .get(&url)
                .bearer_auth(token)
                .send()
                .await
                .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

            if !res.status().is_success() {
                let status = res.status();
                let body = res.text().await.unwrap_or_default();
                return Err(ConnectorRefreshError::Network(format!(
                    "Bitbucket /user/emails returned {status}: {body}"
                )));
            }

            let resp: BitbucketEmailResponse = res
                .json()
                .await
                .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))?;

            for email in &resp.values {
                if email.is_primary && email.is_confirmed {
                    return Ok(email.email.clone());
                }
            }

            match resp.next {
                Some(next_url) => url = next_url,
                None => break,
            }
        }

        Err(ConnectorRefreshError::AccessDenied)
    }

    async fn fetch_workspaces(&self, token: &str) -> Result<Vec<String>, ConnectorRefreshError> {
        let mut slugs = Vec::new();
        let mut url = format!("{}/user/workspaces", self.api_url());
        loop {
            let res = self
                .config
                .http
                .get(&url)
                .bearer_auth(token)
                .send()
                .await
                .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

            if !res.status().is_success() {
                let status = res.status();
                let body = res.text().await.unwrap_or_default();
                return Err(ConnectorRefreshError::Network(format!(
                    "Bitbucket /user/workspaces returned {status}: {body}"
                )));
            }

            let resp: BitbucketWorkspacesResponse = res
                .json()
                .await
                .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))?;

            for wa in resp.values {
                slugs.push(wa.workspace.slug);
            }

            match resp.next {
                Some(next_url) => url = next_url,
                None => break,
            }
        }
        Ok(slugs)
    }

    async fn fetch_workspace_permission(
        &self,
        token: &str,
        slug: &str,
    ) -> Result<String, ConnectorRefreshError> {
        let url = format!("{}/user/workspaces/{slug}/permission", self.api_url());

        let res = self
            .config
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(ConnectorRefreshError::Network(format!(
                "Bitbucket /user/workspaces/{slug}/permission returned {status}: {body}"
            )));
        }

        let resp: BitbucketWorkspacePermission = res
            .json()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))?;

        Ok(resp.permission)
    }

    async fn get_groups(&self, token: &str) -> Result<Vec<String>, ConnectorRefreshError> {
        let slugs = self.fetch_workspaces(token).await?;

        let mut groups: Vec<String> = slugs.clone();

        if self.config.get_workspace_permissions {
            for slug in &slugs {
                match self.fetch_workspace_permission(token, slug).await {
                    Ok(perm) => groups.push(format!("{slug}:{perm}")),
                    Err(e) => {
                        warn!(
                            %slug,
                            "Bitbucket connector: failed to get permission for workspace, \
                             skipping permission suffix: {e}"
                        );
                    }
                }
            }
        }

        Ok(groups)
    }

    fn apply_teams_filter(
        &self,
        groups: Vec<String>,
        username: &str,
    ) -> Result<Vec<String>, ConnectorRefreshError> {
        if self.config.teams.is_empty() {
            return Ok(groups);
        }
        let filtered: Vec<String> = groups
            .into_iter()
            .filter(|g| self.config.teams.contains(g))
            .collect();
        if filtered.is_empty() {
            warn!(
                %username,
                "Bitbucket connector: user not in any required team"
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
        let email = self.fetch_primary_email(access_token).await?;
        let raw_groups = self.get_groups(access_token).await?;
        let groups = self.apply_teams_filter(raw_groups, &user.username)?;

        Ok(ExternalUserClaims {
            sub: user.uuid,
            email: Some(email),
            email_verified: Some(true),
            display_name: Some(user.username.clone()),
            username_hint: Some(user.username),
            groups,
        })
    }
}

#[async_trait]
impl RefreshableConnector for BitbucketConnector {
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
        let state = BitbucketSessionState::from_bytes(session_state)?;

        let access_token = if !state.refresh_token.is_empty() {
            let new_tok = self.refresh_access_token(&state.refresh_token).await?;
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
                "Bitbucket connector: sub mismatch on refresh"
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

    fn default_config() -> BitbucketConfig {
        BitbucketConfig::new_for_test(
            TEST_UUID,
            "client-id".into(),
            "client-secret".into(),
            Url::parse("https://netidm.example.com/oauth2/callback").unwrap(),
            HashSet::new(),
            false,
        )
    }

    fn connector(cfg: BitbucketConfig) -> BitbucketConnector {
        BitbucketConnector::new(cfg)
    }

    #[test]
    fn test_bitbucket_user_parse() {
        let json = r#"{
            "username": "alice",
            "uuid": "{12345678-1234-1234-1234-123456789abc}"
        }"#;
        let user: BitbucketUser = serde_json::from_str(json).expect("parse failed");
        assert_eq!(user.username, "alice");
        assert_eq!(user.uuid, "{12345678-1234-1234-1234-123456789abc}");
    }

    #[test]
    fn test_bitbucket_email_parse() {
        let json = r#"{
            "values": [
                {"is_primary": false, "is_confirmed": true, "email": "old@example.com"},
                {"is_primary": true, "is_confirmed": true, "email": "alice@example.com"},
                {"is_primary": true, "is_confirmed": false, "email": "unconfirmed@example.com"}
            ]
        }"#;
        let resp: BitbucketEmailResponse = serde_json::from_str(json).expect("parse failed");
        let primary = resp
            .values
            .iter()
            .find(|e| e.is_primary && e.is_confirmed)
            .map(|e| e.email.as_str());
        assert_eq!(primary, Some("alice@example.com"));
    }

    #[test]
    fn test_bitbucket_workspaces_parse() {
        let json = r#"{
            "values": [
                {"workspace": {"slug": "my-org"}},
                {"workspace": {"slug": "another-org"}}
            ]
        }"#;
        let resp: BitbucketWorkspacesResponse = serde_json::from_str(json).expect("parse failed");
        let slugs: Vec<&str> = resp
            .values
            .iter()
            .map(|v| v.workspace.slug.as_str())
            .collect();
        assert_eq!(slugs, vec!["my-org", "another-org"]);
    }

    #[test]
    fn test_bitbucket_workspace_permission_parse() {
        let json = r#"{"permission": "owner"}"#;
        let resp: BitbucketWorkspacePermission = serde_json::from_str(json).expect("parse failed");
        assert_eq!(resp.permission, "owner");
    }

    #[test]
    fn test_bitbucket_teams_filter_pass() {
        let mut cfg = default_config();
        cfg.teams = ["my-org".to_string()].into_iter().collect();
        let c = connector(cfg);
        let groups = vec!["my-org".to_string(), "another-org".to_string()];
        let filtered = c.apply_teams_filter(groups, "alice").unwrap();
        assert_eq!(filtered, vec!["my-org"]);
    }

    #[test]
    fn test_bitbucket_teams_filter_deny() {
        let mut cfg = default_config();
        cfg.teams = ["required-org".to_string()].into_iter().collect();
        let c = connector(cfg);
        let groups = vec!["my-org".to_string()];
        let err = c.apply_teams_filter(groups, "alice").unwrap_err();
        assert!(matches!(err, ConnectorRefreshError::AccessDenied));
    }

    #[test]
    fn test_bitbucket_teams_empty_allow_all() {
        let c = connector(default_config());
        let groups = vec!["any-org".to_string(), "other-org".to_string()];
        let result = c.apply_teams_filter(groups.clone(), "alice").unwrap();
        assert_eq!(result, groups);
    }

    #[test]
    fn test_bitbucket_session_state_roundtrip() {
        let state = BitbucketSessionState {
            format_version: BITBUCKET_SESSION_STATE_FORMAT_VERSION,
            access_token: "acc123".into(),
            refresh_token: "ref456".into(),
        };
        let bytes = state.to_bytes().unwrap();
        let restored = BitbucketSessionState::from_bytes(&bytes).unwrap();
        assert_eq!(restored.access_token, "acc123");
        assert_eq!(restored.refresh_token, "ref456");
        assert_eq!(
            restored.format_version,
            BITBUCKET_SESSION_STATE_FORMAT_VERSION
        );
    }

    #[test]
    fn test_bitbucket_session_state_wrong_version() {
        let state = BitbucketSessionState {
            format_version: 99,
            access_token: "acc".into(),
            refresh_token: "ref".into(),
        };
        let bytes = state.to_bytes().unwrap();
        let err = BitbucketSessionState::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ConnectorRefreshError::Serialization(_)));
    }
}
