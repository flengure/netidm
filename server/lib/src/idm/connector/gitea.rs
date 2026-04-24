//! Gitea upstream connector (DL38).
//!
//! Exact-parity port of `connector/gitea/gitea.go` from dex.
//! Providers whose `Connector` entry carries
//! `connector_provider_kind = "gitea"` are dispatched here.
//!
//! Uses Gitea's `/api/v1/user` endpoint to resolve identity and
//! `/api/v1/user/orgs` to resolve group membership. The `groups` allowlist
//! acts as an access gate; empty = allow any authenticated Gitea user.
//! Session state carries both an access token and (when issued) a refresh token.

use crate::idm::authsession::handler_connector::ExternalUserClaims;
use crate::idm::connector::traits::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

pub const GITEA_DEFAULT_BASE_URL: &str = "https://gitea.com";
pub const GITEA_SESSION_STATE_FORMAT_VERSION: u8 = 1;

/// Parsed Gitea connector configuration.
pub struct GiteaConfig {
    pub entry_uuid: Uuid,
    /// Root of the Gitea instance, e.g. `https://gitea.example.com`.
    pub base_url: String,
    pub client_id: String,
    client_secret: String,
    pub redirect_uri: Url,
    /// Allowlist of Gitea org names. Empty = allow all authenticated users.
    pub groups: HashSet<String>,
    /// Skip TLS certificate verification (development only).
    pub insecure_ca: bool,
    /// Use `user.login` as `sub` instead of numeric `user.id`.
    pub use_login_as_id: bool,
    /// Emit all orgs the user belongs to as group claims, not only those in `groups`.
    pub load_all_groups: bool,
    pub http: reqwest::Client,
    // Test endpoint overrides.
    pub token_endpoint_override: Option<String>,
    pub user_endpoint_override: Option<String>,
    pub orgs_endpoint_override: Option<String>,
}

impl std::fmt::Debug for GiteaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GiteaConfig")
            .field("entry_uuid", &self.entry_uuid)
            .field("base_url", &self.base_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"***")
            .field("redirect_uri", &self.redirect_uri)
            .field("groups", &self.groups)
            .field("insecure_ca", &self.insecure_ca)
            .field("use_login_as_id", &self.use_login_as_id)
            .field("load_all_groups", &self.load_all_groups)
            .finish()
    }
}

impl GiteaConfig {
    pub fn from_entry(
        entry: &crate::entry::Entry<crate::entry::EntrySealed, crate::entry::EntryCommitted>,
        redirect_uri: Url,
    ) -> Result<Self, OperationError> {
        let entry_uuid = entry.get_uuid();

        let client_id = entry
            .get_ava_single_utf8(Attribute::ConnectorId)
            .ok_or_else(|| {
                error!(?entry_uuid, "Gitea connector entry missing connector_id");
                OperationError::InvalidEntryState
            })?
            .to_string();

        let client_secret = entry
            .get_ava_single_utf8(Attribute::ConnectorSecret)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "Gitea connector entry missing connector_secret"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let base_url = entry
            .get_ava_single_utf8(Attribute::ConnectorGiteaBaseUrl)
            .unwrap_or(GITEA_DEFAULT_BASE_URL)
            .trim_end_matches('/')
            .to_string();

        let groups: HashSet<String> = entry
            .get_ava_set(Attribute::ConnectorGiteaGroups)
            .and_then(|vs| vs.as_utf8_iter())
            .map(|iter| iter.map(str::to_string).collect())
            .unwrap_or_default();

        let insecure_ca = entry
            .get_ava_single_bool(Attribute::ConnectorGiteaInsecureCa)
            .unwrap_or(false);

        let use_login_as_id = entry
            .get_ava_single_bool(Attribute::ConnectorGiteaUseLoginAsId)
            .unwrap_or(false);

        let load_all_groups = entry
            .get_ava_single_bool(Attribute::ConnectorGiteaLoadAllGroups)
            .unwrap_or(false);

        let root_ca_pem = entry
            .get_ava_single_utf8(Attribute::ConnectorGiteaRootCa)
            .map(str::to_string);

        let mut client_builder = reqwest::Client::builder()
            .user_agent(concat!("netidmd/", env!("CARGO_PKG_VERSION")))
            .danger_accept_invalid_certs(insecure_ca);

        if let Some(ref pem) = root_ca_pem {
            match reqwest::Certificate::from_pem(pem.as_bytes()) {
                Ok(cert) => {
                    client_builder = client_builder.add_root_certificate(cert);
                }
                Err(e) => {
                    error!(
                        ?entry_uuid,
                        "Gitea connector: failed to parse root_ca PEM: {e}"
                    );
                    return Err(OperationError::InvalidEntryState);
                }
            }
        }

        let http = client_builder.build().map_err(|e| {
            error!(
                ?entry_uuid,
                "Failed to build HTTP client for Gitea connector: {e}"
            );
            OperationError::InvalidEntryState
        })?;

        Ok(GiteaConfig {
            entry_uuid,
            base_url,
            client_id,
            client_secret,
            redirect_uri,
            groups,
            insecure_ca,
            use_login_as_id,
            load_all_groups,
            http,
            token_endpoint_override: None,
            user_endpoint_override: None,
            orgs_endpoint_override: None,
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
        load_all_groups: bool,
    ) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("netidmd-test")
            .build()
            .expect("reqwest client build");
        GiteaConfig {
            entry_uuid,
            base_url,
            client_id,
            client_secret,
            redirect_uri,
            groups,
            insecure_ca: false,
            use_login_as_id,
            load_all_groups,
            http,
            token_endpoint_override: None,
            user_endpoint_override: None,
            orgs_endpoint_override: None,
        }
    }
}

/// Opaque per-session state. Carries both access and refresh tokens.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GiteaSessionState {
    pub format_version: u8,
    pub access_token: String,
    /// Empty string when the Gitea response did not include a refresh token.
    pub refresh_token: String,
}

impl GiteaSessionState {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorRefreshError> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state is not UTF-8: {e}"))
        })?;
        let state: Self = serde_json::from_str(s).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state JSON parse failed: {e}"))
        })?;
        if state.format_version != GITEA_SESSION_STATE_FORMAT_VERSION {
            return Err(ConnectorRefreshError::Serialization(format!(
                "session-state format_version {} not supported (expected {})",
                state.format_version, GITEA_SESSION_STATE_FORMAT_VERSION
            )));
        }
        Ok(state)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ConnectorRefreshError> {
        serde_json::to_vec(self)
            .map_err(|e| ConnectorRefreshError::Serialization(format!("serialise failed: {e}")))
    }
}

// ---------- Gitea API response shapes ----------

#[derive(Deserialize, Debug)]
struct GiteaTokenResponse {
    access_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    refresh_token: String,
}

#[derive(Deserialize, Debug)]
struct GiteaUser {
    id: i64,
    login: String,
    #[serde(default)]
    full_name: String,
    #[serde(default)]
    email: String,
}

#[derive(Deserialize, Debug)]
struct GiteaOrg {
    name: String,
}

// ---------- Connector ----------

pub struct GiteaConnector {
    config: GiteaConfig,
}

impl GiteaConnector {
    pub fn new(config: GiteaConfig) -> Self {
        Self { config }
    }

    async fn exchange_code(&self, code: &str) -> Result<GiteaTokenResponse, ConnectorRefreshError> {
        let default_url = format!("{}/login/oauth/access_token", self.config.base_url);
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
                "Gitea token endpoint returned {status}: {body}"
            )));
        }

        res.json::<GiteaTokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn refresh_token_grant(
        &self,
        refresh_token: &str,
    ) -> Result<GiteaTokenResponse, ConnectorRefreshError> {
        let default_url = format!("{}/login/oauth/access_token", self.config.base_url);
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
                "Gitea token refresh returned {status}: {body}"
            )));
        }

        res.json::<GiteaTokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn fetch_user(&self, token: &str) -> Result<GiteaUser, ConnectorRefreshError> {
        let default_url = format!("{}/api/v1/user", self.config.base_url);
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
                "Gitea /api/v1/user returned {status}: {body}"
            )));
        }

        res.json::<GiteaUser>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn fetch_orgs(&self, token: &str) -> Result<Vec<String>, ConnectorRefreshError> {
        let default_url = format!("{}/api/v1/user/orgs", self.config.base_url);
        let orgs_url = self
            .config
            .orgs_endpoint_override
            .as_deref()
            .unwrap_or(&default_url);

        let res = self
            .config
            .http
            .get(orgs_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            warn!("Gitea /api/v1/user/orgs returned {status}: {body} — groups will be empty.");
            return Ok(Vec::new());
        }

        let orgs: Vec<GiteaOrg> = res
            .json()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))?;

        Ok(orgs.into_iter().map(|o| o.name).collect())
    }

    fn apply_groups_filter(
        &self,
        orgs: Vec<String>,
        login: &str,
    ) -> Result<Vec<String>, ConnectorRefreshError> {
        if self.config.groups.is_empty() {
            return Ok(orgs);
        }

        let matched: Vec<String> = if self.config.load_all_groups {
            // Emit all orgs but still gate access on at least one required org.
            let gate: bool = orgs.iter().any(|o| self.config.groups.contains(o));
            if !gate {
                warn!(%login, "Gitea connector: user not in any required org");
                return Err(ConnectorRefreshError::AccessDenied);
            }
            orgs
        } else {
            // Emit only the intersection of user's orgs and required orgs.
            let filtered: Vec<String> = orgs
                .into_iter()
                .filter(|o| self.config.groups.contains(o))
                .collect();
            if filtered.is_empty() {
                warn!(%login, "Gitea connector: user not in any required org");
                return Err(ConnectorRefreshError::AccessDenied);
            }
            filtered
        };

        Ok(matched)
    }

    async fn build_claims(
        &self,
        access_token: &str,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        let user = self.fetch_user(access_token).await?;

        let sub = if self.config.use_login_as_id {
            user.login.clone()
        } else {
            user.id.to_string()
        };

        let display_name = if user.full_name.is_empty() {
            user.login.clone()
        } else {
            user.full_name.clone()
        };

        let orgs = self.fetch_orgs(access_token).await?;
        let groups = self.apply_groups_filter(orgs, &user.login)?;

        Ok(ExternalUserClaims {
            sub,
            email: Some(user.email),
            email_verified: Some(true),
            display_name: Some(display_name),
            username_hint: Some(user.login),
            groups,
        })
    }
}

#[async_trait]
impl RefreshableConnector for GiteaConnector {
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
        _previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        let state = GiteaSessionState::from_bytes(session_state)?;

        let access_token = if !state.refresh_token.is_empty() {
            let new_tok = self.refresh_token_grant(&state.refresh_token).await?;
            new_tok.access_token
        } else {
            state.access_token.clone()
        };

        let claims = self.build_claims(&access_token).await?;

        let new_state = GiteaSessionState {
            format_version: GITEA_SESSION_STATE_FORMAT_VERSION,
            access_token,
            refresh_token: state.refresh_token,
        };
        let new_state_bytes = new_state.to_bytes()?;

        Ok(RefreshOutcome {
            claims,
            new_session_state: Some(new_state_bytes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::Json;

    /// Spin up a mock Gitea HTTP server using axum.
    /// Returns `(base_url, GiteaConfig)` with all endpoint overrides pre-set.
    async fn make_test_server(
        user: serde_json::Value,
        orgs: serde_json::Value,
        groups: HashSet<String>,
        use_login_as_id: bool,
    ) -> (String, GiteaConfig) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let user_clone = user.clone();
        let orgs_clone = orgs.clone();

        let app = axum::Router::new()
            .route(
                "/login/oauth/access_token",
                post(|| async {
                    Json(serde_json::json!({
                        "access_token": "test_token",
                        "refresh_token": ""
                    }))
                }),
            )
            .route(
                "/api/v1/user",
                get(move || {
                    let u = user_clone.clone();
                    async move { Json(u) }
                }),
            )
            .route(
                "/api/v1/user/orgs",
                get(move || {
                    let o = orgs_clone.clone();
                    async move { Json(o) }
                }),
            );

        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");

        let redirect_uri = Url::parse("https://idm.example.com/ui/login/oauth2_landing")
            .expect("valid redirect URI");

        let config = GiteaConfig {
            entry_uuid: Uuid::new_v4(),
            base_url: base.clone(),
            client_id: "client_id".to_string(),
            client_secret: "client_secret".to_string(),
            redirect_uri,
            groups,
            insecure_ca: false,
            use_login_as_id,
            load_all_groups: false,
            http: reqwest::Client::builder()
                .user_agent("netidmd-test")
                .build()
                .unwrap(),
            token_endpoint_override: Some(format!("{base}/login/oauth/access_token")),
            user_endpoint_override: Some(format!("{base}/api/v1/user")),
            orgs_endpoint_override: Some(format!("{base}/api/v1/user/orgs")),
        };

        (base, config)
    }

    #[tokio::test]
    async fn test_callback_claims_no_groups_filter() {
        let (_base, config) = make_test_server(
            serde_json::json!({
                "id": 42, "login": "alice",
                "full_name": "Alice Smith", "email": "alice@example.com"
            }),
            serde_json::json!([{"name": "org-a"}, {"name": "org-b"}]),
            HashSet::new(),
            false,
        )
        .await;

        let connector = GiteaConnector::new(config);
        let claims = connector
            .fetch_callback_claims("code123", None)
            .await
            .expect("claims ok");

        assert_eq!(claims.sub, "42");
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.username_hint.as_deref(), Some("alice"));
        let groups = claims.groups;
        assert!(groups.contains(&"org-a".to_string()));
        assert!(groups.contains(&"org-b".to_string()));
    }

    #[tokio::test]
    async fn test_callback_claims_access_gate_enforced() {
        let (_base, config) = make_test_server(
            serde_json::json!({
                "id": 7, "login": "bob",
                "full_name": "Bob", "email": "bob@example.com"
            }),
            serde_json::json!([{"name": "some-other-org"}]),
            ["required-org".to_string()].into_iter().collect(),
            false,
        )
        .await;

        let connector = GiteaConnector::new(config);
        let result = connector.fetch_callback_claims("code123", None).await;
        assert!(
            matches!(result, Err(ConnectorRefreshError::AccessDenied)),
            "expected AccessDenied, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_use_login_as_id() {
        let (_base, config) = make_test_server(
            serde_json::json!({
                "id": 99, "login": "carol",
                "full_name": "Carol", "email": "carol@example.com"
            }),
            serde_json::json!([]),
            HashSet::new(),
            true,
        )
        .await;

        let connector = GiteaConnector::new(config);
        let claims = connector
            .fetch_callback_claims("code", None)
            .await
            .expect("claims ok");
        assert_eq!(claims.sub, "carol");
    }
}
