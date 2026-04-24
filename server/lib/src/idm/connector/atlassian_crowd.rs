//! Atlassian Crowd REST API v2 upstream connector (DL40).
//!
//! Password-based connector using Crowd's REST API for authentication and
//! group membership resolution. Providers whose `Connector` entry carries
//! `connector_provider_kind = "crowd"` are dispatched here.
//!
//! Uses `POST /rest/usermanagement/1/authentication?username=<user>` for
//! authentication and `GET /rest/usermanagement/1/user/group/nested?username=<user>`
//! for group membership. The `groups` allowlist acts as an access gate;
//! empty = allow any authenticated Crowd user.
//!
//! Sessions issued for Crowd users do not carry a refresh token; the
//! `RefreshableConnector::refresh()` implementation returns `TokenRevoked`
//! immediately, forcing re-authentication when the session expires.

use crate::idm::authsession::handler_connector::ExternalUserClaims;
use crate::idm::connector::traits::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use hashbrown::HashSet;
use serde::Deserialize;
use uuid::Uuid;

/// Parsed Crowd connector configuration.
#[derive(Debug, Clone)]
pub struct CrowdConfig {
    pub entry_uuid: Uuid,
    /// Crowd REST base URL, e.g. `https://crowd.example.com`.
    pub base_url: String,
    /// Crowd application name for HTTP Basic auth.
    pub client_name: String,
    /// Crowd application password for HTTP Basic auth.
    client_secret: String,
    /// Allowlist of Crowd group names. Empty = allow any authenticated user.
    pub groups: HashSet<String>,
}

impl CrowdConfig {
    pub fn from_entry(
        entry: &crate::entry::Entry<crate::entry::EntrySealed, crate::entry::EntryCommitted>,
    ) -> Result<Self, OperationError> {
        let entry_uuid = entry.get_uuid();

        let base_url = entry
            .get_ava_single_utf8(Attribute::ConnectorCrowdBaseUrl)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "Crowd connector entry missing connector_crowd_base_url"
                );
                OperationError::InvalidEntryState
            })?
            .trim_end_matches('/')
            .to_string();

        let client_name = entry
            .get_ava_single_utf8(Attribute::ConnectorCrowdClientName)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "Crowd connector entry missing connector_crowd_client_name"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let client_secret = entry
            .get_ava_single_utf8(Attribute::ConnectorCrowdClientSecret)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "Crowd connector entry missing connector_crowd_client_secret"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let groups: HashSet<String> = entry
            .get_ava_set(Attribute::ConnectorCrowdGroups)
            .and_then(|vs| vs.as_utf8_iter())
            .map(|iter| iter.map(str::to_string).collect())
            .unwrap_or_default();

        Ok(CrowdConfig {
            entry_uuid,
            base_url,
            client_name,
            client_secret,
            groups,
        })
    }
}

// ─── Crowd API response shapes ───────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct CrowdUser {
    name: String,
    #[serde(rename = "display-name", default)]
    display_name: String,
    #[serde(default)]
    email: String,
}

#[derive(Deserialize, Debug)]
struct CrowdGroup {
    name: String,
}

#[derive(Deserialize, Debug)]
struct CrowdGroupsResponse {
    #[serde(default)]
    groups: Vec<CrowdGroup>,
}

// ─── Connector ───────────────────────────────────────────────────────────────

pub struct CrowdConnector {
    config: CrowdConfig,
    http: reqwest::Client,
    /// Test endpoint override for the authentication endpoint.
    pub auth_endpoint_override: Option<String>,
    /// Test endpoint override for the nested groups endpoint.
    pub groups_endpoint_override: Option<String>,
}

impl CrowdConnector {
    pub fn new(config: CrowdConfig) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("netidmd/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Self {
            config,
            http,
            auth_endpoint_override: None,
            groups_endpoint_override: None,
        }
    }

    async fn fetch_groups(&self, username: &str) -> Result<Vec<String>, ConnectorRefreshError> {
        let default_url = format!(
            "{}/rest/usermanagement/1/user/group/nested?username={}",
            self.config.base_url, username
        );
        let groups_url = self
            .groups_endpoint_override
            .as_deref()
            .unwrap_or(&default_url);

        let res = self
            .http
            .get(groups_url)
            .basic_auth(&self.config.client_name, Some(&self.config.client_secret))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            warn!("Crowd groups endpoint returned {status}: {body} — groups will be empty.");
            return Ok(Vec::new());
        }

        let resp: CrowdGroupsResponse = res.json().await.map_err(|e| {
            ConnectorRefreshError::Serialization(format!("Crowd groups response parse failed: {e}"))
        })?;

        Ok(resp.groups.into_iter().map(|g| g.name).collect())
    }

    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<ExternalUserClaims>, ConnectorRefreshError> {
        let default_url = format!(
            "{}/rest/usermanagement/1/authentication?username={}",
            self.config.base_url, username
        );
        let auth_url = self
            .auth_endpoint_override
            .as_deref()
            .unwrap_or(&default_url);

        let body = serde_json::json!({"value": password});

        let res = self
            .http
            .post(auth_url)
            .basic_auth(&self.config.client_name, Some(&self.config.client_secret))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        let status = res.status();

        if status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED
        {
            return Ok(None);
        }

        if !status.is_success() {
            let body_text = res.text().await.unwrap_or_default();
            return Err(ConnectorRefreshError::Network(format!(
                "Crowd authentication returned {status}: {body_text}"
            )));
        }

        let user: CrowdUser = res.json().await.map_err(|e| {
            ConnectorRefreshError::Serialization(format!("Crowd user response parse failed: {e}"))
        })?;

        let all_groups = self.fetch_groups(username).await?;

        // Apply groups filter
        let groups = if self.config.groups.is_empty() {
            all_groups
        } else {
            let matched: Vec<String> = all_groups
                .into_iter()
                .filter(|g| self.config.groups.contains(g))
                .collect();
            if matched.is_empty() {
                warn!(
                    username = %user.name,
                    "Crowd connector: user not in any required group"
                );
                return Ok(None);
            }
            matched
        };

        let email = if user.email.is_empty() {
            None
        } else {
            Some(user.email)
        };

        let display_name = if user.display_name.is_empty() {
            None
        } else {
            Some(user.display_name)
        };

        Ok(Some(ExternalUserClaims {
            sub: user.name.clone(),
            email,
            email_verified: None,
            display_name,
            username_hint: Some(user.name),
            groups,
        }))
    }
}

#[async_trait]
impl RefreshableConnector for CrowdConnector {
    async fn refresh(
        &self,
        _session_state: &[u8],
        _previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        // Crowd password connectors have no persistent token — force re-auth.
        Err(ConnectorRefreshError::TokenRevoked)
    }

    async fn authenticate_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<ExternalUserClaims>, ConnectorRefreshError> {
        self.authenticate(username, password).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::routing::{get, post};
    use axum::Json;
    use std::collections::HashMap;

    async fn make_test_server(
        auth_status: u16,
        auth_body: serde_json::Value,
        groups_body: serde_json::Value,
        groups_filter: HashSet<String>,
    ) -> (String, CrowdConnector) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let auth_body_clone = auth_body.clone();
        let groups_body_clone = groups_body.clone();

        let app = axum::Router::new()
            .route(
                "/rest/usermanagement/1/authentication",
                post(move |_q: Query<HashMap<String, String>>| {
                    let body = auth_body_clone.clone();
                    async move {
                        (
                            axum::http::StatusCode::from_u16(auth_status).unwrap(),
                            Json(body),
                        )
                    }
                }),
            )
            .route(
                "/rest/usermanagement/1/user/group/nested",
                get(move |_q: Query<HashMap<String, String>>| {
                    let body = groups_body_clone.clone();
                    async move { Json(body) }
                }),
            );

        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let config = CrowdConfig {
            entry_uuid: Uuid::new_v4(),
            base_url: base.clone(),
            client_name: "myapp".to_string(),
            client_secret: "appsecret".to_string(),
            groups: groups_filter,
        };

        let mut connector = CrowdConnector::new(config);
        connector.auth_endpoint_override = Some(format!(
            "{base}/rest/usermanagement/1/authentication?username=placeholder"
        ));
        connector.groups_endpoint_override = Some(format!(
            "{base}/rest/usermanagement/1/user/group/nested?username=placeholder"
        ));

        (base, connector)
    }

    #[tokio::test]
    async fn test_successful_login_no_filter() {
        let (_base, connector) = make_test_server(
            200,
            serde_json::json!({
                "name": "alice",
                "display-name": "Alice Smith",
                "email": "alice@example.com"
            }),
            serde_json::json!({"groups": [{"name": "developers"}, {"name": "qa"}]}),
            HashSet::new(),
        )
        .await;

        let result = connector
            .authenticate_password("alice", "secret")
            .await
            .expect("no error");

        let claims = result.expect("some claims");
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.username_hint.as_deref(), Some("alice"));
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert!(claims.groups.contains(&"developers".to_string()));
        assert!(claims.groups.contains(&"qa".to_string()));
    }

    #[tokio::test]
    async fn test_wrong_password_returns_none() {
        let (_base, connector) = make_test_server(
            400,
            serde_json::json!({"reason": "INVALID_USER_AUTHENTICATION", "message": "Failed to authenticate principal, password was invalid"}),
            serde_json::json!({"groups": []}),
            HashSet::new(),
        )
        .await;

        let result = connector
            .authenticate_password("alice", "wrong")
            .await
            .expect("no connector error");

        assert!(result.is_none(), "expected None for wrong password");
    }

    #[tokio::test]
    async fn test_groups_filter_passes() {
        let mut filter = HashSet::new();
        filter.insert("admin".to_string());

        let (_base, connector) = make_test_server(
            200,
            serde_json::json!({
                "name": "bob",
                "display-name": "Bob Jones",
                "email": "bob@example.com"
            }),
            serde_json::json!({"groups": [{"name": "admin"}, {"name": "users"}]}),
            filter,
        )
        .await;

        let result = connector
            .authenticate_password("bob", "pass")
            .await
            .expect("no error");

        let claims = result.expect("some claims");
        // Only "admin" passes filter
        assert_eq!(claims.groups, vec!["admin"]);
    }

    #[tokio::test]
    async fn test_groups_filter_denies() {
        let mut filter = HashSet::new();
        filter.insert("admin".to_string());

        let (_base, connector) = make_test_server(
            200,
            serde_json::json!({
                "name": "carol",
                "display-name": "Carol",
                "email": "carol@example.com"
            }),
            serde_json::json!({"groups": [{"name": "users"}]}),
            filter,
        )
        .await;

        let result = connector
            .authenticate_password("carol", "pass")
            .await
            .expect("no connector error");

        assert!(result.is_none(), "expected None when not in required group");
    }

    #[tokio::test]
    async fn test_refresh_always_revokes() {
        let (_base, connector) = make_test_server(
            200,
            serde_json::json!({}),
            serde_json::json!({"groups": []}),
            HashSet::new(),
        )
        .await;

        let prev = ExternalUserClaims {
            sub: "u1".to_string(),
            email: None,
            email_verified: None,
            display_name: None,
            username_hint: None,
            groups: vec![],
        };
        let err = connector.refresh(&[], &prev).await.unwrap_err();
        assert!(matches!(err, ConnectorRefreshError::TokenRevoked));
    }
}
