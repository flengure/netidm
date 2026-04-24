//! OpenStack Keystone v3 upstream connector (DL39).
//!
//! Password-based connector using Keystone's token authentication API.
//! Providers whose `Connector` entry carries
//! `connector_provider_kind = "keystone"` are dispatched here.
//!
//! Uses `POST /v3/auth/tokens` with `scope: unscoped` for authentication.
//! Roles on the token are mapped to group claims. The `groups` allowlist
//! acts as an access gate; empty = allow any authenticated Keystone user.
//!
//! Sessions issued for Keystone users do not carry a refresh token; the
//! `RefreshableConnector::refresh()` implementation returns `TokenRevoked`
//! immediately, forcing re-authentication when the session expires.

use crate::idm::authsession::handler_connector::ExternalUserClaims;
use crate::idm::connector::traits::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use hashbrown::HashSet;
use serde::Deserialize;
use uuid::Uuid;

/// Parsed Keystone connector configuration.
#[derive(Debug, Clone)]
pub struct KeystoneConfig {
    pub entry_uuid: Uuid,
    /// Keystone v3 endpoint URL, e.g. `https://keystone.example.com:5000`.
    pub host: String,
    /// Domain for user lookup (default "Default").
    pub domain: String,
    /// Allowlist of role names. Empty = allow any authenticated user.
    pub groups: HashSet<String>,
    /// Skip TLS certificate verification (development only).
    pub insecure_ca: bool,
}

impl KeystoneConfig {
    pub fn from_entry(
        entry: &crate::entry::Entry<crate::entry::EntrySealed, crate::entry::EntryCommitted>,
    ) -> Result<Self, OperationError> {
        let entry_uuid = entry.get_uuid();

        let host = entry
            .get_ava_single_utf8(Attribute::ConnectorKeystoneHost)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "Keystone connector entry missing connector_keystone_host"
                );
                OperationError::InvalidEntryState
            })?
            .trim_end_matches('/')
            .to_string();

        let domain = entry
            .get_ava_single_utf8(Attribute::ConnectorKeystoneDomain)
            .unwrap_or("Default")
            .to_string();

        let groups: HashSet<String> = entry
            .get_ava_set(Attribute::ConnectorKeystoneGroups)
            .and_then(|vs| vs.as_utf8_iter())
            .map(|iter| iter.map(str::to_string).collect())
            .unwrap_or_default();

        let insecure_ca = entry
            .get_ava_single_bool(Attribute::ConnectorKeystoneInsecureCa)
            .unwrap_or(false);

        Ok(KeystoneConfig {
            entry_uuid,
            host,
            domain,
            groups,
            insecure_ca,
        })
    }
}

// ─── Keystone API response shapes ───────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct KeystoneTokenUser {
    id: String,
    name: String,
}

#[derive(Deserialize, Debug)]
struct KeystoneTokenRole {
    name: String,
}

#[derive(Deserialize, Debug)]
struct KeystoneToken {
    user: KeystoneTokenUser,
    #[serde(default)]
    roles: Vec<KeystoneTokenRole>,
}

#[derive(Deserialize, Debug)]
struct KeystoneAuthResponse {
    token: KeystoneToken,
}

// ─── Connector ──────────────────────────────────────────────────────────────

pub struct KeystoneConnector {
    config: KeystoneConfig,
    http: reqwest::Client,
    /// Test endpoint override for the auth/tokens endpoint.
    pub auth_endpoint_override: Option<String>,
}

impl KeystoneConnector {
    pub fn new(config: KeystoneConfig) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("netidmd/", env!("CARGO_PKG_VERSION")))
            .danger_accept_invalid_certs(config.insecure_ca)
            .build()
            .unwrap_or_default();
        Self {
            config,
            http,
            auth_endpoint_override: None,
        }
    }

    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<ExternalUserClaims>, ConnectorRefreshError> {
        let default_url = format!("{}/v3/auth/tokens", self.config.host);
        let auth_url = self
            .auth_endpoint_override
            .as_deref()
            .unwrap_or(&default_url);

        let body = serde_json::json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": username,
                            "domain": {"name": self.config.domain},
                            "password": password
                        }
                    }
                },
                "scope": "unscoped"
            }
        });

        let res = self
            .http
            .post(auth_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        let status = res.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Ok(None);
        }

        if status != reqwest::StatusCode::CREATED {
            let body_text = res.text().await.unwrap_or_default();
            return Err(ConnectorRefreshError::Network(format!(
                "Keystone auth/tokens returned {status}: {body_text}"
            )));
        }

        let auth_resp: KeystoneAuthResponse = res.json().await.map_err(|e| {
            ConnectorRefreshError::Serialization(format!(
                "Keystone auth response parse failed: {e}"
            ))
        })?;

        let token = auth_resp.token;
        let user_id = token.user.id;
        let username_hint = token.user.name;

        let all_roles: Vec<String> = token.roles.into_iter().map(|r| r.name).collect();

        // Apply groups filter: if allowlist is set, user must be in at least one role.
        let groups = if self.config.groups.is_empty() {
            all_roles
        } else {
            let matched: Vec<String> = all_roles
                .into_iter()
                .filter(|r| self.config.groups.contains(r))
                .collect();
            if matched.is_empty() {
                warn!(
                    %username_hint,
                    "Keystone connector: user not in any required role"
                );
                return Err(ConnectorRefreshError::AccessDenied);
            }
            matched
        };

        Ok(Some(ExternalUserClaims {
            sub: user_id,
            email: None,
            email_verified: None,
            display_name: None,
            username_hint: Some(username_hint),
            groups,
        }))
    }
}

#[async_trait]
impl RefreshableConnector for KeystoneConnector {
    async fn refresh(
        &self,
        _session_state: &[u8],
        _previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        // Keystone password connectors have no persistent token — force re-auth.
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
    use axum::routing::post;
    use axum::Json;

    async fn make_test_server(
        status: u16,
        response_body: serde_json::Value,
        groups_filter: HashSet<String>,
    ) -> (String, KeystoneConnector) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let body_clone = response_body.clone();

        let app = axum::Router::new().route(
            "/v3/auth/tokens",
            post(move || {
                let body = body_clone.clone();
                async move {
                    (
                        axum::http::StatusCode::from_u16(status).unwrap(),
                        Json(body),
                    )
                }
            }),
        );

        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let config = KeystoneConfig {
            entry_uuid: Uuid::new_v4(),
            host: base.clone(),
            domain: "Default".to_string(),
            groups: groups_filter,
            insecure_ca: false,
        };

        let mut connector = KeystoneConnector::new(config);
        connector.auth_endpoint_override = Some(format!("{base}/v3/auth/tokens"));

        (base, connector)
    }

    #[tokio::test]
    async fn test_successful_login_no_filter() {
        let (_base, connector) = make_test_server(
            201,
            serde_json::json!({
                "token": {
                    "user": {"id": "user-uuid-123", "name": "alice"},
                    "roles": [{"name": "member"}, {"name": "reader"}]
                }
            }),
            HashSet::new(),
        )
        .await;

        let result = connector
            .authenticate_password("alice", "secret")
            .await
            .expect("no error");

        let claims = result.expect("some claims");
        assert_eq!(claims.sub, "user-uuid-123");
        assert_eq!(claims.username_hint.as_deref(), Some("alice"));
        assert!(claims.groups.contains(&"member".to_string()));
        assert!(claims.groups.contains(&"reader".to_string()));
    }

    #[tokio::test]
    async fn test_wrong_password_returns_none() {
        let (_base, connector) = make_test_server(
            401,
            serde_json::json!({"error": {"code": 401, "message": "The request you have made requires authentication.", "title": "Unauthorized"}}),
            HashSet::new(),
        )
        .await;

        let result = connector
            .authenticate_password("alice", "wrongpassword")
            .await
            .expect("no connector error");

        assert!(result.is_none(), "expected None for wrong password");
    }

    #[tokio::test]
    async fn test_groups_filter_passes() {
        let mut filter = HashSet::new();
        filter.insert("admin".to_string());

        let (_base, connector) = make_test_server(
            201,
            serde_json::json!({
                "token": {
                    "user": {"id": "user-abc", "name": "bob"},
                    "roles": [{"name": "admin"}, {"name": "member"}]
                }
            }),
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
            201,
            serde_json::json!({
                "token": {
                    "user": {"id": "user-xyz", "name": "carol"},
                    "roles": [{"name": "member"}]
                }
            }),
            filter,
        )
        .await;

        let result = connector.authenticate_password("carol", "pass").await;

        assert!(
            matches!(result, Err(ConnectorRefreshError::AccessDenied)),
            "expected AccessDenied, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_refresh_always_revokes() {
        let (_base, connector) = make_test_server(201, serde_json::json!({}), HashSet::new()).await;

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
