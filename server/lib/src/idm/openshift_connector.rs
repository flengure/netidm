//! OpenShift upstream connector (PR-CONNECTOR-OPENSHIFT).
//!
//! Exact-parity port of `connector/openshift/openshift.go` from dex.
//! Providers whose `OAuth2Client` entry carries
//! `oauth2_client_provider_kind = "openshift"` are dispatched here.
//!
//! OpenShift exposes a single `user:info` scope. The user's identity is
//! returned from the `/apis/user.openshift.io/v1/users/~` API endpoint.
//! Groups come directly from the user object; `allowed_groups` is an
//! access gate (not a mapping filter).
//!
//! Endpoint discovery via `{issuer}/.well-known/oauth-authorization-server`
//! is performed at connector initialisation time. Override URLs are provided
//! for unit tests so no real cluster is needed.

use crate::idm::authsession::handler_oauth2_client::ExternalUserClaims;
use crate::idm::oauth2_connector::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

pub const OPENSHIFT_SESSION_STATE_FORMAT_VERSION: u8 = 1;

/// Parsed OpenShift connector configuration. Built once at server start and
/// registered with the [`crate::idm::oauth2_connector::ConnectorRegistry`].
pub struct OpenShiftConfig {
    pub entry_uuid: Uuid,
    pub issuer: Url,
    pub client_id: String,
    client_secret: String,
    pub redirect_uri: Url,
    /// Empty = allow all authenticated users; non-empty = access gate.
    pub allowed_groups: HashSet<String>,
    pub http: reqwest::Client,
    pub auth_endpoint: Url,
    pub token_endpoint: Url,
    /// Override used in unit tests; skips discovery when set.
    pub auth_endpoint_override: Option<String>,
    /// Override used in unit tests; skips discovery when set.
    pub token_endpoint_override: Option<String>,
    /// Override used in unit tests.
    pub user_endpoint_override: Option<String>,
}

impl std::fmt::Debug for OpenShiftConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenShiftConfig")
            .field("entry_uuid", &self.entry_uuid)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"***")
            .field("redirect_uri", &self.redirect_uri)
            .field("allowed_groups", &self.allowed_groups)
            .finish()
    }
}

#[derive(Deserialize, Debug)]
struct WellKnown {
    authorization_endpoint: String,
    token_endpoint: String,
}

impl OpenShiftConfig {
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
                    "OpenShift connector entry missing oauth2_client_id"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let client_secret = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientSecret)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "OpenShift connector entry missing oauth2_client_secret"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let issuer_str = entry
            .get_ava_single_iutf8(Attribute::OAuth2ClientOpenshiftIssuer)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "OpenShift connector entry missing oauth2_client_openshift_issuer"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let issuer = Url::parse(&issuer_str).map_err(|e| {
            error!(?entry_uuid, "OpenShift connector: invalid issuer URL: {e}");
            OperationError::InvalidEntryState
        })?;

        let allowed_groups: HashSet<String> = entry
            .get_ava_set(Attribute::OAuth2ClientOpenshiftGroups)
            .and_then(|vs| vs.as_utf8_iter())
            .map(|iter| iter.map(str::to_string).collect())
            .unwrap_or_default();

        let insecure_ca = entry
            .get_ava_single_bool(Attribute::OAuth2ClientOpenshiftInsecureCa)
            .unwrap_or(false);

        let root_ca_pem = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientOpenshiftRootCa)
            .map(str::to_string);

        let mut client_builder =
            reqwest::Client::builder().user_agent(concat!("netidmd/", env!("CARGO_PKG_VERSION")));

        if insecure_ca {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        } else if let Some(ref pem) = root_ca_pem {
            match reqwest::Certificate::from_pem(pem.as_bytes()) {
                Ok(cert) => {
                    client_builder = client_builder.add_root_certificate(cert);
                }
                Err(e) => {
                    error!(
                        ?entry_uuid,
                        "OpenShift connector: failed to parse root_ca PEM: {e}"
                    );
                    return Err(OperationError::InvalidEntryState);
                }
            }
        }

        let http = client_builder.build().map_err(|e| {
            error!(
                ?entry_uuid,
                "Failed to build HTTP client for OpenShift connector: {e}"
            );
            OperationError::InvalidEntryState
        })?;

        let well_known_url = format!(
            "{}/.well-known/oauth-authorization-server",
            issuer_str.trim_end_matches('/')
        );

        let (auth_endpoint, token_endpoint) = {
            let http_clone = http.clone();
            let url = well_known_url.clone();
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async move {
                    discover_endpoints(&http_clone, &url, entry_uuid).await
                })
            })
            .map_err(|e| {
                error!(
                    ?entry_uuid,
                    "OpenShift connector: endpoint discovery failed: {e}"
                );
                OperationError::InvalidState
            })?
        };

        Ok(OpenShiftConfig {
            entry_uuid,
            issuer,
            client_id,
            client_secret,
            redirect_uri,
            allowed_groups,
            http,
            auth_endpoint,
            token_endpoint,
            auth_endpoint_override: None,
            token_endpoint_override: None,
            user_endpoint_override: None,
        })
    }

    /// Build a config directly with explicit endpoints, used in unit tests.
    #[cfg(test)]
    pub fn new_for_test(
        entry_uuid: Uuid,
        issuer: Url,
        client_id: String,
        client_secret: String,
        redirect_uri: Url,
        allowed_groups: HashSet<String>,
        auth_endpoint: Url,
        token_endpoint: Url,
    ) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("netidmd-test")
            .build()
            .expect("reqwest client build");
        OpenShiftConfig {
            entry_uuid,
            issuer,
            client_id,
            client_secret,
            redirect_uri,
            allowed_groups,
            http,
            auth_endpoint,
            token_endpoint,
            auth_endpoint_override: None,
            token_endpoint_override: None,
            user_endpoint_override: None,
        }
    }
}

async fn discover_endpoints(
    http: &reqwest::Client,
    well_known_url: &str,
    entry_uuid: Uuid,
) -> Result<(Url, Url), ConnectorRefreshError> {
    let res = http
        .get(well_known_url)
        .send()
        .await
        .map_err(|e| ConnectorRefreshError::Network(format!("discovery GET failed: {e}")))?;

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(ConnectorRefreshError::Network(format!(
            "OpenShift well-known endpoint returned {status}: {body}"
        )));
    }

    let wk: WellKnown = res
        .json()
        .await
        .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))?;

    let auth = Url::parse(&wk.authorization_endpoint).map_err(|e| {
        ConnectorRefreshError::Serialization(format!(
            "invalid authorization_endpoint from discovery ({entry_uuid}): {e}"
        ))
    })?;
    let tok = Url::parse(&wk.token_endpoint).map_err(|e| {
        ConnectorRefreshError::Serialization(format!(
            "invalid token_endpoint from discovery ({entry_uuid}): {e}"
        ))
    })?;

    Ok((auth, tok))
}

/// Opaque per-session state stored on the `Oauth2Session` when
/// `upstream_connector` is set, allowing `refresh()` to re-fetch identity.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpenShiftSessionState {
    pub format_version: u8,
    pub access_token: String,
}

impl OpenShiftSessionState {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorRefreshError> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state is not UTF-8: {e}"))
        })?;
        let state: Self = serde_json::from_str(s).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state JSON parse failed: {e}"))
        })?;
        if state.format_version != OPENSHIFT_SESSION_STATE_FORMAT_VERSION {
            return Err(ConnectorRefreshError::Serialization(format!(
                "session-state format_version {} not supported (expected {})",
                state.format_version, OPENSHIFT_SESSION_STATE_FORMAT_VERSION
            )));
        }
        Ok(state)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ConnectorRefreshError> {
        serde_json::to_vec(self).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state serialisation failed: {e}"))
        })
    }
}

// ---------- OpenShift API response shapes ----------

#[derive(Deserialize, Debug)]
struct OpenShiftTokenResponse {
    access_token: String,
}

#[derive(Deserialize, Debug)]
struct OpenShiftUser {
    metadata: ObjectMeta,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct ObjectMeta {
    uid: String,
    name: String,
}

// ---------- Connector ----------

pub struct OpenShiftConnector {
    config: OpenShiftConfig,
}

impl OpenShiftConnector {
    pub fn new(config: OpenShiftConfig) -> Self {
        Self { config }
    }

    async fn exchange_code(
        &self,
        code: &str,
    ) -> Result<OpenShiftTokenResponse, ConnectorRefreshError> {
        let token_url = self
            .config
            .token_endpoint_override
            .as_deref()
            .unwrap_or(self.config.token_endpoint.as_str());

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
                "OpenShift token endpoint returned {status}: {body}"
            )));
        }

        res.json::<OpenShiftTokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn fetch_user(&self, token: &str) -> Result<OpenShiftUser, ConnectorRefreshError> {
        let user_url = if let Some(ref url) = self.config.user_endpoint_override {
            url.clone()
        } else {
            format!(
                "{}/apis/user.openshift.io/v1/users/~",
                self.config.issuer.as_str().trim_end_matches('/')
            )
        };

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
                "OpenShift users/~ returned {status}: {body}"
            )));
        }

        res.json::<OpenShiftUser>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    fn check_allowed_groups(&self, user: &OpenShiftUser) -> Result<(), ConnectorRefreshError> {
        if self.config.allowed_groups.is_empty() {
            return Ok(());
        }
        let in_group = user
            .groups
            .iter()
            .any(|g| self.config.allowed_groups.contains(g));
        if in_group {
            Ok(())
        } else {
            warn!("OpenShift connector: user not in any required group");
            Err(ConnectorRefreshError::AccessDenied)
        }
    }

    fn build_claims(&self, user: OpenShiftUser) -> ExternalUserClaims {
        ExternalUserClaims {
            sub: user.metadata.uid.clone(),
            email: Some(user.metadata.name.clone()),
            email_verified: None,
            display_name: None,
            username_hint: Some(user.metadata.name),
            groups: user.groups,
        }
    }
}

#[async_trait]
impl RefreshableConnector for OpenShiftConnector {
    async fn fetch_callback_claims(
        &self,
        code: &str,
        _code_verifier: Option<&str>,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        let token_resp = self.exchange_code(code).await?;
        let user = self.fetch_user(&token_resp.access_token).await?;
        self.check_allowed_groups(&user)?;
        Ok(self.build_claims(user))
    }

    async fn refresh(
        &self,
        session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        let state = OpenShiftSessionState::from_bytes(session_state)?;
        let user = self.fetch_user(&state.access_token).await?;
        self.check_allowed_groups(&user)?;

        if user.metadata.uid != previous_claims.sub {
            warn!(
                expected = %previous_claims.sub,
                got = %user.metadata.uid,
                "OpenShift connector: uid mismatch on refresh"
            );
            return Err(ConnectorRefreshError::TokenRevoked);
        }

        Ok(RefreshOutcome {
            claims: self.build_claims(user),
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

    fn test_config(allowed_groups: HashSet<String>) -> OpenShiftConfig {
        OpenShiftConfig::new_for_test(
            uuid!("00000000-0000-0000-0000-000000000001"),
            Url::parse("https://openshift.example.com").unwrap(),
            "client-id".into(),
            "client-secret".into(),
            Url::parse("https://netidm.example.com/oauth2/callback").unwrap(),
            allowed_groups,
            Url::parse("https://openshift.example.com/oauth/authorize").unwrap(),
            Url::parse("https://openshift.example.com/oauth/token").unwrap(),
        )
    }

    fn sample_user() -> OpenShiftUser {
        OpenShiftUser {
            metadata: ObjectMeta {
                uid: "uid-abc-123".into(),
                name: "alice".into(),
            },
            groups: vec!["dev".into(), "ops".into()],
        }
    }

    #[test]
    fn test_openshift_user_parse() {
        let json = r#"{
            "metadata": { "uid": "uid-abc-123", "name": "alice" },
            "groups": ["dev", "ops"]
        }"#;
        let user: OpenShiftUser = serde_json::from_str(json).expect("parse failed");
        assert_eq!(user.metadata.uid, "uid-abc-123");
        assert_eq!(user.metadata.name, "alice");
        assert_eq!(user.groups, vec!["dev", "ops"]);
    }

    #[test]
    fn test_openshift_user_parse_no_groups() {
        let json = r#"{"metadata": {"uid": "u1", "name": "bob"}}"#;
        let user: OpenShiftUser = serde_json::from_str(json).expect("parse failed");
        assert!(user.groups.is_empty());
    }

    #[test]
    fn test_openshift_allowed_groups_empty_allow_all() {
        let config = test_config(HashSet::new());
        let connector = OpenShiftConnector::new(config);
        let user = sample_user();
        assert!(connector.check_allowed_groups(&user).is_ok());
    }

    #[test]
    fn test_openshift_allowed_groups_gate_pass() {
        let mut allowed = HashSet::new();
        allowed.insert("ops".into());
        let config = test_config(allowed);
        let connector = OpenShiftConnector::new(config);
        let user = sample_user();
        assert!(connector.check_allowed_groups(&user).is_ok());
    }

    #[test]
    fn test_openshift_allowed_groups_gate_deny() {
        let mut allowed = HashSet::new();
        allowed.insert("admins".into());
        let config = test_config(allowed);
        let connector = OpenShiftConnector::new(config);
        let user = sample_user();
        assert!(matches!(
            connector.check_allowed_groups(&user),
            Err(ConnectorRefreshError::AccessDenied)
        ));
    }

    #[test]
    fn test_openshift_build_claims() {
        let config = test_config(HashSet::new());
        let connector = OpenShiftConnector::new(config);
        let user = sample_user();
        let claims = connector.build_claims(user);
        assert_eq!(claims.sub, "uid-abc-123");
        assert_eq!(claims.email, Some("alice".into()));
        assert_eq!(claims.email_verified, None);
        assert_eq!(claims.display_name, None);
        assert_eq!(claims.username_hint, Some("alice".into()));
        assert_eq!(claims.groups, vec!["dev", "ops"]);
    }

    #[test]
    fn test_openshift_session_state_roundtrip() {
        let state = OpenShiftSessionState {
            format_version: OPENSHIFT_SESSION_STATE_FORMAT_VERSION,
            access_token: "tok_xyz".into(),
        };
        let bytes = state.to_bytes().expect("serialise");
        let decoded = OpenShiftSessionState::from_bytes(&bytes).expect("deserialise");
        assert_eq!(decoded.access_token, "tok_xyz");
        assert_eq!(
            decoded.format_version,
            OPENSHIFT_SESSION_STATE_FORMAT_VERSION
        );
    }

    #[test]
    fn test_openshift_session_state_version_mismatch() {
        let state = OpenShiftSessionState {
            format_version: 99,
            access_token: "tok".into(),
        };
        let bytes = state.to_bytes().expect("serialise");
        let result = OpenShiftSessionState::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(ConnectorRefreshError::Serialization(_))
        ));
    }

    #[test]
    fn test_openshift_well_known_parse() {
        let json = r#"{
            "authorization_endpoint": "https://openshift.example.com/oauth/authorize",
            "token_endpoint": "https://openshift.example.com/oauth/token"
        }"#;
        let wk: WellKnown = serde_json::from_str(json).expect("parse failed");
        assert!(wk.authorization_endpoint.contains("/oauth/authorize"));
        assert!(wk.token_endpoint.contains("/oauth/token"));
    }
}
