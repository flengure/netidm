//! LinkedIn upstream connector (PR-CONNECTOR-LINKEDIN).
//!
//! Exact-parity port of `connector/linkedin/linkedin.go` from dex.
//! Providers whose `OAuth2Client` entry carries
//! `oauth2_client_provider_kind = "linkedin"` are dispatched here.
//!
//! LinkedIn's v2 API exposes only basic profile (ID, name) and primary email
//! via the `r_liteprofile` / `r_emailaddress` scopes. There is no
//! group/organisation membership endpoint, so `ExternalUserClaims::groups`
//! is always empty for this connector.
//!
//! [`RefreshableConnector`]: crate::idm::oauth2_connector::RefreshableConnector

use crate::idm::authsession::handler_oauth2_client::ExternalUserClaims;
use crate::idm::oauth2_connector::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

pub static LINKEDIN_TOKEN_ENDPOINT: &str = "https://www.linkedin.com/oauth/v2/accessToken";
pub static LINKEDIN_PROFILE_ENDPOINT: &str = "https://api.linkedin.com/v2/me";
/// The `projection` parameter is LinkedIn's field-selector syntax for the email endpoint.
pub static LINKEDIN_EMAIL_ENDPOINT: &str =
    "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))";

pub const LINKEDIN_SESSION_STATE_FORMAT_VERSION: u8 = 1;

/// Parsed LinkedIn connector configuration. Built once at server start and
/// registered with the [`crate::idm::oauth2_connector::ConnectorRegistry`].
///
/// LinkedIn requires only the three standard OAuth2 fields (no
/// connector-specific schema attributes beyond `oauth2_client_provider_kind`).
pub struct LinkedInConfig {
    pub entry_uuid: Uuid,
    pub client_id: String,
    client_secret: String,
    pub redirect_uri: Url,
    /// Endpoint overrides used in unit tests to point at mock servers.
    pub token_endpoint_override: Option<String>,
    pub profile_endpoint_override: Option<String>,
    pub email_endpoint_override: Option<String>,
    pub http: reqwest::Client,
}

impl std::fmt::Debug for LinkedInConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkedInConfig")
            .field("entry_uuid", &self.entry_uuid)
            .field("client_id", &self.client_id)
            .field("client_secret", &"***")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl LinkedInConfig {
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
                    "LinkedIn connector entry missing oauth2_client_id"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let client_secret = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientSecret)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "LinkedIn connector entry missing oauth2_client_secret"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let http = reqwest::Client::builder()
            .user_agent(concat!("netidmd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| {
                error!(
                    ?entry_uuid,
                    "Failed to build HTTP client for LinkedIn connector: {e}"
                );
                OperationError::InvalidEntryState
            })?;

        Ok(LinkedInConfig {
            entry_uuid,
            client_id,
            client_secret,
            redirect_uri,
            token_endpoint_override: None,
            profile_endpoint_override: None,
            email_endpoint_override: None,
            http,
        })
    }
}

/// Opaque per-session state — stored when `upstream_connector` is set on the
/// `Oauth2Session`, allowing `refresh()` to re-fetch identity without
/// prompting the user again.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinkedInSessionState {
    pub format_version: u8,
    pub access_token: String,
}

impl LinkedInSessionState {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorRefreshError> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state is not UTF-8: {e}"))
        })?;
        let state: Self = serde_json::from_str(s).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state JSON parse failed: {e}"))
        })?;
        if state.format_version != LINKEDIN_SESSION_STATE_FORMAT_VERSION {
            return Err(ConnectorRefreshError::Serialization(format!(
                "session-state format_version {} not supported (expected {})",
                state.format_version, LINKEDIN_SESSION_STATE_FORMAT_VERSION
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

// ---------- LinkedIn API response shapes ----------

#[derive(Deserialize, Debug)]
struct LinkedInProfile {
    id: String,
    #[serde(rename = "localizedFirstName")]
    localized_first_name: String,
    #[serde(rename = "localizedLastName")]
    localized_last_name: String,
}

impl LinkedInProfile {
    /// Dex behaviour: trim "first last"; fall back to email if blank.
    fn fullname(&self, email: &str) -> String {
        let name = format!("{} {}", self.localized_first_name, self.localized_last_name);
        let trimmed = name.trim().to_string();
        if trimmed.is_empty() {
            email.to_string()
        } else {
            trimmed
        }
    }
}

#[derive(Deserialize, Debug)]
struct LinkedInEmailResp {
    elements: Vec<LinkedInEmailElement>,
}

#[derive(Deserialize, Debug)]
struct LinkedInEmailElement {
    // LinkedIn's projection syntax produces a key literally named "handle~".
    #[serde(rename = "handle~")]
    handle: LinkedInEmailHandle,
}

#[derive(Deserialize, Debug)]
struct LinkedInEmailHandle {
    #[serde(rename = "emailAddress")]
    email_address: String,
}

#[derive(Deserialize, Debug)]
struct LinkedInTokenResponse {
    access_token: String,
}

// ---------- Connector ----------

pub struct LinkedInConnector {
    config: LinkedInConfig,
}

impl LinkedInConnector {
    pub fn new(config: LinkedInConfig) -> Self {
        Self { config }
    }

    async fn exchange_code(
        &self,
        code: &str,
    ) -> Result<LinkedInTokenResponse, ConnectorRefreshError> {
        let token_url = self
            .config
            .token_endpoint_override
            .as_deref()
            .unwrap_or(LINKEDIN_TOKEN_ENDPOINT);

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
                "LinkedIn token endpoint returned {status}: {body}"
            )));
        }

        res.json::<LinkedInTokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn fetch_profile(&self, token: &str) -> Result<LinkedInProfile, ConnectorRefreshError> {
        let profile_url = self
            .config
            .profile_endpoint_override
            .as_deref()
            .unwrap_or(LINKEDIN_PROFILE_ENDPOINT);

        let res = self
            .config
            .http
            .get(profile_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(ConnectorRefreshError::Network(format!(
                "LinkedIn /v2/me returned {status}: {body}"
            )));
        }

        res.json::<LinkedInProfile>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn fetch_primary_email(&self, token: &str) -> Result<String, ConnectorRefreshError> {
        let email_url = self
            .config
            .email_endpoint_override
            .as_deref()
            .unwrap_or(LINKEDIN_EMAIL_ENDPOINT);

        let res = self
            .config
            .http
            .get(email_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(ConnectorRefreshError::Network(format!(
                "LinkedIn email endpoint returned {status}: {body}"
            )));
        }

        let email_resp: LinkedInEmailResp = res
            .json()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))?;

        email_resp
            .elements
            .into_iter()
            .next()
            .map(|el| el.handle.email_address)
            .ok_or_else(|| ConnectorRefreshError::Other("LinkedIn: email is not set".into()))
    }

    async fn build_claims(&self, token: &str) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        let profile = self.fetch_profile(token).await?;
        let email = self.fetch_primary_email(token).await?;
        let display_name = profile.fullname(&email);

        Ok(ExternalUserClaims {
            sub: profile.id,
            email: Some(email),
            email_verified: Some(true),
            display_name: Some(display_name),
            username_hint: None,
            groups: vec![],
        })
    }
}

#[async_trait]
impl RefreshableConnector for LinkedInConnector {
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
        let state = LinkedInSessionState::from_bytes(session_state)?;

        let claims = self.build_claims(&state.access_token).await?;

        if claims.sub != previous_claims.sub {
            warn!(
                expected = %previous_claims.sub,
                got = %claims.sub,
                "LinkedIn connector: sub mismatch on refresh"
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

    #[test]
    fn test_linkedin_profile_parse() {
        let json = r#"{
            "id": "abc123",
            "localizedFirstName": "Alice",
            "localizedLastName": "Smith"
        }"#;
        let profile: LinkedInProfile = serde_json::from_str(json).expect("parse failed");
        assert_eq!(profile.id, "abc123");
        assert_eq!(profile.localized_first_name, "Alice");
        assert_eq!(profile.localized_last_name, "Smith");
    }

    #[test]
    fn test_linkedin_email_parse() {
        // The key "handle~" contains a tilde — verify serde rename works.
        let json = r#"{
            "elements": [
                {
                    "handle~": {
                        "emailAddress": "alice@example.com"
                    }
                }
            ]
        }"#;
        let resp: LinkedInEmailResp = serde_json::from_str(json).expect("parse failed");
        assert_eq!(resp.elements.len(), 1);
        assert_eq!(resp.elements[0].handle.email_address, "alice@example.com");
    }

    #[test]
    fn test_linkedin_fullname_normal() {
        let profile = LinkedInProfile {
            id: "x".into(),
            localized_first_name: "Alice".into(),
            localized_last_name: "Smith".into(),
        };
        assert_eq!(profile.fullname("fallback@example.com"), "Alice Smith");
    }

    #[test]
    fn test_linkedin_fullname_fallback_to_email() {
        let profile = LinkedInProfile {
            id: "x".into(),
            localized_first_name: "  ".into(),
            localized_last_name: "   ".into(),
        };
        assert_eq!(
            profile.fullname("fallback@example.com"),
            "fallback@example.com"
        );
    }

    #[test]
    fn test_linkedin_fullname_empty_fields() {
        let profile = LinkedInProfile {
            id: "x".into(),
            localized_first_name: String::new(),
            localized_last_name: String::new(),
        };
        assert_eq!(profile.fullname("user@example.com"), "user@example.com");
    }

    #[test]
    fn test_linkedin_session_state_roundtrip() {
        let state = LinkedInSessionState {
            format_version: LINKEDIN_SESSION_STATE_FORMAT_VERSION,
            access_token: "tok_abc".into(),
        };
        let bytes = state.to_bytes().expect("serialise");
        let decoded = LinkedInSessionState::from_bytes(&bytes).expect("deserialise");
        assert_eq!(decoded.access_token, "tok_abc");
        assert_eq!(
            decoded.format_version,
            LINKEDIN_SESSION_STATE_FORMAT_VERSION
        );
    }

    #[test]
    fn test_linkedin_session_state_version_mismatch() {
        let state = LinkedInSessionState {
            format_version: 99,
            access_token: "tok".into(),
        };
        let bytes = state.to_bytes().expect("serialise");
        let result = LinkedInSessionState::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(ConnectorRefreshError::Serialization(_))
        ));
    }

    #[test]
    fn test_linkedin_email_empty_elements() {
        let json = r#"{"elements": []}"#;
        let resp: LinkedInEmailResp = serde_json::from_str(json).expect("parse failed");
        assert!(resp.elements.is_empty());
    }

    #[test]
    fn test_linkedin_groups_always_empty() {
        // LinkedIn has no group API — verify the claims always carry an empty group list.
        let profile = LinkedInProfile {
            id: "uid1".into(),
            localized_first_name: "Test".into(),
            localized_last_name: "User".into(),
        };
        let display_name = profile.fullname("test@example.com");
        let claims = ExternalUserClaims {
            sub: profile.id.clone(),
            email: Some("test@example.com".into()),
            email_verified: Some(true),
            display_name: Some(display_name),
            username_hint: None,
            groups: vec![],
        };
        assert!(claims.groups.is_empty());
        assert_eq!(claims.email_verified, Some(true));
    }
}
