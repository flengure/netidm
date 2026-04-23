//! Google upstream connector (PR-CONNECTOR-GOOGLE, DL30).
//!
//! Implements [`RefreshableConnector`] for Google Workspace / Google Identity.
//! Providers whose `OAuth2Client` entry carries `oauth2_client_provider_kind =
//! "google"` are dispatched here.
//!
//! Features:
//! * Standard Google OAuth2/OIDC flow (Google's token and userinfo endpoints).
//! * Hosted-domain (`hd` claim) restriction — blocks users from non-Workspace
//!   or wrong-domain accounts before they reach the account-linking chain.
//! * Optional group fetching via the Admin SDK Directory API using service
//!   account impersonation (domain-wide delegation).
//!
//! [`RefreshableConnector`]: crate::idm::oauth2_connector::RefreshableConnector

use crate::idm::authsession::handler_oauth2_client::ExternalUserClaims;
use crate::idm::oauth2_connector::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use compact_jwt::crypto::JwsRs256Signer;
use compact_jwt::jwt::Jwt;
use compact_jwt::JwsSigner;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

pub static GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
pub static GOOGLE_USERINFO_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";
pub static GOOGLE_DIRECTORY_GROUPS_API: &str =
    "https://admin.googleapis.com/admin/directory/v1/groups";
static GOOGLE_SA_JWT_GRANT_TYPE: &str = "urn:ietf:params:oauth2:grant-type:jwt-bearer";
static GOOGLE_DIRECTORY_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.group.readonly";

pub const GOOGLE_SESSION_STATE_FORMAT_VERSION: u8 = 1;

/// Parsed service account JSON key as exported from the Google Cloud Console.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccountKey {
    pub client_email: String,
    pub private_key: String,
}

impl ServiceAccountKey {
    /// Decode the PEM private key to DER bytes so we can load it into
    /// `JwsRs256Signer::from_rs256_der`.
    fn private_key_der(&self) -> Result<Vec<u8>, ConnectorRefreshError> {
        let pem = &self.private_key;
        // Strip PEM header/footer and any whitespace, then base64-decode.
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| {
                ConnectorRefreshError::Serialization(format!(
                    "service account private key base64 decode failed: {e}"
                ))
            })
    }
}

/// Parsed Google connector configuration — one per `OAuth2Client` entry with
/// `oauth2_client_provider_kind = "google"`. Built once at server start and
/// registered with the [`crate::idm::oauth2_connector::ConnectorRegistry`].
#[derive(Clone, Debug)]
pub struct GoogleConfig {
    pub entry_uuid: Uuid,
    /// Google Workspace hosted domain restriction. `None` = accept all accounts.
    pub hosted_domain: Option<String>,
    /// Parsed service account key for Directory API calls.
    pub service_account: Option<ServiceAccountKey>,
    /// Admin email to impersonate via domain-wide delegation.
    pub admin_email: Option<String>,
    /// When true, fetch group memberships from the Admin SDK.
    pub fetch_groups: bool,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: Url,
    /// When true, first-time Google users with no linking match are auto-provisioned.
    pub allow_jit_provisioning: bool,
    pub http: reqwest::Client,
    /// Override for token endpoint URL — `None` uses `GOOGLE_TOKEN_ENDPOINT`.
    /// Set in tests to point at the mock server.
    pub token_endpoint_override: Option<String>,
    /// Override for userinfo endpoint URL — `None` uses `GOOGLE_USERINFO_ENDPOINT`.
    pub userinfo_endpoint_override: Option<String>,
    /// Override for Directory API base URL — `None` uses `GOOGLE_DIRECTORY_GROUPS_API`.
    pub directory_api_override: Option<String>,
}

impl GoogleConfig {
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
                    "Google connector entry missing oauth2_client_id"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let client_secret = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientSecret)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "Google connector entry missing oauth2_client_secret"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let hosted_domain = entry
            .get_ava_single_iutf8(Attribute::OAuth2ClientGoogleHostedDomain)
            .map(str::to_string);

        let service_account_json = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientGoogleServiceAccountJson)
            .map(str::to_string);

        let service_account = service_account_json
            .as_deref()
            .map(|json| {
                serde_json::from_str::<ServiceAccountKey>(json).map_err(|e| {
                    warn!(
                        ?entry_uuid,
                        "Google connector: failed to parse service_account_json: {e}"
                    );
                    OperationError::InvalidEntryState
                })
            })
            .transpose()?;

        let admin_email = entry
            .get_ava_single_iutf8(Attribute::OAuth2ClientGoogleAdminEmail)
            .map(str::to_string);

        let fetch_groups = entry
            .get_ava_single_bool(Attribute::OAuth2ClientGoogleFetchGroups)
            .unwrap_or(false);

        if fetch_groups && service_account.is_none() {
            warn!(
                ?entry_uuid,
                "Google connector: fetch_groups=true but no service_account_json set; \
                 groups will not be fetched"
            );
        }
        if fetch_groups && admin_email.is_none() {
            warn!(
                ?entry_uuid,
                "Google connector: fetch_groups=true but no admin_email set; \
                 groups will not be fetched"
            );
        }

        let allow_jit_provisioning = entry
            .get_ava_single_bool(Attribute::OAuth2ClientGithubAllowJitProvisioning)
            .unwrap_or(false);

        let http = reqwest::Client::builder()
            .user_agent(concat!("netidmd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| {
                error!(
                    ?entry_uuid,
                    "Failed to build HTTP client for Google connector: {e}"
                );
                OperationError::InvalidEntryState
            })?;

        Ok(GoogleConfig {
            entry_uuid,
            hosted_domain,
            service_account,
            admin_email,
            fetch_groups,
            client_id,
            client_secret,
            redirect_uri,
            allow_jit_provisioning,
            http,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            directory_api_override: None,
        })
    }
}

/// Opaque per-session state for the Google connector.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GoogleSessionState {
    pub format_version: u8,
    pub refresh_token: Option<String>,
}

impl GoogleSessionState {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorRefreshError> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state is not UTF-8: {e}"))
        })?;
        let state: Self = serde_json::from_str(s).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state JSON parse failed: {e}"))
        })?;
        if state.format_version != GOOGLE_SESSION_STATE_FORMAT_VERSION {
            return Err(ConnectorRefreshError::Serialization(format!(
                "session-state format_version {} not supported (expected {})",
                state.format_version, GOOGLE_SESSION_STATE_FORMAT_VERSION
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

#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    #[allow(dead_code)]
    id_token: Option<String>,
}

#[derive(Deserialize, Debug)]
struct UserinfoResponse {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    #[serde(rename = "hd")]
    hosted_domain: Option<String>,
}

#[derive(Deserialize, Debug)]
struct DirectoryGroupsResponse {
    groups: Option<Vec<DirectoryGroup>>,
}

#[derive(Deserialize, Debug)]
struct DirectoryGroup {
    email: String,
}

/// Extension struct carrying the `scope` claim needed for the service account JWT.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct SaJwtExt {
    scope: String,
}

pub struct GoogleConnector {
    config: GoogleConfig,
}

impl GoogleConnector {
    pub fn new(config: GoogleConfig) -> Self {
        Self { config }
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, ConnectorRefreshError> {
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];
        let verifier_owned;
        if let Some(cv) = code_verifier {
            verifier_owned = cv.to_string();
            params.push(("code_verifier", verifier_owned.as_str()));
        }

        let token_url = self
            .config
            .token_endpoint_override
            .as_deref()
            .unwrap_or(GOOGLE_TOKEN_ENDPOINT);

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
                "Google token endpoint returned {status}: {body}"
            )));
        }

        res.json::<TokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn exchange_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, ConnectorRefreshError> {
        let params = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];

        let token_url = self
            .config
            .token_endpoint_override
            .as_deref()
            .unwrap_or(GOOGLE_TOKEN_ENDPOINT);

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
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                return Err(ConnectorRefreshError::TokenRevoked);
            }
            return Err(ConnectorRefreshError::Network(format!(
                "Google token refresh returned {status}: {body}"
            )));
        }

        res.json::<TokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    async fn fetch_userinfo(
        &self,
        access_token: &str,
    ) -> Result<UserinfoResponse, ConnectorRefreshError> {
        let userinfo_url = self
            .config
            .userinfo_endpoint_override
            .as_deref()
            .unwrap_or(GOOGLE_USERINFO_ENDPOINT);

        let res = self
            .config
            .http
            .get(userinfo_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            return Err(ConnectorRefreshError::Network(format!(
                "Google userinfo returned {status}"
            )));
        }

        res.json::<UserinfoResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))
    }

    fn check_hosted_domain(&self, hd_claim: Option<&str>) -> Result<(), ConnectorRefreshError> {
        if let Some(required_hd) = &self.config.hosted_domain {
            let actual_hd = hd_claim.unwrap_or("");
            if !actual_hd.eq_ignore_ascii_case(required_hd.as_str()) {
                debug!(
                    required = %required_hd,
                    actual = %actual_hd,
                    "Google connector: hosted domain mismatch"
                );
                return Err(ConnectorRefreshError::AccessDenied);
            }
        }
        Ok(())
    }

    async fn get_service_account_token(&self) -> Result<String, ConnectorRefreshError> {
        let sa =
            self.config.service_account.as_ref().ok_or_else(|| {
                ConnectorRefreshError::Other("no service account configured".into())
            })?;
        let admin_email = self
            .config
            .admin_email
            .as_deref()
            .ok_or_else(|| ConnectorRefreshError::Other("no admin_email configured".into()))?;

        let der = sa.private_key_der()?;
        let signer = JwsRs256Signer::from_rs256_der(&der).map_err(|e| {
            ConnectorRefreshError::Serialization(format!(
                "failed to load service account RSA key: {e:?}"
            ))
        })?;

        let now = (time::OffsetDateTime::UNIX_EPOCH + crate::time::duration_from_epoch_now())
            .unix_timestamp();

        let aud = self
            .config
            .token_endpoint_override
            .as_deref()
            .unwrap_or(GOOGLE_TOKEN_ENDPOINT)
            .to_string();

        let jwt: Jwt<SaJwtExt> = Jwt {
            iss: Some(sa.client_email.clone()),
            sub: Some(admin_email.to_string()),
            aud: Some(aud),
            iat: Some(now),
            exp: Some(now + 3600),
            extensions: SaJwtExt {
                scope: GOOGLE_DIRECTORY_SCOPE.to_string(),
            },
            ..Default::default()
        };

        let signed = signer.sign(&jwt).map_err(|e| {
            ConnectorRefreshError::Serialization(format!(
                "service account JWT signing failed: {e:?}"
            ))
        })?;

        let jwt_str = signed.to_string();

        let params = vec![
            ("grant_type", GOOGLE_SA_JWT_GRANT_TYPE),
            ("assertion", jwt_str.as_str()),
        ];

        let token_url = self
            .config
            .token_endpoint_override
            .as_deref()
            .unwrap_or(GOOGLE_TOKEN_ENDPOINT);

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
                "Google SA token exchange returned {status}: {body}"
            )));
        }

        #[derive(Deserialize)]
        struct SaTokenResponse {
            access_token: String,
        }

        let sa_resp: SaTokenResponse = res
            .json()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))?;

        Ok(sa_resp.access_token)
    }

    async fn fetch_groups_for_user(
        &self,
        user_email: &str,
    ) -> Result<Vec<String>, ConnectorRefreshError> {
        if !self.config.fetch_groups
            || self.config.service_account.is_none()
            || self.config.admin_email.is_none()
        {
            return Ok(Vec::new());
        }

        let sa_token = self.get_service_account_token().await?;

        let directory_url = self
            .config
            .directory_api_override
            .as_deref()
            .unwrap_or(GOOGLE_DIRECTORY_GROUPS_API);

        let res = self
            .config
            .http
            .get(directory_url)
            .query(&[("userKey", user_email)])
            .bearer_auth(&sa_token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(ConnectorRefreshError::Network(format!(
                "Google Directory API returned {status}: {body}"
            )));
        }

        let dir_resp: DirectoryGroupsResponse = res
            .json()
            .await
            .map_err(|e| ConnectorRefreshError::Serialization(e.to_string()))?;

        let groups = dir_resp
            .groups
            .unwrap_or_default()
            .into_iter()
            .map(|g| g.email.to_lowercase())
            .collect();

        Ok(groups)
    }

    async fn build_claims(
        &self,
        token_resp: &TokenResponse,
    ) -> Result<(ExternalUserClaims, Option<String>), ConnectorRefreshError> {
        // Fetch userinfo — always needed for Google (id_token may not carry all claims).
        let userinfo = self.fetch_userinfo(&token_resp.access_token).await?;

        // Hosted domain check.
        self.check_hosted_domain(userinfo.hosted_domain.as_deref())?;

        // Fetch groups if configured.
        let groups = if let Some(email) = &userinfo.email {
            self.fetch_groups_for_user(email).await?
        } else {
            Vec::new()
        };

        let claims = ExternalUserClaims {
            sub: userinfo.sub,
            email: userinfo.email,
            email_verified: userinfo.email_verified,
            display_name: userinfo.name,
            username_hint: None,
            groups,
        };

        Ok((claims, token_resp.refresh_token.clone()))
    }
}

#[async_trait]
impl RefreshableConnector for GoogleConnector {
    async fn refresh(
        &self,
        session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        let state = GoogleSessionState::from_bytes(session_state)?;

        let refresh_token = state
            .refresh_token
            .as_deref()
            .ok_or(ConnectorRefreshError::TokenRevoked)?;

        let token_resp = self.exchange_refresh_token(refresh_token).await?;

        let (claims, new_rt) = self.build_claims(&token_resp).await?;

        if claims.sub != previous_claims.sub {
            warn!(
                expected = %previous_claims.sub,
                got = %claims.sub,
                "Google connector: sub mismatch on refresh"
            );
            return Err(ConnectorRefreshError::TokenRevoked);
        }

        let new_state = GoogleSessionState {
            format_version: GOOGLE_SESSION_STATE_FORMAT_VERSION,
            refresh_token: new_rt.or(state.refresh_token),
        };

        Ok(RefreshOutcome {
            claims,
            new_session_state: Some(new_state.to_bytes()?),
        })
    }

    async fn fetch_callback_claims(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        let token_resp = self.exchange_code(code, code_verifier).await?;
        let (claims, _rt) = self.build_claims(&token_resp).await?;
        Ok(claims)
    }

    fn allow_jit_provisioning(&self) -> bool {
        self.config.allow_jit_provisioning
    }
}
