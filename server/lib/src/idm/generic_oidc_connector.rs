//! Generic OIDC upstream connector (PR-CONNECTOR-GENERIC-OIDC, DL29).
//!
//! Implements [`RefreshableConnector`] for any standards-conformant OIDC provider.
//! Providers whose `OAuth2Client` entry carries `oauth2_client_provider_kind =
//! "generic-oidc"` (or which have no `provider_kind` attribute set — the default)
//! are dispatched here at callback time, bypassing the legacy multi-step
//! `OAuth2AccessTokenRequest` / `OAuth2JwksRequest` state machine.
//!
//! Mirrors dex's `connector/oidc` behaviour: token exchange, id_token
//! verification via JWKS, optional userinfo merge, configurable group
//! extraction (claim key, allowed-groups filter, prefix/suffix), and
//! refresh-token re-fetch that re-derives all claims including groups.
//!
//! [`RefreshableConnector`]: crate::idm::oauth2_connector::RefreshableConnector

use crate::idm::authsession::handler_oauth2_client::ExternalUserClaims;
use crate::idm::oauth2_connector::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use compact_jwt::compact::{JwaAlg, Jwk, JwkKeySet};
use compact_jwt::crypto::{JwsEs256Verifier, JwsRs256Verifier};
use compact_jwt::traits::{JwsVerifiable, JwsVerifier};
use compact_jwt::OidcUnverified;
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use url::Url;
use uuid::Uuid;

pub const GENERIC_OIDC_SESSION_STATE_FORMAT_VERSION: u8 = 1;

/// Parsed generic-OIDC connector config — one per `OAuth2Client` entry with
/// `oauth2_client_provider_kind = "generic-oidc"` (or absent). Built once at
/// `IdmServer::start` and registered with `ConnectorRegistry`; immutable for
/// the lifetime of the process.
#[derive(Clone, Debug)]
pub struct GenericOidcConfig {
    pub entry_uuid: Uuid,
    pub client_id: String,
    pub client_secret: String,
    pub token_endpoint: Url,
    pub redirect_uri: Url,
    pub jwks_uri: Option<Url>,
    pub userinfo_endpoint: Option<Url>,
    pub enable_groups: bool,
    pub groups_key: String,
    pub skip_email_verified: bool,
    pub allowed_groups: HashSet<String>,
    pub get_user_info: bool,
    pub user_id_key: Option<String>,
    pub user_name_key: Option<String>,
    pub override_claim_mapping: bool,
    pub groups_prefix: Option<String>,
    pub groups_suffix: Option<String>,
    pub allow_jit_provisioning: bool,
    pub http: reqwest::Client,
}

impl GenericOidcConfig {
    pub fn from_entry(
        entry: &EntrySealedCommitted,
        redirect_uri: Url,
    ) -> Result<Self, OperationError> {
        let entry_uuid = entry.get_uuid();

        let client_id = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientId)
            .map(str::to_string)
            .ok_or(OperationError::InvalidValueState)?;

        let client_secret = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientSecret)
            .map(str::to_string)
            .ok_or(OperationError::InvalidValueState)?;

        let token_endpoint = entry
            .get_ava_single_url(Attribute::OAuth2TokenEndpoint)
            .cloned()
            .ok_or(OperationError::InvalidValueState)?;

        let jwks_uri = entry.get_ava_single_url(Attribute::OAuth2JwksUri).cloned();

        let userinfo_endpoint = entry
            .get_ava_single_url(Attribute::OAuth2UserinfoEndpoint)
            .cloned();

        let enable_groups = entry
            .get_ava_single_bool(Attribute::OAuth2ClientOidcEnableGroups)
            .unwrap_or(false);

        let groups_key = entry
            .get_ava_single_iutf8(Attribute::OAuth2ClientOidcGroupsKey)
            .unwrap_or("groups")
            .to_string();

        let skip_email_verified = entry
            .get_ava_single_bool(Attribute::OAuth2ClientOidcSkipEmailVerified)
            .unwrap_or(false);

        let allowed_groups: HashSet<String> = entry
            .get_ava_set(Attribute::OAuth2ClientOidcAllowedGroups)
            .and_then(|vs| vs.as_utf8_iter())
            .map(|iter| iter.map(str::to_string).collect())
            .unwrap_or_default();

        let get_user_info = entry
            .get_ava_single_bool(Attribute::OAuth2ClientOidcGetUserInfo)
            .unwrap_or(false);

        let user_id_key = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientOidcUserIdKey)
            .map(str::to_string);

        let user_name_key = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientOidcUserNameKey)
            .map(str::to_string);

        let override_claim_mapping = entry
            .get_ava_single_bool(Attribute::OAuth2ClientOidcOverrideClaimMapping)
            .unwrap_or(false);

        let groups_prefix = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientOidcGroupsPrefix)
            .map(str::to_string);

        let groups_suffix = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientOidcGroupsSuffix)
            .map(str::to_string);

        let allow_jit_provisioning = entry
            .get_ava_single_bool(Attribute::OAuth2JitProvisioning)
            .unwrap_or(false);

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent(concat!(
                "netidm/",
                env!("CARGO_PKG_VERSION"),
                " (connector-generic-oidc)"
            ))
            .build()
            .map_err(|e| {
                error!(
                    ?e,
                    "Failed to build reqwest::Client for generic-OIDC connector"
                );
                OperationError::InvalidValueState
            })?;

        Ok(GenericOidcConfig {
            entry_uuid,
            client_id,
            client_secret,
            token_endpoint,
            redirect_uri,
            jwks_uri,
            userinfo_endpoint,
            enable_groups,
            groups_key,
            skip_email_verified,
            allowed_groups,
            get_user_info,
            user_id_key,
            user_name_key,
            override_claim_mapping,
            groups_prefix,
            groups_suffix,
            allow_jit_provisioning,
            http,
        })
    }
}

/// Opaque per-session state blob for the generic-OIDC connector.
/// Stores the upstream refresh token so `refresh()` can re-exchange it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenericOidcSessionState {
    pub format_version: u8,
    pub refresh_token: Option<String>,
}

impl GenericOidcSessionState {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorRefreshError> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state is not UTF-8: {e}"))
        })?;
        let state: Self = serde_json::from_str(s).map_err(|e| {
            ConnectorRefreshError::Serialization(format!("session-state JSON parse failed: {e}"))
        })?;
        if state.format_version != GENERIC_OIDC_SESSION_STATE_FORMAT_VERSION {
            return Err(ConnectorRefreshError::Serialization(format!(
                "session-state format_version {} not supported (expected {})",
                state.format_version, GENERIC_OIDC_SESSION_STATE_FORMAT_VERSION
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

/// Response from the OIDC token endpoint.
#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
}

pub struct GenericOidcConnector {
    config: GenericOidcConfig,
}

impl GenericOidcConnector {
    pub fn new(config: GenericOidcConfig) -> Self {
        Self { config }
    }

    /// Exchange an authorisation code (or refresh token) for a `TokenResponse`.
    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, ConnectorRefreshError> {
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_uri.as_str()),
        ];

        let verifier_owned;
        if let Some(cv) = code_verifier {
            verifier_owned = cv.to_string();
            params.push(("code_verifier", verifier_owned.as_str()));
        }

        let res = self
            .config
            .http
            .post(self.config.token_endpoint.as_str())
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .form(&params)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        let status = res.status();
        if !status.is_success() {
            return Err(ConnectorRefreshError::UpstreamRejected(status.as_u16()));
        }

        res.json::<TokenResponse>()
            .await
            .map_err(|e| ConnectorRefreshError::Other(format!("token response parse failed: {e}")))
    }

    /// Exchange a refresh token for a new `TokenResponse`.
    async fn exchange_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, ConnectorRefreshError> {
        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];

        let res = self
            .config
            .http
            .post(self.config.token_endpoint.as_str())
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .form(&params)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        let status = res.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::BAD_REQUEST
        {
            return Err(ConnectorRefreshError::TokenRevoked);
        }
        if !status.is_success() {
            return Err(ConnectorRefreshError::UpstreamRejected(status.as_u16()));
        }

        res.json::<TokenResponse>().await.map_err(|e| {
            ConnectorRefreshError::Other(format!("refresh token response parse failed: {e}"))
        })
    }

    /// Fetch and verify an id_token using the provider's JWKS endpoint.
    /// Returns the verified claims as a `serde_json::Value`.
    async fn verify_id_token(
        &self,
        jwks_uri: &Url,
        id_token: &str,
    ) -> Result<serde_json::Value, ConnectorRefreshError> {
        let unverified = OidcUnverified::from_str(id_token)
            .map_err(|e| ConnectorRefreshError::Other(format!("id_token parse failed: {e}")))?;

        let token_kid = unverified.kid().map(str::to_owned);
        let token_alg = unverified.alg();

        let mut keyset = self.fetch_jwks(jwks_uri).await?;
        let jwk = match find_key_in_set(&keyset, token_kid.as_deref()) {
            Some(k) => k.clone(),
            None => {
                keyset = self.fetch_jwks(jwks_uri).await?;
                find_key_in_set(&keyset, token_kid.as_deref())
                    .ok_or_else(|| {
                        warn!("id_token kid not found in JWKS after re-fetch");
                        ConnectorRefreshError::Other("id_token kid not found in JWKS".to_string())
                    })?
                    .clone()
            }
        };

        let exp_unverified = match token_alg {
            JwaAlg::ES256 => {
                let verifier = JwsEs256Verifier::try_from(&jwk).map_err(|e| {
                    ConnectorRefreshError::Other(format!("ES256 verifier build failed: {e}"))
                })?;
                verifier.verify(&unverified).map_err(|e| {
                    ConnectorRefreshError::Other(format!("ES256 id_token verification failed: {e}"))
                })?
            }
            JwaAlg::RS256 => {
                let verifier = JwsRs256Verifier::try_from(&jwk).map_err(|e| {
                    ConnectorRefreshError::Other(format!("RS256 verifier build failed: {e}"))
                })?;
                verifier.verify(&unverified).map_err(|e| {
                    ConnectorRefreshError::Other(format!("RS256 id_token verification failed: {e}"))
                })?
            }
            alg => {
                return Err(ConnectorRefreshError::Other(format!(
                    "unsupported id_token signing algorithm: {alg:?}"
                )));
            }
        };

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let token = exp_unverified.verify_exp(now_secs).map_err(|e| {
            ConnectorRefreshError::Other(format!("id_token expiry verification failed: {e}"))
        })?;

        serde_json::to_value(&token).map_err(|e| {
            ConnectorRefreshError::Other(format!("id_token claims serialization failed: {e}"))
        })
    }

    async fn fetch_jwks(&self, url: &Url) -> Result<JwkKeySet, ConnectorRefreshError> {
        let res = self
            .config
            .http
            .get(url.as_str())
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            return Err(ConnectorRefreshError::UpstreamRejected(
                res.status().as_u16(),
            ));
        }

        res.json::<JwkKeySet>()
            .await
            .map_err(|e| ConnectorRefreshError::Other(format!("JWKS parse failed: {e}")))
    }

    /// Call the userinfo endpoint and return its claims as JSON.
    async fn fetch_userinfo(
        &self,
        userinfo_url: &Url,
        access_token: &str,
    ) -> Result<serde_json::Value, ConnectorRefreshError> {
        let res = self
            .config
            .http
            .get(userinfo_url.as_str())
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(e.to_string()))?;

        if !res.status().is_success() {
            return Err(ConnectorRefreshError::UpstreamRejected(
                res.status().as_u16(),
            ));
        }

        res.json::<serde_json::Value>()
            .await
            .map_err(|e| ConnectorRefreshError::Other(format!("userinfo parse failed: {e}")))
    }

    /// Build `ExternalUserClaims` from a merged claims JSON object.
    fn extract_claims(
        &self,
        claims: &serde_json::Value,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        // Subject: try user_id_key override (when override_mapping or standard absent),
        // then fall back to "sub".
        let sub = self.extract_string(claims, "sub", self.config.user_id_key.as_deref())?;

        // Display name: "name" claim or user_name_key override.
        let display_name =
            self.extract_string_opt(claims, "name", self.config.user_name_key.as_deref());

        // Username hint: preferred_username first, then email local-part.
        let username_hint_raw = claims
            .get("preferred_username")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // Email.
        let email = claims
            .get("email")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let email_verified = claims
            .get("email_verified")
            .and_then(|v| v.as_bool())
            .or(self.config.skip_email_verified.then_some(true));

        let username_hint = username_hint_raw.or_else(|| {
            email
                .as_deref()
                .and_then(|e| e.split('@').next())
                .map(str::to_string)
        });

        // Groups (only when enabled).
        let groups = if self.config.enable_groups {
            self.extract_groups(claims)?
        } else {
            Vec::new()
        };

        Ok(ExternalUserClaims {
            sub,
            email,
            email_verified,
            display_name,
            username_hint,
            groups,
        })
    }

    /// Extract a required string claim. Applies override_claim_mapping logic.
    fn extract_string(
        &self,
        claims: &serde_json::Value,
        standard_key: &str,
        override_key: Option<&str>,
    ) -> Result<String, ConnectorRefreshError> {
        let value = if self.config.override_claim_mapping {
            override_key
                .and_then(|k| claims.get(k).and_then(|v| v.as_str()))
                .or_else(|| claims.get(standard_key).and_then(|v| v.as_str()))
        } else {
            claims
                .get(standard_key)
                .and_then(|v| v.as_str())
                .or_else(|| override_key.and_then(|k| claims.get(k).and_then(|v| v.as_str())))
        };

        value
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                ConnectorRefreshError::Other(format!(
                    "required claim '{standard_key}' not found in provider response"
                ))
            })
    }

    fn extract_string_opt(
        &self,
        claims: &serde_json::Value,
        standard_key: &str,
        override_key: Option<&str>,
    ) -> Option<String> {
        if self.config.override_claim_mapping {
            override_key
                .and_then(|k| claims.get(k).and_then(|v| v.as_str()))
                .or_else(|| claims.get(standard_key).and_then(|v| v.as_str()))
        } else {
            claims
                .get(standard_key)
                .and_then(|v| v.as_str())
                .or_else(|| override_key.and_then(|k| claims.get(k).and_then(|v| v.as_str())))
        }
        .filter(|s| !s.is_empty())
        .map(str::to_string)
    }

    /// Extract groups from claims using dex's exact algorithm.
    /// Handles string, []string, []object{name}, malformed (error).
    fn extract_groups(
        &self,
        claims: &serde_json::Value,
    ) -> Result<Vec<String>, ConnectorRefreshError> {
        let claim_key = &self.config.groups_key;

        let Some(raw) = claims.get(claim_key.as_str()) else {
            return Ok(Vec::new());
        };

        let mut groups = match raw {
            serde_json::Value::String(s) => vec![s.clone()],
            serde_json::Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    match item {
                        serde_json::Value::String(s) => out.push(s.clone()),
                        serde_json::Value::Object(obj) => {
                            if let Some(name) = obj.get("name").and_then(|v| v.as_str()) {
                                out.push(name.to_string());
                            }
                        }
                        _ => {
                            return Err(ConnectorRefreshError::Other(format!(
                                "malformed '{}' claim: array element is neither string nor object",
                                claim_key
                            )));
                        }
                    }
                }
                out
            }
            _ => {
                return Err(ConnectorRefreshError::Other(format!(
                    "malformed '{}' claim: expected string or array",
                    claim_key
                )));
            }
        };

        // allowed_groups filter: if configured and user has no intersection, deny.
        if !self.config.allowed_groups.is_empty() {
            let matching: Vec<String> = groups
                .iter()
                .filter(|g| self.config.allowed_groups.contains(*g))
                .cloned()
                .collect();
            if matching.is_empty() {
                return Err(ConnectorRefreshError::AccessDenied);
            }
            groups = matching;
        }

        // Apply prefix/suffix.
        if self.config.groups_prefix.is_some() || self.config.groups_suffix.is_some() {
            groups = groups
                .into_iter()
                .map(|g| {
                    let mut s = String::new();
                    if let Some(p) = &self.config.groups_prefix {
                        s.push_str(p);
                    }
                    s.push_str(&g);
                    if let Some(sfx) = &self.config.groups_suffix {
                        s.push_str(sfx);
                    }
                    s
                })
                .collect();
        }

        Ok(groups)
    }

    /// Full claim-fetch pipeline shared between login and refresh.
    async fn fetch_claims_from_token(
        &self,
        token_resp: &TokenResponse,
    ) -> Result<ExternalUserClaims, ConnectorRefreshError> {
        let mut claims: serde_json::Value = serde_json::Value::Object(Default::default());

        // 1. id_token verification (if present and JWKS URI is configured).
        if let (Some(id_token), Some(jwks_uri)) = (&token_resp.id_token, &self.config.jwks_uri) {
            let id_claims = self.verify_id_token(jwks_uri, id_token).await?;
            merge_claims(&mut claims, id_claims);
        }

        // 2. Userinfo call: always when get_user_info=true, or when no id_token.
        let need_userinfo = self.config.get_user_info
            || (token_resp.id_token.is_none() && self.config.jwks_uri.is_none());
        if need_userinfo {
            if let Some(userinfo_url) = &self.config.userinfo_endpoint {
                let ui_claims = self
                    .fetch_userinfo(userinfo_url, &token_resp.access_token)
                    .await?;
                merge_claims(&mut claims, ui_claims);
            }
        }

        if claims.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            return Err(ConnectorRefreshError::Other(
                "no claim source available (no id_token, no userinfo endpoint)".to_string(),
            ));
        }

        self.extract_claims(&claims)
    }
}

/// Merge `src` claims into `dst`. Source wins on conflict (userinfo overrides id_token).
fn merge_claims(dst: &mut serde_json::Value, src: serde_json::Value) {
    if let (Some(dst_obj), Some(src_obj)) = (dst.as_object_mut(), src.into_object()) {
        for (k, v) in src_obj {
            dst_obj.insert(k, v);
        }
    }
}

fn jwk_kid(jwk: &Jwk) -> Option<&str> {
    match jwk {
        Jwk::EC { kid, .. } => kid.as_deref(),
        Jwk::RSA { kid, .. } => kid.as_deref(),
    }
}

fn find_key_in_set<'a>(keyset: &'a JwkKeySet, token_kid: Option<&str>) -> Option<&'a Jwk> {
    keyset
        .keys
        .iter()
        .find(|jwk| match (token_kid, jwk_kid(jwk)) {
            (Some(tk), Some(jk)) => tk == jk,
            (None, _) => true,
            _ => false,
        })
}

#[async_trait]
impl RefreshableConnector for GenericOidcConnector {
    async fn refresh(
        &self,
        session_state: &[u8],
        previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        let state = GenericOidcSessionState::from_bytes(session_state)?;

        let refresh_token = state
            .refresh_token
            .as_deref()
            .ok_or(ConnectorRefreshError::TokenRevoked)?;

        let token_resp = self.exchange_refresh_token(refresh_token).await?;

        let claims = self.fetch_claims_from_token(&token_resp).await?;

        if claims.sub != previous_claims.sub {
            warn!(
                expected = %previous_claims.sub,
                got = %claims.sub,
                "generic-OIDC refresh: sub mismatch"
            );
            return Err(ConnectorRefreshError::TokenRevoked);
        }

        let new_state = GenericOidcSessionState {
            format_version: GENERIC_OIDC_SESSION_STATE_FORMAT_VERSION,
            refresh_token: token_resp.refresh_token.or(state.refresh_token),
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
        let claims = self.fetch_claims_from_token(&token_resp).await?;

        // Note: session state (refresh_token) is stored by the core session layer
        // via RefreshOutcome; at login time the core stores it from the token exchange.
        // We return only the claims here; the refresh token is extracted separately
        // and stored on the session by the provisioning path.
        // For DL29 the session state is written in the refresh path when needed.
        let _ = GenericOidcSessionState {
            format_version: GENERIC_OIDC_SESSION_STATE_FORMAT_VERSION,
            refresh_token: token_resp.refresh_token,
        };

        Ok(claims)
    }

    fn allow_jit_provisioning(&self) -> bool {
        self.config.allow_jit_provisioning
    }
}

// Helper: convert serde_json::Value into an owned Map if possible.
trait IntoObject {
    fn into_object(self) -> Option<serde_json::Map<String, serde_json::Value>>;
}

impl IntoObject for serde_json::Value {
    fn into_object(self) -> Option<serde_json::Map<String, serde_json::Value>> {
        match self {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> GenericOidcConfig {
        GenericOidcConfig {
            entry_uuid: Uuid::new_v4(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            token_endpoint: Url::parse("https://op.example.com/token").unwrap(),
            redirect_uri: Url::parse("https://idm.example.com/oauth2/callback").unwrap(),
            jwks_uri: None,
            userinfo_endpoint: None,
            enable_groups: true,
            groups_key: "groups".into(),
            skip_email_verified: false,
            allowed_groups: HashSet::new(),
            get_user_info: false,
            user_id_key: None,
            user_name_key: None,
            override_claim_mapping: false,
            groups_prefix: None,
            groups_suffix: None,
            allow_jit_provisioning: false,
            http: reqwest::Client::new(),
        }
    }

    fn connector(config: GenericOidcConfig) -> GenericOidcConnector {
        GenericOidcConnector::new(config)
    }

    // ── Session state round-trip ──────────────────────────────────────────────

    #[test]
    fn session_state_roundtrip_with_refresh_token() {
        let s = GenericOidcSessionState {
            format_version: GENERIC_OIDC_SESSION_STATE_FORMAT_VERSION,
            refresh_token: Some("rt_abc123".to_string()),
        };
        let bytes = s.to_bytes().unwrap();
        let back = GenericOidcSessionState::from_bytes(&bytes).unwrap();
        assert_eq!(back.refresh_token.as_deref(), Some("rt_abc123"));
        assert_eq!(
            back.format_version,
            GENERIC_OIDC_SESSION_STATE_FORMAT_VERSION
        );
    }

    #[test]
    fn session_state_roundtrip_no_refresh_token() {
        let s = GenericOidcSessionState {
            format_version: GENERIC_OIDC_SESSION_STATE_FORMAT_VERSION,
            refresh_token: None,
        };
        let bytes = s.to_bytes().unwrap();
        let back = GenericOidcSessionState::from_bytes(&bytes).unwrap();
        assert!(back.refresh_token.is_none());
    }

    #[test]
    fn session_state_wrong_version_returns_serialization_error() {
        let s = GenericOidcSessionState {
            format_version: 99,
            refresh_token: None,
        };
        let bytes = s.to_bytes().unwrap();
        let err = GenericOidcSessionState::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ConnectorRefreshError::Serialization(_)));
    }

    // ── Group extraction ──────────────────────────────────────────────────────

    fn claims_with_groups(value: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "sub": "u1", "groups": value })
    }

    #[test]
    fn groups_string_claim_wraps_in_vec() {
        let c = connector(make_config());
        let claims = claims_with_groups(serde_json::json!("admins"));
        let groups = c.extract_groups(&claims).unwrap();
        assert_eq!(groups, vec!["admins"]);
    }

    #[test]
    fn groups_string_array_collected() {
        let c = connector(make_config());
        let claims = claims_with_groups(serde_json::json!(["devs", "ops"]));
        let groups = c.extract_groups(&claims).unwrap();
        assert_eq!(groups, vec!["devs", "ops"]);
    }

    #[test]
    fn groups_object_array_extracts_name_field() {
        let c = connector(make_config());
        let claims = claims_with_groups(serde_json::json!([{"name": "devs"}, {"name": "ops"}]));
        let groups = c.extract_groups(&claims).unwrap();
        assert_eq!(groups, vec!["devs", "ops"]);
    }

    #[test]
    fn groups_absent_returns_empty() {
        let c = connector(make_config());
        let claims = serde_json::json!({ "sub": "u1" });
        let groups = c.extract_groups(&claims).unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn groups_malformed_type_returns_error() {
        let c = connector(make_config());
        let claims = claims_with_groups(serde_json::json!(42));
        assert!(c.extract_groups(&claims).is_err());
    }

    // ── allowed_groups filter ─────────────────────────────────────────────────

    #[test]
    fn allowed_groups_intersection_pass() {
        let mut cfg = make_config();
        cfg.allowed_groups = ["admins".to_string()].into_iter().collect();
        let c = connector(cfg);
        let claims = claims_with_groups(serde_json::json!(["admins", "devs"]));
        let groups = c.extract_groups(&claims).unwrap();
        assert_eq!(groups, vec!["admins"]);
    }

    #[test]
    fn allowed_groups_no_intersection_access_denied() {
        let mut cfg = make_config();
        cfg.allowed_groups = ["admins".to_string()].into_iter().collect();
        let c = connector(cfg);
        let claims = claims_with_groups(serde_json::json!(["devs"]));
        let err = c.extract_groups(&claims).unwrap_err();
        assert!(matches!(err, ConnectorRefreshError::AccessDenied));
    }

    // ── prefix / suffix ───────────────────────────────────────────────────────

    #[test]
    fn groups_prefix_applied() {
        let mut cfg = make_config();
        cfg.groups_prefix = Some("gh:".to_string());
        let c = connector(cfg);
        let claims = claims_with_groups(serde_json::json!(["devs"]));
        let groups = c.extract_groups(&claims).unwrap();
        assert_eq!(groups, vec!["gh:devs"]);
    }

    #[test]
    fn groups_suffix_applied() {
        let mut cfg = make_config();
        cfg.groups_suffix = Some("-team".to_string());
        let c = connector(cfg);
        let claims = claims_with_groups(serde_json::json!(["devs"]));
        let groups = c.extract_groups(&claims).unwrap();
        assert_eq!(groups, vec!["devs-team"]);
    }

    #[test]
    fn groups_prefix_and_suffix_applied() {
        let mut cfg = make_config();
        cfg.groups_prefix = Some("gh:".to_string());
        cfg.groups_suffix = Some("-team".to_string());
        let c = connector(cfg);
        let claims = claims_with_groups(serde_json::json!(["devs"]));
        let groups = c.extract_groups(&claims).unwrap();
        assert_eq!(groups, vec!["gh:devs-team"]);
    }

    // ── extract_claims ────────────────────────────────────────────────────────

    #[test]
    fn extract_claims_standard_fields() {
        let c = connector(make_config());
        let claims = serde_json::json!({
            "sub": "uid-123",
            "email": "alice@example.com",
            "email_verified": true,
            "name": "Alice",
            "preferred_username": "alice",
            "groups": ["devs"]
        });
        let ec = c.extract_claims(&claims).unwrap();
        assert_eq!(ec.sub, "uid-123");
        assert_eq!(ec.email.as_deref(), Some("alice@example.com"));
        assert_eq!(ec.email_verified, Some(true));
        assert_eq!(ec.display_name.as_deref(), Some("Alice"));
        assert_eq!(ec.username_hint.as_deref(), Some("alice"));
        assert_eq!(ec.groups, vec!["devs"]);
    }

    #[test]
    fn extract_claims_skip_email_verified_fills_true() {
        let mut cfg = make_config();
        cfg.skip_email_verified = true;
        let c = connector(cfg);
        let claims = serde_json::json!({ "sub": "u1", "email": "a@b.com" });
        let ec = c.extract_claims(&claims).unwrap();
        assert_eq!(ec.email_verified, Some(true));
    }

    #[test]
    fn extract_claims_groups_disabled_returns_empty() {
        let mut cfg = make_config();
        cfg.enable_groups = false;
        let c = connector(cfg);
        let claims = serde_json::json!({ "sub": "u1", "groups": ["devs"] });
        let ec = c.extract_claims(&claims).unwrap();
        assert!(ec.groups.is_empty());
    }

    #[test]
    fn extract_claims_missing_sub_returns_error() {
        let c = connector(make_config());
        let claims = serde_json::json!({ "email": "a@b.com" });
        assert!(c.extract_claims(&claims).is_err());
    }
}
