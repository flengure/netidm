use super::{CredState, BAD_AUTH_TYPE_MSG, BAD_OAUTH2_CSRF_STATE_MSG};
use crate::idm::account::OAuth2AccountCredential;
use crate::idm::authentication::{AuthCredential, AuthExternal};
use crate::idm::oauth2::PkceS256Secret;
use crate::idm::oauth2_client::OAuth2ClientProvider;
use crate::prelude::*;
use crate::utils;
use crate::value::{AuthType, SessionExtMetadata};
use base64::{engine::general_purpose, Engine as _};
use netidm_proto::oauth2::{
    AccessTokenRequest, AccessTokenResponse, AuthorisationRequest, AuthorisationRequestOidc,
    GrantTypeReq, ResponseType,
};
use serde_json;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Identity claims extracted from an external OAuth2/OIDC provider after token exchange.
#[derive(Debug, Clone)]
pub struct ExternalUserClaims {
    /// Stable, provider-assigned subject identifier (required).
    pub sub: String,
    /// User's email address, if provided by the provider.
    pub email: Option<String>,
    /// Whether the email has been verified by the provider.
    pub email_verified: Option<bool>,
    /// User's display name from the provider (e.g. `name` claim).
    pub display_name: Option<String>,
    /// Username hint for account creation (e.g. GitHub `login`, Google email local-part).
    pub username_hint: Option<String>,
}

pub struct CredHandlerOAuth2Client {
    // For logging - this is the trust provider we are using.
    provider_id: Uuid,
    provider_name: String,

    // The users ID as the remote trust provider knows them.
    user_id: String,
    user_cred_id: Uuid,

    request_scopes: BTreeSet<String>,
    client_id: String,
    client_basic_secret: String,
    client_redirect_url: Url,
    authorisation_endpoint: Url,
    token_endpoint: Url,
    pkce_secret: PkceS256Secret,
    csrf_state: String,
    userinfo_endpoint: Option<Url>,
    jit_provisioning: bool,
    email_link_accounts: bool,
    claim_map: BTreeMap<Attribute, String>,
}

impl fmt::Debug for CredHandlerOAuth2Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredHandlerOauth2Trust")
            .field("provider_id", &self.provider_id)
            .field("provider_name", &self.provider_name)
            .field("user_id", &self.user_id)
            .field("client_id", &self.client_id)
            .field("authorisation_endpoint", &self.authorisation_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .finish()
    }
}

impl CredHandlerOAuth2Client {
    pub fn new(
        client_provider: &OAuth2ClientProvider,
        client_user_cred: &OAuth2AccountCredential,
    ) -> Self {
        let pkce_secret = PkceS256Secret::default();
        let csrf_state = utils::password_from_random();

        CredHandlerOAuth2Client {
            provider_id: client_provider.uuid,
            provider_name: client_provider.name.clone(),
            request_scopes: client_provider.request_scopes.clone(),
            user_id: client_user_cred.user_id.to_string(),
            user_cred_id: client_user_cred.cred_id,
            client_id: client_provider.client_id.clone(),
            client_basic_secret: client_provider.client_basic_secret.clone(),
            client_redirect_url: client_provider.client_redirect_uri.clone(),
            authorisation_endpoint: client_provider.authorisation_endpoint.clone(),
            token_endpoint: client_provider.token_endpoint.clone(),
            pkce_secret,
            csrf_state,
            userinfo_endpoint: client_provider.userinfo_endpoint.clone(),
            jit_provisioning: client_provider.jit_provisioning,
            email_link_accounts: client_provider.email_link_accounts,
            claim_map: client_provider.claim_map.clone(),
        }
    }

    pub fn start_auth_request(&self) -> (Url, AuthorisationRequest) {
        let pkce_request = self.pkce_secret.to_request();

        (
            self.authorisation_endpoint.clone(),
            AuthorisationRequest {
                redirect_uri: self.client_redirect_url.clone(),
                response_type: ResponseType::Code,
                response_mode: None,
                client_id: self.client_id.clone(),
                state: Some(self.csrf_state.clone()),
                pkce_request: Some(pkce_request),
                scope: self.request_scopes.clone(),
                nonce: None,
                oidc_ext: AuthorisationRequestOidc {
                    login_hint: Some(self.user_id.clone()),
                    ..Default::default()
                },
                max_age: None,
                prompt: Vec::new(),
                unknown_keys: Default::default(),
            },
        )
    }

    pub(super) fn validate(&self, cred: &AuthCredential, current_time: Duration) -> CredState {
        match cred {
            AuthCredential::OAuth2AuthorisationResponse { code, state } => {
                self.validate_authorisation_response(code, state.as_deref())
            }
            AuthCredential::OAuth2AccessTokenResponse { response } => {
                self.validate_access_token_response(response, current_time)
            }
            AuthCredential::OAuth2UserinfoResponse { body } => {
                self.validate_userinfo_response(body, current_time)
            }
            _ => CredState::Denied(BAD_AUTH_TYPE_MSG),
        }
    }

    fn validate_authorisation_response(&self, code: &str, state: Option<&str>) -> CredState {
        // Validate our csrf state

        let csrf_valid = state.map(|s| s == self.csrf_state).unwrap_or_default();

        if !csrf_valid {
            return CredState::Denied(BAD_OAUTH2_CSRF_STATE_MSG);
        }

        let code_verifier = Some(self.pkce_secret.verifier().to_string());

        let grant_type_req = GrantTypeReq::AuthorizationCode {
            code: code.into(),
            redirect_uri: self.client_redirect_url.clone(),
            code_verifier,
        };

        let request = AccessTokenRequest::from(grant_type_req);

        CredState::External(AuthExternal::OAuth2AccessTokenRequest {
            token_url: self.token_endpoint.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_basic_secret.clone(),
            request,
        })
    }

    fn validate_access_token_response(
        &self,
        response: &AccessTokenResponse,
        current_time: Duration,
    ) -> CredState {
        let cred_id = self.user_cred_id;
        let access_expires_at = current_time + Duration::from_secs(response.expires_in as u64);

        let ext_session_metadata = SessionExtMetadata::OAuth2 {
            access_token: response.access_token.clone(),
            refresh_token: response.refresh_token.clone(),
            access_expires_at,
        };

        if self.jit_provisioning {
            if response.id_token.is_none() {
                if let Some(ref userinfo_url) = self.userinfo_endpoint {
                    return CredState::External(AuthExternal::OAuth2UserinfoRequest {
                        userinfo_url: userinfo_url.clone(),
                        access_token: response.access_token.clone(),
                    });
                }
            }
            if let Some(claims) = self.extract_claims(response) {
                return CredState::ProvisioningRequired {
                    provider_uuid: self.provider_id,
                    claims,
                    email_link_accounts: self.email_link_accounts,
                };
            }
            warn!(
                provider_id = ?self.provider_id,
                "jit_provisioning is enabled but no claims could be extracted from the token response"
            );
        }

        CredState::Success {
            auth_type: AuthType::OAuth2Trust,
            cred_id,
            ext_session_metadata,
        }
    }

    fn validate_userinfo_response(
        &self,
        body: &serde_json::Value,
        _current_time: Duration,
    ) -> CredState {
        let claims = Self::claims_from_userinfo_json(body, &self.claim_map);
        match claims {
            Some(claims) => CredState::ProvisioningRequired {
                provider_uuid: self.provider_id,
                claims,
                email_link_accounts: self.email_link_accounts,
            },
            None => {
                warn!(
                    provider_id = ?self.provider_id,
                    "Could not extract required claims from userinfo response"
                );
                CredState::Denied("Failed to extract identity claims from provider")
            }
        }
    }

    /// Extract claims from a userinfo JSON body (GitHub, non-OIDC providers).
    /// The `id` field is used as `sub` (numeric ID → string); `login` as `username_hint`.
    fn claims_from_userinfo_json(
        json: &serde_json::Value,
        claim_map: &BTreeMap<Attribute, String>,
    ) -> Option<ExternalUserClaims> {
        let sub = json.get("id").and_then(|v| {
            v.as_i64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(str::to_string))
        })?;

        let email_claim = claim_map
            .get(&Attribute::Mail)
            .map(String::as_str)
            .unwrap_or("email");
        let email = json
            .get(email_claim)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let display_name_claim = claim_map
            .get(&Attribute::DisplayName)
            .map(String::as_str)
            .unwrap_or("name");
        let display_name = json
            .get(display_name_claim)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let username_hint = json
            .get("login")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                email
                    .as_deref()
                    .and_then(|e| e.split('@').next())
                    .map(str::to_string)
            });

        Some(ExternalUserClaims {
            sub,
            email,
            email_verified: None,
            display_name,
            username_hint,
        })
    }

    /// Extract user identity claims from an access token response.
    /// Tries the id_token JWT first (OIDC providers such as Google).  For
    /// non-OIDC providers (e.g. GitHub), returns None — the caller must issue a
    /// separate userinfo request to `userinfo_endpoint` using the access token.
    fn extract_claims(&self, response: &AccessTokenResponse) -> Option<ExternalUserClaims> {
        if let Some(id_token) = &response.id_token {
            if let Some(claims) = Self::claims_from_id_token(id_token, &self.claim_map) {
                return Some(claims);
            }
        }
        if self.userinfo_endpoint.is_some() {
            trace!(
                provider_id = ?self.provider_id,
                "No id_token present; userinfo endpoint available for follow-up fetch"
            );
        }
        None
    }

    /// Decode an OIDC id_token JWT without verifying the signature and extract
    /// identity claims.  The token was received directly from the token endpoint
    /// over a TLS channel, so we trust the payload without re-verifying the
    /// signature here.
    fn claims_from_id_token(
        id_token: &str,
        claim_map: &BTreeMap<Attribute, String>,
    ) -> Option<ExternalUserClaims> {
        let mut parts = id_token.splitn(3, '.');
        let _header = parts.next();
        let Some(payload_b64) = parts.next() else {
            warn!("id_token has fewer than 2 '.' separated parts");
            return None;
        };
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .or_else(|_| general_purpose::URL_SAFE.decode(payload_b64))
            .map_err(|e| {
                warn!(?e, "Failed to base64-decode id_token payload");
            })
            .ok()?;

        let json: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| {
                warn!(?e, "Failed to parse id_token payload as JSON");
            })
            .ok()?;

        let sub = json
            .get(
                claim_map
                    .get(&Attribute::Name)
                    .map(String::as_str)
                    .unwrap_or("sub"),
            )
            .or_else(|| json.get("sub"))
            .and_then(|v| v.as_str())
            .map(str::to_string)?;

        let email_claim = claim_map
            .get(&Attribute::Mail)
            .map(String::as_str)
            .unwrap_or("email");
        let email = json
            .get(email_claim)
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let email_verified = json.get("email_verified").and_then(|v| v.as_bool());

        let display_name_claim = claim_map
            .get(&Attribute::DisplayName)
            .map(String::as_str)
            .unwrap_or("name");
        let display_name = json
            .get(display_name_claim)
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let username_hint = email
            .as_deref()
            .and_then(|e| e.split('@').next())
            .map(str::to_string);

        Some(ExternalUserClaims {
            sub,
            email,
            email_verified,
            display_name,
            username_hint,
        })
    }
}
