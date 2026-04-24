//! Provider-initiated OAuth2 session for SSO-first login flow.
//!
//! This module provides a lightweight session type used when a user initiates login by clicking
//! an SSO provider button on the login page (before any username is entered). The session holds
//! the provider config and PKCE/CSRF state needed to construct the authorization redirect and
//! validate the subsequent callback.

use crate::idm::authentication::{AuthCredential, AuthExternal, AuthState};
use crate::idm::authsession::handler_connector::ExternalUserClaims;
use crate::idm::connector::{ConnectorProvider, ProviderKind};
use crate::idm::oauth2::PkceS256Secret;
use crate::prelude::*;
use crate::utils;
use netidm_proto::oauth2::{
    AccessTokenRequest, AccessTokenResponse, AuthorisationRequest, AuthorisationRequestOidc,
    GrantTypeReq, ResponseType,
};
use netidm_proto::v1::AuthIssueSession;
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::time::Duration;

const BAD_CSRF_STATE_MSG: &str = "OAuth2 CSRF state mismatch";

/// Tracks the exchange stage for an in-flight provider-initiated session.
#[allow(clippy::enum_variant_names)]
pub(crate) enum ProviderSessionState {
    /// Waiting for the user to return from the provider with a code.
    AwaitingCode,
    /// Code received; `OAuth2AccessTokenResponse` is expected next from the view loop.
    AwaitingToken,
    /// Access token received; userinfo response is expected next from the view loop.
    AwaitingUserinfo,
}

/// A lightweight OAuth2 session created by the SSO-first provider button flow.
///
/// Unlike a full `AuthSession`, this session has no pre-bound user account. The account is
/// resolved from the provider's identity claims after the OAuth2 exchange completes.
pub(crate) struct ProviderInitiatedSession {
    pub(crate) provider_uuid: Uuid,
    provider_name: String,
    pkce_secret: PkceS256Secret,
    csrf_state: String,
    request_scopes: BTreeSet<String>,
    client_id: String,
    client_basic_secret: String,
    client_redirect_url: Url,
    authorisation_endpoint: Url,
    token_endpoint: Url,
    userinfo_endpoint: Option<Url>,
    pub(crate) _issue: AuthIssueSession,
    pub(crate) jit_provisioning: bool,
    pub(crate) email_link_accounts: bool,
    pub(crate) state: ProviderSessionState,
    provider_kind: ProviderKind,
}

impl ProviderInitiatedSession {
    /// Create a new provider-initiated session from a configured provider.
    pub(crate) fn new(provider: &ConnectorProvider, issue: AuthIssueSession) -> Self {
        let pkce_secret = PkceS256Secret::default();
        let csrf_state = utils::password_from_random();
        ProviderInitiatedSession {
            provider_uuid: provider.uuid,
            provider_name: provider.name.clone(),
            pkce_secret,
            csrf_state,
            request_scopes: provider.request_scopes.clone(),
            client_id: provider.client_id.clone(),
            client_basic_secret: provider.client_basic_secret.clone(),
            client_redirect_url: provider.client_redirect_uri.clone(),
            authorisation_endpoint: provider.authorisation_endpoint.clone(),
            token_endpoint: provider.token_endpoint.clone(),
            userinfo_endpoint: provider.userinfo_endpoint.clone(),
            _issue: issue,
            jit_provisioning: provider.jit_provisioning,
            email_link_accounts: provider.email_link_accounts,
            state: ProviderSessionState::AwaitingCode,
            provider_kind: provider.provider_kind,
        }
    }

    /// Build the authorization redirect URL and request parameters.
    pub(crate) fn start_auth_request(&self) -> (Url, AuthorisationRequest) {
        // Non-OIDC connectors (GitHub, LinkedIn, …) handle their own token exchange
        // without PKCE. Skip the code_challenge for those to avoid a 400 from the
        // upstream token endpoint.
        let pkce = if matches!(
            self.provider_kind,
            ProviderKind::Github
                | ProviderKind::LinkedIn
                | ProviderKind::OpenShift
                | ProviderKind::GitLab
                | ProviderKind::Bitbucket
        ) {
            None
        } else {
            Some(self.pkce_secret.to_request())
        };
        let request = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: self.client_id.clone(),
            state: Some(self.csrf_state.clone()),
            pkce_request: pkce,
            redirect_uri: self.client_redirect_url.clone(),
            scope: self.request_scopes.clone(),
            nonce: None,
            oidc_ext: AuthorisationRequestOidc {
                ..Default::default()
            },
            max_age: None,
            prompt: Vec::new(),
            unknown_keys: Default::default(),
        };
        (self.authorisation_endpoint.clone(), request)
    }

    /// Process an incoming OAuth2 credential step for this provider-initiated session.
    ///
    /// Returns the next `AuthState` to drive the view layer's exchange loop.
    pub(crate) fn validate(&mut self, cred: &AuthCredential, _current_time: Duration) -> AuthState {
        match &self.state {
            ProviderSessionState::AwaitingCode => match cred {
                AuthCredential::OAuth2AuthorisationResponse { code, state } => {
                    let csrf_valid = state
                        .as_deref()
                        .map(|s| s == self.csrf_state)
                        .unwrap_or(false);
                    if !csrf_valid {
                        return AuthState::Denied(BAD_CSRF_STATE_MSG.to_string());
                    }
                    if matches!(
                        self.provider_kind,
                        ProviderKind::Github
                            | ProviderKind::LinkedIn
                            | ProviderKind::OpenShift
                            | ProviderKind::GitLab
                    ) {
                        return AuthState::External(AuthExternal::GitHubCallbackRequest {
                            code: code.clone(),
                            provider_uuid: self.provider_uuid,
                            email_link_accounts: self.email_link_accounts,
                        });
                    }
                    let code_verifier = self.pkce_secret.verifier().to_string();
                    let grant = GrantTypeReq::AuthorizationCode {
                        code: code.clone(),
                        redirect_uri: self.client_redirect_url.clone(),
                        code_verifier: Some(code_verifier.clone()),
                    };
                    let request = AccessTokenRequest::from(grant);
                    self.state = ProviderSessionState::AwaitingToken;
                    AuthState::External(
                        crate::idm::authentication::AuthExternal::OAuth2AccessTokenRequest {
                            token_url: self.token_endpoint.clone(),
                            client_id: self.client_id.clone(),
                            client_secret: self.client_basic_secret.clone(),
                            request,
                        },
                    )
                }
                _ => {
                    AuthState::Denied("unexpected credential type in provider session".to_string())
                }
            },
            ProviderSessionState::AwaitingToken => match cred {
                AuthCredential::OAuth2AccessTokenResponse { response } => {
                    self.process_token_response(response, _current_time)
                }
                _ => {
                    AuthState::Denied("unexpected credential type in provider session".to_string())
                }
            },
            ProviderSessionState::AwaitingUserinfo => match cred {
                AuthCredential::OAuth2UserinfoResponse { body } => {
                    self.process_userinfo_response(body)
                }
                _ => {
                    AuthState::Denied("unexpected credential type in provider session".to_string())
                }
            },
        }
    }

    fn process_token_response(
        &mut self,
        response: &AccessTokenResponse,
        _current_time: Duration,
    ) -> AuthState {
        if self.jit_provisioning && response.id_token.is_none() {
            if let Some(ref userinfo_url) = self.userinfo_endpoint {
                self.state = ProviderSessionState::AwaitingUserinfo;
                return AuthState::External(AuthExternal::OAuth2UserinfoRequest {
                    userinfo_url: userinfo_url.clone(),
                    access_token: response.access_token.clone(),
                });
            }
        }

        let claims = self.extract_claims_from_response(response);
        self.build_provisioning_state(claims)
    }

    fn process_userinfo_response(&self, body: &JsonValue) -> AuthState {
        let claims = self.extract_claims_from_userinfo(body);
        self.build_provisioning_state(claims)
    }

    fn build_provisioning_state(&self, claims: Option<ExternalUserClaims>) -> AuthState {
        match claims {
            Some(claims) => AuthState::ProvisioningRequired {
                provider_uuid: self.provider_uuid,
                claims,
                email_link_accounts: self.email_link_accounts,
            },
            None => {
                warn!(
                    provider = %self.provider_name,
                    "provider-initiated session: no identity claims extracted from provider response"
                );
                AuthState::Denied(
                    "No identity claims returned by provider — cannot identify account".to_string(),
                )
            }
        }
    }

    fn extract_claims_from_response(
        &self,
        response: &AccessTokenResponse,
    ) -> Option<ExternalUserClaims> {
        use base64::{engine::general_purpose, Engine as _};

        // Try id_token first (OIDC providers)
        if let Some(ref id_token) = response.id_token {
            let parts: Vec<&str> = id_token.splitn(3, '.').collect();
            if let Some(payload_b64) = parts.get(1) {
                if let Ok(payload) = general_purpose::URL_SAFE_NO_PAD.decode(payload_b64) {
                    if let Ok(claims_val) = serde_json::from_slice::<JsonValue>(&payload) {
                        return self.claims_from_json(&claims_val);
                    }
                }
            }
        }
        // Fallback: use access token body if it contains claims (non-standard)
        None
    }

    fn extract_claims_from_userinfo(&self, body: &JsonValue) -> Option<ExternalUserClaims> {
        self.claims_from_json(body)
    }

    fn claims_from_json(&self, v: &JsonValue) -> Option<ExternalUserClaims> {
        let sub = v.get("sub").and_then(|s| s.as_str()).map(str::to_string)?;
        Some(ExternalUserClaims {
            sub,
            email: v.get("email").and_then(|s| s.as_str()).map(str::to_string),
            email_verified: v.get("email_verified").and_then(|b| b.as_bool()),
            display_name: v.get("name").and_then(|s| s.as_str()).map(str::to_string),
            username_hint: v
                .get("login")
                .or_else(|| v.get("preferred_username"))
                .and_then(|s| s.as_str())
                .map(str::to_string),
            groups: Vec::new(),
        })
    }
}
