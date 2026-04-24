//! Authproxy upstream connector (DL38).
//!
//! Trusts identity headers set by a reverse proxy (e.g. nginx auth_request,
//! oauth2-proxy, Vouch). The `connector_authproxy_user_header` attribute
//! names the required header carrying the authenticated username. Optional
//! headers carry the user's email and a comma-separated list of group names.
//!
//! This is a direct-identity connector: there is no OAuth2 redirect. When the
//! login handler detects `ProviderKind::AuthProxy`, it calls
//! `AuthProxyConfig::claims_from_headers()` directly, bypassing the normal
//! code-exchange flow.
//!
//! Sessions issued for authproxy users do not carry a refresh token; the
//! `RefreshableConnector::refresh()` implementation returns `TokenRevoked`
//! immediately, forcing re-authentication when the session expires. The
//! operator controls session lifetime via the standard netidm session TTL.

use crate::idm::authsession::handler_connector::ExternalUserClaims;
use crate::idm::connector::traits::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use http::HeaderMap;
use uuid::Uuid;

/// Parsed authproxy connector configuration.
#[derive(Debug, Clone)]
pub struct AuthProxyConfig {
    pub entry_uuid: Uuid,
    /// Name of the HTTP request header that carries the authenticated username,
    /// e.g. `X-Remote-User`. This header is required; its absence is an error.
    pub user_header: String,
    /// Optional header carrying the user's email address.
    pub email_header: Option<String>,
    /// Optional header carrying a comma-separated list of group names.
    pub groups_header: Option<String>,
}

impl AuthProxyConfig {
    pub fn from_entry(
        entry: &crate::entry::Entry<crate::entry::EntrySealed, crate::entry::EntryCommitted>,
    ) -> Result<Self, OperationError> {
        let entry_uuid = entry.get_uuid();

        let user_header = entry
            .get_ava_single_utf8(Attribute::ConnectorAuthproxyUserHeader)
            .ok_or_else(|| {
                error!(
                    ?entry_uuid,
                    "Authproxy connector entry missing \
                     connector_authproxy_user_header"
                );
                OperationError::InvalidEntryState
            })?
            .to_string();

        let email_header = entry
            .get_ava_single_utf8(Attribute::ConnectorAuthproxyEmailHeader)
            .map(str::to_string);

        let groups_header = entry
            .get_ava_single_utf8(Attribute::ConnectorAuthproxyGroupsHeader)
            .map(str::to_string);

        Ok(AuthProxyConfig {
            entry_uuid,
            user_header,
            email_header,
            groups_header,
        })
    }

    /// Extract `ExternalUserClaims` from the HTTP request headers.
    ///
    /// Returns `Err(OperationError::AccessDenied)` when the required
    /// user header is absent or empty. This surfaces as a login failure
    /// with no further information leaked to the browser.
    pub fn claims_from_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<ExternalUserClaims, OperationError> {
        let username = headers
            .get(self.user_header.as_str())
            .and_then(|v: &http::HeaderValue| v.to_str().ok())
            .map(str::trim)
            .filter(|s: &&str| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                warn!(
                    entry_uuid = ?self.entry_uuid,
                    header = %self.user_header,
                    "Authproxy connector: required user header absent or empty"
                );
                OperationError::AccessDenied
            })?;

        let email = self
            .email_header
            .as_deref()
            .and_then(|h: &str| headers.get(h))
            .and_then(|v: &http::HeaderValue| v.to_str().ok())
            .map(str::trim)
            .filter(|s: &&str| !s.is_empty())
            .map(str::to_string);

        let groups: Vec<String> = self
            .groups_header
            .as_deref()
            .and_then(|h: &str| headers.get(h))
            .and_then(|v: &http::HeaderValue| v.to_str().ok())
            .map(|s: &str| {
                s.split(',')
                    .map(str::trim)
                    .filter(|g: &&str| !g.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Ok(ExternalUserClaims {
            sub: username.clone(),
            email,
            email_verified: None,
            display_name: None,
            username_hint: Some(username),
            groups,
        })
    }
}

/// `AuthProxyConnector` implements `RefreshableConnector` so it can be
/// registered in the `ConnectorRegistry`. Neither `fetch_callback_claims`
/// nor `refresh` are reachable through the normal OAuth2 code-exchange path;
/// claims are extracted in the login handler via `AuthProxyConfig::claims_from_headers`.
pub struct AuthProxyConnector {
    pub config: AuthProxyConfig,
}

impl AuthProxyConnector {
    pub fn new(config: AuthProxyConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl RefreshableConnector for AuthProxyConnector {
    async fn refresh(
        &self,
        _session_state: &[u8],
        _previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        // Authproxy sessions have no upstream refresh token.
        // Force re-authentication when the session expires.
        Err(ConnectorRefreshError::TokenRevoked)
    }

    fn claims_from_request_headers(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<ExternalUserClaims, OperationError> {
        self.config.claims_from_headers(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    fn test_config() -> AuthProxyConfig {
        AuthProxyConfig {
            entry_uuid: Uuid::new_v4(),
            user_header: "x-remote-user".to_string(),
            email_header: Some("x-remote-email".to_string()),
            groups_header: Some("x-remote-groups".to_string()),
        }
    }

    #[test]
    fn test_claims_from_headers_all_fields() {
        let config = test_config();
        let headers = make_headers(&[
            ("x-remote-user", "alice"),
            ("x-remote-email", "alice@example.com"),
            ("x-remote-groups", "admins, developers, sre"),
        ]);

        let claims = config.claims_from_headers(&headers).expect("claims ok");
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(claims.username_hint.as_deref(), Some("alice"));
        assert_eq!(
            claims.groups,
            vec!["admins", "developers", "sre"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_claims_from_headers_no_optional() {
        let mut config = test_config();
        config.email_header = None;
        config.groups_header = None;
        let headers = make_headers(&[("x-remote-user", "bob")]);

        let claims = config.claims_from_headers(&headers).expect("claims ok");
        assert_eq!(claims.sub, "bob");
        assert!(claims.email.is_none());
        assert!(claims.groups.is_empty());
    }

    #[test]
    fn test_claims_from_headers_missing_user_header() {
        let config = test_config();
        let headers = make_headers(&[("x-remote-email", "carol@example.com")]);

        let result = config.claims_from_headers(&headers);
        assert!(
            matches!(result, Err(OperationError::AccessDenied)),
            "expected AccessDenied, got: {result:?}"
        );
    }

    #[test]
    fn test_claims_from_headers_empty_user_header() {
        let config = test_config();
        let headers = make_headers(&[("x-remote-user", "  ")]);

        let result = config.claims_from_headers(&headers);
        assert!(matches!(result, Err(OperationError::AccessDenied)));
    }

    #[test]
    fn test_claims_from_headers_groups_trimmed() {
        let config = test_config();
        let headers = make_headers(&[
            ("x-remote-user", "dave"),
            ("x-remote-groups", " group-a , group-b ,  "),
        ]);

        let claims = config.claims_from_headers(&headers).expect("claims ok");
        assert_eq!(
            claims.groups,
            vec!["group-a", "group-b"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }
}
