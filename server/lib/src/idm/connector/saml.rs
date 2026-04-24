//! SAML 2.0 upstream connector (PR-CONNECTOR-SAML, DL33).
//!
//! Implements [`RefreshableConnector`] for SAML-federated sessions.
//!
//! Unlike OAuth2/OIDC connectors, SAML has no refresh endpoint — the IdP
//! cannot be called without initiating a new browser redirect. Following
//! dex's `connector/saml/saml.go` `Refresh()` implementation exactly,
//! this connector is **cache-based**: the claims from the initial assertion
//! are persisted as `SamlCachedState` and restored verbatim on every
//! downstream refresh, keeping the user's group memberships alive for the
//! lifetime of their `Oauth2Session`.
//!
//! [`RefreshableConnector`]: crate::idm::connector::traits::RefreshableConnector

use crate::idm::authsession::handler_connector::ExternalUserClaims;
use crate::idm::connector::traits::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ── Cached state ──────────────────────────────────────────────────────────────

/// Claims snapshot persisted in `upstream_refresh_state` at assertion time.
/// Mirrors dex's `cachedIdentity` struct in `connector/saml/saml.go`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlCachedState {
    pub name_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
}

impl SamlCachedState {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ConnectorRefreshError> {
        serde_json::to_vec(self).map_err(|e| {
            ConnectorRefreshError::Serialization(format!(
                "failed to serialize SamlCachedState: {e}"
            ))
        })
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, ConnectorRefreshError> {
        serde_json::from_slice(b).map_err(|e| {
            ConnectorRefreshError::Serialization(format!(
                "failed to deserialize SamlCachedState: {e}"
            ))
        })
    }
}

// ── Connector struct ──────────────────────────────────────────────────────────

pub struct SamlConnector {
    pub provider_uuid: Uuid,
    pub jit_provisioning: bool,
}

// ── RefreshableConnector impl ─────────────────────────────────────────────────

#[async_trait]
impl RefreshableConnector for SamlConnector {
    async fn refresh(
        &self,
        session_state: &[u8],
        _previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        let state = SamlCachedState::from_bytes(session_state)?;

        Ok(RefreshOutcome {
            claims: ExternalUserClaims {
                sub: state.name_id,
                email: state.email,
                email_verified: Some(true),
                display_name: state.display_name,
                username_hint: None,
                groups: state.groups,
            },
            new_session_state: None,
        })
    }

    fn allow_jit_provisioning(&self) -> bool {
        self.jit_provisioning
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saml_cached_state_round_trip() {
        let state = SamlCachedState {
            name_id: "alice@example.com".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: Some("Alice".to_string()),
            groups: vec!["admin".to_string(), "ops".to_string()],
        };
        let bytes = state.to_bytes().unwrap();
        let back = SamlCachedState::from_bytes(&bytes).unwrap();
        assert_eq!(back.name_id, state.name_id);
        assert_eq!(back.email, state.email);
        assert_eq!(back.display_name, state.display_name);
        assert_eq!(back.groups, state.groups);
    }

    #[tokio::test]
    async fn saml_connector_refresh_restores_cached_state() {
        let state = SamlCachedState {
            name_id: "uid=alice,dc=example,dc=com".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: Some("Alice".to_string()),
            groups: vec!["admin".to_string()],
        };
        let bytes = state.to_bytes().unwrap();

        let connector = SamlConnector {
            provider_uuid: uuid::uuid!("00000000-0000-0000-0000-000000000001"),
            jit_provisioning: false,
        };

        let prev = ExternalUserClaims {
            sub: String::new(),
            email: None,
            email_verified: None,
            display_name: None,
            username_hint: None,
            groups: Vec::new(),
        };

        let outcome = connector.refresh(&bytes, &prev).await.unwrap();
        assert_eq!(outcome.claims.sub, "uid=alice,dc=example,dc=com");
        assert_eq!(outcome.claims.email.as_deref(), Some("alice@example.com"));
        assert_eq!(outcome.claims.groups, vec!["admin"]);
        assert!(outcome.new_session_state.is_none());
    }
}
