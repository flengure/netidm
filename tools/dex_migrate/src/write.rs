use crate::map::ProviderIdentityCreate;
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;

/// Handles writing migrated entries to a running netidm instance via its REST API.
pub struct NetidmWriter {
    base_url: String,
    client: reqwest::Client,
    token: String,
}

impl NetidmWriter {
    pub fn new(base_url: &str, token: &str) -> Self {
        let client = reqwest::Client::builder()
            .build()
            .expect("Failed to build reqwest client");

        NetidmWriter {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            token: token.to_string(),
        }
    }

    /// Create a `ProviderIdentity` entry in netidm via `POST /v1/raw/create`.
    ///
    /// The `ProviderIdentity` entry will have its `ProviderIdentityUserUuid`
    /// set to the migrated `user_id_str` (the upstream user ID) as a placeholder
    /// until the administrator maps these entries to real netidm Person UUIDs.
    pub async fn create_provider_identity(&self, pi: &ProviderIdentityCreate) -> Result<()> {
        let url = format!("{}/v1/raw/create", self.base_url);

        // Build the entry attributes map (netidm proto Entry format).
        let mut attrs: BTreeMap<String, Vec<String>> = BTreeMap::new();

        attrs.insert(
            "class".to_string(),
            vec!["object".to_string(), "provideridentity".to_string()],
        );
        attrs.insert("name".to_string(), vec![pi.name.clone()]);
        attrs.insert(
            "provideridentityuseruuid".to_string(),
            vec![pi.user_id_str.clone()],
        );
        attrs.insert(
            "provideridentityconnectorid".to_string(),
            vec![pi.connector_id.clone()],
        );
        attrs.insert(
            "provideridentityclaimsuserid".to_string(),
            vec![pi.claims_user_id.clone()],
        );

        if let Some(ref username) = pi.claims_username {
            attrs.insert(
                "provideridentityclaimsusername".to_string(),
                vec![username.clone()],
            );
        }

        if let Some(ref email) = pi.claims_email {
            attrs.insert(
                "provideridentityclaimsemail".to_string(),
                vec![email.clone()],
            );
        }

        if let Some(ev) = pi.claims_email_verified {
            attrs.insert(
                "provideridentityclaimsemailverified".to_string(),
                vec![ev.to_string()],
            );
        }

        if !pi.claims_groups.is_empty() {
            attrs.insert(
                "provideridentityclaimsgroups".to_string(),
                pi.claims_groups.clone(),
            );
        }

        attrs.insert(
            "provideridentitycreatedat".to_string(),
            vec![pi.created_at.clone()],
        );
        attrs.insert(
            "provideridentitylastlogin".to_string(),
            vec![pi.last_login.clone()],
        );

        // Wrap in the proto CreateRequest format.
        let body = serde_json::json!({
            "entries": [{ "attrs": attrs }]
        });

        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("HTTP request to {url} failed"))?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            bail!(
                "netidm returned HTTP {} for entry '{}': {}",
                status,
                pi.name,
                text
            );
        }

        Ok(())
    }
}
