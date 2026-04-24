use crate::{ClientError, NetidmClient};
use netidm_proto::constants::{ATTR_DISPLAYNAME, ATTR_NAME, ATTR_SAML_GROUP_MAPPING};
use netidm_proto::v1::Entry;
use uuid::Uuid;

pub struct SamlClientConfig<'a> {
    pub name: &'a str,
    pub display_name: &'a str,
    pub idp_sso_url: &'a str,
    pub idp_certificate: &'a str,
    pub entity_id: &'a str,
    pub acs_url: &'a str,
    pub name_id_format: Option<&'a str>,
    pub email_attr: Option<&'a str>,
    pub displayname_attr: Option<&'a str>,
    pub groups_attr: Option<&'a str>,
    pub jit_provisioning: bool,
    pub sso_issuer: Option<&'a str>,
    pub groups_delim: Option<&'a str>,
    pub insecure_skip_sig_validation: bool,
    pub filter_groups: bool,
}

impl NetidmClient {
    #[instrument(level = "debug")]
    pub async fn idm_saml_client_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/saml_client").await
    }

    pub async fn idm_saml_client_create(
        &self,
        cfg: SamlClientConfig<'_>,
    ) -> Result<(), ClientError> {
        let mut new_entry = Entry::default();
        new_entry
            .attrs
            .insert(ATTR_NAME.to_string(), vec![cfg.name.to_string()]);
        new_entry.attrs.insert(
            ATTR_DISPLAYNAME.to_string(),
            vec![cfg.display_name.to_string()],
        );
        new_entry.attrs.insert(
            "saml_idp_sso_url".to_string(),
            vec![cfg.idp_sso_url.to_string()],
        );
        new_entry.attrs.insert(
            "saml_idp_certificate".to_string(),
            vec![cfg.idp_certificate.to_string()],
        );
        new_entry.attrs.insert(
            "saml_entity_id".to_string(),
            vec![cfg.entity_id.to_string()],
        );
        new_entry
            .attrs
            .insert("saml_acs_url".to_string(), vec![cfg.acs_url.to_string()]);
        if let Some(fmt) = cfg.name_id_format {
            new_entry
                .attrs
                .insert("saml_name_id_format".to_string(), vec![fmt.to_string()]);
        }
        if let Some(attr) = cfg.email_attr {
            new_entry
                .attrs
                .insert("saml_attr_map_email".to_string(), vec![attr.to_string()]);
        }
        if let Some(attr) = cfg.displayname_attr {
            new_entry.attrs.insert(
                "saml_attr_map_displayname".to_string(),
                vec![attr.to_string()],
            );
        }
        if let Some(attr) = cfg.groups_attr {
            new_entry
                .attrs
                .insert("saml_attr_map_groups".to_string(), vec![attr.to_string()]);
        }
        if cfg.jit_provisioning {
            new_entry.attrs.insert(
                "saml_jit_provisioning".to_string(),
                vec!["true".to_string()],
            );
        }
        if let Some(issuer) = cfg.sso_issuer {
            new_entry
                .attrs
                .insert("saml_sso_issuer".to_string(), vec![issuer.to_string()]);
        }
        if let Some(delim) = cfg.groups_delim {
            new_entry
                .attrs
                .insert("saml_groups_delim".to_string(), vec![delim.to_string()]);
        }
        if cfg.insecure_skip_sig_validation {
            new_entry.attrs.insert(
                "saml_insecure_skip_sig_validation".to_string(),
                vec!["true".to_string()],
            );
        }
        if cfg.filter_groups {
            new_entry
                .attrs
                .insert("saml_filter_groups".to_string(), vec!["true".to_string()]);
        }
        self.perform_post_request("/v1/saml_client", new_entry)
            .await
    }

    pub async fn idm_saml_client_get(&self, name: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/saml_client/{name}").as_str())
            .await
    }

    pub async fn idm_saml_client_delete(&self, name: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/saml_client/{name}").as_str())
            .await
    }

    pub async fn idm_saml_client_update_cert(
        &self,
        name: &str,
        idp_certificate: &str,
    ) -> Result<(), ClientError> {
        let mut update = Entry::default();
        update.attrs.insert(
            "saml_idp_certificate".to_string(),
            vec![idp_certificate.to_string()],
        );
        self.perform_patch_request(format!("/v1/saml_client/{name}").as_str(), update)
            .await
    }

    /// Add a mapping from an upstream SAML group name to a netidm group UUID
    /// on a SAML upstream client. Server rejects the request if a mapping
    /// for the same `upstream` name already exists on the connector
    /// (FR-007a).
    pub async fn idm_saml_client_add_group_mapping(
        &self,
        name: &str,
        upstream: &str,
        netidm_group_uuid: Uuid,
    ) -> Result<(), ClientError> {
        let upstream_enc = urlencoding::encode(upstream);
        self.perform_post_request(
            format!("/v1/saml_client/{name}/_group_mapping/{upstream_enc}").as_str(),
            netidm_group_uuid.to_string(),
        )
        .await
    }

    /// Remove the group mapping for `upstream` from a SAML upstream client.
    /// Idempotent.
    pub async fn idm_saml_client_remove_group_mapping(
        &self,
        name: &str,
        upstream: &str,
    ) -> Result<(), ClientError> {
        let upstream_enc = urlencoding::encode(upstream);
        self.perform_delete_request(
            format!("/v1/saml_client/{name}/_group_mapping/{upstream_enc}").as_str(),
        )
        .await
    }

    /// List all upstream-to-netidm group mappings on a SAML upstream client.
    pub async fn idm_saml_client_list_group_mappings(
        &self,
        name: &str,
    ) -> Result<Vec<(String, Uuid)>, ClientError> {
        let entry: Option<Entry> = self
            .perform_get_request(format!("/v1/saml_client/{name}").as_str())
            .await?;
        let entry = entry.ok_or_else(|| {
            ClientError::InvalidRequest(format!("no such SAML upstream client: {name}"))
        })?;
        let raw = entry
            .attrs
            .get(ATTR_SAML_GROUP_MAPPING)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::with_capacity(raw.len());
        for value in raw {
            if let Some((upstream, uuid_str)) = value.rsplit_once(':') {
                if let Ok(uuid) = Uuid::parse_str(uuid_str) {
                    out.push((upstream.to_string(), uuid));
                }
            }
        }
        Ok(out)
    }

    /// Set (replace) the SAML service provider's Single Logout Service
    /// URL. Single-value: re-invoking replaces the previous URL.
    /// Rejects malformed URLs.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer or
    /// the server rejects the URL as malformed.
    pub async fn idm_saml_client_set_slo_url(
        &self,
        name: &str,
        url: &str,
    ) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/saml_client/{name}/_slo_url").as_str(),
            url.to_string(),
        )
        .await
    }

    /// Clear the SAML service provider's Single Logout Service URL.
    /// Idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer.
    pub async fn idm_saml_client_clear_slo_url(&self, name: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/saml_client/{name}/_slo_url").as_str())
            .await
    }

    // ── DL33 — SAML dex-parity additions ─────────────────────────────────────

    pub async fn idm_saml_client_set_sso_issuer(
        &self,
        name: &str,
        issuer: &str,
    ) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/saml_client/{name}/_sso_issuer").as_str(),
            issuer.to_string(),
        )
        .await
    }

    pub async fn idm_saml_client_clear_sso_issuer(&self, name: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/saml_client/{name}/_sso_issuer").as_str())
            .await
    }

    pub async fn idm_saml_client_set_groups_delim(
        &self,
        name: &str,
        delim: &str,
    ) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/saml_client/{name}/_groups_delim").as_str(),
            delim.to_string(),
        )
        .await
    }

    pub async fn idm_saml_client_clear_groups_delim(
        &self,
        name: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/saml_client/{name}/_groups_delim").as_str())
            .await
    }

    pub async fn idm_saml_client_add_allowed_group(
        &self,
        name: &str,
        group: &str,
    ) -> Result<(), ClientError> {
        let group_enc = urlencoding::encode(group);
        self.perform_post_request(
            format!("/v1/saml_client/{name}/_allowed_groups/{group_enc}").as_str(),
            (),
        )
        .await
    }

    pub async fn idm_saml_client_remove_allowed_group(
        &self,
        name: &str,
        group: &str,
    ) -> Result<(), ClientError> {
        let group_enc = urlencoding::encode(group);
        self.perform_delete_request(
            format!("/v1/saml_client/{name}/_allowed_groups/{group_enc}").as_str(),
        )
        .await
    }

    pub async fn idm_saml_client_set_insecure_skip_sig_validation(
        &self,
        name: &str,
        value: bool,
    ) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/saml_client/{name}/_insecure_skip_sig_validation").as_str(),
            value,
        )
        .await
    }

    pub async fn idm_saml_client_set_filter_groups(
        &self,
        name: &str,
        value: bool,
    ) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/saml_client/{name}/_filter_groups").as_str(),
            value,
        )
        .await
    }
}
