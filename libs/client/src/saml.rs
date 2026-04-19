use crate::{ClientError, NetidmClient};
use netidm_proto::constants::{ATTR_DISPLAYNAME, ATTR_NAME};
use netidm_proto::v1::Entry;

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
        new_entry
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![cfg.display_name.to_string()]);
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
        self.perform_post_request("/v1/saml_client", new_entry).await
    }

    pub async fn idm_saml_client_get(
        &self,
        name: &str,
    ) -> Result<Option<Entry>, ClientError> {
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
}
