use crate::{ClientError, NetidmClient};
use netidm_proto::attribute::Attribute;
use netidm_proto::constants::{
    ATTR_DISPLAYNAME, ATTR_KEY_ACTION_REVOKE, ATTR_KEY_ACTION_ROTATE, ATTR_NAME,
    ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE, ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT,
    ATTR_OAUTH2_AUTHORISATION_ENDPOINT, ATTR_OAUTH2_CLAIM_MAP_DISPLAYNAME,
    ATTR_OAUTH2_CLAIM_MAP_EMAIL, ATTR_OAUTH2_CLAIM_MAP_NAME, ATTR_OAUTH2_CLIENT_ID,
    ATTR_OAUTH2_CLIENT_SECRET, ATTR_OAUTH2_CONSENT_PROMPT_ENABLE,
    ATTR_OAUTH2_DOMAIN_EMAIL_LINK_ACCOUNTS, ATTR_OAUTH2_EMAIL_LINK_ACCOUNTS,
    ATTR_OAUTH2_ISSUER, ATTR_OAUTH2_JIT_PROVISIONING, ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE,
    ATTR_OAUTH2_JWKS_URI, ATTR_OAUTH2_PREFER_SHORT_USERNAME, ATTR_OAUTH2_REQUEST_SCOPES,
    ATTR_OAUTH2_RS_BASIC_SECRET, ATTR_OAUTH2_RS_ORIGIN, ATTR_OAUTH2_RS_ORIGIN_LANDING,
    ATTR_OAUTH2_STRICT_REDIRECT_URI, ATTR_OAUTH2_TOKEN_ENDPOINT, ATTR_OAUTH2_USERINFO_ENDPOINT,
};
use serde::Deserialize;
use netidm_proto::internal::{ImageValue, Oauth2ClaimMapJoin};
use netidm_proto::v1::Entry;
use reqwest::multipart;
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;

impl NetidmClient {
    // ==== Oauth2 resource server configuration
    #[instrument(level = "debug")]
    pub async fn idm_oauth2_rs_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/oauth2").await
    }

    pub async fn idm_oauth2_rs_basic_create(
        &self,
        name: &str,
        displayname: &str,
        origin: &str,
    ) -> Result<(), ClientError> {
        let mut new_oauth2_rs = Entry::default();
        new_oauth2_rs
            .attrs
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        new_oauth2_rs
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![displayname.to_string()]);
        new_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_RS_ORIGIN_LANDING.to_string(),
            vec![origin.to_string()],
        );
        new_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_STRICT_REDIRECT_URI.to_string(),
            vec!["true".to_string()],
        );
        self.perform_post_request("/v1/oauth2/_basic", new_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_public_create(
        &self,
        name: &str,
        displayname: &str,
        origin: &str,
    ) -> Result<(), ClientError> {
        let mut new_oauth2_rs = Entry::default();
        new_oauth2_rs
            .attrs
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        new_oauth2_rs
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![displayname.to_string()]);
        new_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_RS_ORIGIN_LANDING.to_string(),
            vec![origin.to_string()],
        );
        new_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_STRICT_REDIRECT_URI.to_string(),
            vec!["true".to_string()],
        );
        self.perform_post_request("/v1/oauth2/_public", new_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_get(&self, client_name: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/oauth2/{client_name}").as_str())
            .await
    }

    pub async fn idm_oauth2_rs_get_basic_secret(
        &self,
        client_name: &str,
    ) -> Result<Option<String>, ClientError> {
        self.perform_get_request(format!("/v1/oauth2/{client_name}/_basic_secret").as_str())
            .await
    }

    pub async fn idm_oauth2_rs_revoke_key(
        &self,
        client_name: &str,
        key_id: &str,
    ) -> Result<(), ClientError> {
        self.perform_post_request(
            &format!("/v1/oauth2/{client_name}/_attr/{ATTR_KEY_ACTION_REVOKE}"),
            vec![key_id.to_string()],
        )
        .await
    }

    pub async fn idm_oauth2_rs_rotate_keys(
        &self,
        client_name: &str,
        rotate_at_time: OffsetDateTime,
    ) -> Result<(), ClientError> {
        let rfc_3339_str = rotate_at_time.format(&Rfc3339).map_err(|_| {
            ClientError::InvalidRequest("Unable to format rfc 3339 datetime".into())
        })?;

        self.perform_post_request(
            &format!("/v1/oauth2/{client_name}/_attr/{ATTR_KEY_ACTION_ROTATE}"),
            vec![rfc_3339_str],
        )
        .await
    }

    pub async fn idm_oauth2_rs_update(
        &self,
        id: &str,
        name: Option<&str>,
        displayname: Option<&str>,
        landing: Option<&str>,
        reset_secret: bool,
    ) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };

        if let Some(newname) = name {
            update_oauth2_rs
                .attrs
                .insert(ATTR_NAME.to_string(), vec![newname.to_string()]);
        }
        if let Some(newdisplayname) = displayname {
            update_oauth2_rs.attrs.insert(
                ATTR_DISPLAYNAME.to_string(),
                vec![newdisplayname.to_string()],
            );
        }
        if let Some(newlanding) = landing {
            update_oauth2_rs.attrs.insert(
                ATTR_OAUTH2_RS_ORIGIN_LANDING.to_string(),
                vec![newlanding.to_string()],
            );
        }
        if reset_secret {
            update_oauth2_rs
                .attrs
                .insert(ATTR_OAUTH2_RS_BASIC_SECRET.to_string(), Vec::new());
        }
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_update_scope_map(
        &self,
        id: &str,
        group: &str,
        scopes: Vec<&str>,
    ) -> Result<(), ClientError> {
        let scopes: Vec<String> = scopes.into_iter().map(str::to_string).collect();
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_scopemap/{group}").as_str(),
            scopes,
        )
        .await
    }

    pub async fn idm_oauth2_rs_delete_scope_map(
        &self,
        id: &str,
        group: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/oauth2/{id}/_scopemap/{group}").as_str())
            .await
    }

    pub async fn idm_oauth2_rs_update_sup_scope_map(
        &self,
        id: &str,
        group: &str,
        scopes: Vec<&str>,
    ) -> Result<(), ClientError> {
        let scopes: Vec<String> = scopes.into_iter().map(str::to_string).collect();
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_sup_scopemap/{group}").as_str(),
            scopes,
        )
        .await
    }

    pub async fn idm_oauth2_rs_delete_sup_scope_map(
        &self,
        id: &str,
        group: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/oauth2/{id}/_sup_scopemap/{group}").as_str())
            .await
    }

    pub async fn idm_oauth2_rs_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(["/v1/oauth2/", id].concat().as_str())
            .await
    }

    /// Want to delete the image associated with a resource server? Here's your thing!
    pub async fn idm_oauth2_rs_delete_image(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/oauth2/{id}/_image").as_str())
            .await
    }

    /// Want to add/update the image associated with a resource server? Here's your thing!
    pub async fn idm_oauth2_rs_update_image(
        &self,
        id: &str,
        image: ImageValue,
    ) -> Result<(), ClientError> {
        let file_content_type = image.filetype.as_content_type_str();

        let file_data = match multipart::Part::bytes(image.contents.clone())
            .file_name(image.filename)
            .mime_str(file_content_type)
        {
            Ok(part) => part,
            Err(err) => {
                error!(
                    "Failed to generate multipart body from image data: {:}",
                    err
                );
                return Err(ClientError::SystemError);
            }
        };

        let form = multipart::Form::new().part("image", file_data);

        // send it
        let response = self
            .client
            .post(self.make_url(&format!("/v1/oauth2/{id}/_image")))
            .multipart(form);

        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };
        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;
        self.expect_version(&response).await;

        let opid = self.get_kopid_from_response(&response);

        self.ok_or_clienterror(&opid, response)
            .await?
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))
    }

    pub async fn idm_oauth2_rs_enable_pkce(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE.to_string(),
            Vec::new(),
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_pkce(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_enable_legacy_crypto(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_legacy_crypto(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_prefer_short_username(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_PREFER_SHORT_USERNAME.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_prefer_spn_username(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_PREFER_SHORT_USERNAME.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_enable_public_localhost_redirect(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_public_localhost_redirect(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_enable_strict_redirect_uri(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_STRICT_REDIRECT_URI.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_strict_redirect_uri(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_STRICT_REDIRECT_URI.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_update_claim_map(
        &self,
        id: &str,
        claim_name: &str,
        group_id: &str,
        values: &[String],
    ) -> Result<(), ClientError> {
        let values: Vec<String> = values.to_vec();
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_claimmap/{claim_name}/{group_id}").as_str(),
            values,
        )
        .await
    }

    pub async fn idm_oauth2_rs_update_claim_map_join(
        &self,
        id: &str,
        claim_name: &str,
        join: Oauth2ClaimMapJoin,
    ) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_claimmap/{claim_name}").as_str(),
            join,
        )
        .await
    }

    pub async fn idm_oauth2_rs_delete_claim_map(
        &self,
        id: &str,
        claim_name: &str,
        group_id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(
            format!("/v1/oauth2/{id}/_claimmap/{claim_name}/{group_id}").as_str(),
        )
        .await
    }

    pub async fn idm_oauth2_client_add_origin(
        &self,
        id: &str,
        origin: &Url,
    ) -> Result<(), ClientError> {
        // TODO: should we normalise loopback origins, so when a user specifies `http://localhost/foo` we store it as `http://[::1]/foo`?

        let url_to_add = &[origin.as_str()];
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_attr/{ATTR_OAUTH2_RS_ORIGIN}").as_str(),
            url_to_add,
        )
        .await
    }

    pub async fn idm_oauth2_client_remove_origin(
        &self,
        id: &str,
        origin: &Url,
    ) -> Result<(), ClientError> {
        let url_to_remove = &[origin.as_str()];
        self.perform_delete_request_with_body(
            format!("/v1/oauth2/{id}/_attr/{ATTR_OAUTH2_RS_ORIGIN}").as_str(),
            url_to_remove,
        )
        .await
    }

    pub async fn idm_oauth2_client_device_flow_update(
        &self,
        id: &str,
        value: bool,
    ) -> Result<(), ClientError> {
        match value {
            true => {
                let mut update_oauth2_rs = Entry {
                    attrs: BTreeMap::new(),
                };
                update_oauth2_rs.attrs.insert(
                    Attribute::OAuth2DeviceFlowEnable.into(),
                    vec![value.to_string()],
                );
                self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
                    .await
            }
            false => {
                self.perform_delete_request(&format!(
                    "/v1/oauth2/{}/_attr/{}",
                    id,
                    Attribute::OAuth2DeviceFlowEnable.as_str()
                ))
                .await
            }
        }
    }

    pub async fn idm_oauth2_rs_enable_consent_prompt(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_CONSENT_PROMPT_ENABLE.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{}", id).as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_consent_prompt(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_CONSENT_PROMPT_ENABLE.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{}", id).as_str(), update_oauth2_rs)
            .await
    }

    // ==== OAuth2 Client Provider (Netidm as OAuth2 client to external providers)

    pub async fn idm_oauth2_client_get(&self, name: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/oauth2/_client/{name}").as_str())
            .await
    }

    pub async fn idm_oauth2_client_create_github(
        &self,
        name: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry::default();
        entry
            .attrs
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        entry
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![name.to_string()]);
        entry.attrs.insert(
            ATTR_OAUTH2_CLIENT_ID.to_string(),
            vec![client_id.to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_CLIENT_SECRET.to_string(),
            vec![client_secret.to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_AUTHORISATION_ENDPOINT.to_string(),
            vec!["https://github.com/login/oauth/authorize".to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_TOKEN_ENDPOINT.to_string(),
            vec!["https://github.com/login/oauth/access_token".to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_USERINFO_ENDPOINT.to_string(),
            vec!["https://api.github.com/user".to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_REQUEST_SCOPES.to_string(),
            vec!["read:user".to_string(), "user:email".to_string()],
        );
        self.perform_post_request("/v1/oauth2/_client", entry).await
    }

    pub async fn idm_oauth2_client_create_google(
        &self,
        name: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry::default();
        entry
            .attrs
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        entry
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![name.to_string()]);
        entry.attrs.insert(
            ATTR_OAUTH2_CLIENT_ID.to_string(),
            vec![client_id.to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_CLIENT_SECRET.to_string(),
            vec![client_secret.to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_AUTHORISATION_ENDPOINT.to_string(),
            vec!["https://accounts.google.com/o/oauth2/v2/auth".to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_TOKEN_ENDPOINT.to_string(),
            vec!["https://oauth2.googleapis.com/token".to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_REQUEST_SCOPES.to_string(),
            vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
        );
        self.perform_post_request("/v1/oauth2/_client", entry).await
    }

    pub async fn idm_oauth2_client_create_oidc(
        &self,
        name: &str,
        issuer: &Url,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), ClientError> {
        #[derive(Deserialize)]
        struct OidcDiscovery {
            issuer: String,
            authorization_endpoint: String,
            token_endpoint: String,
            #[serde(default)]
            userinfo_endpoint: Option<String>,
            #[serde(default)]
            jwks_uri: Option<String>,
        }

        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.as_str().trim_end_matches('/')
        );

        let resp = self
            .client()
            .get(&discovery_url)
            .send()
            .await
            .map_err(ClientError::Transport)?;

        if !resp.status().is_success() {
            return Err(ClientError::Http(
                resp.status(),
                None,
                "OIDC discovery request failed".to_string(),
            ));
        }

        let doc: OidcDiscovery = resp
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, "OIDC discovery document".to_string()))?;

        if doc.issuer != issuer.as_str().trim_end_matches('/') {
            return Err(ClientError::Http(
                reqwest::StatusCode::BAD_REQUEST,
                None,
                format!(
                    "OIDC discovery issuer mismatch: expected {}, got {}",
                    issuer, doc.issuer
                ),
            ));
        }

        let mut entry = Entry::default();
        entry
            .attrs
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        entry
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![name.to_string()]);
        entry.attrs.insert(
            ATTR_OAUTH2_CLIENT_ID.to_string(),
            vec![client_id.to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_CLIENT_SECRET.to_string(),
            vec![client_secret.to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_AUTHORISATION_ENDPOINT.to_string(),
            vec![doc.authorization_endpoint],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_TOKEN_ENDPOINT.to_string(),
            vec![doc.token_endpoint],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_ISSUER.to_string(),
            vec![issuer.to_string()],
        );
        entry.attrs.insert(
            ATTR_OAUTH2_REQUEST_SCOPES.to_string(),
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
        );
        if let Some(userinfo_url) = doc.userinfo_endpoint {
            entry.attrs.insert(
                ATTR_OAUTH2_USERINFO_ENDPOINT.to_string(),
                vec![userinfo_url],
            );
        }
        if let Some(jwks_url) = doc.jwks_uri {
            entry
                .attrs
                .insert(ATTR_OAUTH2_JWKS_URI.to_string(), vec![jwks_url]);
        }
        self.perform_post_request("/v1/oauth2/_client", entry).await
    }

    pub async fn idm_oauth2_client_enable_jit_provisioning(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_OAUTH2_JIT_PROVISIONING.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), entry)
            .await
    }

    pub async fn idm_oauth2_client_disable_jit_provisioning(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_OAUTH2_JIT_PROVISIONING.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), entry)
            .await
    }

    pub async fn idm_oauth2_client_enable_email_link_accounts(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_OAUTH2_EMAIL_LINK_ACCOUNTS.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), entry)
            .await
    }

    pub async fn idm_oauth2_client_disable_email_link_accounts(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_OAUTH2_EMAIL_LINK_ACCOUNTS.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), entry)
            .await
    }

    pub async fn idm_oauth2_domain_enable_email_link_accounts(&self) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/domain/_attr/{ATTR_OAUTH2_DOMAIN_EMAIL_LINK_ACCOUNTS}"),
            vec!["true"],
        )
        .await
    }

    pub async fn idm_oauth2_domain_disable_email_link_accounts(&self) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/domain/_attr/{ATTR_OAUTH2_DOMAIN_EMAIL_LINK_ACCOUNTS}"),
            vec!["false"],
        )
        .await
    }

    pub async fn idm_oauth2_client_set_claim_map(
        &self,
        id: &str,
        netidm_attr: &str,
        provider_claim: &str,
    ) -> Result<(), ClientError> {
        let attr_key = match netidm_attr {
            "name" => ATTR_OAUTH2_CLAIM_MAP_NAME,
            "displayname" => ATTR_OAUTH2_CLAIM_MAP_DISPLAYNAME,
            "mail" | "email" => ATTR_OAUTH2_CLAIM_MAP_EMAIL,
            other => {
                return Err(ClientError::InvalidRequest(format!(
                    "Unknown claim map attribute '{other}'; expected name, displayname, or mail"
                )));
            }
        };
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry
            .attrs
            .insert(attr_key.to_string(), vec![provider_claim.to_string()]);
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), entry)
            .await
    }
}
