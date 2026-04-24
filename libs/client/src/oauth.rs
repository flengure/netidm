use crate::{ClientError, NetidmClient};
use netidm_proto::attribute::Attribute;
use netidm_proto::constants::{
    ATTR_DISPLAYNAME, ATTR_KEY_ACTION_REVOKE, ATTR_KEY_ACTION_ROTATE, ATTR_NAME,
    ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE, ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT,
    ATTR_OAUTH2_AUTHORISATION_ENDPOINT, ATTR_OAUTH2_CLAIM_MAP_DISPLAYNAME,
    ATTR_OAUTH2_CLAIM_MAP_EMAIL, ATTR_OAUTH2_CLAIM_MAP_NAME,
    ATTR_CONNECTOR_GITHUB_ALLOWED_TEAMS, ATTR_CONNECTOR_GITHUB_ALLOW_JIT_PROVISIONING,
    ATTR_CONNECTOR_GITHUB_HOST, ATTR_CONNECTOR_GITHUB_LOAD_ALL_GROUPS,
    ATTR_CONNECTOR_GITHUB_ORG_FILTER, ATTR_CONNECTOR_GITHUB_PREFERRED_EMAIL_DOMAIN,
    ATTR_CONNECTOR_GITHUB_TEAM_NAME_FIELD, ATTR_CONNECTOR_ID,
    ATTR_CONNECTOR_LDAP_BIND_DN, ATTR_CONNECTOR_LDAP_BIND_PW,
    ATTR_CONNECTOR_LDAP_GROUP_SEARCH_BASE_DN, ATTR_CONNECTOR_LDAP_GROUP_SEARCH_FILTER,
    ATTR_CONNECTOR_LDAP_GROUP_SEARCH_NAME_ATTR,
    ATTR_CONNECTOR_LDAP_GROUP_SEARCH_USER_MATCHERS, ATTR_CONNECTOR_LDAP_HOST,
    ATTR_CONNECTOR_LDAP_INSECURE_NO_SSL, ATTR_CONNECTOR_LDAP_INSECURE_SKIP_VERIFY,
    ATTR_CONNECTOR_LDAP_USER_SEARCH_BASE_DN, ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_ATTR,
    ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_SUFFIX, ATTR_CONNECTOR_LDAP_USER_SEARCH_FILTER,
    ATTR_CONNECTOR_LDAP_USER_SEARCH_ID_ATTR, ATTR_CONNECTOR_LDAP_USER_SEARCH_NAME_ATTR,
    ATTR_CONNECTOR_LDAP_USER_SEARCH_USERNAME, ATTR_CONNECTOR_PROVIDER_KIND,
    ATTR_CONNECTOR_SECRET, ATTR_OAUTH2_CONSENT_PROMPT_ENABLE,
    ATTR_OAUTH2_DOMAIN_EMAIL_LINK_ACCOUNTS, ATTR_OAUTH2_EMAIL_LINK_ACCOUNTS,
    ATTR_OAUTH2_GROUP_MAPPING, ATTR_OAUTH2_ISSUER, ATTR_OAUTH2_JIT_PROVISIONING,
    ATTR_OAUTH2_JWKS_URI, ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE, ATTR_OAUTH2_LINK_BY,
    ATTR_OAUTH2_PREFER_SHORT_USERNAME, ATTR_OAUTH2_REQUEST_SCOPES, ATTR_OAUTH2_RS_BASIC_SECRET,
    ATTR_OAUTH2_RS_ORIGIN, ATTR_OAUTH2_RS_ORIGIN_LANDING, ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI,
    ATTR_OAUTH2_STRICT_REDIRECT_URI, ATTR_OAUTH2_TOKEN_ENDPOINT, ATTR_OAUTH2_USERINFO_ENDPOINT,
};
use netidm_proto::internal::{ImageValue, Oauth2ClaimMapJoin};
use netidm_proto::v1::Entry;
use reqwest::multipart;
use serde::Deserialize;
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

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

    pub async fn idm_connector_add_origin(
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

    pub async fn idm_connector_remove_origin(
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

    pub async fn idm_connector_device_flow_update(
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

    pub async fn idm_connector_get(&self, name: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/oauth2/_client/{name}").as_str())
            .await
    }

    pub async fn idm_connector_create_github(
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
            ATTR_CONNECTOR_ID.to_string(),
            vec![client_id.to_string()],
        );
        entry.attrs.insert(
            ATTR_CONNECTOR_SECRET.to_string(),
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

    pub async fn idm_connector_create_google(
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
            ATTR_CONNECTOR_ID.to_string(),
            vec![client_id.to_string()],
        );
        entry.attrs.insert(
            ATTR_CONNECTOR_SECRET.to_string(),
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

    pub async fn idm_connector_create_oidc(
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
            ATTR_CONNECTOR_ID.to_string(),
            vec![client_id.to_string()],
        );
        entry.attrs.insert(
            ATTR_CONNECTOR_SECRET.to_string(),
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
        entry
            .attrs
            .insert(ATTR_OAUTH2_ISSUER.to_string(), vec![issuer.to_string()]);
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

    pub async fn idm_connector_enable_jit_provisioning(
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

    pub async fn idm_connector_disable_jit_provisioning(
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

    pub async fn idm_connector_enable_email_link_accounts(
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

    pub async fn idm_connector_disable_email_link_accounts(
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

    /// Set the per-connector `link_by` selector (DL24+) on an upstream OAuth2
    /// client. `link_by` must be one of `"email"`, `"username"`, `"id"`; the
    /// server rejects any other value. See `LinkBy` in `netidmd_lib` for the
    /// per-strategy match semantics.
    ///
    /// Targets `/v1/oauth2/_client/{id}` (upstream clients). The RS-scoped
    /// `/v1/oauth2/{id}` PATCH route does not match `Connector` entries.
    pub async fn idm_connector_set_link_by(
        &self,
        id: &str,
        link_by: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry
            .attrs
            .insert(ATTR_OAUTH2_LINK_BY.to_string(), vec![link_by.to_string()]);
        self.perform_patch_request(format!("/v1/oauth2/_client/{id}").as_str(), entry)
            .await
    }

    /// Add a URI to the OAuth2 client's `OAuth2RsPostLogoutRedirectUri`
    /// allowlist. URIs on this allowlist are accepted as
    /// `post_logout_redirect_uri` values on OIDC RP-Initiated Logout
    /// requests (exact match). Idempotent: adding a URI already present
    /// succeeds with no side effect. Rejects malformed (non-absolute) URIs.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer or
    /// the server rejects the URI as malformed.
    pub async fn idm_connector_add_post_logout_redirect_uri(
        &self,
        id: &str,
        uri: &str,
    ) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_post_logout_redirect_uri").as_str(),
            uri.to_string(),
        )
        .await
    }

    /// Remove a URI from the OAuth2 client's `OAuth2RsPostLogoutRedirectUri`
    /// allowlist. Idempotent: removing a URI not present returns `Ok(())`
    /// with no side effect.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer.
    pub async fn idm_connector_remove_post_logout_redirect_uri(
        &self,
        id: &str,
        uri: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request_with_body(
            format!("/v1/oauth2/{id}/_post_logout_redirect_uri").as_str(),
            uri.to_string(),
        )
        .await
    }

    /// List all URIs on the OAuth2 client's
    /// `OAuth2RsPostLogoutRedirectUri` allowlist. Order is whatever the
    /// server returns (no ordering guarantee).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the client entry cannot be fetched.
    pub async fn idm_connector_list_post_logout_redirect_uris(
        &self,
        id: &str,
    ) -> Result<Vec<String>, ClientError> {
        let entry: Option<Entry> = self
            .perform_get_request(format!("/v1/oauth2/{id}").as_str())
            .await?;
        let entry = entry.ok_or_else(|| {
            ClientError::InvalidRequest(format!("no such OAuth2 resource server: {id}"))
        })?;
        Ok(entry
            .attrs
            .get(ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI)
            .cloned()
            .unwrap_or_default())
    }

    /// Set (replace) the OAuth2 client's back-channel logout endpoint URI.
    /// Single-value: calling again overwrites the previous URI. Rejects
    /// malformed URIs.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer or
    /// the server rejects the URI as malformed.
    pub async fn idm_connector_set_backchannel_logout_uri(
        &self,
        id: &str,
        uri: &str,
    ) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_backchannel_logout_uri").as_str(),
            uri.to_string(),
        )
        .await
    }

    /// Clear the OAuth2 client's back-channel logout endpoint URI.
    /// Idempotent: clearing an already-absent attribute returns `Ok(())`
    /// with no side effect.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer.
    pub async fn idm_connector_clear_backchannel_logout_uri(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/oauth2/{id}/_backchannel_logout_uri").as_str())
            .await
    }

    /// Add a mapping from an upstream group name to a netidm group UUID on an
    /// OAuth2 upstream client connector. Stored as a single value in the
    /// connector's `oauth2_group_mapping` attribute. The server rejects the
    /// request if a mapping for the same `upstream` name already exists on
    /// the connector (FR-007a).
    pub async fn idm_connector_add_group_mapping(
        &self,
        id: &str,
        upstream: &str,
        netidm_group_uuid: Uuid,
    ) -> Result<(), ClientError> {
        let upstream_enc = urlencoding::encode(upstream);
        self.perform_post_request(
            format!("/v1/oauth2/_client/{id}/_group_mapping/{upstream_enc}").as_str(),
            netidm_group_uuid.to_string(),
        )
        .await
    }

    /// Remove the group mapping for `upstream` from an OAuth2 upstream client.
    /// Idempotent: removing a mapping that is not present succeeds with no
    /// side effect. Users who had memberships granted through the removed
    /// mapping keep them until their next authentication through this
    /// connector (FR-007b).
    pub async fn idm_connector_remove_group_mapping(
        &self,
        id: &str,
        upstream: &str,
    ) -> Result<(), ClientError> {
        let upstream_enc = urlencoding::encode(upstream);
        self.perform_delete_request(
            format!("/v1/oauth2/_client/{id}/_group_mapping/{upstream_enc}").as_str(),
        )
        .await
    }

    /// List all upstream-to-netidm group mappings on an OAuth2 upstream
    /// client. Returns pairs of `(upstream_name, netidm_group_uuid)` in the
    /// order the server returns them (no ordering guarantee).
    pub async fn idm_connector_list_group_mappings(
        &self,
        id: &str,
    ) -> Result<Vec<(String, Uuid)>, ClientError> {
        let entry: Option<Entry> = self
            .perform_get_request(format!("/v1/oauth2/_client/{id}").as_str())
            .await?;
        let entry = entry.ok_or_else(|| {
            ClientError::InvalidRequest(format!("no such OAuth2 upstream client: {id}"))
        })?;
        let raw = entry
            .attrs
            .get(ATTR_OAUTH2_GROUP_MAPPING)
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

    pub async fn idm_connector_set_claim_map(
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

    /// Set the provider kind discriminator on an OAuth2 client entry.
    /// Use `"github"` for GitHub / GitHub Enterprise connectors.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer or the
    /// server rejects the value.
    pub async fn idm_connector_set_provider_kind(
        &self,
        id: &str,
        kind: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_PROVIDER_KIND.to_string(),
            vec![kind.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    /// Set the GitHub / GitHub Enterprise base URL for this connector.
    /// Defaults to `https://github.com/` when absent. Set to your GHE
    /// appliance root (e.g. `https://github.example.com/`) to route all
    /// OAuth and API calls through that host.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails or the server rejects the URL.
    pub async fn idm_connector_github_set_host(
        &self,
        id: &str,
        url: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_GITHUB_HOST.to_string(),
            vec![url.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    /// Add an org name to the GitHub connector's org-filter list.
    /// When the list is non-empty only teams belonging to the listed orgs
    /// appear in the user's group claims. The filter is a group-mapping
    /// filter only — it never rejects logins.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer.
    pub async fn idm_connector_github_add_org_filter(
        &self,
        id: &str,
        org: &str,
    ) -> Result<(), ClientError> {
        let mut current: Vec<String> = self
            .idm_connector_get(id)
            .await?
            .and_then(|e| e.attrs.get(ATTR_CONNECTOR_GITHUB_ORG_FILTER).cloned())
            .unwrap_or_default();
        if !current.contains(&org.to_string()) {
            current.push(org.to_string());
        }
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry
            .attrs
            .insert(ATTR_CONNECTOR_GITHUB_ORG_FILTER.to_string(), current);
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    /// Remove an org name from the GitHub connector's org-filter list.
    /// Idempotent: removing an org not in the list succeeds with no side effect.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer.
    pub async fn idm_connector_github_remove_org_filter(
        &self,
        id: &str,
        org: &str,
    ) -> Result<(), ClientError> {
        let current: Vec<String> = self
            .idm_connector_get(id)
            .await?
            .and_then(|e| e.attrs.get(ATTR_CONNECTOR_GITHUB_ORG_FILTER).cloned())
            .unwrap_or_default();
        let updated: Vec<String> = current.into_iter().filter(|v| v != org).collect();
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry
            .attrs
            .insert(ATTR_CONNECTOR_GITHUB_ORG_FILTER.to_string(), updated);
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    /// Add a team slug (`org:team`) to the GitHub connector's allowed-teams
    /// access gate. When the list is non-empty, users must be a member of at
    /// least one listed team to complete login.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer.
    pub async fn idm_connector_github_add_allowed_team(
        &self,
        id: &str,
        team: &str,
    ) -> Result<(), ClientError> {
        let mut current: Vec<String> = self
            .idm_connector_get(id)
            .await?
            .and_then(|e| {
                e.attrs
                    .get(ATTR_CONNECTOR_GITHUB_ALLOWED_TEAMS)
                    .cloned()
            })
            .unwrap_or_default();
        if !current.contains(&team.to_string()) {
            current.push(team.to_string());
        }
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry
            .attrs
            .insert(ATTR_CONNECTOR_GITHUB_ALLOWED_TEAMS.to_string(), current);
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    /// Remove a team slug from the GitHub connector's allowed-teams gate.
    /// Idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer.
    pub async fn idm_connector_github_remove_allowed_team(
        &self,
        id: &str,
        team: &str,
    ) -> Result<(), ClientError> {
        let current: Vec<String> = self
            .idm_connector_get(id)
            .await?
            .and_then(|e| {
                e.attrs
                    .get(ATTR_CONNECTOR_GITHUB_ALLOWED_TEAMS)
                    .cloned()
            })
            .unwrap_or_default();
        let updated: Vec<String> = current.into_iter().filter(|v| v != team).collect();
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry
            .attrs
            .insert(ATTR_CONNECTOR_GITHUB_ALLOWED_TEAMS.to_string(), updated);
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    /// Set which GitHub team name field is used when mapping teams to netidm
    /// group names. Valid values: `"slug"` (default), `"name"`, `"both"`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails or the server rejects the value.
    pub async fn idm_connector_github_set_team_name_field(
        &self,
        id: &str,
        field: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_GITHUB_TEAM_NAME_FIELD.to_string(),
            vec![field.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    /// Enable or disable loading all GitHub team memberships as group claims
    /// (regardless of group mappings). When `true`, every team the user
    /// belongs to appears in their session groups.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer.
    pub async fn idm_connector_github_set_load_all_groups(
        &self,
        id: &str,
        enable: bool,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_GITHUB_LOAD_ALL_GROUPS.to_string(),
            vec![enable.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    /// Set the preferred email domain for the GitHub connector. When set,
    /// the connector picks the user's email address from that domain first
    /// among their verified GitHub emails.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer.
    pub async fn idm_connector_github_set_preferred_email_domain(
        &self,
        id: &str,
        domain: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_GITHUB_PREFERRED_EMAIL_DOMAIN.to_string(),
            vec![domain.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    /// Clear the preferred email domain on a GitHub connector.
    /// After clearing, the connector selects the first verified email
    /// returned by GitHub. Passing an empty value list via PATCH purges
    /// the attribute.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer.
    pub async fn idm_connector_github_clear_preferred_email_domain(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_GITHUB_PREFERRED_EMAIL_DOMAIN.to_string(),
            vec![],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    /// Enable or disable Just-In-Time provisioning for the GitHub connector.
    /// When enabled, the first login from a GitHub user with no matching
    /// local Person auto-provisions that Person.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer.
    pub async fn idm_connector_github_set_allow_jit_provisioning(
        &self,
        id: &str,
        enable: bool,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_GITHUB_ALLOW_JIT_PROVISIONING.to_string(),
            vec![enable.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    // ── LDAP inbound connector methods (DL32) ─────────────────────────────────

    pub async fn idm_connector_create_ldap(&self, name: &str) -> Result<(), ClientError> {
        let mut entry = Entry::default();
        entry
            .attrs
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        entry
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![name.to_string()]);
        entry.attrs.insert(
            ATTR_CONNECTOR_PROVIDER_KIND.to_string(),
            vec!["ldap".to_string()],
        );
        self.perform_post_request("/v1/oauth2/_client", entry).await
    }

    pub async fn idm_connector_ldap_set_host(
        &self,
        id: &str,
        host: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_HOST.to_string(),
            vec![host.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_insecure_no_ssl(
        &self,
        id: &str,
        enable: bool,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_INSECURE_NO_SSL.to_string(),
            vec![enable.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_insecure_skip_verify(
        &self,
        id: &str,
        enable: bool,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_INSECURE_SKIP_VERIFY.to_string(),
            vec![enable.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_bind_dn(
        &self,
        id: &str,
        bind_dn: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_BIND_DN.to_string(),
            vec![bind_dn.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_bind_pw(
        &self,
        id: &str,
        bind_pw: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_BIND_PW.to_string(),
            vec![bind_pw.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_user_search_base_dn(
        &self,
        id: &str,
        base_dn: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_USER_SEARCH_BASE_DN.to_string(),
            vec![base_dn.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_user_search_filter(
        &self,
        id: &str,
        filter: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_USER_SEARCH_FILTER.to_string(),
            vec![filter.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_add_user_search_username(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<(), ClientError> {
        let mut current: Vec<String> = self
            .idm_connector_get(id)
            .await?
            .and_then(|e| {
                e.attrs
                    .get(ATTR_CONNECTOR_LDAP_USER_SEARCH_USERNAME)
                    .cloned()
            })
            .unwrap_or_default();
        if !current.contains(&attr.to_string()) {
            current.push(attr.to_string());
        }
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_USER_SEARCH_USERNAME.to_string(),
            current,
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_remove_user_search_username(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<(), ClientError> {
        let current: Vec<String> = self
            .idm_connector_get(id)
            .await?
            .and_then(|e| {
                e.attrs
                    .get(ATTR_CONNECTOR_LDAP_USER_SEARCH_USERNAME)
                    .cloned()
            })
            .unwrap_or_default();
        let updated: Vec<String> = current.into_iter().filter(|a| a != attr).collect();
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_USER_SEARCH_USERNAME.to_string(),
            updated,
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_user_id_attr(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_USER_SEARCH_ID_ATTR.to_string(),
            vec![attr.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_user_email_attr(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_ATTR.to_string(),
            vec![attr.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_user_name_attr(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_USER_SEARCH_NAME_ATTR.to_string(),
            vec![attr.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_user_email_suffix(
        &self,
        id: &str,
        suffix: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_USER_SEARCH_EMAIL_SUFFIX.to_string(),
            vec![suffix.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_group_search_base_dn(
        &self,
        id: &str,
        base_dn: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_GROUP_SEARCH_BASE_DN.to_string(),
            vec![base_dn.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_group_search_filter(
        &self,
        id: &str,
        filter: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_GROUP_SEARCH_FILTER.to_string(),
            vec![filter.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_set_group_name_attr(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<(), ClientError> {
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_GROUP_SEARCH_NAME_ATTR.to_string(),
            vec![attr.to_string()],
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_add_user_matcher(
        &self,
        id: &str,
        matcher: &str,
    ) -> Result<(), ClientError> {
        let mut current: Vec<String> = self
            .idm_connector_get(id)
            .await?
            .and_then(|e| {
                e.attrs
                    .get(ATTR_CONNECTOR_LDAP_GROUP_SEARCH_USER_MATCHERS)
                    .cloned()
            })
            .unwrap_or_default();
        if !current.contains(&matcher.to_string()) {
            current.push(matcher.to_string());
        }
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_GROUP_SEARCH_USER_MATCHERS.to_string(),
            current,
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }

    pub async fn idm_connector_ldap_remove_user_matcher(
        &self,
        id: &str,
        matcher: &str,
    ) -> Result<(), ClientError> {
        let current: Vec<String> = self
            .idm_connector_get(id)
            .await?
            .and_then(|e| {
                e.attrs
                    .get(ATTR_CONNECTOR_LDAP_GROUP_SEARCH_USER_MATCHERS)
                    .cloned()
            })
            .unwrap_or_default();
        let updated: Vec<String> = current.into_iter().filter(|m| m != matcher).collect();
        let mut entry = Entry {
            attrs: BTreeMap::new(),
        };
        entry.attrs.insert(
            ATTR_CONNECTOR_LDAP_GROUP_SEARCH_USER_MATCHERS.to_string(),
            updated,
        );
        self.perform_patch_request(&format!("/v1/oauth2/_client/{id}"), entry)
            .await
    }
}
