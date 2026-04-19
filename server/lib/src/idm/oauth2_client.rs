use crate::idm::server::IdmServerProxyWriteTransaction;
use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// TODO: Move to constants once we have a good path here. Will probably need to be part
// of the axum config etc.
// I'm pretty sure this can preserve query strings if we wanted to stash info or flag things?
pub const OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH: &str = "/ui/login/oauth2_landing";

#[derive(Clone)]
pub struct OAuth2ClientProvider {
    pub(crate) name: String,
    /// Human-readable button label. Falls back to `name` when no DisplayName is set.
    pub(crate) display_name: String,
    pub(crate) uuid: Uuid,
    pub(crate) client_id: String,
    pub(crate) client_basic_secret: String,
    /// This is the origin of THIS netidm server.
    pub(crate) client_redirect_uri: Url,
    pub(crate) request_scopes: BTreeSet<String>,
    pub(crate) authorisation_endpoint: Url,
    pub(crate) token_endpoint: Url,
    pub(crate) userinfo_endpoint: Option<Url>,
    pub(crate) jit_provisioning: bool,
    /// Effective email-link-accounts setting: per-provider if set, otherwise global domain default.
    pub(crate) email_link_accounts: bool,
    /// Optional logo image URL shown on the SSO login button (DL20+).
    pub(crate) logo_uri: Option<Url>,
    /// OIDC issuer URL, set when this provider was configured via OIDC discovery (DL21+).
    pub(crate) issuer: Option<Url>,
    /// JWKS endpoint URL for cryptographic verification of id_tokens (DL21+).
    /// When set, `id_token` JWTs are verified against this JWKS rather than decoded unverified.
    pub(crate) jwks_uri: Option<Url>,
    /// Maps a Netidm attribute to the provider claim name used at JIT provisioning time.
    pub(crate) claim_map: BTreeMap<Attribute, String>,
}

impl fmt::Debug for OAuth2ClientProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2ClientProvider")
            .field("provider_id", &self.name)
            .field("display_name", &self.display_name)
            .field("provider_name", &self.uuid)
            .field("client_id", &self.client_id)
            .finish()
    }
}

impl OAuth2ClientProvider {
    #[cfg(test)]
    pub fn new_test<'a, I: IntoIterator<Item = &'a str>>(
        client_id: &str,
        domain: &str,
        request_scopes: I,
    ) -> Self {
        // In prod will be build from our true origin + the actual landing pad.
        let mut client_redirect_uri =
            Url::parse("https://idm.example.com").expect("invalid test data");
        client_redirect_uri.set_path(OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH);

        let mut domain = Url::parse(domain).expect("invalid test data");

        domain.set_path("/oauth2/authorise");
        let authorisation_endpoint = domain.clone();

        domain.set_path("/oauth2/token");
        let token_endpoint = domain.clone();

        let client_basic_secret = crate::utils::password_from_random();

        let request_scopes = request_scopes.into_iter().map(String::from).collect();

        Self {
            name: "test_client_provider".to_string(),
            display_name: "Test Client Provider".to_string(),
            uuid: Uuid::new_v4(),
            client_id: client_id.to_string(),
            client_basic_secret,
            client_redirect_uri,
            request_scopes,
            authorisation_endpoint,
            token_endpoint,
            userinfo_endpoint: None,
            jit_provisioning: false,
            email_link_accounts: false,
            logo_uri: None,
            issuer: None,
            jwks_uri: None,
            claim_map: BTreeMap::new(),
        }
    }
}

impl IdmServerProxyWriteTransaction<'_> {
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_oauth2_client_providers(&mut self) -> Result<(), OperationError> {
        let oauth2_client_provider_entries = self.qs_write.internal_search(filter!(f_eq(
            Attribute::Class,
            EntryClass::OAuth2Client.into(),
        )))?;

        // Preprocess
        let mut oauth2_client_provider_structs =
            Vec::with_capacity(oauth2_client_provider_entries.len());

        let mut client_redirect_uri = self.origin.clone();
        client_redirect_uri.set_path(OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH);

        let global_email_link_accounts = self
            .qs_write
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .ok()
            .and_then(|e| e.get_ava_single_bool(Attribute::OAuth2DomainEmailLinkAccounts))
            .unwrap_or(false);

        for provider_entry in oauth2_client_provider_entries {
            let uuid = provider_entry.get_uuid();
            trace!(?uuid, "Checking OAuth2 Provider configuration");

            let name = provider_entry
                .get_ava_single_iname(Attribute::Name)
                .map(str::to_string)
                .ok_or(OperationError::InvalidValueState)?;

            let display_name = provider_entry
                .get_ava_single_utf8(Attribute::DisplayName)
                .map(str::to_string)
                .unwrap_or_else(|| name.clone());

            let client_id = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2ClientId)
                .map(str::to_string)
                .ok_or(OperationError::InvalidValueState)?;

            let client_basic_secret = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2ClientSecret)
                .map(str::to_string)
                .ok_or(OperationError::InvalidValueState)?;

            let authorisation_endpoint = provider_entry
                .get_ava_single_url(Attribute::OAuth2AuthorisationEndpoint)
                .cloned()
                .ok_or(OperationError::InvalidValueState)?;

            let token_endpoint = provider_entry
                .get_ava_single_url(Attribute::OAuth2TokenEndpoint)
                .cloned()
                .ok_or(OperationError::InvalidValueState)?;

            let request_scopes = provider_entry
                .get_ava_as_oauthscopes(Attribute::OAuth2RequestScopes)
                .ok_or(OperationError::InvalidValueState)?
                .map(str::to_string)
                .collect();

            let userinfo_endpoint = provider_entry
                .get_ava_single_url(Attribute::OAuth2UserinfoEndpoint)
                .cloned();

            let jit_provisioning = provider_entry
                .get_ava_single_bool(Attribute::OAuth2JitProvisioning)
                .unwrap_or(false);

            let email_link_accounts = provider_entry
                .get_ava_single_bool(Attribute::OAuth2EmailLinkAccounts)
                .unwrap_or(global_email_link_accounts);

            let logo_uri = provider_entry
                .get_ava_single_url(Attribute::OAuth2ClientLogoUri)
                .cloned();

            let issuer = provider_entry
                .get_ava_single_url(Attribute::OAuth2Issuer)
                .cloned();

            let jwks_uri = provider_entry
                .get_ava_single_url(Attribute::OAuth2JwksUri)
                .cloned();

            let mut claim_map = BTreeMap::new();
            if let Some(v) = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2ClaimMapName)
                .map(str::to_string)
            {
                claim_map.insert(Attribute::Name, v);
            }
            if let Some(v) = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2ClaimMapDisplayname)
                .map(str::to_string)
            {
                claim_map.insert(Attribute::DisplayName, v);
            }
            if let Some(v) = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2ClaimMapEmail)
                .map(str::to_string)
            {
                claim_map.insert(Attribute::Mail, v);
            }

            let provider = OAuth2ClientProvider {
                name,
                display_name,
                uuid,
                client_id,
                client_basic_secret,
                client_redirect_uri: client_redirect_uri.clone(),
                request_scopes,
                authorisation_endpoint,
                token_endpoint,
                userinfo_endpoint,
                jit_provisioning,
                email_link_accounts,
                logo_uri,
                issuer,
                jwks_uri,
                claim_map,
            };

            oauth2_client_provider_structs.push((uuid, provider));
        }

        // Clear the existing set.
        self.oauth2_client_providers.clear();

        // Add them all
        self.oauth2_client_providers
            .extend(oauth2_client_provider_structs);

        // Done!
        Ok(())
    }
}
