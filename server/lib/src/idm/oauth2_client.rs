use crate::idm::server::IdmServerProxyWriteTransaction;
use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// TODO: Move to constants once we have a good path here. Will probably need to be part
// of the axum config etc.
// I'm pretty sure this can preserve query strings if we wanted to stash info or flag things?
pub const OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH: &str = "/ui/login/oauth2_landing";

/// Per-connector account-linking key selector (DL24+).
///
/// Controls which claim from the upstream identity is matched against existing local
/// Person entries when deciding whether to link an inbound login or JIT-create a new
/// account.
///
/// - `Email` — match `claims.email` against `Attribute::Mail` (pre-DL24 default).
/// - `Username` — match `claims.username_hint` against `Attribute::Name`.
/// - `Id` — match `claims.sub` against `Attribute::OAuth2AccountUniqueUserId` restricted
///   to this provider (immutable; matches only users already provisioned against this
///   connector, so first-time logins fall through to JIT).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LinkBy {
    #[default]
    Email,
    Username,
    Id,
}

impl LinkBy {
    /// Canonical string form for storage in the `oauth2_link_by` attribute.
    ///
    /// Used by the admin CLI when echoing back a `set-link-by` operation
    /// (see `netidm system oauth2-client set-link-by`). Takes `self` by value
    /// because `LinkBy` is a 1-byte `Copy` enum.
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            LinkBy::Email => "email",
            LinkBy::Username => "username",
            LinkBy::Id => "id",
        }
    }

    /// Parse strictly; returns `None` on an unknown value. Used by CLI / API input
    /// validation where we want to reject garbage rather than silently default.
    pub fn from_str_strict(s: &str) -> Option<Self> {
        match s {
            "email" => Some(LinkBy::Email),
            "username" => Some(LinkBy::Username),
            "id" => Some(LinkBy::Id),
            _ => None,
        }
    }
}

/// Discriminator selecting the concrete upstream connector implementation that
/// handles an `OAuth2Client` entry (DL28+).
///
/// Backed by the `oauth2_client_provider_kind` attribute. Absence — and the
/// case-insensitive `"generic-oidc"` — both map to [`ProviderKind::GenericOidc`],
/// which is the pre-DL28 behaviour (byte-identical per FR-016). Connector-
/// specific branches (currently only [`ProviderKind::Github`]) route the auth
/// flow to a non-OIDC callback handler in `idm::github_connector` — the
/// generic OIDC code-exchange / userinfo / JWKS path is bypassed entirely.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProviderKind {
    /// RFC 6749 + OIDC compliant upstream (the pre-DL28 default).
    #[default]
    GenericOidc,
    /// GitHub / GitHub Enterprise (non-OIDC) — PR-CONNECTOR-GITHUB.
    Github,
    /// Google Workspace / Google Identity (OIDC + Directory API) — PR-CONNECTOR-GOOGLE.
    Google,
    /// Microsoft Azure AD / Entra ID (OAuth2 + Microsoft Graph) — PR-CONNECTOR-MICROSOFT.
    Microsoft,
    /// Inbound LDAP / Active Directory password connector — PR-CONNECTOR-LDAP.
    Ldap,
    /// LinkedIn OAuth2 connector — PR-CONNECTOR-LINKEDIN.
    LinkedIn,
    /// OpenShift OAuth2 connector — PR-CONNECTOR-OPENSHIFT.
    OpenShift,
    /// GitLab OAuth2 connector — PR-CONNECTOR-GITLAB.
    GitLab,
}

impl ProviderKind {
    /// Canonical string form for storage in the `oauth2_client_provider_kind`
    /// attribute. Echoed back by the admin CLI.
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::GenericOidc => "generic-oidc",
            ProviderKind::Github => "github",
            ProviderKind::Google => "google",
            ProviderKind::Microsoft => "microsoft",
            ProviderKind::Ldap => "ldap",
            ProviderKind::LinkedIn => "linkedin",
            ProviderKind::OpenShift => "openshift",
            ProviderKind::GitLab => "gitlab",
        }
    }

    /// Lenient parse used at entry-load time. Unknown values and absence both
    /// fall back to [`ProviderKind::GenericOidc`] so legacy entries stay on
    /// the OIDC path. Garbage values are logged at `warn` by the caller so
    /// they surface in `journalctl`.
    pub fn from_str_or_default(s: &str) -> Self {
        match s {
            "github" => ProviderKind::Github,
            "google" => ProviderKind::Google,
            "microsoft" => ProviderKind::Microsoft,
            "ldap" => ProviderKind::Ldap,
            "linkedin" => ProviderKind::LinkedIn,
            "openshift" => ProviderKind::OpenShift,
            "gitlab" => ProviderKind::GitLab,
            _ => ProviderKind::GenericOidc,
        }
    }
}

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
    /// Per-connector account-linking key selector (DL24+). Defaults to `LinkBy::Email` when
    /// the `oauth2_link_by` attribute is absent, preserving pre-DL24 behaviour.
    pub(crate) link_by: LinkBy,
    /// Optional logo image URL shown on the SSO login button (DL20+).
    pub(crate) logo_uri: Option<Url>,
    /// OIDC issuer URL, set when this provider was configured via OIDC discovery (DL21+).
    pub(crate) issuer: Option<Url>,
    /// JWKS endpoint URL for cryptographic verification of id_tokens (DL21+).
    /// When set, `id_token` JWTs are verified against this JWKS rather than decoded unverified.
    pub(crate) jwks_uri: Option<Url>,
    /// Maps a Netidm attribute to the provider claim name used at JIT provisioning time.
    pub(crate) claim_map: BTreeMap<Attribute, String>,
    /// Upstream-to-netidm group mappings (DL25+). Each entry maps an
    /// upstream group name to the target netidm group's UUID. Used at
    /// login time by
    /// [`crate::idm::group_mapping::reconcile_upstream_memberships`].
    pub(crate) group_mapping: Vec<crate::idm::group_mapping::GroupMapping>,
    /// Discriminator selecting the concrete connector implementation that
    /// handles this provider's callback (DL28+). Absence / unknown values
    /// map to [`ProviderKind::GenericOidc`] — byte-identical behaviour to
    /// DL27 per FR-016.
    pub(crate) provider_kind: ProviderKind,
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
            link_by: LinkBy::default(),
            logo_uri: None,
            issuer: None,
            jwks_uri: None,
            claim_map: BTreeMap::new(),
            group_mapping: Vec::new(),
            provider_kind: ProviderKind::default(),
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

        for provider_entry in &oauth2_client_provider_entries {
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

            let link_by = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2LinkBy)
                .map(|s| {
                    LinkBy::from_str_strict(s).unwrap_or_else(|| {
                        warn!(
                            ?uuid,
                            value = %s,
                            "OAuth2 provider has an unrecognised oauth2_link_by value; \
                             falling back to LinkBy::Email"
                        );
                        LinkBy::Email
                    })
                })
                .unwrap_or_default();

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

            let mut group_mapping = Vec::new();
            if let Some(raw_values) = provider_entry
                .get_ava_set(Attribute::OAuth2GroupMapping)
                .and_then(|vs| vs.as_utf8_iter())
            {
                for raw in raw_values {
                    match crate::idm::group_mapping::GroupMapping::parse(raw) {
                        Ok(gm) => group_mapping.push(gm),
                        Err(_) => warn!(
                            ?uuid,
                            value = %raw,
                            "OAuth2GroupMapping entry is unparseable; skipping"
                        ),
                    }
                }
            }

            let provider_kind = provider_entry
                .get_ava_single_iutf8(Attribute::OAuth2ClientProviderKind)
                .map(|s| {
                    let kind = ProviderKind::from_str_or_default(s);
                    if !matches!(s, "generic-oidc" | "github" | "google" | "microsoft") {
                        warn!(
                            ?uuid,
                            value = %s,
                            "OAuth2 provider has an unrecognised oauth2_client_provider_kind \
                             value; falling back to ProviderKind::GenericOidc"
                        );
                    }
                    kind
                })
                .unwrap_or_default();

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
                link_by,
                logo_uri,
                issuer,
                jwks_uri,
                claim_map,
                group_mapping,
                provider_kind,
            };

            oauth2_client_provider_structs.push((uuid, provider));
        }

        // Clear the existing set.
        self.oauth2_client_providers.clear();

        // Add them all
        self.oauth2_client_providers
            .extend(oauth2_client_provider_structs);

        // T017: register GitHub connectors with the ConnectorRegistry.
        // Iterate all GitHub-kind entries a second time (list is already
        // resolved above; connector build may be slightly expensive so we
        // keep it separate from the main loop). Failures are logged at error
        // but MUST NOT prevent netidmd from starting.
        for provider_entry in &oauth2_client_provider_entries {
            let entry_uuid = provider_entry.get_uuid();
            let is_github = provider_entry
                .get_ava_single_iutf8(Attribute::OAuth2ClientProviderKind)
                .map(|s| s == "github")
                .unwrap_or(false);
            if !is_github {
                continue;
            }
            match crate::idm::github_connector::GitHubConfig::from_entry(
                provider_entry,
                client_redirect_uri.clone(),
            ) {
                Ok(config) => {
                    let connector = std::sync::Arc::new(
                        crate::idm::github_connector::GitHubConnector::new(config),
                    );
                    self.connector_registry.register(entry_uuid, connector);
                    trace!(?entry_uuid, "registered GitHub connector");
                }
                Err(e) => {
                    error!(
                        ?entry_uuid,
                        ?e,
                        "Failed to build GitHub connector config; skipping this provider"
                    );
                }
            }
        }

        // Register Google connectors with the ConnectorRegistry.
        for provider_entry in &oauth2_client_provider_entries {
            let entry_uuid = provider_entry.get_uuid();
            let is_google = provider_entry
                .get_ava_single_iutf8(Attribute::OAuth2ClientProviderKind)
                .map(|s| s == "google")
                .unwrap_or(false);
            if !is_google {
                continue;
            }
            match crate::idm::google_connector::GoogleConfig::from_entry(
                provider_entry,
                client_redirect_uri.clone(),
            ) {
                Ok(config) => {
                    let connector = std::sync::Arc::new(
                        crate::idm::google_connector::GoogleConnector::new(config),
                    );
                    self.connector_registry.register(entry_uuid, connector);
                    trace!(?entry_uuid, "registered Google connector");
                }
                Err(e) => {
                    error!(
                        ?entry_uuid,
                        ?e,
                        "Failed to build Google connector config; skipping this provider"
                    );
                }
            }
        }

        // Register Microsoft connectors with the ConnectorRegistry.
        for provider_entry in &oauth2_client_provider_entries {
            let entry_uuid = provider_entry.get_uuid();
            let is_microsoft = provider_entry
                .get_ava_single_iutf8(Attribute::OAuth2ClientProviderKind)
                .map(|s| s == "microsoft")
                .unwrap_or(false);
            if !is_microsoft {
                continue;
            }
            match crate::idm::microsoft_connector::MicrosoftConfig::from_entry(
                provider_entry,
                client_redirect_uri.clone(),
            ) {
                Ok(config) => {
                    let connector = std::sync::Arc::new(
                        crate::idm::microsoft_connector::MicrosoftConnector::new(config),
                    );
                    self.connector_registry.register(entry_uuid, connector);
                    trace!(?entry_uuid, "registered Microsoft connector");
                }
                Err(e) => {
                    error!(
                        ?entry_uuid,
                        ?e,
                        "Failed to build Microsoft connector config; skipping this provider"
                    );
                }
            }
        }

        // Register LDAP connectors with the ConnectorRegistry.
        for provider_entry in &oauth2_client_provider_entries {
            let entry_uuid = provider_entry.get_uuid();
            let is_ldap = provider_entry
                .get_ava_single_iutf8(Attribute::OAuth2ClientProviderKind)
                .map(|s| s == "ldap")
                .unwrap_or(false);
            if !is_ldap {
                continue;
            }
            match crate::idm::ldap_connector::LdapConfig::from_entry(provider_entry) {
                Ok(config) => {
                    let connector =
                        std::sync::Arc::new(crate::idm::ldap_connector::LdapConnector::new(config));
                    self.connector_registry.register(entry_uuid, connector);
                    trace!(?entry_uuid, "registered LDAP connector");
                }
                Err(e) => {
                    error!(
                        ?entry_uuid,
                        ?e,
                        "Failed to build LDAP connector config; skipping this provider"
                    );
                }
            }
        }

        // Register LinkedIn connectors with the ConnectorRegistry.
        for provider_entry in &oauth2_client_provider_entries {
            let entry_uuid = provider_entry.get_uuid();
            let is_linkedin = provider_entry
                .get_ava_single_iutf8(Attribute::OAuth2ClientProviderKind)
                .map(|s| s == "linkedin")
                .unwrap_or(false);
            if !is_linkedin {
                continue;
            }
            match crate::idm::linkedin_connector::LinkedInConfig::from_entry(
                provider_entry,
                client_redirect_uri.clone(),
            ) {
                Ok(config) => {
                    let connector = std::sync::Arc::new(
                        crate::idm::linkedin_connector::LinkedInConnector::new(config),
                    );
                    self.connector_registry.register(entry_uuid, connector);
                    trace!(?entry_uuid, "registered LinkedIn connector");
                }
                Err(e) => {
                    error!(
                        ?entry_uuid,
                        ?e,
                        "Failed to build LinkedIn connector config; skipping this provider"
                    );
                }
            }
        }

        // Register OpenShift connectors with the ConnectorRegistry.
        for provider_entry in &oauth2_client_provider_entries {
            let entry_uuid = provider_entry.get_uuid();
            let is_openshift = provider_entry
                .get_ava_single_iutf8(Attribute::OAuth2ClientProviderKind)
                .map(|s| s == "openshift")
                .unwrap_or(false);
            if !is_openshift {
                continue;
            }
            match crate::idm::openshift_connector::OpenShiftConfig::from_entry(
                provider_entry,
                client_redirect_uri.clone(),
            ) {
                Ok(config) => {
                    let connector = std::sync::Arc::new(
                        crate::idm::openshift_connector::OpenShiftConnector::new(config),
                    );
                    self.connector_registry.register(entry_uuid, connector);
                    trace!(?entry_uuid, "registered OpenShift connector");
                }
                Err(e) => {
                    error!(
                        ?entry_uuid,
                        ?e,
                        "Failed to build OpenShift connector config; skipping this provider"
                    );
                }
            }
        }

        // Register GitLab connectors with the ConnectorRegistry.
        for provider_entry in &oauth2_client_provider_entries {
            let entry_uuid = provider_entry.get_uuid();
            let is_gitlab = provider_entry
                .get_ava_single_iutf8(Attribute::OAuth2ClientProviderKind)
                .map(|s| s == "gitlab")
                .unwrap_or(false);
            if !is_gitlab {
                continue;
            }
            match crate::idm::gitlab_connector::GitLabConfig::from_entry(
                provider_entry,
                client_redirect_uri.clone(),
            ) {
                Ok(config) => {
                    let connector = std::sync::Arc::new(
                        crate::idm::gitlab_connector::GitLabConnector::new(config),
                    );
                    self.connector_registry.register(entry_uuid, connector);
                    trace!(?entry_uuid, "registered GitLab connector");
                }
                Err(e) => {
                    error!(
                        ?entry_uuid,
                        ?e,
                        "Failed to build GitLab connector config; skipping this provider"
                    );
                }
            }
        }

        // Register generic-OIDC connectors with the ConnectorRegistry.
        for provider_entry in &oauth2_client_provider_entries {
            let entry_uuid = provider_entry.get_uuid();
            let is_oidc = provider_entry
                .get_ava_single_iutf8(Attribute::OAuth2ClientProviderKind)
                .map(|s| s == "generic-oidc")
                .unwrap_or(true); // absence defaults to generic-oidc
            if !is_oidc {
                continue;
            }
            match crate::idm::generic_oidc_connector::GenericOidcConfig::from_entry(
                provider_entry,
                client_redirect_uri.clone(),
            ) {
                Ok(config) => {
                    let connector = std::sync::Arc::new(
                        crate::idm::generic_oidc_connector::GenericOidcConnector::new(config),
                    );
                    self.connector_registry.register(entry_uuid, connector);
                    trace!(?entry_uuid, "registered generic-OIDC connector");
                }
                Err(e) => {
                    error!(
                        ?entry_uuid,
                        ?e,
                        "Failed to build generic-OIDC connector config; skipping this provider"
                    );
                }
            }
        }

        Ok(())
    }
}
