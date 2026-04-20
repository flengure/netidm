use crate::idm::server::{IdmServerProxyReadTransaction, IdmServerProxyWriteTransaction};
use crate::prelude::*;
use std::fmt;

#[derive(Clone)]
#[allow(dead_code)]
pub struct SamlClientProvider {
    pub(crate) name: String,
    pub(crate) display_name: String,
    pub(crate) uuid: Uuid,
    /// Our SP entity ID.
    pub(crate) entity_id: Url,
    /// IdP HTTP-POST SSO endpoint.
    pub(crate) idp_sso_url: Url,
    /// PEM-encoded IdP signing certificate.
    pub(crate) idp_certificate: String,
    /// Our ACS (assertion consumer service) URL.
    pub(crate) acs_url: Url,
    /// Optional NameID format hint (e.g. "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress").
    pub(crate) name_id_format: Option<String>,
    /// Assertion attribute name that maps to user email.
    pub(crate) attr_map_email: Option<String>,
    /// Assertion attribute name that maps to display name.
    pub(crate) attr_map_displayname: Option<String>,
    /// Assertion attribute name that maps to group memberships.
    pub(crate) attr_map_groups: Option<String>,
    /// Create a new local account on first successful SAML assertion.
    pub(crate) jit_provisioning: bool,
    /// Upstream-to-netidm group mappings (DL25+). Each entry maps an
    /// upstream group name to the target netidm group's UUID. Used at
    /// login time by
    /// [`crate::idm::group_mapping::reconcile_upstream_memberships`].
    pub(crate) group_mapping: Vec<crate::idm::group_mapping::GroupMapping>,
}

impl fmt::Debug for SamlClientProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SamlClientProvider")
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("uuid", &self.uuid)
            .field("entity_id", &self.entity_id)
            .field("idp_sso_url", &self.idp_sso_url)
            .finish()
    }
}

impl IdmServerProxyWriteTransaction<'_> {
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_saml_client_providers(&mut self) -> Result<(), OperationError> {
        let entries = self.qs_write.internal_search(filter!(f_eq(
            Attribute::Class,
            EntryClass::SamlClient.into(),
        )))?;

        let mut providers = Vec::with_capacity(entries.len());

        for entry in entries {
            let uuid = entry.get_uuid();
            trace!(?uuid, "Loading SamlClientProvider");

            let name = entry
                .get_ava_single_iname(Attribute::Name)
                .map(str::to_string)
                .ok_or(OperationError::InvalidValueState)?;

            let display_name = entry
                .get_ava_single_utf8(Attribute::DisplayName)
                .map(str::to_string)
                .unwrap_or_else(|| name.clone());

            let entity_id = entry
                .get_ava_single_url(Attribute::SamlEntityId)
                .cloned()
                .ok_or(OperationError::InvalidValueState)?;

            let idp_sso_url = entry
                .get_ava_single_url(Attribute::SamlIdpSsoUrl)
                .cloned()
                .ok_or(OperationError::InvalidValueState)?;

            let idp_certificate = entry
                .get_ava_single_utf8(Attribute::SamlIdpCertificate)
                .map(str::to_string)
                .ok_or(OperationError::InvalidValueState)?;

            let acs_url = entry
                .get_ava_single_url(Attribute::SamlAcsUrl)
                .cloned()
                .ok_or(OperationError::InvalidValueState)?;

            let name_id_format = entry
                .get_ava_single_utf8(Attribute::SamlNameIdFormat)
                .map(str::to_string);

            let attr_map_email = entry
                .get_ava_single_utf8(Attribute::SamlAttrMapEmail)
                .map(str::to_string);

            let attr_map_displayname = entry
                .get_ava_single_utf8(Attribute::SamlAttrMapDisplayname)
                .map(str::to_string);

            let attr_map_groups = entry
                .get_ava_single_utf8(Attribute::SamlAttrMapGroups)
                .map(str::to_string);

            let jit_provisioning = entry
                .get_ava_single_bool(Attribute::SamlJitProvisioning)
                .unwrap_or(false);

            let mut group_mapping = Vec::new();
            if let Some(raw_values) = entry
                .get_ava_set(Attribute::SamlGroupMapping)
                .and_then(|vs| vs.as_utf8_iter())
            {
                for raw in raw_values {
                    match crate::idm::group_mapping::GroupMapping::parse(raw) {
                        Ok(gm) => group_mapping.push(gm),
                        Err(_) => warn!(
                            ?uuid,
                            value = %raw,
                            "SamlGroupMapping entry is unparseable; skipping"
                        ),
                    }
                }
            }

            providers.push((
                uuid,
                SamlClientProvider {
                    name,
                    display_name,
                    uuid,
                    entity_id,
                    idp_sso_url,
                    idp_certificate,
                    acs_url,
                    name_id_format,
                    attr_map_email,
                    attr_map_displayname,
                    attr_map_groups,
                    jit_provisioning,
                    group_mapping,
                },
            ));
        }

        self.saml_client_providers.clear();
        self.saml_client_providers.extend(providers);

        Ok(())
    }
}

impl IdmServerProxyReadTransaction<'_> {
    /// Find a SAML client provider by name (case-sensitive iname match).
    pub fn get_saml_client_provider_by_name(&self, name: &str) -> Option<SamlClientProvider> {
        self.saml_client_providers
            .iter()
            .find(|(_, p)| p.name == name)
            .map(|(_, p)| p.clone())
    }
}

impl IdmServerProxyWriteTransaction<'_> {
    /// Find a SAML client provider by name (case-sensitive iname match).
    pub fn get_saml_client_provider_by_name(&self, name: &str) -> Option<SamlClientProvider> {
        self.saml_client_providers
            .iter()
            .find(|(_, p)| p.name == name)
            .map(|(_, p)| p.clone())
    }
}
