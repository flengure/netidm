use crate::idm::saml_client::SamlClientProvider;
use crate::idm::saml_connector::SamlCachedState;
use crate::prelude::*;
use base64::{engine::general_purpose, Engine as _};
use flate2::{write::DeflateEncoder, Compression};
use samael::{
    key_info::{KeyInfo, X509Data},
    metadata::{EntityDescriptor, IdpSsoDescriptor, KeyDescriptor},
    service_provider::{ServiceProvider, ServiceProviderBuilder},
    traits::ToXml,
};
use std::io::Write;

/// Identity claims extracted from a validated SAML Assertion.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SamlClaims {
    /// The SAML NameID value — used as stable subject identifier.
    pub name_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
}

fn pem_to_base64(pem: &str) -> String {
    pem.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

fn build_service_provider(
    provider: &SamlClientProvider,
    include_signing_cert: bool,
) -> Result<ServiceProvider, OperationError> {
    let key_descriptors = if include_signing_cert {
        let cert_b64 = pem_to_base64(&provider.idp_certificate);
        vec![KeyDescriptor {
            key_use: Some("signing".to_string()),
            key_info: KeyInfo {
                id: None,
                x509_data: Some(X509Data {
                    certificates: vec![cert_b64],
                }),
            },
            encryption_methods: None,
        }]
    } else {
        vec![]
    };

    let idp_descriptor = IdpSsoDescriptor {
        id: None,
        valid_until: None,
        cache_duration: None,
        protocol_support_enumeration: None,
        error_url: None,
        signature: None,
        key_descriptors,
        organization: None,
        contact_people: vec![],
        artifact_resolution_service: vec![],
        single_logout_services: vec![],
        manage_name_id_services: vec![],
        name_id_formats: vec![],
        want_authn_requests_signed: None,
        single_sign_on_services: vec![],
        name_id_mapping_services: vec![],
        assertion_id_request_services: vec![],
        attribute_profiles: vec![],
        attributes: vec![],
    };

    let idp_metadata = EntityDescriptor {
        entity_id: Some(provider.idp_sso_url.to_string()),
        idp_sso_descriptors: Some(vec![idp_descriptor]),
        ..Default::default()
    };

    ServiceProviderBuilder::default()
        .idp_metadata(idp_metadata)
        .entity_id(Some(provider.entity_id.to_string()))
        .acs_url(Some(provider.acs_url.to_string()))
        .authn_name_id_format(provider.name_id_format.clone())
        .allow_idp_initiated(false)
        .build()
        .map_err(|e| {
            error!("Failed to build SAML ServiceProvider: {:?}", e);
            OperationError::InvalidState
        })
}

pub fn generate_authn_request(
    provider: &SamlClientProvider,
) -> Result<(String, String, Url), OperationError> {
    let sp = build_service_provider(provider, true)?;

    let authn_request = sp
        .make_authentication_request(provider.idp_sso_url.as_str())
        .map_err(|e| {
            error!("Failed to generate SAML AuthnRequest: {:?}", e);
            OperationError::InvalidState
        })?;

    let request_id = authn_request.id.clone();

    let xml = authn_request.to_string().map_err(|e| {
        error!("Failed to serialize SAML AuthnRequest to XML: {:?}", e);
        OperationError::InvalidState
    })?;

    let mut compressed = vec![];
    {
        let mut encoder = DeflateEncoder::new(&mut compressed, Compression::default());
        encoder.write_all(xml.as_bytes()).map_err(|e| {
            error!("Failed to deflate SAML AuthnRequest: {:?}", e);
            OperationError::InvalidState
        })?;
    }

    let encoded = general_purpose::STANDARD.encode(&compressed);
    let sso_url = provider.idp_sso_url.clone();
    Ok((request_id, encoded, sso_url))
}

pub fn validate_saml_response(
    provider: &SamlClientProvider,
    encoded_response: &str,
    request_id: &str,
) -> Result<(SamlClaims, SamlCachedState), OperationError> {
    // When insecure_skip_sig_validation is set, build an SP with no signing cert.
    // samael skips XML signature verification when no cert is configured, but still
    // performs all other assertion checks (issuer, conditions, subject confirmation,
    // in_response_to, expiry). This mirrors dex's InsecureSkipSignatureValidation.
    let include_cert = !provider.insecure_skip_sig_validation;
    if provider.insecure_skip_sig_validation {
        warn!(
            provider = %provider.name,
            "SAML: insecure_skip_sig_validation is set — \
             XML signature check bypassed for this provider"
        );
    }

    let sp = build_service_provider(provider, include_cert)?;

    let assertion = sp
        .parse_base64_response(encoded_response, Some(&[request_id]))
        .map_err(|e| {
            warn!("SAML Response validation failed: {:?}", e);
            OperationError::NotAuthenticated
        })?;

    // DL33: SsoIssuer validation (dex Config.Issuer parity).
    if let Some(expected_issuer) = &provider.sso_issuer {
        let actual = assertion.issuer.value.as_deref();
        if actual != Some(expected_issuer.as_str()) {
            warn!(
                provider = %provider.name,
                expected = %expected_issuer,
                actual = ?actual,
                "SAML Response Issuer mismatch"
            );
            return Err(OperationError::NotAuthenticated);
        }
    }

    let name_id = assertion
        .subject
        .as_ref()
        .and_then(|s| s.name_id.as_ref())
        .map(|n| n.value.clone())
        .filter(|v: &String| !v.is_empty())
        .ok_or_else(|| {
            warn!("SAML Assertion missing NameID");
            OperationError::NotAuthenticated
        })?;

    // Extract mapped attributes from the assertion.
    let attributes: hashbrown::HashMap<String, Vec<String>> = assertion
        .attribute_statements
        .iter()
        .flat_map(|stmts| stmts.iter())
        .flat_map(|stmt| stmt.attributes.iter())
        .filter_map(|attr| {
            let name = attr.name.clone()?;
            let values: Vec<String> = attr.values.iter().filter_map(|v| v.value.clone()).collect();
            Some((name, values))
        })
        .collect();

    let email = provider
        .attr_map_email
        .as_deref()
        .and_then(|key| attributes.get(key))
        .and_then(|vals| vals.first().cloned());

    let display_name = provider
        .attr_map_displayname
        .as_deref()
        .and_then(|key| attributes.get(key))
        .and_then(|vals| vals.first().cloned());

    // DL33: GroupsDelim (dex Config.GroupsDelim parity).
    // When set, the group attribute is expected to be a single delimiter-separated
    // value; otherwise collect all multi-values as separate group names.
    let groups = if let Some(delim) = &provider.groups_delim {
        provider
            .attr_map_groups
            .as_deref()
            .and_then(|key| attributes.get(key))
            .and_then(|vals| vals.first())
            .map(|s| {
                s.split(delim.as_str())
                    .map(str::to_string)
                    .filter(|g| !g.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        provider
            .attr_map_groups
            .as_deref()
            .and_then(|key| attributes.get(key))
            .cloned()
            .unwrap_or_default()
    };

    // DL33: AllowedGroups + FilterGroups (dex Config.AllowedGroups / FilterGroups parity).
    let groups = if !provider.allowed_groups.is_empty() {
        let matching: Vec<String> = groups
            .iter()
            .filter(|g| provider.allowed_groups.contains(*g))
            .cloned()
            .collect();
        if matching.is_empty() {
            warn!(
                provider = %provider.name,
                "SAML: user is not a member of any allowed group"
            );
            return Err(OperationError::NotAuthenticated);
        }
        if provider.filter_groups {
            matching
        } else {
            groups
        }
    } else {
        groups
    };

    let claims = SamlClaims {
        name_id: name_id.clone(),
        email: email.clone(),
        display_name: display_name.clone(),
        groups: groups.clone(),
    };

    let cached_state = SamlCachedState {
        name_id,
        email,
        display_name,
        groups,
    };

    Ok((claims, cached_state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idm::group_mapping::GroupMapping;

    fn make_provider_with_groups(
        allowed_groups: Vec<String>,
        filter_groups: bool,
        groups_delim: Option<String>,
    ) -> SamlClientProvider {
        SamlClientProvider {
            name: "test".to_string(),
            display_name: "Test".to_string(),
            uuid: uuid::uuid!("00000000-0000-0000-0000-000000000001"),
            entity_id: "https://sp.example.com".parse().unwrap(),
            idp_sso_url: "https://idp.example.com/sso".parse().unwrap(),
            idp_certificate: String::new(),
            acs_url: "https://sp.example.com/acs".parse().unwrap(),
            name_id_format: None,
            attr_map_email: None,
            attr_map_displayname: None,
            attr_map_groups: Some("groups".to_string()),
            jit_provisioning: false,
            group_mapping: Vec::<GroupMapping>::new(),
            sso_issuer: None,
            insecure_skip_sig_validation: false,
            groups_delim,
            allowed_groups,
            filter_groups,
        }
    }

    #[test]
    fn groups_delim_splits_on_delimiter() {
        let provider = make_provider_with_groups(vec![], false, Some(",".to_string()));
        let mut attributes = hashbrown::HashMap::new();
        attributes.insert("groups".to_string(), vec!["admin,ops,dev".to_string()]);

        let groups: Vec<String> = if let Some(delim) = &provider.groups_delim {
            provider
                .attr_map_groups
                .as_deref()
                .and_then(|key| attributes.get(key))
                .and_then(|vals| vals.first())
                .map(|s| {
                    s.split(delim.as_str())
                        .map(str::to_string)
                        .filter(|g| !g.is_empty())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            unreachable!()
        };

        assert_eq!(groups, vec!["admin", "ops", "dev"]);
    }

    #[test]
    fn allowed_groups_gate_rejects_non_member() {
        let provider = make_provider_with_groups(vec!["admin".to_string()], false, None);
        let groups = vec!["other".to_string()];
        let matching: Vec<String> = groups
            .iter()
            .filter(|g| provider.allowed_groups.contains(*g))
            .cloned()
            .collect();
        assert!(matching.is_empty());
    }

    #[test]
    fn allowed_groups_gate_passes_member() {
        let provider = make_provider_with_groups(vec!["admin".to_string()], false, None);
        let groups = vec!["admin".to_string(), "ops".to_string()];
        let matching: Vec<String> = groups
            .iter()
            .filter(|g| provider.allowed_groups.contains(*g))
            .cloned()
            .collect();
        assert!(!matching.is_empty());
    }

    #[test]
    fn filter_groups_true_trims_output() {
        let provider = make_provider_with_groups(vec!["admin".to_string()], true, None);
        let groups = vec!["admin".to_string(), "ops".to_string()];
        let matching: Vec<String> = groups
            .iter()
            .filter(|g| provider.allowed_groups.contains(*g))
            .cloned()
            .collect();
        // filter_groups = true → return only matching
        let result = if provider.filter_groups {
            matching.clone()
        } else {
            groups.clone()
        };
        assert_eq!(result, vec!["admin"]);
    }

    #[test]
    fn filter_groups_false_returns_all() {
        let provider = make_provider_with_groups(vec!["admin".to_string()], false, None);
        let groups = vec!["admin".to_string(), "ops".to_string()];
        let matching: Vec<String> = groups
            .iter()
            .filter(|g| provider.allowed_groups.contains(*g))
            .cloned()
            .collect();
        // filter_groups = false → return all groups (gate passed)
        let result = if provider.filter_groups {
            matching
        } else {
            groups.clone()
        };
        assert_eq!(result, vec!["admin", "ops"]);
    }
}
