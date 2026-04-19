use crate::idm::saml_client::SamlClientProvider;
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

fn build_service_provider(provider: &SamlClientProvider) -> Result<ServiceProvider, OperationError> {
    let cert_b64 = pem_to_base64(&provider.idp_certificate);

    let key_descriptor = KeyDescriptor {
        key_use: Some("signing".to_string()),
        key_info: KeyInfo {
            id: None,
            x509_data: Some(X509Data {
                certificates: vec![cert_b64],
            }),
        },
        encryption_methods: None,
    };

    let idp_descriptor = IdpSsoDescriptor {
        id: None,
        valid_until: None,
        cache_duration: None,
        protocol_support_enumeration: None,
        error_url: None,
        signature: None,
        key_descriptors: vec![key_descriptor],
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
    let sp = build_service_provider(provider)?;

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
) -> Result<SamlClaims, OperationError> {
    let sp = build_service_provider(provider)?;

    let assertion = sp
        .parse_base64_response(encoded_response, Some(&[request_id]))
        .map_err(|e| {
            warn!("SAML Response validation failed: {:?}", e);
            OperationError::NotAuthenticated
        })?;

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
            let values: Vec<String> = attr
                .values
                .iter()
                .filter_map(|v| v.value.clone())
                .collect();
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

    let groups = provider
        .attr_map_groups
        .as_deref()
        .and_then(|key| attributes.get(key))
        .cloned()
        .unwrap_or_default();

    Ok(SamlClaims {
        name_id,
        email,
        display_name,
        groups,
    })
}
