//! Schema entries for DL22: SAML 2.0 upstream connector (SamlClient entry class).

#[cfg(test)]
pub(crate) use crate::migration_data::dl14::schema::SCHEMA_ATTR_DISPLAYNAME_DL7;

use crate::constants::{
    UUID_SCHEMA_ATTR_SAML_ACS_URL, UUID_SCHEMA_ATTR_SAML_ATTR_MAP_DISPLAYNAME,
    UUID_SCHEMA_ATTR_SAML_ATTR_MAP_EMAIL, UUID_SCHEMA_ATTR_SAML_ATTR_MAP_GROUPS,
    UUID_SCHEMA_ATTR_SAML_ENTITY_ID, UUID_SCHEMA_ATTR_SAML_IDP_CERTIFICATE,
    UUID_SCHEMA_ATTR_SAML_IDP_SSO_URL, UUID_SCHEMA_ATTR_SAML_JIT_PROVISIONING,
    UUID_SCHEMA_ATTR_SAML_NAME_ID_FORMAT, UUID_SCHEMA_CLASS_SAML_CLIENT,
};
use crate::prelude::*;

pub static SCHEMA_ATTR_SAML_IDP_SSO_URL_DL22: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_IDP_SSO_URL,
        name: Attribute::SamlIdpSsoUrl,
        description: "IdP HTTP-POST SSO endpoint URL.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

pub static SCHEMA_ATTR_SAML_IDP_CERTIFICATE_DL22: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_IDP_CERTIFICATE,
        name: Attribute::SamlIdpCertificate,
        description: "IdP X.509 signing certificate in PEM format.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_SAML_ENTITY_ID_DL22: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_ENTITY_ID,
        name: Attribute::SamlEntityId,
        description: "SP entity ID (our issuer in AuthnRequests).".to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

pub static SCHEMA_ATTR_SAML_ACS_URL_DL22: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_ACS_URL,
        name: Attribute::SamlAcsUrl,
        description: "Assertion Consumer Service URL where the IdP POSTs SAML Responses."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

pub static SCHEMA_ATTR_SAML_NAME_ID_FORMAT_DL22: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_NAME_ID_FORMAT,
        name: Attribute::SamlNameIdFormat,
        description: "Requested NameID format URI; absent implies unspecified.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_SAML_ATTR_MAP_EMAIL_DL22: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_ATTR_MAP_EMAIL,
        name: Attribute::SamlAttrMapEmail,
        description: "Assertion attribute name whose value is the user's email address."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_SAML_ATTR_MAP_DISPLAYNAME_DL22: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_ATTR_MAP_DISPLAYNAME,
        name: Attribute::SamlAttrMapDisplayname,
        description: "Assertion attribute name whose value is the user's display name.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_SAML_ATTR_MAP_GROUPS_DL22: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_ATTR_MAP_GROUPS,
        name: Attribute::SamlAttrMapGroups,
        description: "Assertion attribute name whose values are the user's group names."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

pub static SCHEMA_ATTR_SAML_JIT_PROVISIONING_DL22: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_JIT_PROVISIONING,
        name: Attribute::SamlJitProvisioning,
        description: "Whether to auto-create accounts for first-time SAML users.".to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// Schema class for a SAML 2.0 Identity Provider configuration.
pub static SCHEMA_CLASS_SAML_CLIENT_DL22: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SAML_CLIENT,
    name: EntryClass::SamlClient.into(),
    description: "A SAML 2.0 Identity Provider configuration used for SP-initiated SSO."
        .to_string(),
    systemmust: vec![
        Attribute::Name,
        Attribute::DisplayName,
        Attribute::SamlIdpSsoUrl,
        Attribute::SamlIdpCertificate,
        Attribute::SamlEntityId,
        Attribute::SamlAcsUrl,
    ],
    systemmay: vec![
        Attribute::SamlNameIdFormat,
        Attribute::SamlAttrMapEmail,
        Attribute::SamlAttrMapDisplayname,
        Attribute::SamlAttrMapGroups,
        Attribute::SamlJitProvisioning,
    ],
    ..Default::default()
});
