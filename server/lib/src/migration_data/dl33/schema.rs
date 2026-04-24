//! Schema entries for DL33: SAML connector dex-parity additions (PR-CONNECTOR-SAML).
//!
//! Adds five optional config attributes on `EntryClass::SamlClient`:
//! `SamlSsoIssuer`, `SamlInsecureSkipSigValidation`, `SamlGroupsDelim`,
//! `SamlAllowedGroups`, and `SamlFilterGroups`.

use crate::constants::{
    UUID_SCHEMA_ATTR_SAML_ALLOWED_GROUPS, UUID_SCHEMA_ATTR_SAML_FILTER_GROUPS,
    UUID_SCHEMA_ATTR_SAML_GROUPS_DELIM, UUID_SCHEMA_ATTR_SAML_INSECURE_SKIP_SIG_VALIDATION,
    UUID_SCHEMA_ATTR_SAML_SSO_ISSUER, UUID_SCHEMA_CLASS_SAML_CLIENT,
};
use crate::prelude::*;

/// Expected issuer string in SAML responses. When set, any response whose
/// `<Issuer>` element does not match is rejected.
pub static SCHEMA_ATTR_SAML_SSO_ISSUER_DL33: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_SSO_ISSUER,
        name: Attribute::SamlSsoIssuer,
        description: "Expected issuer in SAML responses. When set, responses with a \
                      non-matching <Issuer> element are rejected."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// When true, XML signature validation on SAML responses is skipped.
/// Dangerous — use only in dev/test against trusted IdPs.
pub static SCHEMA_ATTR_SAML_INSECURE_SKIP_SIG_VALIDATION_DL33: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_INSECURE_SKIP_SIG_VALIDATION,
        name: Attribute::SamlInsecureSkipSigValidation,
        description: "When true, skip XML signature validation on SAML responses. \
                      Dangerous — use only in dev/test. Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// Delimiter used to split a single group attribute value into multiple group names.
/// When set, the group attribute is expected to contain a delimiter-separated list
/// (e.g. `","` → `"admin,ops"` becomes `["admin", "ops"]`). When absent, multi-value
/// collection is used instead.
pub static SCHEMA_ATTR_SAML_GROUPS_DELIM_DL33: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_GROUPS_DELIM,
        name: Attribute::SamlGroupsDelim,
        description: "Delimiter for splitting a single group attribute value into multiple \
                      group names (e.g. \",\"). When absent, multi-valued collection is used."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Allowlist of group names. When set, only users in at least one listed group are
/// permitted to authenticate. Multi-value — each value is one allowed group name.
pub static SCHEMA_ATTR_SAML_ALLOWED_GROUPS_DL33: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_ALLOWED_GROUPS,
        name: Attribute::SamlAllowedGroups,
        description: "Allowlist of group names. Users not in any listed group are rejected. \
                      Multi-value — each value is one permitted group name."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// When true and `saml_allowed_groups` is set, only the matching allowed groups
/// are returned in the user's group claims. When false, all groups are returned
/// (allowed_groups acts only as an access gate).
pub static SCHEMA_ATTR_SAML_FILTER_GROUPS_DL33: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_SAML_FILTER_GROUPS,
        name: Attribute::SamlFilterGroups,
        description: "When true and saml_allowed_groups is set, trim group claims to only \
                      the allowed set. When false, allowed_groups is an access gate only. \
                      Default: false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// SAML client class updated for DL33: adds the five dex-parity config attributes
/// to `systemmay`. Carries forward all DL26 `systemmay` entries.
pub static SCHEMA_CLASS_SAML_CLIENT_DL33: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
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
        Attribute::SamlGroupMapping,
        Attribute::SamlSingleLogoutServiceUrl,
        // DL33 additions — PR-CONNECTOR-SAML
        Attribute::SamlSsoIssuer,
        Attribute::SamlInsecureSkipSigValidation,
        Attribute::SamlGroupsDelim,
        Attribute::SamlAllowedGroups,
        Attribute::SamlFilterGroups,
    ],
    ..Default::default()
});
