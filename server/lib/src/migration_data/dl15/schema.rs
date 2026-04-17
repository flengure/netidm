//! Schema entries for DL15: OAuth2 social login with JIT provisioning.


use crate::constants::{
    UUID_SCHEMA_ATTR_OAUTH2_CLAIM_MAP_DISPLAYNAME, UUID_SCHEMA_ATTR_OAUTH2_CLAIM_MAP_EMAIL,
    UUID_SCHEMA_ATTR_OAUTH2_CLAIM_MAP_NAME, UUID_SCHEMA_ATTR_OAUTH2_JIT_PROVISIONING,
    UUID_SCHEMA_ATTR_OAUTH2_USERINFO_ENDPOINT, UUID_SCHEMA_CLASS_OAUTH2_CLIENT,
};
use crate::prelude::*;

// T005
pub static SCHEMA_ATTR_OAUTH2_USERINFO_ENDPOINT_DL15: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_USERINFO_ENDPOINT,
        name: Attribute::OAuth2UserinfoEndpoint,
        description: "The userinfo endpoint URL for non-OIDC OAuth2 providers (e.g. GitHub)."
            .to_string(),
        syntax: SyntaxType::Url,
        ..Default::default()
    });

// T006
pub static SCHEMA_ATTR_OAUTH2_JIT_PROVISIONING_DL15: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_JIT_PROVISIONING,
        name: Attribute::OAuth2JitProvisioning,
        description:
            "When true, automatically create a Netidm account for first-time users of this provider."
                .to_string(),
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

// T007
pub static SCHEMA_ATTR_OAUTH2_CLAIM_MAP_NAME_DL15: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLAIM_MAP_NAME,
        name: Attribute::OAuth2ClaimMapName,
        description:
            "The provider claim name to use as the Netidm account username (iname) on JIT provisioning."
                .to_string(),
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

// T008
pub static SCHEMA_ATTR_OAUTH2_CLAIM_MAP_DISPLAYNAME_DL15: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLAIM_MAP_DISPLAYNAME,
        name: Attribute::OAuth2ClaimMapDisplayname,
        description:
            "The provider claim name to use as the Netidm account display name on JIT provisioning."
                .to_string(),
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

// T009
pub static SCHEMA_ATTR_OAUTH2_CLAIM_MAP_EMAIL_DL15: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_CLAIM_MAP_EMAIL,
        name: Attribute::OAuth2ClaimMapEmail,
        description:
            "The provider claim name to use as the Netidm account email address on JIT provisioning."
                .to_string(),
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

// T010 — updated OAuth2Client class with new optional attributes
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL15: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_CLIENT,
    name: EntryClass::OAuth2Client.into(),
    description:
        "The class representing a configured OAuth2 Confidential Client acting as an authentication source."
            .to_string(),
    systemmust: vec![
        Attribute::Name,
        Attribute::OAuth2ClientId,
        Attribute::OAuth2ClientSecret,
        Attribute::OAuth2AuthorisationEndpoint,
        Attribute::OAuth2TokenEndpoint,
        Attribute::OAuth2RequestScopes,
    ],
    systemmay: vec![
        Attribute::OAuth2UserinfoEndpoint,
        Attribute::OAuth2JitProvisioning,
        Attribute::OAuth2ClaimMapName,
        Attribute::OAuth2ClaimMapDisplayname,
        Attribute::OAuth2ClaimMapEmail,
    ],
    ..Default::default()
});
