//! Access control profiles updated for DL29.
//!
//! The existing `idm_acp_connector_admin` ACP gains the ten new DL29
//! generic-OIDC attributes in its search / modify / create allowlists.
//!
//! Forked from `IDM_ACP_OAUTH2_CLIENT_ADMIN_DL28`; unchanged except for
//! the new attribute additions.

use crate::constants::{
    UUID_IDM_ACP_OAUTH2_CLIENT_ADMIN, UUID_IDM_OAUTH2_CLIENT_ADMINS, UUID_SYSTEM_ADMINS,
};
use crate::prelude::*;

pub(crate) use crate::migration_data::dl21::access::{
    BuiltinAcp, BuiltinAcpReceiver, BuiltinAcpTarget,
};

static FILTER_RECYCLED_OR_TOMBSTONE_DL29: LazyLock<ProtoFilter> = LazyLock::new(|| {
    ProtoFilter::Or(vec![
        match_class_filter!(EntryClass::Recycled),
        match_class_filter!(EntryClass::Tombstone),
    ])
});

static FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL29: LazyLock<ProtoFilter> =
    LazyLock::new(|| ProtoFilter::AndNot(Box::new(FILTER_RECYCLED_OR_TOMBSTONE_DL29.clone())));

/// DL29 refresh of `idm_acp_connector_admin`. Forks DL28 and adds the
/// ten generic-OIDC connector config attributes introduced by
/// PR-CONNECTOR-GENERIC-OIDC.
pub(crate) static IDM_ACP_OAUTH2_CLIENT_ADMIN_DL29: LazyLock<BuiltinAcp> =
    LazyLock::new(|| BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_connector_admin",
        uuid: UUID_IDM_ACP_OAUTH2_CLIENT_ADMIN,
        description:
            "Builtin IDM Control for granting oauth2 trust provider administration rights.",
        receiver: BuiltinAcpReceiver::Group(vec![
            UUID_IDM_OAUTH2_CLIENT_ADMINS,
            UUID_SYSTEM_ADMINS,
        ]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Connector),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL29.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::Spn,
            Attribute::ConnectorId,
            Attribute::ConnectorSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::ConnectorLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            // DL28 additions
            Attribute::ConnectorProviderKind,
            Attribute::ConnectorGithubHost,
            Attribute::ConnectorGithubOrgFilter,
            Attribute::ConnectorGithubAllowedTeams,
            Attribute::ConnectorGithubTeamNameField,
            Attribute::ConnectorGithubLoadAllGroups,
            Attribute::ConnectorGithubPreferredEmailDomain,
            Attribute::ConnectorGithubAllowJitProvisioning,
            // DL29 additions
            Attribute::ConnectorOidcEnableGroups,
            Attribute::ConnectorOidcGroupsKey,
            Attribute::ConnectorOidcSkipEmailVerified,
            Attribute::ConnectorOidcAllowedGroups,
            Attribute::ConnectorOidcGetUserInfo,
            Attribute::ConnectorOidcUserIdKey,
            Attribute::ConnectorOidcUserNameKey,
            Attribute::ConnectorOidcOverrideClaimMapping,
            Attribute::ConnectorOidcGroupsPrefix,
            Attribute::ConnectorOidcGroupsSuffix,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::ConnectorId,
            Attribute::ConnectorSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::ConnectorLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            // DL28 additions
            Attribute::ConnectorProviderKind,
            Attribute::ConnectorGithubHost,
            Attribute::ConnectorGithubOrgFilter,
            Attribute::ConnectorGithubAllowedTeams,
            Attribute::ConnectorGithubTeamNameField,
            Attribute::ConnectorGithubLoadAllGroups,
            Attribute::ConnectorGithubPreferredEmailDomain,
            Attribute::ConnectorGithubAllowJitProvisioning,
            // DL29 additions
            Attribute::ConnectorOidcEnableGroups,
            Attribute::ConnectorOidcGroupsKey,
            Attribute::ConnectorOidcSkipEmailVerified,
            Attribute::ConnectorOidcAllowedGroups,
            Attribute::ConnectorOidcGetUserInfo,
            Attribute::ConnectorOidcUserIdKey,
            Attribute::ConnectorOidcUserNameKey,
            Attribute::ConnectorOidcOverrideClaimMapping,
            Attribute::ConnectorOidcGroupsPrefix,
            Attribute::ConnectorOidcGroupsSuffix,
        ],
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::ConnectorId,
            Attribute::ConnectorSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::ConnectorLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            // DL28 additions
            Attribute::ConnectorProviderKind,
            Attribute::ConnectorGithubHost,
            Attribute::ConnectorGithubOrgFilter,
            Attribute::ConnectorGithubAllowedTeams,
            Attribute::ConnectorGithubTeamNameField,
            Attribute::ConnectorGithubLoadAllGroups,
            Attribute::ConnectorGithubPreferredEmailDomain,
            Attribute::ConnectorGithubAllowJitProvisioning,
            // DL29 additions
            Attribute::ConnectorOidcEnableGroups,
            Attribute::ConnectorOidcGroupsKey,
            Attribute::ConnectorOidcSkipEmailVerified,
            Attribute::ConnectorOidcAllowedGroups,
            Attribute::ConnectorOidcGetUserInfo,
            Attribute::ConnectorOidcUserIdKey,
            Attribute::ConnectorOidcUserNameKey,
            Attribute::ConnectorOidcOverrideClaimMapping,
            Attribute::ConnectorOidcGroupsPrefix,
            Attribute::ConnectorOidcGroupsSuffix,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::ConnectorId,
            Attribute::ConnectorSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::ConnectorLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            // DL28 additions
            Attribute::ConnectorProviderKind,
            Attribute::ConnectorGithubHost,
            Attribute::ConnectorGithubOrgFilter,
            Attribute::ConnectorGithubAllowedTeams,
            Attribute::ConnectorGithubTeamNameField,
            Attribute::ConnectorGithubLoadAllGroups,
            Attribute::ConnectorGithubPreferredEmailDomain,
            Attribute::ConnectorGithubAllowJitProvisioning,
            // DL29 additions
            Attribute::ConnectorOidcEnableGroups,
            Attribute::ConnectorOidcGroupsKey,
            Attribute::ConnectorOidcSkipEmailVerified,
            Attribute::ConnectorOidcAllowedGroups,
            Attribute::ConnectorOidcGetUserInfo,
            Attribute::ConnectorOidcUserIdKey,
            Attribute::ConnectorOidcUserNameKey,
            Attribute::ConnectorOidcOverrideClaimMapping,
            Attribute::ConnectorOidcGroupsPrefix,
            Attribute::ConnectorOidcGroupsSuffix,
        ],
        create_classes: vec![EntryClass::Object, EntryClass::Connector],
        ..Default::default()
    });
