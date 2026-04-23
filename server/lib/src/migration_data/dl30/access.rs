//! Access control profiles updated for DL30.
//!
//! The existing `idm_acp_oauth2_client_admin` ACP gains the four new DL30
//! Google-specific attributes in its search / modify / create allowlists.
//!
//! Forked from `IDM_ACP_OAUTH2_CLIENT_ADMIN_DL29`; unchanged except for
//! the new attribute additions.

use crate::constants::{
    UUID_IDM_ACP_OAUTH2_CLIENT_ADMIN, UUID_IDM_OAUTH2_CLIENT_ADMINS, UUID_SYSTEM_ADMINS,
};
use crate::prelude::*;

pub(crate) use crate::migration_data::dl21::access::{
    BuiltinAcp, BuiltinAcpReceiver, BuiltinAcpTarget,
};

static FILTER_RECYCLED_OR_TOMBSTONE_DL30: LazyLock<ProtoFilter> = LazyLock::new(|| {
    ProtoFilter::Or(vec![
        match_class_filter!(EntryClass::Recycled),
        match_class_filter!(EntryClass::Tombstone),
    ])
});

static FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL30: LazyLock<ProtoFilter> =
    LazyLock::new(|| ProtoFilter::AndNot(Box::new(FILTER_RECYCLED_OR_TOMBSTONE_DL30.clone())));

/// DL30 refresh of `idm_acp_oauth2_client_admin`. Forks DL29 and adds the
/// four Google connector config attributes introduced by PR-CONNECTOR-GOOGLE.
pub(crate) static IDM_ACP_OAUTH2_CLIENT_ADMIN_DL30: LazyLock<BuiltinAcp> =
    LazyLock::new(|| BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_oauth2_client_admin",
        uuid: UUID_IDM_ACP_OAUTH2_CLIENT_ADMIN,
        description:
            "Builtin IDM Control for granting oauth2 trust provider administration rights.",
        receiver: BuiltinAcpReceiver::Group(vec![
            UUID_IDM_OAUTH2_CLIENT_ADMINS,
            UUID_SYSTEM_ADMINS,
        ]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::OAuth2Client),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED_DL30.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::Spn,
            Attribute::OAuth2ClientId,
            Attribute::OAuth2ClientSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::OAuth2ClientLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            // DL28 additions
            Attribute::OAuth2ClientProviderKind,
            Attribute::OAuth2ClientGithubHost,
            Attribute::OAuth2ClientGithubOrgFilter,
            Attribute::OAuth2ClientGithubAllowedTeams,
            Attribute::OAuth2ClientGithubTeamNameField,
            Attribute::OAuth2ClientGithubLoadAllGroups,
            Attribute::OAuth2ClientGithubPreferredEmailDomain,
            Attribute::OAuth2ClientGithubAllowJitProvisioning,
            // DL29 additions
            Attribute::OAuth2ClientOidcEnableGroups,
            Attribute::OAuth2ClientOidcGroupsKey,
            Attribute::OAuth2ClientOidcSkipEmailVerified,
            Attribute::OAuth2ClientOidcAllowedGroups,
            Attribute::OAuth2ClientOidcGetUserInfo,
            Attribute::OAuth2ClientOidcUserIdKey,
            Attribute::OAuth2ClientOidcUserNameKey,
            Attribute::OAuth2ClientOidcOverrideClaimMapping,
            Attribute::OAuth2ClientOidcGroupsPrefix,
            Attribute::OAuth2ClientOidcGroupsSuffix,
            // DL30 additions
            Attribute::OAuth2ClientGoogleHostedDomain,
            Attribute::OAuth2ClientGoogleServiceAccountJson,
            Attribute::OAuth2ClientGoogleAdminEmail,
            Attribute::OAuth2ClientGoogleFetchGroups,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::OAuth2ClientId,
            Attribute::OAuth2ClientSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::OAuth2ClientLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            // DL28 additions
            Attribute::OAuth2ClientProviderKind,
            Attribute::OAuth2ClientGithubHost,
            Attribute::OAuth2ClientGithubOrgFilter,
            Attribute::OAuth2ClientGithubAllowedTeams,
            Attribute::OAuth2ClientGithubTeamNameField,
            Attribute::OAuth2ClientGithubLoadAllGroups,
            Attribute::OAuth2ClientGithubPreferredEmailDomain,
            Attribute::OAuth2ClientGithubAllowJitProvisioning,
            // DL29 additions
            Attribute::OAuth2ClientOidcEnableGroups,
            Attribute::OAuth2ClientOidcGroupsKey,
            Attribute::OAuth2ClientOidcSkipEmailVerified,
            Attribute::OAuth2ClientOidcAllowedGroups,
            Attribute::OAuth2ClientOidcGetUserInfo,
            Attribute::OAuth2ClientOidcUserIdKey,
            Attribute::OAuth2ClientOidcUserNameKey,
            Attribute::OAuth2ClientOidcOverrideClaimMapping,
            Attribute::OAuth2ClientOidcGroupsPrefix,
            Attribute::OAuth2ClientOidcGroupsSuffix,
            // DL30 additions
            Attribute::OAuth2ClientGoogleHostedDomain,
            Attribute::OAuth2ClientGoogleServiceAccountJson,
            Attribute::OAuth2ClientGoogleAdminEmail,
            Attribute::OAuth2ClientGoogleFetchGroups,
        ],
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::OAuth2ClientId,
            Attribute::OAuth2ClientSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::OAuth2ClientLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            // DL28 additions
            Attribute::OAuth2ClientProviderKind,
            Attribute::OAuth2ClientGithubHost,
            Attribute::OAuth2ClientGithubOrgFilter,
            Attribute::OAuth2ClientGithubAllowedTeams,
            Attribute::OAuth2ClientGithubTeamNameField,
            Attribute::OAuth2ClientGithubLoadAllGroups,
            Attribute::OAuth2ClientGithubPreferredEmailDomain,
            Attribute::OAuth2ClientGithubAllowJitProvisioning,
            // DL29 additions
            Attribute::OAuth2ClientOidcEnableGroups,
            Attribute::OAuth2ClientOidcGroupsKey,
            Attribute::OAuth2ClientOidcSkipEmailVerified,
            Attribute::OAuth2ClientOidcAllowedGroups,
            Attribute::OAuth2ClientOidcGetUserInfo,
            Attribute::OAuth2ClientOidcUserIdKey,
            Attribute::OAuth2ClientOidcUserNameKey,
            Attribute::OAuth2ClientOidcOverrideClaimMapping,
            Attribute::OAuth2ClientOidcGroupsPrefix,
            Attribute::OAuth2ClientOidcGroupsSuffix,
            // DL30 additions
            Attribute::OAuth2ClientGoogleHostedDomain,
            Attribute::OAuth2ClientGoogleServiceAccountJson,
            Attribute::OAuth2ClientGoogleAdminEmail,
            Attribute::OAuth2ClientGoogleFetchGroups,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::OAuth2ClientId,
            Attribute::OAuth2ClientSecret,
            Attribute::OAuth2AuthorisationEndpoint,
            Attribute::OAuth2TokenEndpoint,
            Attribute::OAuth2UserinfoEndpoint,
            Attribute::OAuth2RequestScopes,
            Attribute::OAuth2JitProvisioning,
            Attribute::OAuth2EmailLinkAccounts,
            Attribute::OAuth2ClientLogoUri,
            Attribute::OAuth2Issuer,
            Attribute::OAuth2JwksUri,
            Attribute::OAuth2LinkBy,
            Attribute::OAuth2GroupMapping,
            // DL28 additions
            Attribute::OAuth2ClientProviderKind,
            Attribute::OAuth2ClientGithubHost,
            Attribute::OAuth2ClientGithubOrgFilter,
            Attribute::OAuth2ClientGithubAllowedTeams,
            Attribute::OAuth2ClientGithubTeamNameField,
            Attribute::OAuth2ClientGithubLoadAllGroups,
            Attribute::OAuth2ClientGithubPreferredEmailDomain,
            Attribute::OAuth2ClientGithubAllowJitProvisioning,
            // DL29 additions
            Attribute::OAuth2ClientOidcEnableGroups,
            Attribute::OAuth2ClientOidcGroupsKey,
            Attribute::OAuth2ClientOidcSkipEmailVerified,
            Attribute::OAuth2ClientOidcAllowedGroups,
            Attribute::OAuth2ClientOidcGetUserInfo,
            Attribute::OAuth2ClientOidcUserIdKey,
            Attribute::OAuth2ClientOidcUserNameKey,
            Attribute::OAuth2ClientOidcOverrideClaimMapping,
            Attribute::OAuth2ClientOidcGroupsPrefix,
            Attribute::OAuth2ClientOidcGroupsSuffix,
            // DL30 additions
            Attribute::OAuth2ClientGoogleHostedDomain,
            Attribute::OAuth2ClientGoogleServiceAccountJson,
            Attribute::OAuth2ClientGoogleAdminEmail,
            Attribute::OAuth2ClientGoogleFetchGroups,
        ],
        create_classes: vec![EntryClass::Object, EntryClass::OAuth2Client],
        ..Default::default()
    });
