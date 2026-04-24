//! Schema entries for DL28: GitHub upstream connector (PR-CONNECTOR-GITHUB).
//!
//! Adds one discriminator attribute and seven GitHub-specific config
//! attributes on `EntryClass::Connector`. Every addition is optional
//! with a documented default — pre-DL28 `Connector` entries decode
//! unchanged.
//!
//! The discriminator attribute `ConnectorProviderKind` selects the
//! concrete connector implementation that handles a given client entry.
//! This PR ships one value (`"github"`); future connectors (generic-OIDC,
//! Google, Microsoft, LDAP, SAML-upstream, …) extend the set without
//! needing a schema migration each.

use crate::constants::{
    UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_ALLOWED_TEAMS,
    UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_ALLOW_JIT_PROVISIONING,
    UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_HOST,
    UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_LOAD_ALL_GROUPS,
    UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_ORG_FILTER,
    UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_PREFERRED_EMAIL_DOMAIN,
    UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_TEAM_NAME_FIELD,
    UUID_SCHEMA_ATTR_CONNECTOR_PROVIDER_KIND, UUID_SCHEMA_CLASS_CONNECTOR,
};
use crate::prelude::*;

/// Discriminator attribute selecting the concrete connector implementation
/// that handles an `Connector` entry. Values used in DL28: `"github"`.
/// Absence defaults to `"generic-oidc"` at the dispatch site — preserving
/// PR-OIDC-CONNECTOR's behaviour for pre-DL28 entries.
pub static SCHEMA_ATTR_CONNECTOR_PROVIDER_KIND_DL28: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_PROVIDER_KIND,
        name: Attribute::ConnectorProviderKind,
        description: "Discriminator selecting the concrete upstream connector implementation \
                      that handles this Connector entry. Absence = generic-oidc."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// GitHub or GitHub Enterprise host URL (e.g. `https://github.com` or
/// `https://github.acme.internal`). Used as the base for OAuth2
/// authorise/token endpoints; REST calls derive from it. Single-value URL.
pub static SCHEMA_ATTR_CONNECTOR_GITHUB_HOST_DL28: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_HOST,
        name: Attribute::ConnectorGithubHost,
        description: "GitHub host URL for the OAuth2 flow. Defaults to https://github.com; \
                      set to a GitHub Enterprise host for on-prem deployments."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Url,
        ..Default::default()
    });

/// Allowlist of GitHub org slugs whose team memberships contribute to the
/// group-mapping reconciler. Empty or absent = no filter. A user whose orgs
/// do not intersect the allowlist STILL authenticates successfully; only
/// their groups claim is narrowed. Access-gate semantics live separately on
/// `ConnectorGithubAllowedTeams`.
pub static SCHEMA_ATTR_CONNECTOR_GITHUB_ORG_FILTER_DL28: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_ORG_FILTER,
        name: Attribute::ConnectorGithubOrgFilter,
        description: "Allowlist of GitHub org slugs whose teams contribute to the netidm \
                      groups claim. Empty = no filter. Does NOT reject logins; see \
                      connector_github_allowed_teams for that."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Access-gate allowlist. When non-empty, a login succeeds ONLY if the
/// user's GitHub team set intersects this list. Rejection happens BEFORE
/// any Person provisioning or linking logic runs. Each entry is in
/// `org-slug:team-slug` form. Empty or absent = gate off.
pub static SCHEMA_ATTR_CONNECTOR_GITHUB_ALLOWED_TEAMS_DL28: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_ALLOWED_TEAMS,
        name: Attribute::ConnectorGithubAllowedTeams,
        description: "Access-gate allowlist. Non-empty = login only when user's GitHub teams \
                      intersect this list. Entry form: org-slug:team-slug."
            .to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    });

/// Team-name rendering policy: `"slug"` (default — stable across renames),
/// `"name"` (human-readable), or `"both"` (emits both strings to the
/// mapping reconciler). Single-value iutf8 enum.
pub static SCHEMA_ATTR_CONNECTOR_GITHUB_TEAM_NAME_FIELD_DL28: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_TEAM_NAME_FIELD,
        name: Attribute::ConnectorGithubTeamNameField,
        description: "Team-name rendering policy for upstream group names: slug (default), \
                      name, or both. Matches dex's teamNameField config."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// When true, users' plain org memberships (without team scoping) also
/// feed the group-mapping reconciler, in addition to their team
/// memberships. Defaults to false. Mirrors dex's loadAllGroups config.
pub static SCHEMA_ATTR_CONNECTOR_GITHUB_LOAD_ALL_GROUPS_DL28: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_LOAD_ALL_GROUPS,
        name: Attribute::ConnectorGithubLoadAllGroups,
        description: "When true, org memberships without team scoping also feed the group \
                      mapping reconciler. Defaults to false."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// Preferred email domain (e.g. `"acme.com"`). When set and the user has
/// multiple verified emails, pick the first verified email whose domain
/// matches. Single-value iutf8; bare DNS domain only (no `@`, no scheme).
pub static SCHEMA_ATTR_CONNECTOR_GITHUB_PREFERRED_EMAIL_DOMAIN_DL28: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_PREFERRED_EMAIL_DOMAIN,
        name: Attribute::ConnectorGithubPreferredEmailDomain,
        description: "Preferred email domain when the user has multiple verified emails. \
                      Bare DNS domain (e.g. 'acme.com'). Mirrors dex's preferredEmailDomain."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Utf8StringInsensitive,
        ..Default::default()
    });

/// When true, a first-time GitHub user with no match from the linking
/// chain is auto-provisioned. When false (default), such users are
/// rejected with an operator-guided error. Conservative default matches
/// the netidm constitution's §V Security-by-Hierarchy preference for
/// Elimination over Administrative Controls.
pub static SCHEMA_ATTR_CONNECTOR_GITHUB_ALLOW_JIT_PROVISIONING_DL28: LazyLock<SchemaAttribute> =
    LazyLock::new(|| SchemaAttribute {
        uuid: UUID_SCHEMA_ATTR_CONNECTOR_GITHUB_ALLOW_JIT_PROVISIONING,
        name: Attribute::ConnectorGithubAllowJitProvisioning,
        description: "When true, first-time GitHub users with no matching netidm Person are \
                  auto-provisioned. Defaults to false (pre-provision required)."
            .to_string(),
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

/// OAuth2 client class updated for DL28: adds the one discriminator attribute
/// plus the seven GitHub-specific config attributes to `systemmay`. Carries
/// forward DL25's `systemmay` set unchanged.
pub static SCHEMA_CLASS_OAUTH2_CLIENT_DL28: LazyLock<SchemaClass> = LazyLock::new(|| SchemaClass {
    uuid: UUID_SCHEMA_CLASS_CONNECTOR,
    name: EntryClass::Connector.into(),
    description: "The class representing a configured OAuth2 Confidential Client acting as \
                      an authentication source."
        .to_string(),
    systemmust: vec![
        Attribute::Name,
        Attribute::ConnectorId,
        Attribute::ConnectorSecret,
        Attribute::OAuth2AuthorisationEndpoint,
        Attribute::OAuth2TokenEndpoint,
        Attribute::OAuth2RequestScopes,
    ],
    systemmay: vec![
        Attribute::DisplayName,
        Attribute::OAuth2UserinfoEndpoint,
        Attribute::OAuth2JitProvisioning,
        Attribute::OAuth2ClaimMapName,
        Attribute::OAuth2ClaimMapDisplayname,
        Attribute::OAuth2ClaimMapEmail,
        Attribute::OAuth2EmailLinkAccounts,
        Attribute::ConnectorLogoUri,
        Attribute::OAuth2Issuer,
        Attribute::OAuth2JwksUri,
        Attribute::OAuth2LinkBy,
        Attribute::OAuth2GroupMapping,
        // DL28 additions — PR-CONNECTOR-GITHUB
        Attribute::ConnectorProviderKind,
        Attribute::ConnectorGithubHost,
        Attribute::ConnectorGithubOrgFilter,
        Attribute::ConnectorGithubAllowedTeams,
        Attribute::ConnectorGithubTeamNameField,
        Attribute::ConnectorGithubLoadAllGroups,
        Attribute::ConnectorGithubPreferredEmailDomain,
        Attribute::ConnectorGithubAllowJitProvisioning,
    ],
    ..Default::default()
});
