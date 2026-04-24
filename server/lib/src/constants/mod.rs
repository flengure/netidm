// Re-export as needed

pub mod entries;
pub mod uuids;
pub mod values;

pub use self::entries::*;
pub use self::uuids::*;
pub use self::values::*;

use std::time::Duration;

// This value no longer requires incrementing during releases. It only
// serves as a "once off" marker so that we know when the initial db
// index is performed on first-run.
//
// It's also useful if we need to force a reindex due to a bug though :)
pub const SYSTEM_INDEX_VERSION: i64 = 32;

/*
 * domain functional levels
 *
 * The idea here is to allow topology wide upgrades to be performed. We have to
 * assume that across multiple netidm instances there may be cases where we have version
 * N and version N minus 1 as upgrades are rolled out.
 *
 * Imagine we set up a new cluster. Machine A and B both have level 1 support.
 * We upgrade machine A. It has support up to level 2, but machine B does not.
 * So the overall functional level is level 1. Then we upgrade B, which supports
 * up to level 2. We still don't do the upgrade! The topology is still level 1
 * unless an admin at this point *intervenes* and forces the update. OR what
 * happens we we update machine A again and it now supports up to level 3, with
 * a target level of 2. So we update machine A now to level 2, and that can
 * still replicate to machine B since it also supports level 2.
 *
 * effectively it means that "some features" may be a "release behind" for users
 * who don't muck with the levels, but it means that we can do mixed version
 * upgrades.
 */
pub type DomainVersion = u32;

/// Domain level 0 - new install, no domain level previously assigned.
pub const DOMAIN_LEVEL_0: DomainVersion = 0;

pub const PATCH_LEVEL_2: u32 = 2;

/// Domain Level 28: GitHub upstream connector (PR-CONNECTOR-GITHUB).
/// First concrete implementation of the `RefreshableConnector` trait
/// introduced in DL27. Adds one discriminator attribute
/// (`ConnectorProviderKind`) plus seven GitHub-specific config
/// attributes on `EntryClass::Connector`.
pub const DOMAIN_LEVEL_28: DomainVersion = 28;

/// DL29 — Generic OIDC upstream connector (PR-CONNECTOR-GENERIC-OIDC).
/// Adds ten OIDC-specific config attributes on `EntryClass::Connector`
/// and routes all `generic-oidc` provider entries through
/// `GenericOidcConnector` / `ConnectorRegistry`.
pub const DOMAIN_LEVEL_29: DomainVersion = 29;

/// DL30 — Google upstream connector (PR-CONNECTOR-GOOGLE).
/// Adds four Google-specific config attributes on `EntryClass::Connector`:
/// hosted-domain restriction (`hd` claim), service-account JSON key,
/// admin impersonation email, and a fetch-groups toggle for Admin SDK access.
pub const DOMAIN_LEVEL_30: DomainVersion = 30;

/// DL31 — Microsoft Azure AD upstream connector (PR-CONNECTOR-MICROSOFT).
/// Adds thirteen Microsoft-specific config attributes on `EntryClass::Connector`:
/// tenant, group settings, sovereign-cloud URL overrides, prompt/hint params,
/// custom scopes, preferred-username field, and JIT provisioning toggle.
pub const DOMAIN_LEVEL_31: DomainVersion = 31;

/// DL32 — Inbound LDAP federation connector (PR-CONNECTOR-LDAP).
/// Adds twenty-four LDAP-specific config attributes on `EntryClass::Connector`:
/// connection/TLS settings, user search config, and group search config.
pub const DOMAIN_LEVEL_32: DomainVersion = 32;

/// DL33 — SAML connector dex-parity additions (PR-CONNECTOR-SAML).
/// Adds five new optional config attributes on `EntryClass::SamlClient`:
/// `SamlSsoIssuer` (response issuer validation), `SamlInsecureSkipSigValidation`
/// (bypass XML signature check), `SamlGroupsDelim` (delimiter-separated groups),
/// `SamlAllowedGroups` (access gate), and `SamlFilterGroups` (filter output to
/// allowed set). Also fixes the NameIDPolicyFormat pass-through bug and implements
/// `RefreshableConnector` for SAML (cache-based, mirroring dex's `Refresh()`).
pub const DOMAIN_LEVEL_33: DomainVersion = 33;
/// DL34 — OpenShift connector dex-parity additions (PR-CONNECTOR-OPENSHIFT).
/// Adds 4 new `systemmay` attributes on `EntryClass::Connector`:
/// `connector_openshift_issuer`, `connector_openshift_groups`,
/// `connector_openshift_insecure_ca`, `connector_openshift_root_ca`.
pub const DOMAIN_LEVEL_34: DomainVersion = 34;
/// DL35 — GitLab connector dex-parity additions (PR-CONNECTOR-GITLAB).
/// Adds 5 new `systemmay` attributes on `EntryClass::Connector`:
/// `connector_gitlab_base_url`, `connector_gitlab_groups`,
/// `connector_gitlab_use_login_as_id`, `connector_gitlab_get_groups_permission`,
/// `connector_gitlab_root_ca`.
pub const DOMAIN_LEVEL_35: DomainVersion = 35;
/// DL36: Bitbucket Cloud connector dex-parity additions (PR-CONNECTOR-BITBUCKET).
/// Adds `connector_bitbucket_teams`, `connector_bitbucket_get_workspace_permissions`,
/// `connector_bitbucket_include_team_groups`.
pub const DOMAIN_LEVEL_36: DomainVersion = 36;
/// DL37: GitHub `use_login_as_id` attr registration; `ProviderIdentity` entry class
/// for per-user per-connector identity records;
/// `oauth2_rs_trusted_peers` and `oauth2_rs_allowed_connectors` on `OAuth2ResourceServer`.
pub const DOMAIN_LEVEL_37: DomainVersion = 37;

/// DL38: authproxy connector (`ConnectorAuthproxyUserHeader`, `ConnectorAuthproxyEmailHeader`,
/// `ConnectorAuthproxyGroupsHeader`) and gitea connector (`ConnectorGiteaBaseUrl`,
/// `ConnectorGiteaGroups`, `ConnectorGiteaInsecureCa`, `ConnectorGiteaRootCa`,
/// `ConnectorGiteaLoadAllGroups`, `ConnectorGiteaUseLoginAsId`) schema attrs on `Connector`.
pub const DOMAIN_LEVEL_38: DomainVersion = 38;
/// DL39: OpenStack Keystone connector schema attrs on `Connector`.
pub const DOMAIN_LEVEL_39: DomainVersion = 39;
/// DL40: Atlassian Crowd connector schema attrs on `Connector`.
pub const DOMAIN_LEVEL_40: DomainVersion = 40;

pub const DOMAIN_TGT_LEVEL: DomainVersion = DOMAIN_LEVEL_40;
pub const DOMAIN_TGT_PATCH_LEVEL: u32 = PATCH_LEVEL_2;
pub const DOMAIN_MAX_LEVEL: DomainVersion = DOMAIN_LEVEL_40;
pub const DOMAIN_MIN_CREATION_LEVEL: DomainVersion = DOMAIN_LEVEL_40;
pub const DOMAIN_PREVIOUS_TGT_LEVEL: DomainVersion = DOMAIN_TGT_LEVEL - 1;
pub const DOMAIN_TGT_NEXT_LEVEL: DomainVersion = DOMAIN_TGT_LEVEL + 1;
pub const DOMAIN_MIGRATION_FROM_INVALID: DomainVersion = DOMAIN_MIN_CREATION_LEVEL;
pub const DOMAIN_MIGRATION_FROM_MIN: DomainVersion = DOMAIN_PREVIOUS_TGT_LEVEL;
pub const DOMAIN_MIN_REMIGRATION_LEVEL: DomainVersion = DOMAIN_PREVIOUS_TGT_LEVEL;
pub const DOMAIN_MINIMUM_REPLICATION_LEVEL: DomainVersion = DOMAIN_TGT_LEVEL;
pub const DOMAIN_MAXIMUM_REPLICATION_LEVEL: DomainVersion = DOMAIN_TGT_LEVEL;

// On test builds define to 60 seconds
#[cfg(test)]
pub const PURGE_FREQUENCY: u64 = 60;
// For production 10 minutes.
#[cfg(not(test))]
pub const PURGE_FREQUENCY: u64 = 600;

/// The duration for which messages will be retained after their send_after time. Defaults to
/// 7 days
pub const DEFAULT_MESSAGE_RETENTION: Duration = Duration::from_secs(86400 * 7);

/// The number of delayed actions to consider per write transaction. Higher
/// values allow more coalescing to occur, but may consume more ram and cause
/// some latency while dequeuing and writing those operations.
pub const DELAYED_ACTION_BATCH_SIZE: usize = 256;

/// The amount of time to wait to acquire a database ticket before timing out.
/// Higher values allow greater operation queuing but can cause feedback
/// loops where operations will stall for long periods.
pub const DB_LOCK_ACQUIRE_TIMEOUT_MILLIS: u64 = 5000;

#[cfg(test)]
/// In test, we limit the changelog to 10 minutes.
pub const CHANGELOG_MAX_AGE: u64 = 600;
#[cfg(not(test))]
/// A replica may be up to 7 days out of sync before being denied updates.
pub const CHANGELOG_MAX_AGE: u64 = 7 * 86400;

#[cfg(test)]
/// In test, we limit the recyclebin to 5 minutes.
pub const RECYCLEBIN_MAX_AGE: u64 = 300;
#[cfg(not(test))]
/// In production we allow 1 week
pub const RECYCLEBIN_MAX_AGE: u64 = 7 * 86400;

// 5 minute auth session window.
pub const AUTH_SESSION_TIMEOUT: u64 = 300;
// 5 minute mfa reg window
pub const MFAREG_SESSION_TIMEOUT: u64 = 300;
pub const PW_MIN_LENGTH: u32 = 10;

// Maximum - Sessions have no upper bound.
pub const MAXIMUM_AUTH_SESSION_EXPIRY: u32 = u32::MAX;
// Default - sessions last for 1 day
pub const DEFAULT_AUTH_SESSION_EXPIRY: u32 = 86400;
// Maximum - privileges last for 1 hour.
pub const MAXIMUM_AUTH_PRIVILEGE_EXPIRY: u32 = 3600;
// Default - privileges last for 10 minutes.
pub const DEFAULT_AUTH_PRIVILEGE_EXPIRY: u32 = 600;
// Default - directly privileged sessions only last 1 hour.
pub const DEFAULT_AUTH_SESSION_LIMITED_EXPIRY: u32 = 3600;
// Default - oauth refresh tokens last for 16 hours.
pub const OAUTH_REFRESH_TOKEN_EXPIRY: u64 = 3600 * 16;

/// How long access tokens should last. This is NOT the length
/// of the refresh token, which is bound to the issuing session.
pub const OAUTH2_ACCESS_TOKEN_EXPIRY: u32 = 15 * 60;

/// The amount of time a suppliers clock can be "ahead" before
/// we warn about possible clock synchronisation issues.
pub const REPL_SUPPLIER_ADVANCE_WINDOW: Duration = Duration::from_secs(600);

/// The number of days that the default replication MTLS cert lasts for when
/// configured manually. Defaults to 4 years (including 1 day for the leap year).
pub const REPL_MTLS_CERTIFICATE_EXPIRY: u64 = 1461 * 86400;

/// The default number of entries that a user may retrieve in a search
pub const DEFAULT_LIMIT_SEARCH_MAX_RESULTS: u64 = 1024;
/// The default number of entries than an api token may retrieve in a search;
pub const DEFAULT_LIMIT_API_SEARCH_MAX_RESULTS: u64 = u64::MAX >> 1;
/// the default number of entries that may be examined in a partially indexed
/// query.
pub const DEFAULT_LIMIT_SEARCH_MAX_FILTER_TEST: u64 = 2048;
/// the default number of entries that may be examined in a partially indexed
/// query by an api token.
pub const DEFAULT_LIMIT_API_SEARCH_MAX_FILTER_TEST: u64 = 16384;
/// The maximum number of items in a filter, regardless of nesting level.
pub const DEFAULT_LIMIT_FILTER_MAX_ELEMENTS: u64 = 32;

/// The maximum amount of recursion allowed in a filter.
pub const DEFAULT_LIMIT_FILTER_DEPTH_MAX: u64 = 12;

/// The maximum number of sessions allowed on a single entry.
pub(crate) const SESSION_MAXIMUM: usize = 48;

#[cfg(test)]
// Test only certificate. This is a self-signed server cert.
pub(crate) const TEST_X509_CERT_DATA: &str = r#"-----BEGIN CERTIFICATE-----
MIICeDCCAh6gAwIBAgIBAjAKBggqhkjOPQQDAjCBhDELMAkGA1UEBhMCQVUxDDAK
BgNVBAgMA1FMRDEPMA0GA1UECgwGS2FuaWRtMRwwGgYDVQQDDBNLYW5pZG0gR2Vu
ZXJhdGVkIENBMTgwNgYDVQQLDC9EZXZlbG9wbWVudCBhbmQgRXZhbHVhdGlvbiAt
IE5PVCBGT1IgUFJPRFVDVElPTjAeFw0yNTA3MjkwMzMxMDNaFw0yNTA4MDMwMzMx
MDNaMHoxCzAJBgNVBAYTAkFVMQwwCgYDVQQIDANRTEQxDzANBgNVBAoMBkthbmlk
bTESMBAGA1UEAwwJbG9jYWxob3N0MTgwNgYDVQQLDC9EZXZlbG9wbWVudCBhbmQg
RXZhbHVhdGlvbiAtIE5PVCBGT1IgUFJPRFVDVElPTjBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABPFkpVzFH+feItm9JFFm/noge+BlZLpdGWOuSUvfoivAzCgPr7Kr
nGd8kUzIyJermePzu2SVQLaEt/7GY8Ha+2ujgYkwgYYwCQYDVR0TBAIwADAOBgNV
HQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFOjucEtX
mj/wQ7npVaMOyDtLU6dUMB8GA1UdIwQYMBaAFNo5o+5ea0sNMlW/75VgGJCv2AcJ
MBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgNIADBFAiEA1TACf4eS
g07LRiKhlMgA+6xxztxiZCuV6LakRp7FZdECIFp0rFSiFJdkLEO9IyqYc+zPW770
ta41VMU3u9UQfHxF
-----END CERTIFICATE-----
"#;
