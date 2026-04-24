//! Inbound LDAP federation connector (PR-CONNECTOR-LDAP, DL32).
//!
//! Exact-parity Rust port of `github.com/dexidp/dex/connector/ldap/ldap.go`.
//!
//! Implements [`RefreshableConnector`] for LDAP / Active Directory.
//! Providers whose `OAuth2Client` entry carries `oauth2_client_provider_kind =
//! "ldap"` are dispatched here.
//!
//! Unlike all other connectors, LDAP is a *password connector*: the user enters
//! credentials directly into netidm's UI, and netidm binds to the LDAP server
//! to verify them. There is no OAuth2 redirect. The `authenticate_password`
//! trait method handles the login; `refresh` re-fetches the user's claims
//! using the stored session state.
//!
//! [`RefreshableConnector`]: crate::idm::oauth2_connector::RefreshableConnector

use crate::idm::authsession::handler_oauth2_client::ExternalUserClaims;
use crate::idm::oauth2_connector::{ConnectorRefreshError, RefreshOutcome, RefreshableConnector};
use crate::prelude::*;
use async_trait::async_trait;
use hashbrown::HashSet;
use ldap3_client::proto::{LdapFilter, LdapSearchScope};
use ldap3_client::{LdapClientBuilder, LdapEntry, LdapError};
use serde::{Deserialize, Serialize};
use url::Url;

pub const LDAP_SESSION_STATE_FORMAT_VERSION: u8 = 1;

// ── Session state ────────────────────────────────────────────────────────────

/// Opaque state stored in `upstream_refresh_state` for the duration of a
/// federated LDAP session. Mirrors dex's `refreshData` struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapSessionState {
    pub format_version: u8,
    /// DN of the user entry as found during the initial search-then-bind.
    pub user_dn: String,
    /// Escaped username used during the initial search; re-used on refresh.
    pub username_used: String,
}

// ── Configuration structs ────────────────────────────────────────────────────

/// Scope for LDAP searches. Mirrors dex's scope constants.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum LdapScope {
    #[default]
    Subtree,
    OneLevel,
}

impl LdapScope {
    fn to_proto(&self) -> LdapSearchScope {
        match self {
            LdapScope::Subtree => LdapSearchScope::Subtree,
            LdapScope::OneLevel => LdapSearchScope::OneLevel,
        }
    }

    fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "one" | "onelevel" | "single" => LdapScope::OneLevel,
            _ => LdapScope::Subtree,
        }
    }
}

/// A single `userAttr:groupAttr[:recursionGroupAttr]` matcher that correlates
/// a user entry attribute to a group entry attribute. Mirrors dex's `UserMatcher`.
#[derive(Clone, Debug)]
pub struct UserMatcher {
    pub user_attr: String,
    pub group_attr: String,
    /// When set, traverse the membership hierarchy via this attribute on the
    /// group entry (e.g. `memberOf` or `member`).
    pub recursion_group_attr: Option<String>,
}

impl UserMatcher {
    fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        match parts.as_slice() {
            [ua, ga] => Some(UserMatcher {
                user_attr: ua.to_string(),
                group_attr: ga.to_string(),
                recursion_group_attr: None,
            }),
            [ua, ga, rga] => Some(UserMatcher {
                user_attr: ua.to_string(),
                group_attr: ga.to_string(),
                recursion_group_attr: Some(rga.to_string()),
            }),
            _ => None,
        }
    }
}

/// User search configuration. Mirrors dex's `UserSearch` struct.
#[derive(Clone, Debug)]
pub struct UserSearchConfig {
    pub base_dn: String,
    pub filter: Option<LdapFilter>,
    /// Attributes to match against the typed username.
    /// Multi-value: if multiple are configured a `(|...)` OR filter is built.
    pub username_attrs: Vec<String>,
    pub scope: LdapScope,
    /// Attribute whose value becomes the upstream `sub`. Defaults to "uid".
    pub id_attr: String,
    /// Attribute supplying the email. Defaults to "mail".
    pub email_attr: Option<String>,
    pub name_attr: Option<String>,
    pub preferred_username_attr: Option<String>,
    /// If set, email = `<id_attr_value>@<email_suffix>`.
    pub email_suffix: Option<String>,
}

/// Group search configuration. Mirrors dex's `GroupSearch` struct.
#[derive(Clone, Debug)]
pub struct GroupSearchConfig {
    pub base_dn: String,
    pub filter: Option<LdapFilter>,
    pub scope: LdapScope,
    pub user_matchers: Vec<UserMatcher>,
    pub name_attr: String,
}

/// Full connector configuration built from an `OAuth2Client` entry.
#[derive(Clone, Debug)]
pub struct LdapConfig {
    /// `ldap://host:port` or `ldaps://host:port`
    pub url: Url,
    pub insecure_skip_verify: bool,
    pub bind_dn: Option<String>,
    pub bind_pw: Option<String>,
    pub username_prompt: Option<String>,
    pub user_search: UserSearchConfig,
    pub group_search: Option<GroupSearchConfig>,
    pub allow_jit_provisioning: bool,
}

impl LdapConfig {
    /// Build a `LdapConfig` from an `OAuth2Client` entry.
    ///
    /// Returns `Err` if any required field is absent or unparseable.
    pub fn from_entry(
        entry: &crate::entry::Entry<crate::entry::EntrySealed, crate::entry::EntryCommitted>,
    ) -> Result<Self, OperationError> {
        // ── Required: host ───────────────────────────────────────────────────
        let raw_host = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientLdapHost)
            .ok_or_else(|| {
                error!("LDAP connector missing required attribute: oauth2_client_ldap_host");
                OperationError::InvalidAttribute("oauth2_client_ldap_host is required".to_string())
            })?;

        // Derive URL from host. If host starts with ldap:// or ldaps:// use
        // it directly, otherwise default to ldaps://.
        let url_str = if raw_host.starts_with("ldap://") || raw_host.starts_with("ldaps://") {
            raw_host.to_string()
        } else {
            // Default to LDAPS unless insecure_no_ssl is set
            let no_ssl = entry
                .get_ava_single_bool(Attribute::OAuth2ClientLdapInsecureNoSsl)
                .unwrap_or(false);
            if no_ssl {
                format!("ldap://{raw_host}")
            } else {
                format!("ldaps://{raw_host}")
            }
        };

        let url = Url::parse(&url_str).map_err(|e| {
            error!(?e, raw_host, "Invalid LDAP host URL");
            OperationError::InvalidAttribute(format!("invalid ldap host: {e}"))
        })?;

        let insecure_skip_verify = entry
            .get_ava_single_bool(Attribute::OAuth2ClientLdapInsecureSkipVerify)
            .unwrap_or(false);

        if entry
            .get_ava_single_bool(Attribute::OAuth2ClientLdapStartTls)
            .unwrap_or(false)
        {
            warn!(
                "LDAP connector: start_tls is configured but not supported by ldap3_client. \
                 Use ldaps:// instead."
            );
        }

        let bind_dn = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientLdapBindDn)
            .map(str::to_string);
        let bind_pw = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientLdapBindPw)
            .map(str::to_string);
        let username_prompt = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientLdapUsernamePrompt)
            .map(str::to_string);

        // ── UserSearch — required: base_dn, username_attrs ───────────────────
        let user_base_dn = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientLdapUserSearchBaseDn)
            .ok_or_else(|| {
                error!(
                    "LDAP connector missing required attribute: \
                     oauth2_client_ldap_user_search_base_dn"
                );
                OperationError::InvalidAttribute(
                    "oauth2_client_ldap_user_search_base_dn is required".to_string(),
                )
            })?
            .to_string();

        let username_attrs: Vec<String> = entry
            .get_ava_set(Attribute::OAuth2ClientLdapUserSearchUsername)
            .and_then(|vs| vs.as_utf8_iter())
            .map(|iter| iter.map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_default();

        if username_attrs.is_empty() {
            error!(
                "LDAP connector: at least one oauth2_client_ldap_user_search_username \
                 value is required"
            );
            return Err(OperationError::InvalidAttribute(
                "oauth2_client_ldap_user_search_username must have at least one value".to_string(),
            ));
        }

        let user_filter = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientLdapUserSearchFilter)
            .and_then(|s| {
                ldap3_client::filter::parse_ldap_filter_str(s)
                    .map_err(|e| {
                        warn!(?e, "Failed to parse user_search_filter; ignoring");
                    })
                    .ok()
            });

        let user_scope = entry
            .get_ava_single_iutf8(Attribute::OAuth2ClientLdapUserSearchScope)
            .map(LdapScope::from_str)
            .unwrap_or_default();

        let id_attr = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientLdapUserSearchIdAttr)
            .unwrap_or("uid")
            .to_string();

        let email_attr = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientLdapUserSearchEmailAttr)
            .map(str::to_string);

        let name_attr = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientLdapUserSearchNameAttr)
            .map(str::to_string);

        let preferred_username_attr = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientLdapUserSearchPreferredUsernameAttr)
            .map(str::to_string);

        let email_suffix = entry
            .get_ava_single_utf8(Attribute::OAuth2ClientLdapUserSearchEmailSuffix)
            .map(str::to_string);

        let user_search = UserSearchConfig {
            base_dn: user_base_dn,
            filter: user_filter,
            username_attrs,
            scope: user_scope,
            id_attr,
            email_attr,
            name_attr,
            preferred_username_attr,
            email_suffix,
        };

        // ── GroupSearch — optional: only if base_dn is configured ────────────
        let group_search = if let Some(gs_base_str) =
            entry.get_ava_single_utf8(Attribute::OAuth2ClientLdapGroupSearchBaseDn)
        {
            let gs_base = gs_base_str.to_string();

            let gs_filter = entry
                .get_ava_single_utf8(Attribute::OAuth2ClientLdapGroupSearchFilter)
                .and_then(|s| {
                    ldap3_client::filter::parse_ldap_filter_str(s)
                        .map_err(|e| {
                            warn!(?e, "Failed to parse group_search_filter; ignoring");
                        })
                        .ok()
                });

            let gs_scope = entry
                .get_ava_single_iutf8(Attribute::OAuth2ClientLdapGroupSearchScope)
                .map(LdapScope::from_str)
                .unwrap_or_default();

            let user_matchers: Vec<UserMatcher> = entry
                .get_ava_set(Attribute::OAuth2ClientLdapGroupSearchUserMatchers)
                .and_then(|vs| vs.as_utf8_iter())
                .map(|iter| {
                    iter.filter_map(|s: &str| {
                        UserMatcher::parse(s).or_else(|| {
                            warn!(
                                "Invalid user_matcher format \
                                 (expected attr:attr or attr:attr:attr): {s}"
                            );
                            None
                        })
                    })
                    .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let gs_name_attr = entry
                .get_ava_single_utf8(Attribute::OAuth2ClientLdapGroupSearchNameAttr)
                .unwrap_or("cn")
                .to_string();

            Some(GroupSearchConfig {
                base_dn: gs_base,
                filter: gs_filter,
                scope: gs_scope,
                user_matchers,
                name_attr: gs_name_attr,
            })
        } else {
            None
        };

        let allow_jit_provisioning = false; // LDAP connector does not expose JIT toggle yet

        Ok(LdapConfig {
            url,
            insecure_skip_verify,
            bind_dn,
            bind_pw,
            username_prompt,
            user_search,
            group_search,
            allow_jit_provisioning,
        })
    }
}

// ── Connector struct ─────────────────────────────────────────────────────────

pub struct LdapConnector {
    config: LdapConfig,
}

impl LdapConnector {
    #[must_use]
    pub fn new(config: LdapConfig) -> Self {
        Self { config }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Escape a value for use in an LDAP filter assertion.
/// RFC 4515 §3: chars `\`, `*`, `(`, `)`, NUL must be escaped.
fn ldap_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str(r"\5c"),
            '*' => out.push_str(r"\2a"),
            '(' => out.push_str(r"\28"),
            ')' => out.push_str(r"\29"),
            '\0' => out.push_str(r"\00"),
            c => out.push(c),
        }
    }
    out
}

/// Build the username match filter.
///
/// - single attr:    `(uid=escaped_value)`
/// - multiple attrs: `(|(uid=val)(mail=val))`
///
/// If `base_filter` is also set, wrap both: `(&(base)(username_filter))`.
fn build_user_filter(
    username_attrs: &[String],
    escaped_value: &str,
    base_filter: Option<LdapFilter>,
) -> LdapFilter {
    let username_conditions: Vec<LdapFilter> = username_attrs
        .iter()
        .map(|attr| LdapFilter::Equality(attr.clone(), escaped_value.to_string()))
        .collect();

    let username_filter = if username_conditions.len() == 1 {
        username_conditions.into_iter().next().unwrap_or_else(|| {
            error!("username_conditions was empty despite len==1 check");
            LdapFilter::Present(String::new())
        })
    } else {
        LdapFilter::Or(username_conditions)
    };

    match base_filter {
        Some(base) => LdapFilter::And(vec![base, username_filter]),
        None => username_filter,
    }
}

/// Extract `ExternalUserClaims` from an LDAP entry using the configured
/// attribute mappings. `user_dn` is the entry's DN.
fn claims_from_entry(cfg: &UserSearchConfig, entry: &LdapEntry) -> ExternalUserClaims {
    let id_value = if cfg.id_attr.eq_ignore_ascii_case("dn") {
        entry.dn.clone()
    } else {
        entry
            .get_ava_single(&cfg.id_attr)
            .unwrap_or(&entry.dn)
            .to_string()
    };

    let email = match &cfg.email_suffix {
        Some(suffix) => Some(format!("{id_value}@{suffix}")),
        None => cfg
            .email_attr
            .as_deref()
            .and_then(|attr| entry.get_ava_single(attr))
            .map(str::to_string),
    };

    let display_name = cfg
        .name_attr
        .as_deref()
        .and_then(|attr| entry.get_ava_single(attr))
        .map(str::to_string);

    let username_hint = cfg
        .preferred_username_attr
        .as_deref()
        .and_then(|attr| entry.get_ava_single(attr))
        .map(str::to_string);

    ExternalUserClaims {
        sub: id_value,
        email,
        email_verified: Some(true),
        display_name,
        username_hint,
        groups: Vec::new(),
    }
}

/// Get attribute values from an entry, handling the special literal "DN".
fn entry_attr_values(entry: &LdapEntry, attr: &str) -> Vec<String> {
    if attr.eq_ignore_ascii_case("dn") {
        vec![entry.dn.clone()]
    } else {
        entry
            .attrs
            .get(attr)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect()
    }
}

// ── Group fetch ──────────────────────────────────────────────────────────────

async fn fetch_groups(
    client: &mut ldap3_client::LdapClient,
    user_entry: &LdapEntry,
    group_cfg: &GroupSearchConfig,
) -> Result<Vec<String>, ConnectorRefreshError> {
    let mut groups: HashSet<String> = HashSet::new();

    for matcher in &group_cfg.user_matchers {
        let user_values = entry_attr_values(user_entry, &matcher.user_attr);

        for user_val in &user_values {
            let escaped_val = ldap_escape(user_val);
            let match_filter =
                LdapFilter::Equality(matcher.group_attr.clone(), escaped_val.clone());

            let combined_filter = match &group_cfg.filter {
                Some(base) => LdapFilter::And(vec![base.clone(), match_filter]),
                None => match_filter,
            };

            let result = client
                .search(&group_cfg.base_dn, combined_filter)
                .scope(group_cfg.scope.to_proto())
                .attrs([group_cfg.name_attr.as_str()])
                .send()
                .await
                .map_err(|e| ConnectorRefreshError::Network(format!("group search failed: {e}")))?;

            if let Some(rga) = &matcher.recursion_group_attr {
                // BFS group hierarchy traversal.
                let mut visited: HashSet<String> = HashSet::new();
                let mut queue: Vec<ldap3_client::LdapEntry> = result.entries;

                while let Some(group_entry) = queue.pop() {
                    if !visited.insert(group_entry.dn.clone()) {
                        continue;
                    }
                    if let Some(name) = group_entry.get_ava_single(&group_cfg.name_attr) {
                        groups.insert(name.to_string());
                    }

                    // Search for parent groups via the recursion attribute
                    let esc_dn = ldap_escape(&group_entry.dn);
                    let parent_filter = match &group_cfg.filter {
                        Some(base) => LdapFilter::And(vec![
                            base.clone(),
                            LdapFilter::Equality(rga.clone(), esc_dn),
                        ]),
                        None => LdapFilter::Equality(rga.clone(), esc_dn),
                    };
                    let parent_result = client
                        .search(&group_cfg.base_dn, parent_filter)
                        .scope(group_cfg.scope.to_proto())
                        .attrs([group_cfg.name_attr.as_str()])
                        .send()
                        .await
                        .map_err(|e| {
                            ConnectorRefreshError::Network(format!(
                                "recursive group search failed: {e}"
                            ))
                        })?;
                    queue.extend(parent_result.entries);
                }
            } else {
                for group_entry in result.entries {
                    if let Some(name) = group_entry.get_ava_single(&group_cfg.name_attr) {
                        groups.insert(name.to_string());
                    }
                }
            }
        }
    }

    Ok(groups.into_iter().collect())
}

// ── open_ldap_client ─────────────────────────────────────────────────────────

async fn open_ldap_client(
    config: &LdapConfig,
) -> Result<ldap3_client::LdapClient, ConnectorRefreshError> {
    let builder = LdapClientBuilder::new(&config.url);

    let builder = if config.insecure_skip_verify {
        builder.danger_accept_invalid_certs()
    } else {
        builder
    };

    builder.build().await.map_err(|e| match e {
        LdapError::ConnectError | LdapError::ResolverError => {
            ConnectorRefreshError::Network(format!("LDAP connect failed: {e}"))
        }
        LdapError::TlsError => {
            ConnectorRefreshError::Network(format!("LDAP TLS handshake failed: {e}"))
        }
        other => ConnectorRefreshError::Other(format!("LDAP client build error: {other}")),
    })
}

// ── RefreshableConnector impl ─────────────────────────────────────────────────

#[async_trait]
impl RefreshableConnector for LdapConnector {
    async fn refresh(
        &self,
        session_state: &[u8],
        _previous_claims: &ExternalUserClaims,
    ) -> Result<RefreshOutcome, ConnectorRefreshError> {
        let state: LdapSessionState = serde_json::from_slice(session_state).map_err(|e| {
            ConnectorRefreshError::Serialization(format!(
                "failed to deserialize LDAP session state: {e}"
            ))
        })?;

        let mut client = open_ldap_client(&self.config).await?;

        // Bind as service account
        if let (Some(dn), Some(pw)) = (&self.config.bind_dn, &self.config.bind_pw) {
            client.bind(dn, pw).await.map_err(|e| {
                ConnectorRefreshError::Network(format!("service account bind failed: {e}"))
            })?;
        }

        // Re-run user search with the stored username
        let filter = build_user_filter(
            &self.config.user_search.username_attrs,
            &state.username_used,
            self.config.user_search.filter.clone(),
        );

        let result = client
            .search(&self.config.user_search.base_dn, filter)
            .scope(self.config.user_search.scope.to_proto())
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(format!("user search failed: {e}")))?;

        if result.entries.is_empty() {
            return Err(ConnectorRefreshError::TokenRevoked);
        }

        let user_entry = result.entries.first().ok_or_else(|| {
            error!("entries was empty after non-empty check during refresh");
            ConnectorRefreshError::TokenRevoked
        })?;

        if user_entry.dn != state.user_dn {
            error!(
                old_dn = %state.user_dn,
                new_dn = %user_entry.dn,
                "LDAP user DN changed during refresh — revoking session"
            );
            return Err(ConnectorRefreshError::TokenRevoked);
        }

        let mut claims = claims_from_entry(&self.config.user_search, user_entry);

        if let Some(gs) = &self.config.group_search {
            claims.groups = fetch_groups(&mut client, user_entry, gs)
                .await
                .unwrap_or_else(|e| {
                    warn!(
                        ?e,
                        "Group fetch failed during refresh; returning empty groups"
                    );
                    Vec::new()
                });
        }

        let new_state = LdapSessionState {
            format_version: LDAP_SESSION_STATE_FORMAT_VERSION,
            user_dn: user_entry.dn.clone(),
            username_used: state.username_used,
        };
        let new_state_bytes = serde_json::to_vec(&new_state).map_err(|e| {
            ConnectorRefreshError::Serialization(format!(
                "failed to serialize LDAP session state: {e}"
            ))
        })?;

        Ok(RefreshOutcome {
            claims,
            new_session_state: Some(new_state_bytes),
        })
    }

    async fn authenticate_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<ExternalUserClaims>, ConnectorRefreshError> {
        // Reject empty password immediately — some LDAP servers permit
        // anonymous bind when password is empty, which would be a security hole.
        if password.is_empty() {
            return Ok(None);
        }

        let escaped_username = ldap_escape(username);

        let mut client = open_ldap_client(&self.config).await?;

        // Bind as service account (or anonymous if no bind DN configured).
        if let (Some(dn), Some(pw)) = (&self.config.bind_dn, &self.config.bind_pw) {
            client.bind(dn, pw).await.map_err(|e| {
                ConnectorRefreshError::Network(format!("service account bind failed: {e}"))
            })?;
        }

        // Search for the user.
        let filter = build_user_filter(
            &self.config.user_search.username_attrs,
            &escaped_username,
            self.config.user_search.filter.clone(),
        );

        let result = client
            .search(&self.config.user_search.base_dn, filter)
            .scope(self.config.user_search.scope.to_proto())
            .send()
            .await
            .map_err(|e| ConnectorRefreshError::Network(format!("user search failed: {e}")))?;

        match result.entries.len() {
            0 => return Ok(None),
            n if n > 1 => {
                warn!(
                    username,
                    count = n,
                    "LDAP user search returned multiple entries"
                );
                return Err(ConnectorRefreshError::Other(
                    "ambiguous user search result".to_string(),
                ));
            }
            _ => {}
        }

        let user_entry = result.entries.into_iter().next().ok_or_else(|| {
            error!("entries was empty after length check");
            ConnectorRefreshError::Other("internal error: entries empty".to_string())
        })?;

        // Attempt bind as the discovered user to verify the password.
        match client
            .bind(user_entry.dn.clone(), password.to_string())
            .await
        {
            Ok(()) => {}
            Err(LdapError::InvalidCredentials) => return Ok(None),
            Err(e) => {
                return Err(ConnectorRefreshError::Network(format!(
                    "user bind failed: {e}"
                )));
            }
        }

        let mut claims = claims_from_entry(&self.config.user_search, &user_entry);

        if let Some(gs) = &self.config.group_search {
            claims.groups = fetch_groups(&mut client, &user_entry, gs)
                .await
                .unwrap_or_else(|e| {
                    warn!(
                        ?e,
                        "Group fetch failed during authenticate_password; returning empty groups"
                    );
                    Vec::new()
                });
        }

        trace!("LDAP authenticate_password succeeded");
        Ok(Some(claims))
    }

    fn allow_jit_provisioning(&self) -> bool {
        self.config.allow_jit_provisioning
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldap_escape_special_chars() {
        assert_eq!(ldap_escape(r"a\b"), r"a\5cb");
        assert_eq!(ldap_escape("a*b"), r"a\2ab");
        assert_eq!(ldap_escape("a(b)"), r"a\28b\29");
        assert_eq!(ldap_escape("normal"), "normal");
    }

    #[test]
    fn build_user_filter_single_attr() {
        let f = build_user_filter(&["uid".to_string()], "alice", None);
        assert_eq!(
            f,
            LdapFilter::Equality("uid".to_string(), "alice".to_string())
        );
    }

    #[test]
    fn build_user_filter_multi_attr() {
        let f = build_user_filter(&["uid".to_string(), "mail".to_string()], "alice", None);
        assert_eq!(
            f,
            LdapFilter::Or(vec![
                LdapFilter::Equality("uid".to_string(), "alice".to_string()),
                LdapFilter::Equality("mail".to_string(), "alice".to_string()),
            ])
        );
    }

    #[test]
    fn build_user_filter_with_base() {
        use ldap3_client::filter::parse_ldap_filter_str;
        let base = parse_ldap_filter_str("(objectClass=person)").unwrap();
        let f = build_user_filter(&["uid".to_string()], "alice", Some(base.clone()));
        assert_eq!(
            f,
            LdapFilter::And(vec![
                base,
                LdapFilter::Equality("uid".to_string(), "alice".to_string()),
            ])
        );
    }

    #[test]
    fn user_matcher_parse_two_parts() {
        let m = UserMatcher::parse("uid:member").unwrap();
        assert_eq!(m.user_attr, "uid");
        assert_eq!(m.group_attr, "member");
        assert!(m.recursion_group_attr.is_none());
    }

    #[test]
    fn user_matcher_parse_three_parts() {
        let m = UserMatcher::parse("uid:member:memberOf").unwrap();
        assert_eq!(m.recursion_group_attr.as_deref(), Some("memberOf"));
    }

    #[test]
    fn user_matcher_parse_invalid() {
        assert!(UserMatcher::parse("uid").is_none());
        assert!(UserMatcher::parse("").is_none());
    }

    #[test]
    fn ldap_session_state_round_trip() {
        let s = LdapSessionState {
            format_version: LDAP_SESSION_STATE_FORMAT_VERSION,
            user_dn: "uid=alice,dc=example,dc=com".to_string(),
            username_used: "alice".to_string(),
        };
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: LdapSessionState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.user_dn, s.user_dn);
        assert_eq!(back.username_used, s.username_used);
        assert_eq!(back.format_version, LDAP_SESSION_STATE_FORMAT_VERSION);
    }
}
