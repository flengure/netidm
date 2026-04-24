use crate::dex_types::DexUserIdentity;

/// Data required to create a `ProviderIdentity` entry in netidm.
pub struct ProviderIdentityCreate {
    /// The `name` attribute — must be a valid iname.
    pub name: String,
    /// Upstream user ID as a string (used in place of person UUID at migration time).
    pub user_id_str: String,
    /// The connector ID that produced this identity.
    pub connector_id: String,
    /// Upstream stable user ID (`sub`).
    pub claims_user_id: String,
    /// Upstream username, if any.
    pub claims_username: Option<String>,
    /// Upstream email address, if any.
    pub claims_email: Option<String>,
    /// Whether the upstream email was verified.
    pub claims_email_verified: Option<bool>,
    /// Upstream group membership claims.
    pub claims_groups: Vec<String>,
    /// RFC3339 timestamp for `ProviderIdentityCreatedAt`.
    pub created_at: String,
    /// RFC3339 timestamp for `ProviderIdentityLastLogin`.
    pub last_login: String,
}

/// Convert a dex `DexUserIdentity` into a `ProviderIdentityCreate` record.
///
/// Returns `None` when the identity lacks a usable user ID (empty `user_id`
/// and empty `preferred_username`).
pub fn identity_to_provider_identity(id: &DexUserIdentity) -> Option<ProviderIdentityCreate> {
    let user_id = if !id.claims.user_id.is_empty() {
        id.claims.user_id.clone()
    } else if !id.claims.preferred_username.is_empty() {
        id.claims.preferred_username.clone()
    } else {
        tracing::warn!(
            dex_id = %id.id,
            "Skipping identity with no user_id or preferred_username"
        );
        return None;
    };

    // Build a name that is a valid netidm iname:
    // - alphanumeric, hyphens, underscores only
    // - max 64 characters
    let raw_name = format!("pi-migrate-{}-{}", &id.connector_id, &user_id);
    let name: String = raw_name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(64)
        .collect();

    Some(ProviderIdentityCreate {
        name,
        user_id_str: user_id.clone(),
        connector_id: id.connector_id.clone(),
        claims_user_id: user_id,
        claims_username: if id.claims.username.is_empty() {
            None
        } else {
            Some(id.claims.username.clone())
        },
        claims_email: if id.claims.email.is_empty() {
            None
        } else {
            Some(id.claims.email.clone())
        },
        claims_email_verified: Some(id.claims.email_verified),
        claims_groups: id.claims.groups.clone(),
        created_at: "1970-01-01T00:00:00Z".to_string(),
        last_login: "1970-01-01T00:00:00Z".to_string(),
    })
}
