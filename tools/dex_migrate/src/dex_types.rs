use serde::Deserialize;

/// A user identity record as stored in the dex SQLite database.
#[derive(Debug, Deserialize)]
pub struct DexUserIdentity {
    /// Row ID — typically `connector_id\0user_id` in older dex schemas.
    pub id: String,
    /// JSON blob of dex claims.
    pub claims: DexClaims,
    /// The dex connector ID that produced this identity.
    pub connector_id: String,
}

/// Upstream identity claims stored by dex in its `user_identities` table.
#[derive(Debug, Deserialize, Default)]
pub struct DexClaims {
    /// Stable upstream user ID (numeric GitHub ID, LDAP DN, etc.).
    #[serde(default)]
    pub user_id: String,
    /// Username / login handle.
    #[serde(default)]
    pub username: String,
    /// Email address.
    #[serde(default)]
    pub email: String,
    /// Whether the email was verified by the upstream provider.
    #[serde(default)]
    pub email_verified: bool,
    /// Group membership claims.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Preferred username (OIDC).
    #[serde(default)]
    pub preferred_username: String,
}
