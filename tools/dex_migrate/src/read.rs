use crate::dex_types::{DexClaims, DexUserIdentity};
use anyhow::{Context, Result};

/// Open a dex SQLite database file for reading.
pub fn open_db(path: &str) -> Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open(path)
        .with_context(|| format!("Failed to open dex SQLite database at {path}"))?;
    Ok(conn)
}

/// List all tables in the SQLite database (for diagnostics / schema detection).
pub fn list_tables(conn: &rusqlite::Connection) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .context("Failed to prepare table-list query")?;
    let names: Result<Vec<String>, _> = stmt
        .query_map([], |row| row.get(0))
        .context("Failed to query table list")?
        .collect();
    names.context("Failed to collect table names")
}

/// Read all user identity records from the dex database.
///
/// Tries `user_identities` first (dex ≥ 2.27).  Falls back to scanning the
/// BoltDB-style `keys` key-value table used by older dex SQLite exports.
/// Returns an empty `Vec` (not an error) when neither table exists.
pub fn read_user_identities(conn: &rusqlite::Connection) -> Result<Vec<DexUserIdentity>> {
    // Try the modern dex table name first.
    if let Ok(rows) = try_read_from_user_identities(conn) {
        return Ok(rows);
    }

    // Older dex SQLite schemas use a generic `keys` k-v table with a NUL byte
    // separator between the bucket prefix and the key.  Try to find entries
    // whose ID contains the user-identity bucket prefix.
    if let Ok(rows) = try_read_from_keys_table(conn) {
        if !rows.is_empty() {
            return Ok(rows);
        }
    }

    tracing::warn!(
        "Neither 'user_identities' nor 'keys' table found in dex database; \
         no identities to migrate"
    );
    Ok(Vec::new())
}

/// Attempt to read from the `user_identities` table (dex ≥ 2.27).
fn try_read_from_user_identities(conn: &rusqlite::Connection) -> Result<Vec<DexUserIdentity>> {
    let mut stmt = conn
        .prepare("SELECT id, claims, connector_id FROM user_identities")
        .context("Failed to prepare user_identities query")?;

    let rows: Result<Vec<DexUserIdentity>, _> = stmt
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let claims_json: String = row.get(1)?;
            let connector_id: String = row.get(2)?;
            Ok((id, claims_json, connector_id))
        })
        .context("Failed to execute user_identities query")?
        .map(|r| {
            let (id, claims_json, connector_id) =
                r.context("Failed to read user_identities row")?;
            let claims: DexClaims = serde_json::from_str(&claims_json)
                .with_context(|| format!("Failed to parse claims JSON for id={id}"))?;
            Ok(DexUserIdentity {
                id,
                claims,
                connector_id,
            })
        })
        .collect();

    rows
}

/// Attempt to read user identities from the generic BoltDB-style `keys` table.
///
/// In old dex SQLite exports the `keys` table has columns `(id TEXT, value BLOB)`.
/// The bucket prefix for user identities is `userIdentities\x00` (or similar).
/// We scan for rows whose `id` contains a NUL byte (`\0`) and try to parse
/// the value as a JSON claims blob.
fn try_read_from_keys_table(conn: &rusqlite::Connection) -> Result<Vec<DexUserIdentity>> {
    // Some dex SQLite schemas use `(id, claims, connector_id)` column layout
    // inside the `keys` table as well.  Try the three-column form first.
    if let Ok(rows) = try_read_keys_three_columns(conn) {
        return Ok(rows);
    }

    // Fall back to the two-column `(id, value)` format and infer connector_id
    // from the id prefix.
    try_read_keys_two_columns(conn)
}

fn try_read_keys_three_columns(conn: &rusqlite::Connection) -> Result<Vec<DexUserIdentity>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, claims, connector_id FROM keys \
             WHERE id LIKE '%' || char(0) || '%'",
        )
        .context("Failed to prepare keys 3-col query")?;

    let rows: Result<Vec<DexUserIdentity>, _> = stmt
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let claims_json: String = row.get(1)?;
            let connector_id: String = row.get(2)?;
            Ok((id, claims_json, connector_id))
        })
        .context("Failed to execute keys 3-col query")?
        .map(|r| {
            let (id, claims_json, connector_id) = r.context("Failed to read keys row")?;
            let claims: DexClaims = serde_json::from_str(&claims_json)
                .with_context(|| format!("Failed to parse claims JSON for id={id}"))?;
            Ok(DexUserIdentity {
                id,
                claims,
                connector_id,
            })
        })
        .collect();

    rows
}

fn try_read_keys_two_columns(conn: &rusqlite::Connection) -> Result<Vec<DexUserIdentity>> {
    let mut stmt = conn
        .prepare("SELECT id, value FROM keys WHERE id LIKE '%' || char(0) || '%'")
        .context("Failed to prepare keys 2-col query")?;

    let rows: Result<Vec<DexUserIdentity>, _> = stmt
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let value: String = row.get(1)?;
            Ok((id, value))
        })
        .context("Failed to execute keys 2-col query")?
        .filter_map(|r| {
            let (id, value) = match r.context("Failed to read keys row") {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            // The id is typically `<connector_id>\0<user_id>` — split on NUL.
            let mut parts = id.splitn(2, '\0');
            let connector_id = parts.next().unwrap_or("").to_string();
            if connector_id.is_empty() {
                return None; // Not a user identity row.
            }

            let claims: DexClaims = match serde_json::from_str(&value) {
                Ok(c) => c,
                Err(_) => {
                    tracing::debug!(id = %id, "Skipping keys row — value is not parseable claims JSON");
                    return None;
                }
            };

            Some(Ok(DexUserIdentity {
                id: id.clone(),
                claims,
                connector_id,
            }))
        })
        .collect();

    rows
}
