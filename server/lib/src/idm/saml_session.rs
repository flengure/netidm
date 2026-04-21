//! Per-SP SAML session index — the DB-layer helpers the SAML Single
//! Logout handler uses to correlate an inbound `<LogoutRequest>` to a
//! specific netidm session.
//!
//! Each `SamlSession` entry ties a (user, SP, `<SessionIndex>`, UAT)
//! tuple together. Populated when netidm issues a SAML
//! `<AuthnResponse>` that carries a `<SessionIndex>`; consulted when an
//! SP sends a `<LogoutRequest>`. Two lookup patterns:
//!
//!   * By `(sp_uuid, session_index)` — the single-session SLO case per
//!     spec §FR-011a, Q3/B ("SessionIndex present").
//!   * By `(sp_uuid, user_uuid)` — the all-sessions-at-this-SP case
//!     per spec §FR-011a when `<SessionIndex>` is absent.
//!
//! Scaffolding landed in this commit; the emission path on SAML
//! `<AuthnResponse>` generation (spec §FR-011b) and the SLO handler
//! that drives the lookups (spec §FR-011, FR-011a) land with the rest
//! of US4 in subsequent PR-RP-LOGOUT commits.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::prelude::*;
use netidm_proto::internal::OperationError;

/// A materialised view of a `SamlSession` entry. Read-only from the
/// caller's perspective; the authoritative state is in the DB.
#[derive(Debug, Clone)]
pub struct SamlSession {
    /// The `SamlSession` entry's own UUID.
    pub uuid: Uuid,
    /// The authenticated user whose session this is.
    pub user_uuid: Uuid,
    /// The SAML service provider this session was issued for. `None`
    /// only for Stage-2 backfill entries from the DL26 migration (no
    /// SP provenance recorded for pre-existing sessions).
    pub sp_uuid: Option<Uuid>,
    /// The `<SessionIndex>` value emitted in the matching
    /// `<AuthnStatement>`. Opaque to the SP; netidm uses a UUID-v4
    /// string.
    pub session_index: String,
    /// The netidm UAT that backs this SAML session. `terminate_session`
    /// is called against this UUID when the SLO handler matches.
    pub uat_uuid: Uuid,
    /// Emission time.
    pub created: OffsetDateTime,
}

/// Create a new `SamlSession` entry. Called once per SAML
/// `<AuthnResponse>` issued so an SP can later reference this session
/// via its `<SessionIndex>` on an SLO request. Returns the new
/// record's UUID and the fresh `SessionIndex` string.
///
/// The `SessionIndex` is a UUID-v4 string — opaque to the SP, unique
/// without coordination, and carries no per-user or per-time
/// information. See `specs/009-rp-logout/research.md` R5.
///
/// # Errors
///
/// Returns any [`OperationError`] propagated from the underlying
/// `internal_create`.
pub fn create_saml_session(
    qs_write: &mut crate::server::QueryServerWriteTransaction<'_>,
    user_uuid: Uuid,
    sp_uuid: Uuid,
    uat_uuid: Uuid,
    now: OffsetDateTime,
) -> Result<(Uuid, String), OperationError> {
    let entry_uuid = Uuid::new_v4();
    let session_index = Uuid::new_v4().to_string();

    let entry = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::SamlSession.to_value()),
        (Attribute::Uuid, Value::Uuid(entry_uuid)),
        (Attribute::SamlSessionUser, Value::Refer(user_uuid)),
        (Attribute::SamlSessionSp, Value::Refer(sp_uuid)),
        (
            Attribute::SamlSessionIndex,
            Value::new_iutf8(session_index.as_str())
        ),
        (Attribute::SamlSessionUatUuid, Value::Uuid(uat_uuid)),
        (Attribute::SamlSessionCreated, Value::DateTime(now))
    );

    qs_write.internal_create(vec![entry]).map_err(|e| {
        admin_error!(?e, "Failed to create SamlSession entry");
        e
    })?;

    Ok((entry_uuid, session_index))
}

/// Find the single `SamlSession` whose (SP, SessionIndex) pair
/// matches. Used by the SLO handler when the inbound
/// `<LogoutRequest>` carries a `<SessionIndex>` — the "present"
/// branch of spec §FR-011a.
///
/// Returns `Ok(None)` if no matching entry exists.
///
/// # Errors
///
/// Returns any [`OperationError`] propagated from the underlying
/// search.
pub fn find_saml_session_by_index(
    qs_write: &mut crate::server::QueryServerWriteTransaction<'_>,
    sp_uuid: Uuid,
    session_index: &str,
) -> Result<Option<SamlSession>, OperationError> {
    let filter = filter!(f_and!([
        f_eq(Attribute::Class, EntryClass::SamlSession.into()),
        f_eq(Attribute::SamlSessionSp, PartialValue::Refer(sp_uuid)),
        f_eq(
            Attribute::SamlSessionIndex,
            PartialValue::new_iutf8(session_index)
        ),
    ]));
    let entries = qs_write.internal_search(filter)?;
    match entries.into_iter().next() {
        Some(entry) => Ok(Some(materialise(&entry)?)),
        None => Ok(None),
    }
}

/// Find every `SamlSession` entry for the given (SP, user) pair.
/// Used by the SLO handler when the inbound `<LogoutRequest>` omits
/// the `<SessionIndex>` — the "absent" branch of spec §FR-011a, which
/// terminates every session the `<NameID>` principal currently holds
/// at that specific SP.
///
/// # Errors
///
/// Returns any [`OperationError`] propagated from the underlying
/// search.
pub fn find_saml_sessions_by_user_sp(
    qs_write: &mut crate::server::QueryServerWriteTransaction<'_>,
    sp_uuid: Uuid,
    user_uuid: Uuid,
) -> Result<Vec<SamlSession>, OperationError> {
    let filter = filter!(f_and!([
        f_eq(Attribute::Class, EntryClass::SamlSession.into()),
        f_eq(Attribute::SamlSessionSp, PartialValue::Refer(sp_uuid)),
        f_eq(Attribute::SamlSessionUser, PartialValue::Refer(user_uuid)),
    ]));
    let entries = qs_write.internal_search(filter)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        out.push(materialise(&entry)?);
    }
    Ok(out)
}

/// Delete a `SamlSession` entry by its own UUID. Called by the SLO
/// handler after the matching netidm session has been terminated via
/// [`crate::idm::logout::terminate_session`]. Idempotent — a missing
/// entry is treated as success.
///
/// # Errors
///
/// Returns any [`OperationError`] propagated from the underlying
/// `internal_delete` other than `NoMatchingEntries`.
pub fn delete_saml_session(
    qs_write: &mut crate::server::QueryServerWriteTransaction<'_>,
    entry_uuid: Uuid,
) -> Result<(), OperationError> {
    let filter = filter!(f_and!([
        f_eq(Attribute::Class, EntryClass::SamlSession.into()),
        f_eq(Attribute::Uuid, PartialValue::Uuid(entry_uuid)),
    ]));
    match qs_write.internal_delete(&filter) {
        Ok(()) => Ok(()),
        Err(OperationError::NoMatchingEntries) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Hydrate one DB entry into a [`SamlSession`]. Used by both lookup
/// helpers.
fn materialise(
    entry: &std::sync::Arc<crate::entry::EntrySealedCommitted>,
) -> Result<SamlSession, OperationError> {
    let uuid = entry.get_uuid();
    let user_uuid = entry
        .get_ava_single_refer(Attribute::SamlSessionUser)
        .ok_or_else(|| {
            OperationError::InvalidAttribute(format!("SamlSession {uuid} missing user reference"))
        })?;
    let sp_uuid = entry.get_ava_single_refer(Attribute::SamlSessionSp);
    let session_index = entry
        .get_ava_single_iutf8(Attribute::SamlSessionIndex)
        .map(str::to_string)
        .ok_or_else(|| {
            OperationError::InvalidAttribute(format!("SamlSession {uuid} missing session_index"))
        })?;
    let uat_uuid = entry
        .get_ava_single_uuid(Attribute::SamlSessionUatUuid)
        .ok_or_else(|| {
            OperationError::InvalidAttribute(format!("SamlSession {uuid} missing uat_uuid"))
        })?;
    let created = entry
        .get_ava_single_datetime(Attribute::SamlSessionCreated)
        .ok_or_else(|| {
            OperationError::InvalidAttribute(format!("SamlSession {uuid} missing created"))
        })?;
    Ok(SamlSession {
        uuid,
        user_uuid,
        sp_uuid,
        session_index,
        uat_uuid,
        created,
    })
}
