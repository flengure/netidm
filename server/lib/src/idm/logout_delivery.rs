//! Persistent back-channel logout delivery queue.
//!
//! At session-termination time, one [`LogoutDelivery`] entry is inserted per
//! registered relying-party back-channel logout endpoint. A background
//! worker in `netidmd` polls for `pending` entries whose `next_attempt` has
//! passed and POSTs the stored logout token to the target endpoint with a
//! bounded per-request timeout. Delivery failures are retried per a bounded
//! schedule with exponential backoff; after exhaustion the record is marked
//! `failed` and stops retrying.
//!
//! This module covers the **data model and CRUD helpers** (types,
//! enqueue, result-marking, pending-entry read). The actual async worker
//! (`run_worker`) and the `terminate_session` integration that enqueues
//! records land in subsequent commits of the US3 work in PR-RP-LOGOUT.

use std::str::FromStr;
use std::time::Duration;

use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::prelude::*;
use netidm_proto::internal::OperationError;

/// Terminal / intermediate state of a single logout-delivery attempt.
///
/// State machine: `Pending → Succeeded` (terminal) or
/// `Pending → Pending (attempts++)` repeatedly until the retry budget is
/// exhausted, then `Pending → Failed` (terminal). Both terminal states
/// never auto-transition back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutDeliveryStatus {
    /// The worker has not yet delivered this token, or the previous
    /// attempt failed and retry budget remains.
    Pending,
    /// The target endpoint returned a 2xx. Terminal.
    Succeeded,
    /// The retry budget is exhausted. Terminal.
    Failed,
}

impl LogoutDeliveryStatus {
    /// Canonical string form stored in the DB.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LogoutDeliveryStatus::Pending => "pending",
            LogoutDeliveryStatus::Succeeded => "succeeded",
            LogoutDeliveryStatus::Failed => "failed",
        }
    }

    /// Whether the status is terminal (no further transitions expected).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            LogoutDeliveryStatus::Succeeded | LogoutDeliveryStatus::Failed
        )
    }
}

impl FromStr for LogoutDeliveryStatus {
    type Err = OperationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(LogoutDeliveryStatus::Pending),
            "succeeded" => Ok(LogoutDeliveryStatus::Succeeded),
            "failed" => Ok(LogoutDeliveryStatus::Failed),
            _ => Err(OperationError::InvalidAttribute(format!(
                "'{s}' is not a valid LogoutDeliveryStatus (pending | succeeded | failed)"
            ))),
        }
    }
}

/// Retry schedule: six total delivery attempts spread over roughly 10.5 h
/// (attempt 0 is immediate; subsequent attempts at +1m, +5m, +30m, +2h, +8h).
/// Budget chosen to cover common outage classes (RP restart, brief network
/// partition, deploy window) without retrying indefinitely. See
/// `specs/009-rp-logout/research.md` R1.
pub const RETRY_SCHEDULE: [Duration; 6] = [
    Duration::ZERO,
    Duration::from_secs(60),     // +1 min
    Duration::from_secs(300),    // +5 min
    Duration::from_secs(1_800),  // +30 min
    Duration::from_secs(7_200),  // +2 h
    Duration::from_secs(28_800), // +8 h
];

/// Per-request HTTP timeout for one delivery attempt. Dex-convention
/// value; see `specs/009-rp-logout/research.md` R1.
pub const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of one delivery attempt, reported back to
/// [`mark_logout_delivery_result`].
#[derive(Debug, Clone, Copy)]
pub enum DeliveryOutcome {
    /// The target endpoint returned a 2xx.
    Succeeded,
    /// The attempt failed (non-2xx / timeout / network error) but the
    /// retry budget has not yet been exhausted.
    TransientFailure,
}

/// A materialised view of a `LogoutDelivery` entry in the netidm DB.
/// Read-only from the worker's perspective; the only writer is this
/// module itself (enqueue + state transitions).
#[derive(Debug, Clone)]
pub struct LogoutDelivery {
    pub uuid: Uuid,
    pub endpoint: Url,
    pub logout_token: String,
    pub status: LogoutDeliveryStatus,
    pub attempts: u32,
    pub next_attempt: OffsetDateTime,
    pub created: OffsetDateTime,
    pub rp: Uuid,
}

/// Enqueue a new logout delivery. Creates a `LogoutDelivery` entry with
/// `status = pending`, `attempts = 0`, and `next_attempt = now()` so the
/// worker picks it up on its next tick (or its Notify wake-up, once
/// wired in US3 part 2). Returns the new record's UUID.
///
/// # Errors
///
/// Returns any [`OperationError`] propagated from the underlying
/// `internal_create`. The most common path is schema-validation failure
/// if `logout_token` is empty or the endpoint URL cannot serialise.
pub fn enqueue_logout_delivery(
    qs_write: &mut crate::server::QueryServerWriteTransaction<'_>,
    rp_uuid: Uuid,
    endpoint: &Url,
    logout_token: &str,
    now: OffsetDateTime,
) -> Result<Uuid, OperationError> {
    let uuid = Uuid::new_v4();
    let entry = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::LogoutDelivery.to_value()),
        (Attribute::Uuid, Value::Uuid(uuid)),
        (
            Attribute::LogoutDeliveryEndpoint,
            Value::Url(endpoint.clone())
        ),
        (
            Attribute::LogoutDeliveryToken,
            Value::new_utf8s(logout_token)
        ),
        (
            Attribute::LogoutDeliveryStatus,
            Value::new_iutf8(LogoutDeliveryStatus::Pending.as_str())
        ),
        (Attribute::LogoutDeliveryAttempts, Value::Uint32(0)),
        (Attribute::LogoutDeliveryNextAttempt, Value::DateTime(now)),
        (Attribute::LogoutDeliveryCreated, Value::DateTime(now)),
        (Attribute::LogoutDeliveryRp, Value::Refer(rp_uuid))
    );

    qs_write.internal_create(vec![entry]).map_err(|e| {
        admin_error!(?e, "Failed to enqueue logout delivery");
        e
    })?;

    Ok(uuid)
}

/// Record the outcome of one delivery attempt. On `Succeeded`, marks the
/// record terminal. On `TransientFailure`, increments `attempts` and
/// either schedules the next retry per [`RETRY_SCHEDULE`] or — if the
/// budget is exhausted — marks the record `Failed` (terminal).
///
/// Callers are responsible for committing the enclosing write
/// transaction; this function only issues the modify.
///
/// # Errors
///
/// Returns any [`OperationError`] propagated from the underlying
/// `internal_search_uuid` / `internal_modify`. Returns
/// `OperationError::NoMatchingEntries` if the record does not exist.
/// Returns `OperationError::InvalidAttribute` if the record's current
/// status cannot be decoded (DB corruption).
pub fn mark_logout_delivery_result(
    qs_write: &mut crate::server::QueryServerWriteTransaction<'_>,
    delivery_uuid: Uuid,
    outcome: DeliveryOutcome,
    now: OffsetDateTime,
) -> Result<LogoutDeliveryStatus, OperationError> {
    let entry = qs_write.internal_search_uuid(delivery_uuid)?;

    let current_attempts = entry
        .get_ava_single_uint32(Attribute::LogoutDeliveryAttempts)
        .unwrap_or(0);

    let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(delivery_uuid)));

    match outcome {
        DeliveryOutcome::Succeeded => {
            let ml = ModifyList::new_list(vec![
                Modify::Purged(Attribute::LogoutDeliveryStatus),
                Modify::Present(
                    Attribute::LogoutDeliveryStatus,
                    Value::new_iutf8(LogoutDeliveryStatus::Succeeded.as_str()),
                ),
                Modify::Purged(Attribute::LogoutDeliveryAttempts),
                Modify::Present(
                    Attribute::LogoutDeliveryAttempts,
                    Value::Uint32(current_attempts.saturating_add(1)),
                ),
            ]);
            qs_write.internal_modify(&filter, &ml)?;
            Ok(LogoutDeliveryStatus::Succeeded)
        }
        DeliveryOutcome::TransientFailure => {
            let new_attempts = current_attempts.saturating_add(1);
            let budget_exhausted = (new_attempts as usize) >= RETRY_SCHEDULE.len();
            let new_status = if budget_exhausted {
                LogoutDeliveryStatus::Failed
            } else {
                LogoutDeliveryStatus::Pending
            };
            let next_attempt = if budget_exhausted {
                now
            } else {
                let offset = RETRY_SCHEDULE
                    .get(new_attempts as usize)
                    .copied()
                    .unwrap_or(Duration::ZERO);
                now + offset
            };
            let ml = ModifyList::new_list(vec![
                Modify::Purged(Attribute::LogoutDeliveryStatus),
                Modify::Present(
                    Attribute::LogoutDeliveryStatus,
                    Value::new_iutf8(new_status.as_str()),
                ),
                Modify::Purged(Attribute::LogoutDeliveryAttempts),
                Modify::Present(
                    Attribute::LogoutDeliveryAttempts,
                    Value::Uint32(new_attempts),
                ),
                Modify::Purged(Attribute::LogoutDeliveryNextAttempt),
                Modify::Present(
                    Attribute::LogoutDeliveryNextAttempt,
                    Value::DateTime(next_attempt),
                ),
            ]);
            qs_write.internal_modify(&filter, &ml)?;
            Ok(new_status)
        }
    }
}

/// Read a single `LogoutDelivery` entry by UUID and materialise it as a
/// [`LogoutDelivery`] value. Used by the worker to hydrate a record it's
/// about to attempt.
///
/// # Errors
///
/// Returns `OperationError::NoMatchingEntries` if the UUID does not
/// exist. Returns `OperationError::InvalidAttribute` on corrupt entries
/// (missing required fields, unparseable status, etc.).
pub fn load_logout_delivery(
    qs_write: &mut crate::server::QueryServerWriteTransaction<'_>,
    delivery_uuid: Uuid,
) -> Result<LogoutDelivery, OperationError> {
    let entry = qs_write.internal_search_uuid(delivery_uuid)?;

    let endpoint = entry
        .get_ava_single_url(Attribute::LogoutDeliveryEndpoint)
        .cloned()
        .ok_or_else(|| {
            OperationError::InvalidAttribute(format!(
                "LogoutDelivery {delivery_uuid} missing endpoint"
            ))
        })?;
    let logout_token = entry
        .get_ava_single_utf8(Attribute::LogoutDeliveryToken)
        .map(str::to_string)
        .ok_or_else(|| {
            OperationError::InvalidAttribute(format!(
                "LogoutDelivery {delivery_uuid} missing token"
            ))
        })?;
    let status_str = entry
        .get_ava_single_iutf8(Attribute::LogoutDeliveryStatus)
        .ok_or_else(|| {
            OperationError::InvalidAttribute(format!(
                "LogoutDelivery {delivery_uuid} missing status"
            ))
        })?;
    let status = LogoutDeliveryStatus::from_str(status_str)?;
    let attempts = entry
        .get_ava_single_uint32(Attribute::LogoutDeliveryAttempts)
        .unwrap_or(0);
    let next_attempt = entry
        .get_ava_single_datetime(Attribute::LogoutDeliveryNextAttempt)
        .ok_or_else(|| {
            OperationError::InvalidAttribute(format!(
                "LogoutDelivery {delivery_uuid} missing next_attempt"
            ))
        })?;
    let created = entry
        .get_ava_single_datetime(Attribute::LogoutDeliveryCreated)
        .ok_or_else(|| {
            OperationError::InvalidAttribute(format!(
                "LogoutDelivery {delivery_uuid} missing created"
            ))
        })?;
    let rp = entry
        .get_ava_single_refer(Attribute::LogoutDeliveryRp)
        .ok_or_else(|| {
            OperationError::InvalidAttribute(format!(
                "LogoutDelivery {delivery_uuid} missing rp reference"
            ))
        })?;

    Ok(LogoutDelivery {
        uuid: delivery_uuid,
        endpoint,
        logout_token,
        status,
        attempts,
        next_attempt,
        created,
        rp,
    })
}

/// Enumerate every `LogoutDelivery` entry currently in `pending` state
/// whose `next_attempt` has passed. Returns the UUIDs in the order the
/// underlying search returns them (no ordering guarantee).
///
/// # Errors
///
/// Returns any [`OperationError`] propagated from the underlying search.
pub fn list_due_pending_deliveries(
    qs_write: &mut crate::server::QueryServerWriteTransaction<'_>,
    now: OffsetDateTime,
) -> Result<Vec<Uuid>, OperationError> {
    let status_val = PartialValue::new_iutf8(LogoutDeliveryStatus::Pending.as_str());
    let filter = filter!(f_and!([
        f_eq(Attribute::Class, EntryClass::LogoutDelivery.into()),
        f_eq(Attribute::LogoutDeliveryStatus, status_val),
    ]));
    let entries = qs_write.internal_search(filter)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let due = entry
            .get_ava_single_datetime(Attribute::LogoutDeliveryNextAttempt)
            .is_some_and(|na| na <= now);
        if due {
            out.push(entry.get_uuid());
        }
    }
    Ok(out)
}

/// Poll interval for the back-channel logout worker. Covers missed
/// notifications and retries whose `next_attempt` has come due.
pub const WORKER_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// List every `LogoutDelivery` entry optionally filtered by status,
/// rendered as a DTO suitable for the admin queue API. Used by
/// `QueryServerReadV1::handle_list_logout_deliveries`.
///
/// The RP UUID is taken verbatim from the `LogoutDeliveryRp`
/// attribute; the admin CLI / UI can resolve it to a human name via a
/// separate lookup if desired. The raw logout-token JWS is NOT in the
/// returned DTO — admins see status, attempts, timing, and endpoint
/// only; the token body is an implementation detail.
///
/// # Errors
///
/// Returns any [`OperationError`] propagated from the underlying
/// search.
pub fn list_logout_deliveries(
    qs_read: &mut crate::server::QueryServerReadTransaction<'_>,
    ident: &crate::prelude::Identity,
    status: Option<LogoutDeliveryStatus>,
) -> Result<Vec<netidm_proto::v1::LogoutDeliveryDto>, OperationError> {
    let filter = if let Some(s) = status {
        filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::LogoutDelivery.into()),
            f_eq(
                Attribute::LogoutDeliveryStatus,
                PartialValue::new_iutf8(s.as_str())
            ),
        ]))
    } else {
        filter!(f_eq(Attribute::Class, EntryClass::LogoutDelivery.into()))
    };
    let entries = qs_read.impersonate_search(filter.clone(), filter, ident)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let endpoint = entry
            .get_ava_single_url(Attribute::LogoutDeliveryEndpoint)
            .map(ToString::to_string)
            .unwrap_or_default();
        let status_str = entry
            .get_ava_single_iutf8(Attribute::LogoutDeliveryStatus)
            .unwrap_or("unknown")
            .to_string();
        let attempts = entry
            .get_ava_single_uint32(Attribute::LogoutDeliveryAttempts)
            .unwrap_or(0);
        let next_attempt = entry
            .get_ava_single_datetime(Attribute::LogoutDeliveryNextAttempt)
            .map(|dt| {
                dt.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let created = entry
            .get_ava_single_datetime(Attribute::LogoutDeliveryCreated)
            .map(|dt| {
                dt.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let rp = entry
            .get_ava_single_refer(Attribute::LogoutDeliveryRp)
            .unwrap_or_else(uuid::Uuid::nil);
        out.push(netidm_proto::v1::LogoutDeliveryDto {
            uuid: entry.get_uuid(),
            endpoint,
            status: status_str,
            attempts,
            next_attempt,
            created,
            rp,
        });
    }
    Ok(out)
}

/// Load one `LogoutDelivery` by UUID and render it as a
/// [`netidm_proto::v1::LogoutDeliveryDto`]. Returns `Ok(None)` if the
/// UUID does not exist; `Err` only on DB-level failures.
///
/// # Errors
///
/// Returns any [`OperationError`] other than `NoMatchingEntries`
/// propagated from the underlying search.
pub fn show_logout_delivery(
    qs_read: &mut crate::server::QueryServerReadTransaction<'_>,
    ident: &crate::prelude::Identity,
    delivery_uuid: uuid::Uuid,
) -> Result<Option<netidm_proto::v1::LogoutDeliveryDto>, OperationError> {
    let filter = filter!(f_and!([
        f_eq(Attribute::Class, EntryClass::LogoutDelivery.into()),
        f_eq(Attribute::Uuid, PartialValue::Uuid(delivery_uuid)),
    ]));
    let mut entries = qs_read.impersonate_search(filter.clone(), filter, ident)?;
    let entry = match entries.pop() {
        Some(e) => e,
        None => return Ok(None),
    };
    let endpoint = entry
        .get_ava_single_url(Attribute::LogoutDeliveryEndpoint)
        .map(ToString::to_string)
        .unwrap_or_default();
    let status = entry
        .get_ava_single_iutf8(Attribute::LogoutDeliveryStatus)
        .unwrap_or("unknown")
        .to_string();
    let attempts = entry
        .get_ava_single_uint32(Attribute::LogoutDeliveryAttempts)
        .unwrap_or(0);
    let next_attempt = entry
        .get_ava_single_datetime(Attribute::LogoutDeliveryNextAttempt)
        .map(|dt| {
            dt.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let created = entry
        .get_ava_single_datetime(Attribute::LogoutDeliveryCreated)
        .map(|dt| {
            dt.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let rp = entry
        .get_ava_single_refer(Attribute::LogoutDeliveryRp)
        .unwrap_or_else(uuid::Uuid::nil);
    Ok(Some(netidm_proto::v1::LogoutDeliveryDto {
        uuid: delivery_uuid,
        endpoint,
        status,
        attempts,
        next_attempt,
        created,
        rp,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_delivery_status_round_trip() {
        for &s in &[
            LogoutDeliveryStatus::Pending,
            LogoutDeliveryStatus::Succeeded,
            LogoutDeliveryStatus::Failed,
        ] {
            let round_tripped =
                LogoutDeliveryStatus::from_str(s.as_str()).expect("round-trip must succeed");
            assert_eq!(round_tripped, s);
        }
    }

    #[test]
    fn logout_delivery_status_rejects_unknown() {
        assert!(LogoutDeliveryStatus::from_str("garbage").is_err());
        assert!(LogoutDeliveryStatus::from_str("").is_err());
        // Case-sensitive: "Pending" with capital P is not the canonical form.
        assert!(LogoutDeliveryStatus::from_str("Pending").is_err());
    }

    #[test]
    fn logout_delivery_status_terminal_flags() {
        assert!(!LogoutDeliveryStatus::Pending.is_terminal());
        assert!(LogoutDeliveryStatus::Succeeded.is_terminal());
        assert!(LogoutDeliveryStatus::Failed.is_terminal());
    }

    #[test]
    fn retry_schedule_budgets_roughly_ten_hours() {
        // Sanity-check the schedule shape: 6 attempts, monotonically
        // non-decreasing, total >= 10 h but < 24 h.
        assert_eq!(RETRY_SCHEDULE.len(), 6);
        assert_eq!(RETRY_SCHEDULE[0], Duration::ZERO);
        let mut prev = Duration::ZERO;
        for &step in &RETRY_SCHEDULE {
            assert!(step >= prev, "retry schedule must be non-decreasing");
            prev = step;
        }
        let total: Duration = RETRY_SCHEDULE.iter().sum();
        assert!(total >= Duration::from_secs(36_000), "total budget < 10 h");
        assert!(total < Duration::from_secs(86_400), "total budget >= 24 h");
    }

    #[test]
    fn delivery_timeout_is_bounded() {
        // Per-request bound, not the retry bound. Must be small so a
        // hung endpoint doesn't delay the worker's poll loop.
        assert!(DELIVERY_TIMEOUT <= Duration::from_secs(30));
    }
}
