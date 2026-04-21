//! Persistent back-channel logout delivery queue and worker.
//!
//! At session-termination time, one [`LogoutDelivery`] entry is inserted per
//! registered back-channel logout endpoint. A background worker in `netidmd`
//! polls for `pending` entries and POSTs each with a bounded per-request
//! timeout and a bounded retry budget using exponential backoff.
//!
//! Module scaffolding only in DL26 Foundational phase; the `LogoutDelivery`
//! entity shape, retry schedule, and worker implementation land with US3
//! (Phase 5) of PR-RP-LOGOUT (specs/009-rp-logout/).
