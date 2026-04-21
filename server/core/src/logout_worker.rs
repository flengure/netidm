//! Background worker that drives OIDC Back-Channel Logout deliveries.
//!
//! The data model, CRUD helpers, retry schedule, and per-request timeout
//! live in [`netidmd_lib::idm::logout_delivery`]. This module owns the
//! async glue: the tokio task that polls for due records, POSTs the
//! signed logout token to each relying party's registered endpoint via
//! `reqwest`, and reports the outcome back into the persistent queue.
//!
//! One worker is spawned per `netidmd` instance at startup. The worker
//! listens for a shared `Notify` signal so `terminate_session` can wake
//! it immediately after enqueueing a new delivery; otherwise it polls on
//! [`netidmd_lib::idm::logout_delivery::WORKER_POLL_INTERVAL`].

use std::sync::Arc;

use time::OffsetDateTime;
use tokio::sync::{broadcast, Notify};
use uuid::Uuid;

use netidmd_lib::idm::logout_delivery::{
    list_due_pending_deliveries, load_logout_delivery, mark_logout_delivery_result,
    DeliveryOutcome, LogoutDeliveryStatus, DELIVERY_TIMEOUT, WORKER_POLL_INTERVAL,
};
use netidmd_lib::idm::server::IdmServer;
use netidmd_lib::prelude::duration_from_epoch_now;

/// Spawn the back-channel logout delivery worker on the ambient tokio
/// runtime. Returns the `JoinHandle` so the caller can await clean
/// shutdown; in practice `netidmd` lets the shutdown broadcast drive the
/// exit and joins on top-level shutdown.
///
/// The `reqwest::Client` is constructed inside this function so every
/// netidmd instance gets a dedicated client with the right timeout
/// applied. Callers that want to share one client between the worker
/// and other tasks can instead call [`run_worker`] directly.
pub fn spawn_worker(
    idms: Arc<IdmServer>,
    shutdown: broadcast::Receiver<crate::CoreAction>,
) -> tokio::task::JoinHandle<()> {
    let notify = idms.logout_delivery_notify();
    let http = match reqwest::Client::builder()
        .timeout(DELIVERY_TIMEOUT)
        .user_agent(concat!(
            "netidm/",
            env!("CARGO_PKG_VERSION"),
            " (backchannel-logout)"
        ))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(?e, "Failed to build reqwest client for logout worker");
            // Still spawn a task that just waits for shutdown so the
            // handle type is consistent; delivery is effectively disabled
            // until netidmd restarts.
            return tokio::spawn(async move {
                let mut sd = shutdown;
                // Degraded mode: just consume shutdown actions forever.
                while let Ok(action) = sd.recv().await {
                    if matches!(action, crate::CoreAction::Shutdown) {
                        break;
                    }
                }
            });
        }
    };
    tokio::spawn(run_worker(idms, http, notify, shutdown))
}

/// Drive pending `LogoutDelivery` records to completion. Runs until the
/// shutdown broadcast yields.
pub async fn run_worker(
    idms: Arc<IdmServer>,
    http: reqwest::Client,
    notify: Arc<Notify>,
    mut shutdown: broadcast::Receiver<crate::CoreAction>,
) {
    let mut poll = tokio::time::interval(WORKER_POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Drop the tick `interval` fires immediately on construction; we
    // want the first pass triggered by the regular schedule or a
    // Notify signal, not a no-op at boot.
    poll.tick().await;

    loop {
        tokio::select! {
            biased;
            Ok(action) = shutdown.recv() => {
                match action {
                    crate::CoreAction::Shutdown => {
                        tracing::info!("Back-channel logout delivery worker shutting down");
                        return;
                    }
                    crate::CoreAction::Reload => {
                        // Reload is a no-op for this worker — no in-memory
                        // state to refresh; the DB read on each tick picks
                        // up any new configuration immediately.
                        continue;
                    }
                }
            }
            _ = poll.tick() => {}
            () = notify.notified() => {}
        }

        let due = match collect_due_deliveries(idms.as_ref()).await {
            Ok(ids) => ids,
            Err(e) => {
                tracing::error!(?e, "Logout delivery worker: failed to list due entries");
                continue;
            }
        };

        for delivery_uuid in due {
            attempt_one_delivery(idms.as_ref(), &http, delivery_uuid).await;
        }
    }
}

async fn collect_due_deliveries(idms: &IdmServer) -> Result<Vec<Uuid>, OperationError> {
    let ct = duration_from_epoch_now();
    let mut txn = idms.proxy_write(ct).await?;
    let now = OffsetDateTime::UNIX_EPOCH + ct;
    let ids = list_due_pending_deliveries(&mut txn.qs_write, now)?;
    drop(txn);
    Ok(ids)
}

async fn attempt_one_delivery(idms: &IdmServer, http: &reqwest::Client, delivery_uuid: Uuid) {
    let ct = duration_from_epoch_now();
    let entry = match idms.proxy_write(ct).await {
        Ok(mut t) => {
            let loaded = load_logout_delivery(&mut t.qs_write, delivery_uuid);
            drop(t);
            match loaded {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(?e, %delivery_uuid, "Failed to load logout delivery");
                    return;
                }
            }
        }
        Err(e) => {
            tracing::error!(?e, %delivery_uuid, "Failed to open write txn to load delivery");
            return;
        }
    };

    if entry.status.is_terminal() {
        return;
    }

    let outcome = match post_logout_token(http, &entry.endpoint, &entry.logout_token).await {
        Ok(()) => {
            tracing::info!(
                %delivery_uuid,
                endpoint = %entry.endpoint,
                rp = %entry.rp,
                "Back-channel logout delivered"
            );
            DeliveryOutcome::Succeeded
        }
        Err(reason) => {
            tracing::warn!(
                %delivery_uuid,
                endpoint = %entry.endpoint,
                rp = %entry.rp,
                %reason,
                attempts = entry.attempts,
                "Back-channel logout delivery attempt failed"
            );
            DeliveryOutcome::TransientFailure
        }
    };

    let ct_mark = duration_from_epoch_now();
    let now = OffsetDateTime::UNIX_EPOCH + ct_mark;
    match idms.proxy_write(ct_mark).await {
        Ok(mut t) => {
            match mark_logout_delivery_result(&mut t.qs_write, delivery_uuid, outcome, now) {
                Ok(status) => {
                    if let Err(e) = t.commit() {
                        tracing::error!(?e, %delivery_uuid, "Failed to commit delivery result");
                    } else if status == LogoutDeliveryStatus::Failed {
                        tracing::error!(
                            %delivery_uuid,
                            endpoint = %entry.endpoint,
                            rp = %entry.rp,
                            "Back-channel logout delivery permanently failed after retry budget exhausted"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(?e, %delivery_uuid, "Failed to mark delivery result");
                }
            }
        }
        Err(e) => {
            tracing::error!(?e, %delivery_uuid, "Failed to open write txn to mark delivery");
        }
    }
}

/// POST the logout token to the RP's back-channel endpoint per OIDC
/// Back-Channel Logout 1.0 §2.8: `application/x-www-form-urlencoded`
/// body containing `logout_token=<JWS>`. Returns `Ok(())` on 2xx,
/// `Err(description)` otherwise.
async fn post_logout_token(
    http: &reqwest::Client,
    endpoint: &url::Url,
    token: &str,
) -> Result<(), String> {
    let form = [("logout_token", token)];
    let resp = http
        .post(endpoint.as_str())
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

use netidmd_lib::prelude::OperationError;
