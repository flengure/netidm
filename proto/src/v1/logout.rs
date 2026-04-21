//! Back-channel logout delivery DTOs — the shape admins see when
//! inspecting the `LogoutDelivery` queue via the CLI or client SDK.
//!
//! The server assembles these from `LogoutDelivery` entries read through
//! the admin-read ACP added in DL26. Only the fields safe to expose are
//! included — the raw `logout_token` JWS is intentionally **not** in
//! this DTO, since it may carry privacy-sensitive claims that admins
//! would otherwise only see indirectly through the server logs.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// One `LogoutDelivery` record rendered for the admin queue API.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct LogoutDeliveryDto {
    /// The delivery record's own UUID.
    #[schema(value_type = String, format = "uuid")]
    pub uuid: Uuid,
    /// Target URL netidm POSTs the logout token to.
    pub endpoint: String,
    /// Current status: `pending`, `succeeded`, or `failed`.
    pub status: String,
    /// Count of delivery attempts made so far.
    pub attempts: u32,
    /// When the worker should next attempt this delivery, RFC-3339.
    pub next_attempt: String,
    /// When this delivery was enqueued, RFC-3339.
    pub created: String,
    /// UUID of the relying party this delivery is targeted at.
    #[schema(value_type = String, format = "uuid")]
    pub rp: Uuid,
}

/// List response — the admin queue API returns a batch of records.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct LogoutDeliveryListResponse {
    pub items: Vec<LogoutDeliveryDto>,
}

/// Optional filter on the `LogoutDelivery` queue.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LogoutDeliveryFilter {
    Pending,
    Succeeded,
    Failed,
}

impl LogoutDeliveryFilter {
    /// Canonical string form — matches the values persisted in the
    /// `LogoutDeliveryStatus` attribute.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LogoutDeliveryFilter::Pending => "pending",
            LogoutDeliveryFilter::Succeeded => "succeeded",
            LogoutDeliveryFilter::Failed => "failed",
        }
    }
}
