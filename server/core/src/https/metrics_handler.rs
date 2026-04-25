use axum::{extract::State, http::header::CONTENT_TYPE, response::IntoResponse};
use prometheus_client::{
    encoding::{text::encode, EncodeLabelSet},
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};
use std::sync::{atomic::AtomicU64, Arc, LazyLock};
use std::time::Duration;
use tracing::error;

use super::ServerState;

// ---------------------------------------------------------------------------
// Label types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct HttpLabels {
    pub method: String,
    pub path: String,
    pub status: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct HttpDurationLabels {
    pub method: String,
    pub path: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct ForwardAuthLabels {
    pub outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct Oauth2TokenLabels {
    pub grant_type: String,
    pub outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct AuthDecisionLabels {
    pub outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct Oauth2AuthorizeLabels {
    pub outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct Oauth2ConsentLabels {
    pub outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BuildInfoLabels {
    version: String,
}

// ---------------------------------------------------------------------------
// Histogram constructor — fn pointer (no captures)
// ---------------------------------------------------------------------------

fn new_http_duration_histogram() -> Histogram {
    Histogram::new([
        0.005f64, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ])
}

// ---------------------------------------------------------------------------
// NetidmMetrics
// ---------------------------------------------------------------------------

pub(crate) struct NetidmMetrics {
    registry: Registry,
    // HTTP layer
    pub(crate) http_requests: Family<HttpLabels, Counter<u64, AtomicU64>>,
    pub(crate) http_duration: Family<HttpDurationLabels, Histogram, fn() -> Histogram>,
    // Forward auth gate
    pub(crate) forward_auth_decisions: Family<ForwardAuthLabels, Counter<u64, AtomicU64>>,
    // OAuth2 token endpoint
    pub(crate) oauth2_token_grants: Family<Oauth2TokenLabels, Counter<u64, AtomicU64>>,
    // IDM authentication (v1/auth)
    pub(crate) auth_decisions: Family<AuthDecisionLabels, Counter<u64, AtomicU64>>,
    // OAuth2 authorize endpoint
    pub(crate) oauth2_authorize_decisions: Family<Oauth2AuthorizeLabels, Counter<u64, AtomicU64>>,
    // OAuth2 consent (permit / reject)
    pub(crate) oauth2_consent_decisions: Family<Oauth2ConsentLabels, Counter<u64, AtomicU64>>,
}

impl NetidmMetrics {
    fn new() -> Self {
        let mut registry = Registry::default();

        let build_info: Family<BuildInfoLabels, Gauge> = Family::default();
        build_info
            .get_or_create(&BuildInfoLabels {
                version: env!("CARGO_PKG_VERSION").to_string(),
            })
            .set(1);
        registry.register("netidm_build", "Netidm build information", build_info);

        let http_requests: Family<HttpLabels, Counter<u64, AtomicU64>> = Family::default();
        registry.register(
            "netidm_http_requests",
            "Total HTTP requests by method, matched path, and status code",
            http_requests.clone(),
        );

        let http_duration: Family<HttpDurationLabels, Histogram, fn() -> Histogram> =
            Family::new_with_constructor(new_http_duration_histogram);
        registry.register(
            "netidm_http_request_duration_seconds",
            "HTTP request duration in seconds by method and matched path",
            http_duration.clone(),
        );

        let forward_auth_decisions: Family<ForwardAuthLabels, Counter<u64, AtomicU64>> =
            Family::default();
        registry.register(
            "netidm_forward_auth_decisions",
            "Forward auth gate decisions by outcome (allow / deny / skip)",
            forward_auth_decisions.clone(),
        );

        let oauth2_token_grants: Family<Oauth2TokenLabels, Counter<u64, AtomicU64>> =
            Family::default();
        registry.register(
            "netidm_oauth2_token_grants",
            "OAuth2 token grant requests by grant_type and outcome (success / error)",
            oauth2_token_grants.clone(),
        );

        let auth_decisions: Family<AuthDecisionLabels, Counter<u64, AtomicU64>> = Family::default();
        registry.register(
            "netidm_auth_decisions",
            "IDM authentication decisions by outcome (success / denied / error)",
            auth_decisions.clone(),
        );

        let oauth2_authorize_decisions: Family<Oauth2AuthorizeLabels, Counter<u64, AtomicU64>> =
            Family::default();
        registry.register(
            "netidm_oauth2_authorize_decisions",
            "OAuth2 authorize endpoint outcomes (consent_pending / auto_permitted / auth_required / denied / error)",
            oauth2_authorize_decisions.clone(),
        );

        let oauth2_consent_decisions: Family<Oauth2ConsentLabels, Counter<u64, AtomicU64>> =
            Family::default();
        registry.register(
            "netidm_oauth2_consent_decisions",
            "OAuth2 consent screen outcomes (permitted / rejected / error)",
            oauth2_consent_decisions.clone(),
        );

        NetidmMetrics {
            registry,
            http_requests,
            http_duration,
            forward_auth_decisions,
            oauth2_token_grants,
            auth_decisions,
            oauth2_authorize_decisions,
            oauth2_consent_decisions,
        }
    }

    pub(crate) fn record_http(&self, method: &str, path: &str, status: &str, duration: Duration) {
        self.http_requests
            .get_or_create(&HttpLabels {
                method: method.to_string(),
                path: path.to_string(),
                status: status.to_string(),
            })
            .inc();
        self.http_duration
            .get_or_create(&HttpDurationLabels {
                method: method.to_string(),
                path: path.to_string(),
            })
            .observe(duration.as_secs_f64());
    }

    pub(crate) fn inc_forward_auth(&self, outcome: &'static str) {
        self.forward_auth_decisions
            .get_or_create(&ForwardAuthLabels {
                outcome: outcome.to_string(),
            })
            .inc();
    }

    pub(crate) fn inc_oauth2_token(&self, grant_type: &str, outcome: &'static str) {
        self.oauth2_token_grants
            .get_or_create(&Oauth2TokenLabels {
                grant_type: grant_type.to_string(),
                outcome: outcome.to_string(),
            })
            .inc();
    }

    pub(crate) fn inc_auth(&self, outcome: &'static str) {
        self.auth_decisions
            .get_or_create(&AuthDecisionLabels {
                outcome: outcome.to_string(),
            })
            .inc();
    }

    pub(crate) fn inc_oauth2_authorize(&self, outcome: &'static str) {
        self.oauth2_authorize_decisions
            .get_or_create(&Oauth2AuthorizeLabels {
                outcome: outcome.to_string(),
            })
            .inc();
    }

    pub(crate) fn inc_oauth2_consent(&self, outcome: &'static str) {
        self.oauth2_consent_decisions
            .get_or_create(&Oauth2ConsentLabels {
                outcome: outcome.to_string(),
            })
            .inc();
    }

    pub(crate) fn encode_to_string(&self) -> Result<String, std::fmt::Error> {
        let mut body = String::new();
        encode(&mut body, &self.registry)?;
        Ok(body)
    }
}

// ---------------------------------------------------------------------------
// Global singleton — accessible from any code in server/core without
// threading through ServerState.
// ---------------------------------------------------------------------------

static GLOBAL_METRICS: LazyLock<Arc<NetidmMetrics>> =
    LazyLock::new(|| Arc::new(NetidmMetrics::new()));

pub(crate) fn global_metrics() -> &'static Arc<NetidmMetrics> {
    &GLOBAL_METRICS
}

// ---------------------------------------------------------------------------
// HTTP handler — GET /metrics
// ---------------------------------------------------------------------------

pub async fn metrics_handler(State(state): State<ServerState>) -> impl IntoResponse {
    match state.metrics.encode_to_string() {
        Ok(body) => (
            [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(err) => {
            error!(?err, "Failed to encode Prometheus metrics");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
