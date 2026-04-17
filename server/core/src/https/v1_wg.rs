use super::apidocs::response_schema::{ApiResponseWithout200, DefaultApiResponse};
use super::errors::WebError;
use super::middleware::KOpId;
use super::ServerState;
use crate::https::extractors::VerifiedClientInformation;
use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use netidm_proto::constants::APPLICATION_JSON;
use netidm_proto::internal::OperationError;
use netidm_proto::wg::{
    WgConnectRequest, WgConnectResponse, WgPeerResponse, WgTokenCreate, WgTokenCreatedResponse,
    WgTokenInfo, WgTunnelCreate, WgTunnelPatch, WgTunnelResponse,
};

// ---- Tunnel handlers ----

#[utoipa::path(
    get,
    path = "/v1/wg/tunnel",
    responses(
        (status = 200, content_type = APPLICATION_JSON, body = Vec<WgTunnelResponse>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "wg",
    operation_id = "wg_tunnel_list"
)]
pub async fn wg_tunnel_list(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<WgTunnelResponse>>, WebError> {
    let backend = format!("{:?}", state.wg_manager.backend_kind());
    state
        .qe_r_ref
        .handle_wg_tunnel_list(client_auth_info, backend, kopid.eventid)
        .await
        .map(Json)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/wg/tunnel",
    request_body = WgTunnelCreate,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "wg",
    operation_id = "wg_tunnel_create"
)]
pub async fn wg_tunnel_create(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(req): Json<WgTunnelCreate>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_wg_tunnel_create(client_auth_info, req, kopid.eventid)
        .await
        .map(Json)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/wg/tunnel/{id}",
    responses(
        (status = 200, content_type = APPLICATION_JSON, body = WgTunnelResponse),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "wg",
    operation_id = "wg_tunnel_get"
)]
pub async fn wg_tunnel_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<WgTunnelResponse>>, WebError> {
    let backend = format!("{:?}", state.wg_manager.backend_kind());
    state
        .qe_r_ref
        .handle_wg_tunnel_get(client_auth_info, id, backend, kopid.eventid)
        .await
        .map(Json)
        .map_err(WebError::from)
}

#[utoipa::path(
    patch,
    path = "/v1/wg/tunnel/{id}",
    request_body = WgTunnelPatch,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "wg",
    operation_id = "wg_tunnel_patch"
)]
pub async fn wg_tunnel_patch(
    State(_state): State<ServerState>,
    Path(_id): Path<String>,
    Extension(_kopid): Extension<KOpId>,
    VerifiedClientInformation(_client_auth_info): VerifiedClientInformation,
    Json(_req): Json<WgTunnelPatch>,
) -> Result<Json<()>, WebError> {
    Err(WebError::OperationError(OperationError::InvalidState))
}

#[utoipa::path(
    delete,
    path = "/v1/wg/tunnel/{id}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "wg",
    operation_id = "wg_tunnel_delete"
)]
pub async fn wg_tunnel_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_wg_tunnel_delete(client_auth_info, id, kopid.eventid)
        .await
        .map(Json)
        .map_err(WebError::from)
}

// ---- Peer handlers ----

#[utoipa::path(
    get,
    path = "/v1/wg/tunnel/{id}/peer",
    responses(
        (status = 200, content_type = APPLICATION_JSON, body = Vec<WgPeerResponse>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "wg",
    operation_id = "wg_peer_list"
)]
pub async fn wg_peer_list(
    State(state): State<ServerState>,
    Path(tunnel_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<WgPeerResponse>>, WebError> {
    state
        .qe_r_ref
        .handle_wg_peer_list(client_auth_info, tunnel_id, kopid.eventid)
        .await
        .map(Json)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/wg/tunnel/{id}/peer/{peer_id}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "wg",
    operation_id = "wg_peer_delete"
)]
pub async fn wg_peer_delete(
    State(state): State<ServerState>,
    Path((_tunnel_id, peer_id)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    let peer_uuid = uuid::Uuid::parse_str(&peer_id).map_err(|_| {
        WebError::OperationError(OperationError::InvalidAttribute("Invalid UUID".to_string()))
    })?;
    state
        .qe_w_ref
        .handle_wg_peer_delete(client_auth_info, peer_uuid, kopid.eventid)
        .await
        .map(Json)
        .map_err(WebError::from)
}

// ---- Token handlers ----

#[utoipa::path(
    get,
    path = "/v1/wg/tunnel/{id}/token",
    responses(
        (status = 200, content_type = APPLICATION_JSON, body = Vec<WgTokenInfo>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "wg",
    operation_id = "wg_token_list"
)]
pub async fn wg_token_list(
    State(state): State<ServerState>,
    Path(tunnel_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<WgTokenInfo>>, WebError> {
    state
        .qe_r_ref
        .handle_wg_token_list(client_auth_info, tunnel_id, kopid.eventid)
        .await
        .map(Json)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/wg/tunnel/{id}/token",
    request_body = WgTokenCreate,
    responses(
        (status = 200, content_type = APPLICATION_JSON, body = WgTokenCreatedResponse),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "wg",
    operation_id = "wg_token_create"
)]
pub async fn wg_token_create(
    State(state): State<ServerState>,
    Path(tunnel_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(req): Json<WgTokenCreate>,
) -> Result<Json<WgTokenCreatedResponse>, WebError> {
    state
        .qe_w_ref
        .handle_wg_token_create(client_auth_info, tunnel_id, req, kopid.eventid)
        .await
        .map(Json)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/wg/tunnel/{id}/token/{token_id}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "wg",
    operation_id = "wg_token_delete"
)]
pub async fn wg_token_delete(
    State(state): State<ServerState>,
    Path((tunnel_id, token_id)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_wg_token_delete(client_auth_info, tunnel_id, token_id, kopid.eventid)
        .await
        .map(Json)
        .map_err(WebError::from)
}

// ---- Client registration ----

#[utoipa::path(
    post,
    path = "/v1/wg/connect",
    request_body = WgConnectRequest,
    responses(
        (status = 200, content_type = APPLICATION_JSON, body = WgConnectResponse),
        ApiResponseWithout200,
    ),
    tag = "wg",
    operation_id = "wg_connect"
)]
pub async fn wg_connect(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(req): Json<WgConnectRequest>,
) -> Result<Json<WgConnectResponse>, WebError> {
    let caller_name = format!("peer-{}", &kopid.eventid.as_simple());
    state
        .qe_w_ref
        .handle_wg_connect(client_auth_info, caller_name, req, kopid.eventid)
        .await
        .map(Json)
        .map_err(WebError::from)
}

// ---- Router ----

pub fn route_setup() -> Router<ServerState> {
    Router::new()
        .route("/v1/wg/tunnel", get(wg_tunnel_list).post(wg_tunnel_create))
        .route(
            "/v1/wg/tunnel/{id}",
            get(wg_tunnel_get)
                .patch(wg_tunnel_patch)
                .delete(wg_tunnel_delete),
        )
        .route("/v1/wg/tunnel/{id}/peer", get(wg_peer_list))
        .route("/v1/wg/tunnel/{id}/peer/{peer_id}", delete(wg_peer_delete))
        .route(
            "/v1/wg/tunnel/{id}/token",
            get(wg_token_list).post(wg_token_create),
        )
        .route(
            "/v1/wg/tunnel/{id}/token/{token_id}",
            delete(wg_token_delete),
        )
        .route("/v1/wg/connect", post(wg_connect))
}
