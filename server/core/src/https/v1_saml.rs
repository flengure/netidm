use super::apidocs::response_schema::DefaultApiResponse;
use super::errors::WebError;
use super::middleware::KOpId;
use super::v1::{json_rest_event_get, json_rest_event_post};
use super::ServerState;

use crate::https::extractors::VerifiedClientInformation;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use netidm_proto::v1::Entry as ProtoEntry;
use netidmd_lib::prelude::*;

/// Lists all SAML client providers.
pub(crate) async fn saml_client_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::SamlClient.into()));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

/// Create a new SAML client provider.
pub(crate) async fn saml_client_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes = vec![
        EntryClass::SamlClient.to_string(),
        EntryClass::Object.to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

/// Get a specific SAML client provider by name.
pub(crate) async fn saml_client_id_get(
    State(state): State<ServerState>,
    Path(name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::SamlClient.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&name))
    ]));
    state
        .qe_r_ref
        .handle_internalsearch(client_auth_info, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop())
        .map(Json::from)
        .map_err(WebError::from)
}

/// Delete a SAML client provider by name.
pub(crate) async fn saml_client_id_delete(
    State(state): State<ServerState>,
    Path(name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::SamlClient.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&name))
    ]));
    state
        .qe_w_ref
        .handle_internaldelete(client_auth_info, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

/// Patch a SAML client provider (e.g., update the IdP certificate).
pub(crate) async fn saml_client_id_patch(
    State(state): State<ServerState>,
    Path(name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::SamlClient.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&name))
    ]));
    state
        .qe_w_ref
        .handle_internalpatch(client_auth_info, filter, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/saml_client/{name}/_group_mapping/{upstream}",
    request_body=String,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "saml",
    operation_id = "saml_client_id_group_mapping_post"
)]
/// Add a group mapping to a SAML upstream client.
///
/// The request body is the netidm group UUID (as a JSON string). The server
/// rejects the request with `OperationError::InvalidAttribute` if an existing
/// mapping for the same `upstream` name already exists on the connector
/// (FR-007a). The `upstream` name is taken verbatim from the URL path and may
/// contain colons.
pub(crate) async fn saml_client_id_group_mapping_post(
    State(state): State<ServerState>,
    Path((name, upstream)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(netidm_group_uuid): Json<String>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_saml_client_group_mapping_add(
            client_auth_info,
            name,
            upstream,
            netidm_group_uuid,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/saml_client/{name}/_group_mapping/{upstream}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "saml",
    operation_id = "saml_client_id_group_mapping_delete"
)]
/// Remove a group mapping from a SAML upstream client.
///
/// If no mapping for `upstream` exists on the connector the request succeeds
/// with no side effect (idempotent).
pub(crate) async fn saml_client_id_group_mapping_delete(
    State(state): State<ServerState>,
    Path((name, upstream)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_saml_client_group_mapping_remove(client_auth_info, name, upstream, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/saml_client/{name}/_slo_url",
    request_body=String,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "saml",
    operation_id = "saml_client_id_slo_url_post"
)]
/// Set (replace) the SAML service provider's Single Logout Service URL.
/// Single-value: re-invoking replaces the previous URL. Rejects malformed
/// URLs. Advertised back to the SP in the IdP metadata once SAML SLO
/// lands in US4.
pub(crate) async fn saml_client_id_slo_url_post(
    State(state): State<ServerState>,
    Path(name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(url): Json<String>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_saml_client_slo_url_set(client_auth_info, name, url, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/saml_client/{name}/_slo_url",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "saml",
    operation_id = "saml_client_id_slo_url_delete"
)]
/// Clear the SAML service provider's Single Logout Service URL.
/// Idempotent.
pub(crate) async fn saml_client_id_slo_url_delete(
    State(state): State<ServerState>,
    Path(name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_saml_client_slo_url_clear(client_auth_info, name, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}
