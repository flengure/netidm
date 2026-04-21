use super::apidocs::response_schema::{ApiResponseWithout200, DefaultApiResponse};
use super::errors::WebError;
use super::middleware::KOpId;
use super::oauth2::oauth2_id;
use super::v1::{
    json_rest_event_delete_id_attr, json_rest_event_get, json_rest_event_post,
    json_rest_event_post_id_attr,
};
use super::ServerState;

use crate::https::extractors::VerifiedClientInformation;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use netidm_proto::internal::{ImageType, ImageValue, Oauth2ClaimMapJoin};
use netidm_proto::v1::Entry as ProtoEntry;
use netidmd_lib::prelude::*;
use netidmd_lib::valueset::image::ImageValueThings;
use sketching::admin_error;

#[utoipa::path(
    get,
    path = "/v1/oauth2",
    responses(
        (status = 200,content_type=APPLICATION_JSON, body=Vec<ProtoEntry>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_get"
)]
/// Lists all the OAuth2 Resource Servers
pub(crate) async fn oauth2_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Vec<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_eq(
        Attribute::Class,
        EntryClass::OAuth2ResourceServer.into()
    ));
    json_rest_event_get(state, None, filter, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/_basic",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_basic_post"
)]
/// Create a new Confidential OAuth2 client that authenticates with Http Basic.
pub(crate) async fn oauth2_basic_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes = vec![
        EntryClass::OAuth2ResourceServer.to_string(),
        EntryClass::OAuth2ResourceServerBasic.to_string(),
        EntryClass::Account.to_string(),
        EntryClass::Object.to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/_public",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_public_post"
)]
/// Create a new Public OAuth2 client
pub(crate) async fn oauth2_public_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes = vec![
        EntryClass::OAuth2ResourceServer.to_string(),
        EntryClass::OAuth2ResourceServerPublic.to_string(),
        EntryClass::Account.to_string(),
        EntryClass::Object.to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

#[utoipa::path(
    get,
    path = "/v1/oauth2/{rs_name}",
    responses(
        (status = 200, body=Option<ProtoEntry>, content_type=APPLICATION_JSON),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_get"
)]
/// Get the details of a given OAuth2 Resource Server.
pub(crate) async fn oauth2_id_get(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_r_ref
        .handle_internalsearch(client_auth_info, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop())
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    get,
    path = "/v1/oauth2/{rs_name}/_basic_secret",
    responses(
        (status = 200,content_type=APPLICATION_JSON, body=Option<String>),
        ApiResponseWithout200,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_get_basic_secret"
)]
/// Get the basic secret for a given OAuth2 Resource Server. This is used for authentication.
#[instrument(level = "info", skip(state))]
pub(crate) async fn oauth2_id_get_basic_secret(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
) -> Result<Json<Option<String>>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_r_ref
        .handle_oauth2_basic_secret_read(client_auth_info, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    patch,
    path = "/v1/oauth2/{rs_name}",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_patch"
)]
/// Modify an OAuth2 Resource Server
pub(crate) async fn oauth2_id_patch(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);

    state
        .qe_w_ref
        .handle_internalpatch(client_auth_info, filter, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_scopemap/{group}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_scopemap_post"
)]
/// Modify the scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_scopemap_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, group)): Path<(String, String)>,
    Json(scopes): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);

    state
        .qe_w_ref
        .handle_oauth2_scopemap_update(client_auth_info, group, scopes, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_attr/{attr}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2/attr",
    operation_id = "oauth2_id_attr_post",
)]
pub async fn oauth2_id_attr_post(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(values): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(
        Attribute::Class,
        EntryClass::OAuth2ResourceServer.into()
    ));
    json_rest_event_post_id_attr(state, id, attr, filter, values, kopid, client_auth_info).await
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_attr/{attr}",
    request_body=Option<Vec<String>>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2/attr",
    operation_id = "oauth2_id_attr_delete",
)]
pub async fn oauth2_id_attr_delete(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    values: Option<Json<Vec<String>>>,
) -> Result<Json<()>, WebError> {
    let filter = filter_all!(f_eq(
        Attribute::Class,
        EntryClass::OAuth2ResourceServer.into()
    ));
    let values = values.map(|v| v.0);
    json_rest_event_delete_id_attr(state, id, attr, filter, values, kopid, client_auth_info).await
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_scopemap/{group}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_scopemap_delete"
)]
// Delete a scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_scopemap_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, group)): Path<(String, String)>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_scopemap_delete(client_auth_info, group, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_claimmap/{claim_name}/{group}",
    request_body=Vec<String>,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_claimmap_post"
)]
/// Modify the claim map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_claimmap_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, claim_name, group)): Path<(String, String, String)>,
    Json(claims): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_claimmap_update(
            client_auth_info,
            claim_name,
            group,
            claims,
            filter,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_claimmap/{claim_name}",
    request_body=Oauth2ClaimMapJoin,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_claimmap_join_post"
)]
/// Modify the claim map join strategy for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_claimmap_join_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, claim_name)): Path<(String, String)>,
    Json(join): Json<Oauth2ClaimMapJoin>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_claimmap_join_update(
            client_auth_info,
            claim_name,
            join,
            filter,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_claimmap/{claim_name}/{group}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_claimmap_delete"
)]
// Delete a claim map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_claimmap_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, claim_name, group)): Path<(String, String, String)>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_claimmap_delete(client_auth_info, claim_name, group, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_sup_scopemap/{group}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_sup_scopemap_post"
)]
/// Create a supplemental scope map for a given OAuth2 Resource Server
pub(crate) async fn oauth2_id_sup_scopemap_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, group)): Path<(String, String)>,
    Json(scopes): Json<Vec<String>>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_sup_scopemap_update(client_auth_info, group, scopes, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_sup_scopemap/{group}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_sup_scopemap_delete"
)]
// Delete a supplemental scope map configuration.
pub(crate) async fn oauth2_id_sup_scopemap_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path((rs_name, group)): Path<(String, String)>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_oauth2_sup_scopemap_delete(client_auth_info, group, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}",
    responses(
        DefaultApiResponse,
        (status = 404),
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_delete"
)]
/// Delete an OAuth2 Resource Server
pub(crate) async fn oauth2_id_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_id(&rs_name);
    state
        .qe_w_ref
        .handle_internaldelete(client_auth_info, filter, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_image",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_image_delete"
)]
// API endpoint for deleting the image associated with an OAuth2 Resource Server.
pub(crate) async fn oauth2_id_image_delete(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_image_update(client_auth_info, oauth2_id(&rs_name), None)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_image",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_image_post"
)]
/// API endpoint for creating/replacing the image associated with an OAuth2 Resource Server.
///
/// It requires a multipart form with the image file, and the content type must be one of the
/// [VALID_IMAGE_UPLOAD_CONTENT_TYPES].
pub(crate) async fn oauth2_id_image_post(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<()>, WebError> {
    // because we might not get an image
    let mut image: Option<ImageValue> = None;

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let filename = field.file_name().map(|f| f.to_string()).clone();
        if let Some(filename) = filename {
            let content_type = field.content_type().map(|f| f.to_string()).clone();

            let content_type = match content_type {
                Some(val) => {
                    if VALID_IMAGE_UPLOAD_CONTENT_TYPES.contains(&val.as_str()) {
                        val
                    } else {
                        debug!("Invalid content type: {}", val);
                        return Err(OperationError::InvalidRequestState.into());
                    }
                }
                None => {
                    debug!("No content type header provided");
                    return Err(OperationError::InvalidRequestState.into());
                }
            };
            let data = match field.bytes().await {
                Ok(val) => val,
                Err(_e) => return Err(OperationError::InvalidRequestState.into()),
            };

            let filetype = match ImageType::try_from_content_type(&content_type) {
                Ok(val) => val,
                Err(_err) => return Err(OperationError::InvalidRequestState.into()),
            };

            image = Some(ImageValue {
                filetype,
                filename: filename.to_string(),
                contents: data.to_vec(),
            });
        };
    }

    match image {
        Some(image) => {
            let image_validation_result = image.validate_image();
            match image_validation_result {
                Err(err) => {
                    admin_error!("Invalid image uploaded: {:?}", err);
                    Err(WebError::from(OperationError::InvalidRequestState))
                }
                Ok(_) => {
                    let rs_filter = oauth2_id(&rs_name);
                    state
                        .qe_w_ref
                        .handle_image_update(client_auth_info, rs_filter, Some(image))
                        .await
                        .map(Json::from)
                        .map_err(WebError::from)
                }
            }
        }
        None => Err(WebError::from(OperationError::InvalidAttribute(
            "No image included, did you mean to use the DELETE method?".to_string(),
        ))),
    }
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/_client",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_client_post"
)]
/// Get the details of a given OAuth2 Client Provider.
pub(crate) async fn oauth2_client_id_get(
    State(state): State<ServerState>,
    Path(name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<Option<ProtoEntry>>, WebError> {
    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::OAuth2Client.into()),
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

/// Create a new OAuth2 Client Provider (Netidm acts as the OAuth2 client to an external provider).
pub(crate) async fn oauth2_client_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let classes = vec![
        EntryClass::OAuth2Client.to_string(),
        EntryClass::Object.to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid, client_auth_info).await
}

/// Filter for an OAuth2 upstream client entry by its name.
fn oauth2_client_filter(name: &str) -> Filter<FilterInvalid> {
    filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::OAuth2Client.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(name))
    ]))
}

#[utoipa::path(
    patch,
    path = "/v1/oauth2/_client/{name}",
    request_body=ProtoEntry,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_client_id_patch"
)]
/// Patch an OAuth2 upstream Client Provider entry.
///
/// The PATCH on `/v1/oauth2/{id}` targets Resource Server (downstream) entries;
/// this route targets the distinct `OAuth2Client` (upstream) class so single-
/// value attribute updates such as `oauth2_link_by` can be applied.
pub(crate) async fn oauth2_client_id_patch(
    State(state): State<ServerState>,
    Path(name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(obj): Json<ProtoEntry>,
) -> Result<Json<()>, WebError> {
    let filter = oauth2_client_filter(&name);
    state
        .qe_w_ref
        .handle_internalpatch(client_auth_info, filter, obj, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_post_logout_redirect_uri",
    request_body=String,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_post_logout_redirect_uri_post"
)]
/// Add a URI to the OAuth2 relying party's `OAuth2RsPostLogoutRedirectUri`
/// allowlist. The request body is the URI as a JSON string. Idempotent:
/// adding a URI already present succeeds with no side effect. Rejects
/// malformed URIs.
pub(crate) async fn oauth2_id_post_logout_redirect_uri_post(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(uri): Json<String>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_oauth2_client_post_logout_redirect_uri_add(
            client_auth_info,
            rs_name,
            uri,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_post_logout_redirect_uri",
    request_body=String,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_post_logout_redirect_uri_delete"
)]
/// Remove a URI from the OAuth2 relying party's
/// `OAuth2RsPostLogoutRedirectUri` allowlist. The request body is the
/// URI as a JSON string. Idempotent: removing a URI not present returns
/// success with no side effect.
pub(crate) async fn oauth2_id_post_logout_redirect_uri_delete(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(uri): Json<String>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_oauth2_client_post_logout_redirect_uri_remove(
            client_auth_info,
            rs_name,
            uri,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/{rs_name}/_backchannel_logout_uri",
    request_body=String,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_backchannel_logout_uri_post"
)]
/// Set the OAuth2 relying party's `OAuth2RsBackchannelLogoutUri`.
/// Single-value: re-invoking replaces the previous URI. Rejects
/// malformed URIs.
pub(crate) async fn oauth2_id_backchannel_logout_uri_post(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(uri): Json<String>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_oauth2_client_backchannel_logout_uri_set(
            client_auth_info,
            rs_name,
            uri,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    delete,
    path = "/v1/oauth2/{rs_name}/_backchannel_logout_uri",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_id_backchannel_logout_uri_delete"
)]
/// Clear the OAuth2 relying party's `OAuth2RsBackchannelLogoutUri`.
/// Idempotent.
pub(crate) async fn oauth2_id_backchannel_logout_uri_delete(
    State(state): State<ServerState>,
    Path(rs_name): Path<String>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_oauth2_client_backchannel_logout_uri_clear(client_auth_info, rs_name, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}

#[utoipa::path(
    post,
    path = "/v1/oauth2/_client/{name}/_group_mapping/{upstream}",
    request_body=String,
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_client_id_group_mapping_post"
)]
/// Add a group mapping to an OAuth2 upstream client.
///
/// The request body is the netidm group UUID (as a JSON string). The server
/// rejects the request with `OperationError::InvalidValueState` if an
/// existing mapping for the same `upstream` name already exists on the
/// connector (FR-007a). The `upstream` name is taken verbatim from the URL
/// path and may contain colons.
pub(crate) async fn oauth2_client_id_group_mapping_post(
    State(state): State<ServerState>,
    Path((name, upstream)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Json(netidm_group_uuid): Json<String>,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_oauth2_client_group_mapping_add(
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
    path = "/v1/oauth2/_client/{name}/_group_mapping/{upstream}",
    responses(
        DefaultApiResponse,
    ),
    security(("token_jwt" = [])),
    tag = "oauth2",
    operation_id = "oauth2_client_id_group_mapping_delete"
)]
/// Remove a group mapping from an OAuth2 upstream client.
///
/// If no mapping for `upstream` exists on the connector the request succeeds
/// with no side effect (idempotent).
pub(crate) async fn oauth2_client_id_group_mapping_delete(
    State(state): State<ServerState>,
    Path((name, upstream)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Result<Json<()>, WebError> {
    state
        .qe_w_ref
        .handle_oauth2_client_group_mapping_remove(client_auth_info, name, upstream, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from)
}
