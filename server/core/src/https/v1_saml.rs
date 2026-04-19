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
