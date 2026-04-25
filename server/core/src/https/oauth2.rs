use std::collections::{BTreeMap, BTreeSet};

use super::errors::WebError;
use super::middleware::KOpId;
use super::ServerState;
use crate::https::extractors::{AuthorisationHeaders, VerifiedClientInformation};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header::CONTENT_TYPE, HeaderValue, Method, StatusCode},
    middleware::from_fn,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Form, Json, Router,
};
use axum_macros::debug_handler;
use netidm_proto::constants::uri::{
    OAUTH2_AUTHORISE, OAUTH2_AUTHORISE_PERMIT, OAUTH2_AUTHORISE_REJECT,
};
use netidm_proto::constants::APPLICATION_JSON;
use netidm_proto::oauth2::AuthorisationResponse;
use tower_http::cors::{AllowOrigin, CorsLayer};

use netidm_proto::oauth2::DeviceAuthorizationResponse;
use netidmd_lib::idm::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenRequest, AuthorisationRequest, AuthoriseResponse,
    ErrorResponse, Oauth2Error, TokenRevokeRequest,
};
use netidmd_lib::prelude::f_eq;
use netidmd_lib::prelude::*;
use netidmd_lib::value::PartialValue;
use serde::{Deserialize, Serialize};
use serde_with::formats::CommaSeparator;
use serde_with::{serde_as, StringWithSeparator};

use uri::{
    OAUTH2_AUTHORISE_DEVICE, OAUTH2_TOKEN_ENDPOINT, OAUTH2_TOKEN_INTROSPECT_ENDPOINT,
    OAUTH2_TOKEN_REVOKE_ENDPOINT,
};

// == Oauth2 Configuration Endpoints ==

/// Get a filter matching a given OAuth2 Resource Server
pub(crate) fn oauth2_id(rs_name: &str) -> Filter<FilterInvalid> {
    filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::OAuth2ResourceServer.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(rs_name))
    ]))
}

#[utoipa::path(
    get,
    path = "/ui/images/oauth2/{rs_name}",
    operation_id = "oauth2_image_get",
    responses(
        (status = 200, description = "Ok", body=&[u8]),
        (status = 401, description = "Authorization required"),
        (status = 403, description = "Not Authorized"),
    ),
    security(("token_jwt" = [])),
    tag = "ui",
)]
/// This returns the image for the OAuth2 Resource Server if the user has permissions
///
pub(crate) async fn oauth2_image_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
) -> Response {
    let rs_filter = oauth2_id(&rs_name);
    let res = state
        .qe_r_ref
        .handle_oauth2_rs_image_get_image(client_auth_info, rs_filter)
        .await;

    match res {
        Ok(Some(image)) => (
            StatusCode::OK,
            [(CONTENT_TYPE, image.filetype.as_content_type_str())],
            image.contents,
        )
            .into_response(),
        Ok(None) => {
            warn!(?rs_name, "No image set for OAuth2 client");
            (StatusCode::NOT_FOUND, "").into_response()
        }
        Err(err) => WebError::from(err).into_response(),
    }
}

// == OAUTH2 PROTOCOL FLOW HANDLERS ==
//
// oauth2 (partial)
// https://tools.ietf.org/html/rfc6749
// oauth2 pkce
// https://tools.ietf.org/html/rfc7636
//
// TODO
// oauth2 token introspection
// https://tools.ietf.org/html/rfc7662
// oauth2 bearer token
// https://tools.ietf.org/html/rfc6750
//
// From https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
//
//       +----------+
//       | Resource |
//       |   Owner  |
//       |          |
//       +----------+
//            ^
//            |
//           (B)
//       +----|-----+          Client Identifier      +---------------+
//       |         -+----(A)-- & Redirection URI ---->|               |
//       |  User-   |                                 | Authorization |
//       |  Agent  -+----(B)-- User authenticates --->|     Server    |
//       |          |                                 |               |
//       |         -+----(C)-- Authorization Code ---<|               |
//       +-|----|---+                                 +---------------+
//         |    |                                         ^      v
//        (A)  (C)                                        |      |
//         |    |                                         |      |
//         ^    v                                         |      |
//       +---------+                                      |      |
//       |         |>---(D)-- Authorization Code ---------'      |
//       |  Client |          & Redirection URI                  |
//       |         |                                             |
//       |         |<---(E)----- Access Token -------------------'
//       +---------+       (w/ Optional Refresh Token)
//
//     Note: The lines illustrating steps (A), (B), and (C) are broken into
//     two parts as they pass through the user-agent.
//
//  In this diagram, netidm is the authorisation server. Each step is handled by:
//
//  * Client Identifier  A)  oauth2_authorise_get
//  * User authenticates B)  normal netidm auth flow
//  * Authorization Code C)  oauth2_authorise_permit_get
//                           oauth2_authorise_reject_get
//  * Authorization Code / Access Token
//                     D/E)  oauth2_token_post
//
//  These functions appear stateless, but the state is managed through encrypted
//  tokens transmitted in the responses of this flow. This is because in a HA setup
//  we can not guarantee that the User-Agent or the Resource Server (client) will
//  access the same Netidm instance, and we can not rely on replication in these
//  cases. As a result, we must have our state in localised tokens so that any
//  valid Netidm instance in the topology can handle these request.
//

#[instrument(level = "debug", skip(state, kopid))]
pub async fn oauth2_authorise_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Json(auth_req): Json<AuthorisationRequest>,
) -> impl IntoResponse {
    let mut res = oauth2_authorise(state, auth_req, kopid, client_auth_info)
        .await
        .into_response();
    if res.status() == StatusCode::FOUND {
        // in post, we need the redirect not to be issued, so we mask 302 to 200
        *res.status_mut() = StatusCode::OK;
    }
    res
}

#[instrument(level = "debug", skip(state, kopid))]
pub async fn oauth2_authorise_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Query(auth_req): Query<AuthorisationRequest>,
) -> impl IntoResponse {
    // Start the oauth2 authorisation flow to present to the user.
    oauth2_authorise(state, auth_req, kopid, client_auth_info).await
}

async fn oauth2_authorise(
    state: ServerState,
    auth_req: AuthorisationRequest,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> impl IntoResponse {
    // Clone auth info before the move so we can reuse it for the auto-permit
    // path when skip_approval_screen is enabled.
    let client_auth_info_permit = if state.skip_approval_screen {
        Some(client_auth_info.clone())
    } else {
        None
    };

    let res: Result<AuthoriseResponse, Oauth2Error> = state
        .qe_r_ref
        .handle_oauth2_authorise(client_auth_info, auth_req, kopid.eventid)
        .await;

    match res {
        Ok(AuthoriseResponse::ConsentRequested {
            client_name,
            scopes,
            pii_scopes,
            consent_token,
        }) => {
            // When `skip_approval_screen` is set globally, bypass the consent UI
            // by immediately auto-permitting with the consent token.
            if let Some(auth_info) = client_auth_info_permit {
                return oauth2_authorise_permit(state, consent_token, kopid, auth_info)
                    .await
                    .into_response();
            }

            // Render a redirect to the consent page for the user to interact with
            // to authorise this session-id
            // This is json so later we can expand it with better detail.
            #[allow(clippy::unwrap_used)]
            let body = serde_json::to_string(&AuthorisationResponse::ConsentRequested {
                client_name,
                scopes,
                pii_scopes,
                consent_token,
            })
            .unwrap();
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::OK)
                .body(body.into())
                .unwrap()
        }
        Ok(AuthoriseResponse::Permitted(success)) => {
            // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.11
            // We could consider changing this to 303?
            #[allow(clippy::unwrap_used)]
            let body =
                Body::from(serde_json::to_string(&AuthorisationResponse::Permitted).unwrap());
            let redirect_uri = success.build_redirect_uri();

            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::FOUND)
                .header(
                    axum::http::header::LOCATION,
                    HeaderValue::from_str(redirect_uri.as_str()).unwrap(),
                )
                .body(body)
                .unwrap()
        }
        Ok(AuthoriseResponse::AuthenticationRequired { .. })
        | Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(
                    axum::http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer"),
                )
                .body(Body::empty())
                .unwrap()
        }
        Err(Oauth2Error::AccessDenied) => {
            // If scopes are not available for this account.
            #[allow(clippy::expect_used)]
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::empty())
                .expect("Failed to generate a forbidden response")
        }
        /*
        RFC - If the request fails due to a missing, invalid, or mismatching
              redirection URI, or if the client identifier is missing or invalid,
              the authorization server SHOULD inform the resource owner of the
              error and MUST NOT automatically redirect the user-agent to the
              invalid redirection URI.
        */
        // To further this, it appears that a malicious client configuration can set a phishing
        // site as the redirect URL, and then use that to trigger certain types of attacks. Instead
        // we do NOT redirect in an error condition, and just render the error ourselves.
        Err(e) => {
            admin_error!(
                "Unable to authorise - Error ID: {:?} error: {}",
                kopid.eventid,
                &e.to_string()
            );
            #[allow(clippy::expect_used)]
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::empty())
                .expect("Failed to generate a bad request response")
        }
    }
}

pub async fn oauth2_authorise_permit_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Json(consent_req): Json<String>,
) -> impl IntoResponse {
    let mut res = oauth2_authorise_permit(state, consent_req, kopid, client_auth_info)
        .await
        .into_response();
    if res.status() == StatusCode::FOUND {
        // in post, we need the redirect not to be issued, so we mask 302 to 200
        *res.status_mut() = StatusCode::OK;
    }
    res
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConsentRequestData {
    token: String,
}

pub async fn oauth2_authorise_permit_get(
    State(state): State<ServerState>,
    Query(token): Query<ConsentRequestData>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
) -> impl IntoResponse {
    // When this is called, this indicates consent to proceed from the user.
    oauth2_authorise_permit(state, token.token, kopid, client_auth_info).await
}

async fn oauth2_authorise_permit(
    state: ServerState,
    consent_req: String,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_oauth2_authorise_permit(client_auth_info, consent_req, kopid.eventid)
        .await;

    match res {
        Ok(success) => {
            // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.11
            // We could consider changing this to 303?
            let redirect_uri = success.build_redirect_uri();

            #[allow(clippy::expect_used)]
            Response::builder()
                .status(StatusCode::FOUND)
                .header(axum::http::header::LOCATION, redirect_uri.as_str())
                .body(Body::empty())
                .expect("Failed to generate response")
        }
        Err(err) => {
            match err {
                OperationError::NotAuthenticated => WebError::from(err).into_response(),
                _ => {
                    // If an error happens in our consent flow, I think
                    // that we should NOT redirect to the calling application
                    // and we need to handle that locally somehow.
                    // This needs to be better!
                    //
                    // Turns out this instinct was correct:
                    //  https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection
                    // Possible to use this with a malicious client configuration to phish / spam.
                    #[allow(clippy::expect_used)]
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .expect("Failed to generate error response")
                }
            }
        }
    }
}

// When this is called, this indicates the user has REJECTED the intent to proceed.
pub async fn oauth2_authorise_reject_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Form(consent_req): Form<ConsentRequestData>,
) -> Response<Body> {
    oauth2_authorise_reject(state, consent_req.token, kopid, client_auth_info).await
}

pub async fn oauth2_authorise_reject_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Query(consent_req): Query<ConsentRequestData>,
) -> Response<Body> {
    oauth2_authorise_reject(state, consent_req.token, kopid, client_auth_info).await
}

// // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
// // If the user willingly rejects the authorisation, we must redirect
// // with an error.
async fn oauth2_authorise_reject(
    state: ServerState,
    consent_req: String,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> Response<Body> {
    // Need to go back to the redir_uri
    // For this, we'll need to lookup where to go.

    let res = state
        .qe_r_ref
        .handle_oauth2_authorise_reject(client_auth_info, consent_req, kopid.eventid)
        .await;

    match res {
        Ok(reject) => {
            let redirect_uri = reject.build_redirect_uri();

            #[allow(clippy::unwrap_used)]
            Response::builder()
                .header(axum::http::header::LOCATION, redirect_uri.as_str())
                .body(Body::empty())
                .unwrap()
        }
        Err(err) => {
            match err {
                OperationError::NotAuthenticated => WebError::from(err).into_response(),
                _ => {
                    // If an error happens in our reject flow, I think
                    // that we should NOT redirect to the calling application
                    // and we need to handle that locally somehow.
                    // This needs to be better!
                    #[allow(clippy::expect_used)]
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .expect("Failed to generate an error response")
                }
            }
        }
    }
}

#[axum_macros::debug_handler]
#[instrument(skip(state, kopid, client_auth_info), level = "DEBUG")]
pub async fn oauth2_token_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Form(tok_req): Form<AccessTokenRequest>,
) -> impl IntoResponse {
    // This is called directly by the resource server, where we then issue
    // the token to the caller.

    // Do we change the method/path we take here based on the type of requested
    // grant? Should we cease the delayed/async session update here and just opt
    // for a wr txn?
    match state
        .qe_w_ref
        .handle_oauth2_token_exchange(client_auth_info, tok_req, kopid.eventid)
        .await
    {
        Ok(tok_res) => (StatusCode::OK, Json(tok_res)).into_response(),
        Err(e) => WebError::OAuth2(e).into_response(),
    }
}

// For future openid integration
pub async fn oauth2_openid_discovery_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_oauth2_openid_discovery(client_id, kopid.eventid)
        .await;

    match res {
        Ok(dsc) => (StatusCode::OK, Json(dsc)).into_response(),
        Err(e) => {
            error!(err = ?e, "Unable to access discovery info");
            WebError::from(e).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct Oauth2OpenIdWebfingerQuery {
    resource: String,
}

pub async fn oauth2_openid_webfinger_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Query(query): Query<Oauth2OpenIdWebfingerQuery>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let Oauth2OpenIdWebfingerQuery { resource } = query;

    let cleaned_resource = resource.strip_prefix("acct:").unwrap_or(&resource);

    let res = state
        .qe_r_ref
        .handle_oauth2_webfinger_discovery(&client_id, cleaned_resource, kopid.eventid)
        .await;

    match res {
        Ok(mut dsc) => (
            StatusCode::OK,
            [(CONTENT_TYPE, "application/jrd+json")],
            Json({
                dsc.subject = resource;
                dsc
            }),
        )
            .into_response(),
        Err(e) => {
            error!(err = ?e, "Unable to access discovery info");
            WebError::from(e).into_response()
        }
    }
}

pub async fn oauth2_rfc8414_metadata_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_oauth2_rfc8414_metadata(client_id, kopid.eventid)
        .await;

    match res {
        Ok(dsc) => (StatusCode::OK, Json(dsc)).into_response(),
        Err(e) => {
            error!(err = ?e, "Unable to access discovery info");
            WebError::from(e).into_response()
        }
    }
}

#[debug_handler]
pub async fn oauth2_openid_userinfo_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
) -> Response {
    // The token we want to inspect is in the authorisation header.
    let Some(client_token) = client_auth_info.bearer_token() else {
        error!("Bearer Authentication Not Provided");
        return WebError::OAuth2(Oauth2Error::AuthenticationRequired).into_response();
    };

    let res = state
        .qe_r_ref
        .handle_oauth2_openid_userinfo(client_id, client_token, kopid.eventid)
        .await;

    match res {
        Ok(uir) => (StatusCode::OK, Json(uir)).into_response(),
        Err(e) => WebError::OAuth2(e).into_response(),
    }
}

pub async fn oauth2_openid_publickey_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Response {
    let res = state
        .qe_r_ref
        .handle_oauth2_openid_publickey(client_id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from);

    match res {
        Ok(jsn) => (StatusCode::OK, jsn).into_response(),
        Err(web_err) => web_err.into_response(),
    }
}

/// This is called directly by the resource server, where we then issue
/// information about this token to the caller.
pub async fn oauth2_token_introspect_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Form(intr_req): Form<AccessTokenIntrospectRequest>,
) -> impl IntoResponse {
    request_trace!("Introspect Request - {:?}", intr_req);
    let res = state
        .qe_r_ref
        .handle_oauth2_token_introspect(client_auth_info, intr_req, kopid.eventid)
        .await;

    match res {
        Ok(atr) => {
            let body = match serde_json::to_string(&atr) {
                Ok(val) => val,
                Err(e) => {
                    admin_warn!("Failed to serialize introspect response: original_data=\"{:?}\" serialization_error=\"{:?}\"", atr, e);
                    format!("{atr:?}")
                }
            };
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .header(CONTENT_TYPE, APPLICATION_JSON)
                .body(Body::from(body))
                .unwrap()
        }
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            #[allow(clippy::expect_used)]
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
                .expect("Failed to generate an unauthorized response")
        }
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
            let err = ErrorResponse {
                error: e.to_string(),
                ..Default::default()
            };

            let body = match serde_json::to_string(&err) {
                Ok(val) => val,
                Err(e) => {
                    format!("{e:?}")
                }
            };
            #[allow(clippy::expect_used)]
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(body))
                .expect("Failed to generate an error response")
        }
    }
}

/// This is called directly by the resource server, where we then revoke
/// the token identified by this request.
pub async fn oauth2_token_revoke_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Form(intr_req): Form<TokenRevokeRequest>,
) -> impl IntoResponse {
    request_trace!("Revoke Request - {:?}", intr_req);

    let res = state
        .qe_w_ref
        .handle_oauth2_token_revoke(client_auth_info, intr_req, kopid.eventid)
        .await;

    match res {
        Ok(()) => StatusCode::OK.into_response(),
        Err(Oauth2Error::AuthenticationRequired) => StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
            let err = ErrorResponse {
                error: e.to_string(),
                ..Default::default()
            };
            (
                StatusCode::BAD_REQUEST,
                serde_json::to_string(&err).unwrap_or_default(),
            )
                .into_response()
        }
    }
}

// 1.90 incorrectly thinks this is dead code - it's literally used in the function below.
#[allow(dead_code)]
#[serde_as]
#[derive(Deserialize, Debug, Serialize)]
pub(crate) struct DeviceFlowForm {
    client_id: String,
    #[serde_as(as = "Option<StringWithSeparator::<CommaSeparator, String>>")]
    scope: Option<BTreeSet<String>>,
    #[serde(flatten)]
    extra: BTreeMap<String, String>, // catches any extra nonsense that gets sent through
}

/// Device flow! [RFC8628](https://datatracker.ietf.org/doc/html/rfc8628)
#[instrument(level = "info", skip(state, kopid, client_auth_info))]
pub(crate) async fn oauth2_authorise_device_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Form(form): Form<DeviceFlowForm>,
) -> Result<Json<DeviceAuthorizationResponse>, WebError> {
    state
        .qe_w_ref
        .handle_oauth2_device_flow_start(
            client_auth_info,
            &form.client_id,
            &form.scope,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::OAuth2)
}

/// Query parameters for the OIDC RP-Initiated Logout 1.0 end-session endpoint.
///
/// Every field is optional at the wire level — the endpoint's behaviour
/// gracefully degrades to a confirmation page when critical hints are
/// missing or invalid.
#[derive(Debug, Deserialize, Default)]
pub struct OidcEndSessionQuery {
    /// Previously-issued ID token. Used to identify the session (`jti`) and
    /// the client (`aud`).
    pub id_token_hint: Option<String>,
    /// Post-logout redirect URI. Honoured only if it matches an entry on the
    /// client's registered allowlist (exact match).
    pub post_logout_redirect_uri: Option<String>,
    /// Opaque value echoed back as `?state=` on the redirect.
    pub state: Option<String>,
    /// Client identifier. Allowed but redundant with `id_token_hint.aud`.
    pub client_id: Option<String>,
    /// Hint about who to log out. Currently ignored by netidm.
    pub logout_hint: Option<String>,
    /// Space-separated BCP47 language tags for the confirmation page.
    pub ui_locales: Option<String>,
}

/// OIDC RP-Initiated Logout 1.0 `end_session_endpoint` handler.
///
/// Minimal DL26-landing implementation: renders a confirmation page. Token
/// verification, session termination, refresh-token revocation, back-channel
/// logout-token enqueue, and post-logout redirect honouring land with the
/// remainder of US1 / US3 in PR-RP-LOGOUT. The route exists here so the
/// advertisement in each client's discovery document resolves to a valid
/// response today.
/// OIDC RP-Initiated Logout 1.0 `end_session_endpoint` handler.
///
/// Delegates to the library-layer handler on `IdmServerProxyWriteTransaction`
/// which verifies the ID-token hint, destroys the named session, and
/// evaluates the post-logout redirect allowlist. This handler then maps the
/// returned [`netidmd_lib::idm::logout::OidcLogoutOutcome`] to either a 302
/// redirect (with `state` URL-encoded onto the query string) or a 200 HTML
/// confirmation page. Both responses carry `Cache-Control: no-store`.
#[debug_handler]
pub async fn oauth2_openid_end_session_get(
    State(state_): State<ServerState>,
    Path(client_id): Path<String>,
    Query(query): Query<OidcEndSessionQuery>,
    Extension(kopid): Extension<KOpId>,
) -> Response {
    let OidcEndSessionQuery {
        id_token_hint,
        post_logout_redirect_uri,
        state,
        client_id: body_client_id,
        logout_hint,
        ui_locales,
    } = query;

    // `logout_hint` and `ui_locales` are accepted per the OIDC RP-Initiated
    // Logout 1.0 spec but netidm does not yet interpret them — we only
    // note their presence for observability.
    trace!(
        has_logout_hint = logout_hint.is_some(),
        has_ui_locales = ui_locales.is_some(),
        "OIDC end_session_endpoint: optional hints received"
    );

    // If a `client_id` form parameter arrived and contradicts the path
    // segment, fall through to the confirmation page without touching any
    // session — this prevents an RP from naming a different client via the
    // body than the one keyed in the URL.
    let client_id_mismatch = body_client_id.as_deref().is_some_and(|c| c != client_id);
    if client_id_mismatch {
        info!(
            event_id = %kopid.eventid,
            client_id = %client_id,
            "OIDC end_session_endpoint: body client_id does not match path — rendering confirmation"
        );
        return end_session_confirmation_response();
    }

    let outcome = state_
        .qe_w_ref
        .handle_oauth2_rp_initiated_logout(
            client_id.clone(),
            id_token_hint,
            post_logout_redirect_uri,
            state,
            kopid.eventid,
        )
        .await;

    match outcome {
        Ok(netidmd_lib::idm::logout::OidcLogoutOutcome::Redirect { mut url, state }) => {
            if let Some(st) = state {
                url.query_pairs_mut().append_pair("state", &st);
            }
            (
                StatusCode::FOUND,
                [
                    (
                        axum::http::header::LOCATION,
                        HeaderValue::try_from(url.as_str())
                            .unwrap_or_else(|_| HeaderValue::from_static("/")),
                    ),
                    (
                        axum::http::header::CACHE_CONTROL,
                        HeaderValue::from_static("no-store"),
                    ),
                ],
            )
                .into_response()
        }
        Ok(netidmd_lib::idm::logout::OidcLogoutOutcome::Confirmation) => {
            end_session_confirmation_response()
        }
        Err(err) => {
            // Unknown client_id or DB-write error — degrade to the confirmation
            // page rather than expose an error response. The relying party
            // can't tell the user what went wrong anyway; the page is the
            // universally useful fallback.
            warn!(
                ?err,
                event_id = %kopid.eventid,
                client_id = %client_id,
                "OIDC end_session_endpoint: library returned error — rendering confirmation"
            );
            end_session_confirmation_response()
        }
    }
}

fn end_session_confirmation_response() -> Response {
    let body = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
                <title>Logged out</title></head><body>\
                <h1>You have been logged out.</h1>\
                <p>You may now close this window.</p>\
                </body></html>\n";
    (
        StatusCode::OK,
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                axum::http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            ),
        ],
        body,
    )
        .into_response()
}

pub fn route_setup(state: ServerState) -> Router<ServerState> {
    // Build the CORS layer from config. Empty or ["*"] = permissive (allow all origins).
    let cors_layer = {
        let origins = &state.allowed_origins;
        if origins.is_empty() || origins.iter().any(|o| o == "*") {
            CorsLayer::permissive()
        } else {
            let allow_origin =
                AllowOrigin::list(origins.iter().filter_map(|o| o.parse::<HeaderValue>().ok()));
            CorsLayer::new()
                .allow_origin(allow_origin)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ])
        }
    };

    // this has all the openid-related routes
    let openid_router = Router::new()
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/openid/{client_id}/.well-known/openid-configuration",
            get(oauth2_openid_discovery_get),
        )
        .route(
            "/oauth2/openid/{client_id}/.well-known/webfinger",
            get(oauth2_openid_webfinger_get),
        )
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/openid/{client_id}/userinfo",
            get(oauth2_openid_userinfo_get).post(oauth2_openid_userinfo_get),
        )
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/openid/{client_id}/public_key.jwk",
            get(oauth2_openid_publickey_get),
        )
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OAUTH2 DISCOVERY URLS
        .route(
            "/oauth2/openid/{client_id}/.well-known/oauth-authorization-server",
            get(oauth2_rfc8414_metadata_get),
        )
        // OIDC RP-Initiated Logout 1.0 end_session_endpoint.
        // ⚠️  IF YOU CHANGE THIS VALUE YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/openid/{client_id}/end_session_endpoint",
            get(oauth2_openid_end_session_get).post(oauth2_openid_end_session_get),
        )
        .with_state(state.clone());

    let mut router = Router::new()
        .route("/oauth2", get(super::v1_oauth2::oauth2_get))
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            OAUTH2_AUTHORISE,
            post(oauth2_authorise_post).get(oauth2_authorise_get),
        )
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            OAUTH2_AUTHORISE_PERMIT,
            post(oauth2_authorise_permit_post).get(oauth2_authorise_permit_get),
        )
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            OAUTH2_AUTHORISE_REJECT,
            post(oauth2_authorise_reject_post).get(oauth2_authorise_reject_get),
        );
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    router = router.route(OAUTH2_AUTHORISE_DEVICE, post(oauth2_authorise_device_post));
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    router = router
        .route(OAUTH2_TOKEN_ENDPOINT, post(oauth2_token_post))
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            OAUTH2_TOKEN_INTROSPECT_ENDPOINT,
            post(oauth2_token_introspect_post),
        )
        .route(OAUTH2_TOKEN_REVOKE_ENDPOINT, post(oauth2_token_revoke_post))
        .merge(openid_router)
        .with_state(state)
        .layer(cors_layer)
        .layer(from_fn(super::middleware::caching::dont_cache_me));

    router
}
