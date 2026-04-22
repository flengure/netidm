use super::constants::Urls;
use super::{cookies, empty_string_as_none, UnrecoverableErrorView};
use crate::https::views::errors::HtmxError;
use crate::https::{
    extractors::{DomainInfo, DomainInfoRead, VerifiedClientInformation},
    middleware::KOpId,
    ServerState,
};
use askama::Template;
use askama_web::WebTemplate;

use axum::http::HeaderMap;
use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
    Extension, Form, Json,
};
use axum_extra::extract::cookie::{CookieJar, SameSite};
use compact_jwt::compact::{JwaAlg, Jwk, JwkKeySet};
use compact_jwt::crypto::{JwsEs256Verifier, JwsRs256Verifier};
use compact_jwt::traits::{JwsVerifiable, JwsVerifier};
use compact_jwt::OidcUnverified;
use hyper::Uri;
use netidm_proto::internal::{
    UserAuthToken, COOKIE_AUTH_METHOD_PREF, COOKIE_AUTH_SESSION_ID, COOKIE_BEARER_TOKEN,
    COOKIE_CU_SESSION_TOKEN, COOKIE_NEXT_REDIRECT, COOKIE_OAUTH2_PROVISION_REQ, COOKIE_OAUTH2_REQ,
    COOKIE_USERNAME,
};
use netidm_proto::{
    oauth2::{AccessTokenRequest, AccessTokenResponse},
    v1::{AuthAllowed, AuthIssueSession, AuthMech},
};
use netidmd_lib::idm::authentication::{AuthCredential, AuthExternal, AuthState, AuthStep};
use netidmd_lib::idm::event::AuthResult;
use netidmd_lib::idm::server::SsoProviderInfo;
use netidmd_lib::prelude::OperationError;
use netidmd_lib::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use webauthn_rs::prelude::PublicKeyCredential;

#[derive(Default, Serialize, Deserialize)]
struct SessionContext {
    #[serde(rename = "u")]
    username: String,

    #[serde(rename = "r")]
    remember_me: bool,

    #[serde(rename = "i", default, skip_serializing_if = "Option::is_none")]
    id: Option<Uuid>,
    #[serde(rename = "p", default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(rename = "t", default, skip_serializing_if = "Option::is_none")]
    totp: Option<String>,

    #[serde(rename = "a", default, skip_serializing_if = "Option::is_none")]
    after_auth_loc: Option<String>,
}

#[derive(Clone)]
pub enum ReauthPurpose {
    ProfileSettings,
}

impl fmt::Display for ReauthPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileSettings => write!(f, "Profile and Settings"),
        }
    }
}
#[derive(Clone)]
pub enum LoginError {
    InvalidUsername,
    SessionExpired,
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUsername => write!(f, "Invalid username"),
            Self::SessionExpired => {
                write!(f, "Your session has expired. Please sign in again.")
            }
        }
    }
}
#[derive(Clone)]
pub struct Reauth {
    pub username: String,
    pub purpose: ReauthPurpose,
}
#[derive(Clone)]
pub struct Oauth2Ctx {
    pub client_name: String,
}

#[derive(Clone)]
pub struct LoginDisplayCtx {
    pub domain_info: DomainInfoRead,
    // We only need this on the first re-auth screen to indicate what we are doing
    pub reauth: Option<Reauth>,
    pub oauth2: Option<Oauth2Ctx>,
    pub error: Option<LoginError>,
    pub available_sso_providers: Vec<SsoProviderInfo>,
}

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
struct LoginView {
    display_ctx: LoginDisplayCtx,
    username: String,
    remember_me: bool,
    show_internal_first: bool,
}

pub struct Mech<'a> {
    name: AuthMech,
    value: &'a str,
    autofocus: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_mech_choose.html")]
struct LoginMechView<'a> {
    display_ctx: LoginDisplayCtx,
    mechs: Vec<Mech<'a>>,
}

#[derive(Default)]
enum LoginTotpError {
    #[default]
    None,
    Syntax,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_totp.html")]
struct LoginTotpView {
    display_ctx: LoginDisplayCtx,
    totp: String,
    errors: LoginTotpError,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_password.html")]
struct LoginPasswordView {
    display_ctx: LoginDisplayCtx,
    password: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_backupcode.html")]
struct LoginBackupCodeView {
    display_ctx: LoginDisplayCtx,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_webauthn.html")]
struct LoginWebauthnView {
    display_ctx: LoginDisplayCtx,
    // Control if we are rendering in security key or passkey mode.
    passkey: bool,
    // chal: RequestChallengeResponse,
    chal: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_denied.html")]
struct LoginDeniedView {
    display_ctx: LoginDisplayCtx,
    reason: String,
    operation_id: Uuid,
}

#[derive(Serialize, Deserialize)]
struct ProvisionCookieData {
    #[serde(rename = "p")]
    provider_uuid: Uuid,
    #[serde(rename = "s")]
    sub: String,
    #[serde(rename = "e", default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(rename = "v", default, skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(rename = "d", default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(rename = "h", default, skip_serializing_if = "Option::is_none")]
    username_hint: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "login_provision.html")]
struct LoginProvisionView {
    display_ctx: LoginDisplayCtx,
    provider_name: String,
    proposed_username: String,
    display_name: Option<String>,
    email: Option<String>,
    error: Option<String>,
}

pub async fn view_logout_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    mut jar: CookieJar,
) -> Response {
    let response = if let Err(err_code) = state
        .qe_w_ref
        .handle_logout(client_auth_info, kopid.eventid)
        .await
    {
        UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
            domain_info,
        }
        .into_response()
    } else {
        Redirect::to(Urls::Login.as_ref()).into_response()
    };

    // Always clear cookies even on an error.
    jar = cookies::destroy(jar, COOKIE_BEARER_TOKEN, &state);
    jar = cookies::destroy(jar, COOKIE_OAUTH2_REQ, &state);
    jar = cookies::destroy(jar, COOKIE_AUTH_SESSION_ID, &state);
    jar = cookies::destroy(jar, COOKIE_CU_SESSION_TOKEN, &state);

    (jar, response).into_response()
}

pub async fn view_reauth_to_referer_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    Extension(kopid): Extension<KOpId>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, HtmxError> {
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let referer = headers.get("Referer").and_then(|hv| hv.to_str().ok());

    let redirect = referer.and_then(|some_referer| Uri::from_str(some_referer).ok());
    let redirect = redirect
        .as_ref()
        .map(|uri| uri.path())
        .unwrap_or(Urls::Apps.as_ref());

    let display_ctx = LoginDisplayCtx {
        domain_info,
        oauth2: None,
        reauth: Some(Reauth {
            username: uat.spn.clone(),
            purpose: ReauthPurpose::ProfileSettings,
        }),
        error: None,
        available_sso_providers: Vec::new(),
    };

    Ok(view_reauth_get(state, client_auth_info, kopid, jar, redirect, display_ctx).await)
}

pub async fn view_reauth_get(
    state: ServerState,
    client_auth_info: ClientAuthInfo,
    kopid: KOpId,
    jar: CookieJar,
    return_location: &str,
    display_ctx: LoginDisplayCtx,
) -> Response {
    // No matter what, we always clear the stored oauth2 cookie to prevent
    // ui loops
    let jar = cookies::destroy(jar, COOKIE_OAUTH2_REQ, &state);

    let session_valid_result = state
        .qe_r_ref
        .handle_auth_valid(client_auth_info.clone(), kopid.eventid)
        .await;

    match session_valid_result {
        Ok(()) => {
            let inter = state
                .qe_r_ref
                .handle_reauth(
                    client_auth_info.clone(),
                    AuthIssueSession::Cookie,
                    kopid.eventid,
                )
                .await;

            // Now process the response if ok.
            match inter {
                Ok(ar) => {
                    let session_context = SessionContext {
                        id: Some(ar.sessionid),
                        username: "".to_string(),
                        password: None,
                        totp: None,
                        remember_me: false,
                        after_auth_loc: Some(return_location.to_string()),
                    };

                    match view_login_step(
                        state,
                        kopid.clone(),
                        jar,
                        ar,
                        client_auth_info,
                        session_context,
                        display_ctx.clone(),
                    )
                    .await
                    {
                        Ok(r) => r,
                        // Okay, these errors are actually REALLY bad.
                        Err(err_code) => UnrecoverableErrorView {
                            err_code,
                            operation_id: kopid.eventid,
                            domain_info: display_ctx.clone().domain_info,
                        }
                        .into_response(),
                    }
                }
                // Probably needs to be way nicer on login, especially something like no matching users ...
                Err(err_code) => UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                    domain_info: display_ctx.domain_info,
                }
                .into_response(),
            }
        }
        Err(OperationError::NotAuthenticated) | Err(OperationError::SessionExpired) => {
            // cookie jar with remember me.

            let username = cookies::get_unsigned(&jar, COOKIE_USERNAME)
                .map(String::from)
                .unwrap_or_default();

            let remember_me = !username.is_empty();

            (
                jar,
                LoginView {
                    display_ctx,
                    username,
                    remember_me,
                    show_internal_first: false,
                },
            )
                .into_response()
        }
        Err(err_code) => UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
            domain_info: display_ctx.domain_info,
        }
        .into_response(),
    }
}

pub fn view_oauth2_get(
    jar: CookieJar,
    display_ctx: LoginDisplayCtx,
    login_hint: Option<String>,
) -> Response {
    let (username, remember_me) = if let Some(login_hint) = login_hint {
        (login_hint, false)
    } else if let Some(cookie_username) =
        // cookie jar with remember me.
        jar.get(COOKIE_USERNAME).map(|c| c.value().to_string())
    {
        (cookie_username, true)
    } else {
        (String::default(), false)
    };

    (
        jar,
        LoginView {
            display_ctx,
            username,
            remember_me,
            show_internal_first: false,
        },
    )
        .into_response()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LoginIndexQuery {
    #[serde(default)]
    reason: Option<String>,
    /// Post-login redirect URL supplied by the forward auth endpoint.
    /// Only relative paths (starting with `/`) are accepted to prevent
    /// open-redirect attacks.
    #[serde(default)]
    next: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SsoInitiateQuery {
    #[serde(default)]
    next: Option<String>,
}

/// Initiate a provider-initiated OAuth2 flow by redirecting to the provider's authorization URL.
///
/// # Errors
/// Returns 404 if the provider name is not found. Returns a redirect on success.
pub async fn view_sso_initiate_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Extension(kopid): Extension<KOpId>,
    Path(provider_name): Path<String>,
    Query(query): Query<SsoInitiateQuery>,
    jar: CookieJar,
) -> Response {
    use axum::http::StatusCode;
    use netidm_proto::v1::AuthIssueSession;

    let auth_result = state
        .qe_r_ref
        .handle_auth(
            None,
            AuthStep::InitOAuth2Provider {
                provider_name,
                issue: AuthIssueSession::Cookie,
            },
            kopid.eventid,
            client_auth_info,
        )
        .await;

    match auth_result {
        Err(OperationError::NoMatchingEntries) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(AuthResult {
            sessionid,
            state:
                AuthState::External(AuthExternal::OAuth2AuthorisationRequest {
                    mut authorisation_url,
                    request,
                }),
        }) => {
            let session_context = SessionContext {
                id: Some(sessionid),
                ..Default::default()
            };

            let jar = if let Some(next) = query.next.as_deref() {
                if next.starts_with('/') {
                    jar.add(cookies::make_unsigned(
                        &state,
                        COOKIE_NEXT_REDIRECT,
                        next.to_string(),
                    ))
                } else {
                    jar
                }
            } else {
                jar
            };

            let jar = match add_session_cookie(&state, jar, &session_context) {
                Ok(j) => j,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };

            let Ok(encoded) = serde_urlencoded::to_string(&request) else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            authorisation_url.set_query(Some(&encoded));

            (jar, Redirect::to(authorisation_url.as_str())).into_response()
        }
        Ok(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `GET /ui/saml/sso/:name`
///
/// Initiates SP-initiated SAML SSO for the named SAML client provider.
/// Generates an AuthnRequest, stores it in the pending map, and redirects
/// the user's browser to the IdP SSO URL.
pub async fn view_saml_sso_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(provider_name): Path<String>,
) -> Response {
    use axum::http::StatusCode;
    use std::time::Instant;

    let result = state
        .qe_r_ref
        .handle_saml_authn_request(provider_name.clone(), kopid.eventid)
        .await;

    match result {
        Err(OperationError::NoMatchingEntries) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!(?e, "Failed to initiate SAML SSO");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok((request_id, encoded_request, sso_url)) => {
            let relay_state = uuid::Uuid::new_v4().to_string();

            // Store the pending request for correlation when the ACS response arrives.
            if let Ok(mut map) = state.saml_pending_requests.lock() {
                map.insert(
                    relay_state.clone(),
                    crate::https::SamlPendingRequest {
                        request_id,
                        provider_name,
                        issued_at: Instant::now(),
                    },
                );
            }

            let mut redirect_url = sso_url;
            redirect_url
                .query_pairs_mut()
                .append_pair("SAMLRequest", &encoded_request)
                .append_pair("RelayState", &relay_state);

            Redirect::to(redirect_url.as_str()).into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

/// `POST /ui/saml/:name/acs`
///
/// Receives the SAML Response from the IdP, validates it, and establishes
/// a user session on success.
pub async fn view_saml_acs_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(provider_name): Path<String>,
    jar: CookieJar,
    Form(form): Form<SamlAcsForm>,
) -> Response {
    use axum::http::StatusCode;
    use std::time::Duration;

    let relay_state = match form.relay_state {
        Some(rs) if !rs.is_empty() => rs,
        _ => {
            warn!("SAML ACS: missing RelayState");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // Look up and consume the pending request.
    let pending = {
        let mut map = match state.saml_pending_requests.lock() {
            Ok(m) => m,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        let pending = map.remove(&relay_state);
        // Evict stale entries (>5 min old) while we have the lock.
        map.retain(|_, v| v.issued_at.elapsed() < Duration::from_secs(300));
        pending
    };

    let pending = match pending {
        Some(p) if p.issued_at.elapsed() < Duration::from_secs(300) => p,
        Some(_) => {
            warn!("SAML ACS: relay_state expired");
            return StatusCode::BAD_REQUEST.into_response();
        }
        None => {
            warn!("SAML ACS: unknown relay_state");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    if pending.provider_name != provider_name {
        warn!("SAML ACS: provider name mismatch");
        return StatusCode::BAD_REQUEST.into_response();
    }

    let login_result = state
        .qe_w_ref
        .handle_saml_complete_login(
            provider_name,
            form.saml_response,
            pending.request_id,
            kopid.eventid,
        )
        .await;

    match login_result {
        Err(e) => {
            warn!(?e, "SAML ACS login failed");
            StatusCode::UNAUTHORIZED.into_response()
        }
        Ok(token) => {
            let token_str = token.to_string();
            let mut bearer_cookie = cookies::make_unsigned(&state, COOKIE_BEARER_TOKEN, token_str);
            bearer_cookie.make_permanent();
            let jar = jar.add(bearer_cookie);
            (jar, Redirect::to("/ui/")).into_response()
        }
    }
}

pub async fn view_index_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    Extension(kopid): Extension<KOpId>,
    Query(query): Query<LoginIndexQuery>,
    jar: CookieJar,
) -> Response {
    // If we are authenticated, redirect to the landing.
    let session_valid_result = state
        .qe_r_ref
        .handle_auth_valid(client_auth_info, kopid.eventid)
        .await;

    // No matter what, we always clear the stored oauth2 cookie to prevent
    // ui loops
    let jar = cookies::destroy(jar, COOKIE_OAUTH2_REQ, &state);

    match session_valid_result {
        Ok(()) => {
            // Send the user to the landing.
            (jar, Redirect::to(Urls::Apps.as_ref())).into_response()
        }
        Err(OperationError::NotAuthenticated) | Err(OperationError::SessionExpired) => {
            // cookie jar with remember me.
            let username = jar
                .get(COOKIE_USERNAME)
                .map(|c| c.value().to_string())
                .unwrap_or_default();

            let remember_me = !username.is_empty();

            let flash_error = match query.reason.as_deref() {
                Some("session_expired") => Some(LoginError::SessionExpired),
                _ => None,
            };

            // Store the post-login redirect in a short-lived cookie so the
            // multi-step login flow can consume it after `AuthState::Success`.
            // Only relative paths are accepted to prevent open-redirect attacks.
            let jar = if let Some(next) = query.next.as_deref() {
                if next.starts_with('/') {
                    jar.add(cookies::make_unsigned(
                        &state,
                        COOKIE_NEXT_REDIRECT,
                        next.to_string(),
                    ))
                } else {
                    jar
                }
            } else {
                jar
            };

            let available_sso_providers = state
                .qe_r_ref
                .handle_list_sso_providers()
                .await
                .unwrap_or_default();

            let show_internal_first = jar
                .get(COOKIE_AUTH_METHOD_PREF)
                .map(|c| c.value() == "internal")
                .unwrap_or(false);

            let display_ctx = LoginDisplayCtx {
                domain_info,
                oauth2: None,
                reauth: None,
                error: flash_error,
                available_sso_providers,
            };

            (
                jar,
                LoginView {
                    display_ctx,
                    username,
                    remember_me,
                    show_internal_first,
                },
            )
                .into_response()
        }
        Err(err_code) => UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
            domain_info,
        }
        .into_response(),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginBeginForm {
    username: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    password: Option<String>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    totp: Option<String>,
    #[serde(default)]
    remember_me: Option<u8>,
}

pub async fn view_login_begin_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(login_begin_form): Form<LoginBeginForm>,
) -> Response {
    let LoginBeginForm {
        username,
        password,
        totp,
        remember_me,
    } = login_begin_form;

    trace!(?remember_me);

    // Init the login.
    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(
            None,
            AuthStep::Init2 {
                username: username.clone(),
                issue: AuthIssueSession::Cookie,
                privileged: false,
            },
            kopid.eventid,
            client_auth_info.clone(),
        )
        .await;

    let remember_me = remember_me.is_some();

    // Consume the next-redirect cookie set by the forward auth endpoint so
    // the success handler can redirect there instead of the default landing.
    let after_auth_loc = cookies::get_unsigned(&jar, COOKIE_NEXT_REDIRECT).map(|s| s.to_string());
    let jar = cookies::destroy(jar, COOKIE_NEXT_REDIRECT, &state);

    let session_context = SessionContext {
        id: None,
        username: username.clone(),
        password,
        totp,
        remember_me,
        after_auth_loc,
    };

    let mut display_ctx = LoginDisplayCtx {
        domain_info: domain_info.clone(),
        oauth2: None,
        reauth: None,
        error: None,
        available_sso_providers: Vec::new(),
    };

    // Now process the response if ok.
    match inter {
        Ok(ar) => {
            match view_login_step(
                state,
                kopid.clone(),
                jar,
                ar,
                client_auth_info,
                session_context,
                display_ctx,
            )
            .await
            {
                Ok(r) => r,
                // Okay, these errors are actually REALLY bad.
                Err(err_code) => UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                    domain_info,
                }
                .into_response(),
            }
        }
        // Probably needs to be way nicer on login, especially something like no matching users ...
        Err(err_code) => match err_code {
            OperationError::NoMatchingEntries => {
                display_ctx.error = Some(LoginError::InvalidUsername);
                LoginView {
                    display_ctx,
                    username,
                    remember_me,
                    show_internal_first: false,
                }
                .into_response()
            }
            _ => UnrecoverableErrorView {
                err_code,
                operation_id: kopid.eventid,
                domain_info,
            }
            .into_response(),
        },
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginMechForm {
    mech: AuthMech,
}

pub async fn view_login_mech_choose_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(login_mech_form): Form<LoginMechForm>,
) -> Response {
    let session_context =
        cookies::get_signed::<SessionContext>(&state, &jar, COOKIE_AUTH_SESSION_ID)
            .unwrap_or_default();

    debug!("Session ID: {:?}", session_context.id);

    let LoginMechForm { mech } = login_mech_form;

    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(
            session_context.id,
            AuthStep::Begin(mech),
            kopid.eventid,
            client_auth_info.clone(),
        )
        .await;

    let display_ctx = LoginDisplayCtx {
        domain_info: domain_info.clone(),
        oauth2: None,
        reauth: None,
        error: None,
        available_sso_providers: Vec::new(),
    };

    // Now process the response if ok.
    match inter {
        Ok(ar) => {
            match view_login_step(
                state,
                kopid.clone(),
                jar,
                ar,
                client_auth_info,
                session_context,
                display_ctx,
            )
            .await
            {
                Ok(r) => r,
                // Okay, these errors are actually REALLY bad.
                Err(err_code) => UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                    domain_info,
                }
                .into_response(),
            }
        }
        // Probably needs to be way nicer on login, especially something like no matching users ...
        Err(err_code) => UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
            domain_info,
        }
        .into_response(),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginTotpForm {
    #[serde(default, deserialize_with = "empty_string_as_none")]
    password: Option<String>,
    totp: String,
}

pub async fn view_login_totp_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    mut jar: CookieJar,
    Form(login_totp_form): Form<LoginTotpForm>,
) -> Response {
    // trim leading and trailing white space.
    let totp = match u32::from_str(login_totp_form.totp.trim()) {
        Ok(val) => val,
        Err(_) => {
            let display_ctx = LoginDisplayCtx {
                domain_info,
                oauth2: None,
                reauth: None,
                error: None,
                available_sso_providers: Vec::new(),
            };
            // If not an int, we need to re-render with an error
            return LoginTotpView {
                display_ctx,
                totp: String::default(),
                errors: LoginTotpError::Syntax,
            }
            .into_response();
        }
    };

    // In some flows the PW manager may not have autocompleted the pw until
    // this point. This could be due to a re-auth flow which skips the username
    // prompt, the use of remember-me+return which then skips the autocomplete.
    //
    // In the case the pw *is* bg filled, we need to add it to the session context
    // here.
    //
    // It's probably not "optimal" to be getting the context out and signing it
    // here to re-add it, but it also helps keep the flow neater in general.

    if let Some(password_autofill) = login_totp_form.password {
        let mut session_context =
            cookies::get_signed::<SessionContext>(&state, &jar, COOKIE_AUTH_SESSION_ID)
                .unwrap_or_default();

        session_context.password = Some(password_autofill);

        // If we can't write this back to the jar, we warn and move on.
        if let Ok(update_jar) = add_session_cookie(&state, jar.clone(), &session_context) {
            jar = update_jar;
        } else {
            warn!("Unable to update session_context, ignoring...");
        }
    }

    let auth_cred = AuthCredential::Totp(totp);
    credential_step(state, kopid, jar, client_auth_info, auth_cred, domain_info).await
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginPwForm {
    password: String,
}

pub async fn view_login_pw_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(login_pw_form): Form<LoginPwForm>,
) -> Response {
    let auth_cred = AuthCredential::Password(login_pw_form.password);
    credential_step(state, kopid, jar, client_auth_info, auth_cred, domain_info).await
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginBackupCodeForm {
    backupcode: String,
}

pub async fn view_login_backupcode_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(login_bc_form): Form<LoginBackupCodeForm>,
) -> Response {
    // People (like me) may copy-paste the bc with whitespace that causes issues. Trim it now.
    let trimmed = login_bc_form.backupcode.trim().to_string();
    let auth_cred = AuthCredential::BackupCode(trimmed);
    credential_step(state, kopid, jar, client_auth_info, auth_cred, domain_info).await
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonedPublicKeyCredential {
    cred: String,
}

pub async fn view_login_passkey_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Form(assertion): Form<JsonedPublicKeyCredential>,
) -> Response {
    let result = serde_json::from_str::<Box<PublicKeyCredential>>(assertion.cred.as_str());
    match result {
        Ok(pkc) => {
            let auth_cred = AuthCredential::Passkey(pkc);
            credential_step(state, kopid, jar, client_auth_info, auth_cred, domain_info).await
        }
        Err(e) => {
            error!(err = ?e, "Unable to deserialize credential submission");
            HtmxError::new(&kopid, OperationError::SerdeJsonError, domain_info).into_response()
        }
    }
}

pub async fn view_login_seckey_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Json(assertion): Json<Box<PublicKeyCredential>>,
) -> Response {
    let auth_cred = AuthCredential::SecurityKey(assertion);
    credential_step(state, kopid, jar, client_auth_info, auth_cred, domain_info).await
}

#[derive(Deserialize)]
pub struct Oauth2AuthorisationResponse {
    code: String,
    state: Option<String>,
}

pub async fn view_login_oauth2_landing(
    State(app_state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    jar: CookieJar,
    Query(Oauth2AuthorisationResponse { code, state }): Query<Oauth2AuthorisationResponse>,
) -> Response {
    let auth_cred = AuthCredential::OAuth2AuthorisationResponse { code, state };
    credential_step(
        app_state,
        kopid,
        jar,
        client_auth_info,
        auth_cred,
        domain_info,
    )
    .await
}

async fn credential_step(
    state: ServerState,
    kopid: KOpId,
    jar: CookieJar,
    client_auth_info: ClientAuthInfo,
    auth_cred: AuthCredential,
    domain_info: DomainInfoRead,
) -> Response {
    let session_context =
        cookies::get_signed::<SessionContext>(&state, &jar, COOKIE_AUTH_SESSION_ID)
            .unwrap_or_default();

    let display_ctx = LoginDisplayCtx {
        domain_info: domain_info.clone(),
        oauth2: None,
        reauth: None,
        error: None,
        available_sso_providers: Vec::new(),
    };

    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(
            session_context.id,
            AuthStep::Cred(auth_cred),
            kopid.eventid,
            client_auth_info.clone(),
        )
        .await;

    // Now process the response if ok.
    match inter {
        Ok(ar) => {
            match view_login_step(
                state,
                kopid.clone(),
                jar,
                ar,
                client_auth_info,
                session_context,
                display_ctx.clone(),
            )
            .await
            {
                Ok(r) => r,
                // Okay, these errors are actually REALLY bad.
                Err(err_code) => UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                    domain_info: display_ctx.domain_info,
                }
                .into_response(),
            }
        }
        // Probably needs to be way nicer on login, especially something like no matching users ...
        Err(err_code) => UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
            domain_info,
        }
        .into_response(),
    }
}

async fn view_login_step(
    state: ServerState,
    kopid: KOpId,
    mut jar: CookieJar,
    auth_result: AuthResult,
    client_auth_info: ClientAuthInfo,
    mut session_context: SessionContext,
    display_ctx: LoginDisplayCtx,
) -> Result<Response, OperationError> {
    trace!(?auth_result);

    let AuthResult {
        state: mut auth_state,
        sessionid,
    } = auth_result;
    session_context.id = Some(sessionid);

    // This lets us break out the loop in case of a fault. Take that halting problem!
    let mut safety = 3;

    // Unlike the api version, only set the cookie.
    let response = loop {
        if safety == 0 {
            error!("loop safety triggered - auth state was unable to resolve. This should NEVER HAPPEN.");
            debug_assert!(false);
            return Err(OperationError::InvalidSessionState);
        }
        // The slow march to the heat death of the loop.
        safety -= 1;

        match auth_state {
            AuthState::Choose(mut allowed) => {
                debug!("🧩 -> AuthState::Choose");

                jar = add_session_cookie(&state, jar, &session_context)?;

                let res = match allowed.len() {
                    // Should never happen.
                    0 => {
                        error!("auth state choose allowed mechs is empty");
                        UnrecoverableErrorView {
                            err_code: OperationError::InvalidState,
                            operation_id: kopid.eventid,
                            domain_info: display_ctx.domain_info,
                        }
                        .into_response()
                    }
                    1 => {
                        #[allow(clippy::indexing_slicing)]
                        // Length checked correctly.
                        let mech = allowed[0].clone();
                        // submit the choice and then loop updating our auth_state.
                        let inter = state // This may change in the future ...
                            .qe_r_ref
                            .handle_auth(
                                Some(sessionid),
                                AuthStep::Begin(mech),
                                kopid.eventid,
                                client_auth_info.clone(),
                            )
                            .await?;

                        // Set the state now for the next loop.
                        auth_state = inter.state;

                        // Autoselect was hit.
                        continue;
                    }

                    // Render the list of options.
                    _ => {
                        allowed.sort_unstable();
                        // Put strongest first.
                        allowed.reverse();

                        let mechs: Vec<_> = allowed
                            .into_iter()
                            .enumerate()
                            .map(|(i, m)| Mech {
                                value: m.to_value(),
                                name: m,
                                // Auto focus the first item, it's the strongest
                                // mechanism and the one we should optimise for.
                                autofocus: i == 0,
                            })
                            .collect();

                        LoginMechView { display_ctx, mechs }.into_response()
                    }
                };
                // break acts as return in a loop.
                break res;
            }
            AuthState::Continue(allowed) => {
                // Reauth inits its session here so we need to be able to add it's cookie here.
                jar = add_session_cookie(&state, jar, &session_context)?;

                let res = match allowed.len() {
                    // Shouldn't be possible.
                    0 => {
                        error!("auth state continued allowed mechs is empty");
                        UnrecoverableErrorView {
                            err_code: OperationError::InvalidState,
                            operation_id: kopid.eventid,
                            domain_info: display_ctx.domain_info,
                        }
                        .into_response()
                    }
                    1 => {
                        #[allow(clippy::indexing_slicing)]
                        // Length checked correctly.
                        let auth_allowed = allowed[0].clone();

                        match auth_allowed {
                            AuthAllowed::Totp => LoginTotpView {
                                display_ctx,
                                totp: session_context.totp.clone().unwrap_or_default(),
                                errors: LoginTotpError::default(),
                            }
                            .into_response(),
                            AuthAllowed::Password => LoginPasswordView {
                                display_ctx,
                                password: session_context.password.clone().unwrap_or_default(),
                            }
                            .into_response(),
                            AuthAllowed::BackupCode => {
                                LoginBackupCodeView { display_ctx }.into_response()
                            }
                            AuthAllowed::SecurityKey(chal) => {
                                let chal_json = serde_json::to_string(&chal)
                                    .map_err(|_| OperationError::SerdeJsonError)?;
                                LoginWebauthnView {
                                    display_ctx,
                                    passkey: false,
                                    chal: chal_json,
                                }
                                .into_response()
                            }
                            AuthAllowed::Passkey(chal) => {
                                let chal_json = serde_json::to_string(&chal)
                                    .map_err(|_| OperationError::SerdeJsonError)?;
                                LoginWebauthnView {
                                    display_ctx,
                                    passkey: true,
                                    chal: chal_json,
                                }
                                .into_response()
                            }
                            _ => return Err(OperationError::InvalidState),
                        }
                    }
                    _ => {
                        // We have changed auth session to only ever return one possibility, and
                        // that one option encodes the possible challenges.
                        return Err(OperationError::InvalidState);
                    }
                };

                // break acts as return in a loop.
                break res;
            }
            AuthState::External(external) => {
                debug!("🧩 -> AuthState::External");
                match external {
                    AuthExternal::OAuth2AuthorisationRequest {
                        mut authorisation_url,
                        request,
                    } => {
                        // Encode the request
                        let Ok(encoded) = serde_urlencoded::to_string(&request) else {
                            error!("Unable to encode request, THIS IS A BUG!!!");
                            debug!(?request);
                            return Err(OperationError::InvalidState);
                        };

                        authorisation_url.set_query(Some(&encoded));

                        let res = Redirect::to(authorisation_url.as_str()).into_response();
                        break res;
                    }
                    AuthExternal::OAuth2AccessTokenRequest {
                        token_url,
                        client_id,
                        client_secret,
                        request,
                    } => {
                        let response = submit_access_token_request(
                            token_url,
                            client_id,
                            client_secret,
                            request,
                        )
                        .await?;

                        let auth_cred = AuthCredential::OAuth2AccessTokenResponse { response };

                        // submit the choice and then loop updating our auth_state.
                        let inter = state // This may change in the future ...
                            .qe_r_ref
                            .handle_auth(
                                Some(sessionid),
                                AuthStep::Cred(auth_cred),
                                kopid.eventid,
                                client_auth_info.clone(),
                            )
                            .await?;

                        // Set the state now for the next loop.
                        auth_state = inter.state;
                        continue;
                    }
                    AuthExternal::OAuth2UserinfoRequest {
                        userinfo_url,
                        access_token,
                    } => {
                        let body = submit_userinfo_request(userinfo_url, access_token).await?;
                        let auth_cred = AuthCredential::OAuth2UserinfoResponse { body };
                        let inter = state
                            .qe_r_ref
                            .handle_auth(
                                Some(sessionid),
                                AuthStep::Cred(auth_cred),
                                kopid.eventid,
                                client_auth_info.clone(),
                            )
                            .await?;
                        auth_state = inter.state;
                        continue;
                    }
                    AuthExternal::OAuth2JwksRequest {
                        jwks_url,
                        id_token,
                        access_token: _,
                    } => {
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        let claims_body =
                            verify_oidc_id_token(&jwks_url, &id_token, now_secs).await?;
                        let auth_cred = AuthCredential::OAuth2JwksTokenResponse { claims_body };
                        let inter = state
                            .qe_r_ref
                            .handle_auth(
                                Some(sessionid),
                                AuthStep::Cred(auth_cred),
                                kopid.eventid,
                                client_auth_info.clone(),
                            )
                            .await?;
                        auth_state = inter.state;
                        continue;
                    }
                    AuthExternal::SamlAuthnRequest { .. } => {
                        error!("SamlAuthnRequest returned in auth session loop — this is a bug");
                        return Err(OperationError::InvalidState);
                    }
                    AuthExternal::GitHubCallbackRequest {
                        code,
                        provider_uuid,
                        email_link_accounts,
                    } => {
                        // Call the registered GitHubConnector to exchange the code
                        // and fetch all claims (T013 — PR-CONNECTOR-GITHUB).
                        let connector = state.qe_r_ref.idms.connector_registry().get(provider_uuid);
                        let Some(connector) = connector else {
                            error!(
                                ?provider_uuid,
                                "GitHub connector not found in registry — \
                                 provider may not have been loaded at startup"
                            );
                            return Err(OperationError::InvalidState);
                        };
                        let claims = connector.fetch_callback_claims(&code).await.map_err(|e| {
                            warn!(?provider_uuid, ?e, "GitHub callback failed");
                            OperationError::InvalidState
                        })?;
                        auth_state = AuthState::ProvisioningRequired {
                            provider_uuid,
                            claims,
                            email_link_accounts,
                        };
                        continue;
                    }
                }
            }
            AuthState::Success(token, issue) => {
                debug!("🧩 -> AuthState::Success");

                match issue {
                    AuthIssueSession::Token => {
                        error!(
                            "Impossible state, should not receive token in a htmx view auth flow"
                        );
                        return Err(OperationError::InvalidState);
                    }
                    AuthIssueSession::Cookie => {
                        // Update jar
                        let token_str = token.to_string();

                        // Important - this can be make unsigned as token_str has its own
                        // signatures.
                        let mut bearer_cookie =
                            cookies::make_unsigned(&state, COOKIE_BEARER_TOKEN, token_str.clone());
                        // Important - can be permanent as the token has its own expiration time internally
                        bearer_cookie.make_permanent();

                        jar = if session_context.remember_me {
                            // Important - can be unsigned as username is just for remember
                            // me and no other purpose.
                            let mut username_cookie = cookies::make_unsigned(
                                &state,
                                COOKIE_USERNAME,
                                session_context.username.clone(),
                            );
                            username_cookie.make_permanent();
                            jar.add(username_cookie)
                        } else {
                            cookies::destroy(jar, COOKIE_USERNAME, &state)
                        };

                        jar = jar.add(bearer_cookie);

                        // Record whether this auth was via SSO or internal credentials
                        // so the login page can show the preferred method next time.
                        let auth_method_pref = if session_context.username.is_empty() {
                            "sso"
                        } else {
                            "internal"
                        };
                        jar = jar.add(cookies::make_unsigned(
                            &state,
                            COOKIE_AUTH_METHOD_PREF,
                            auth_method_pref.to_string(),
                        ));

                        jar = cookies::destroy(jar, COOKIE_AUTH_SESSION_ID, &state);

                        // Now, we need to decided where to go.
                        let res = if jar.get(COOKIE_OAUTH2_REQ).is_some() {
                            Redirect::to(Urls::Oauth2Resume.as_ref()).into_response()
                        } else if let Some(auth_loc) = session_context.after_auth_loc {
                            Redirect::to(auth_loc.as_str()).into_response()
                        } else {
                            Redirect::to(Urls::Apps.as_ref()).into_response()
                        };

                        break res;
                    }
                }
            }
            AuthState::Denied(reason) => {
                debug!("🧩 -> AuthState::Denied");
                jar = cookies::destroy(jar, COOKIE_AUTH_SESSION_ID, &state);

                break LoginDeniedView {
                    display_ctx,
                    reason,
                    operation_id: kopid.eventid,
                }
                .into_response();
            }
            AuthState::ProvisioningRequired {
                provider_uuid,
                claims,
                email_link_accounts,
            } => {
                debug!("🧩 -> AuthState::ProvisioningRequired");
                jar = cookies::destroy(jar, COOKIE_AUTH_SESSION_ID, &state);

                // Attempt account linking when the provider (or domain default) permits it.
                // The connector's `link_by` setting (DL24+) inside `find_and_link_account`
                // decides which claim is matched (email / username / id) and enforces the
                // security precondition appropriate to that strategy (e.g. `email_verified`
                // for the Email branch).
                if email_link_accounts {
                    match state
                        .qe_w_ref
                        .handle_link_account_by_email(
                            provider_uuid,
                            claims.clone(),
                            kopid.eventid,
                            client_auth_info.clone(),
                        )
                        .await
                    {
                        Ok(Some(_linked_uuid)) => {
                            security_info!(
                                %provider_uuid,
                                "OAuth2 account-link: linked existing account — redirecting to login"
                            );
                            break Redirect::to("/ui/login").into_response();
                        }
                        Ok(None) => {
                            // No existing account matched under the connector's link_by;
                            // fall through to provision.
                            debug!("OAuth2 account-link: no matching account found, proceeding to provision");
                        }
                        Err(e) => {
                            warn!(
                                ?e,
                                "OAuth2 account-link: link attempt failed, proceeding to provision"
                            );
                        }
                    }
                }

                let cookie_data = ProvisionCookieData {
                    provider_uuid,
                    sub: claims.sub.clone(),
                    email: claims.email.clone(),
                    email_verified: claims.email_verified,
                    display_name: claims.display_name.clone(),
                    username_hint: claims.username_hint.clone(),
                };

                if let Some(ck) =
                    cookies::make_signed(&state, COOKIE_OAUTH2_PROVISION_REQ, &cookie_data)
                {
                    jar = jar.add(ck);
                } else {
                    error!("Failed to sign provision cookie — cannot redirect to provision page");
                    return Err(OperationError::InvalidState);
                }

                break Redirect::to("/ui/login/provision").into_response();
            }
        }
    };

    Ok((jar, response).into_response())
}

async fn submit_access_token_request(
    token_url: Url,
    client_id: String,
    client_secret: String,
    request: AccessTokenRequest,
) -> Result<AccessTokenResponse, OperationError> {
    // Setup a client and post the req.
    // TODO: Lots of settings we need to be able to configure here,
    // but for a proof of concept defaults are okay.
    //
    // We would probably move the client into the auth server state
    // if anything.
    let client = reqwest::ClientBuilder::new().build().map_err(|err| {
        error!(?err, "Invalid oauth2 http client builder parameters");
        OperationError::InvalidState
    })?;

    let res = client
        .post(token_url.as_str())
        .basic_auth(&client_id, Some(client_secret))
        .form(&request)
        .send()
        .await
        .map_err(|err| {
            error!(
                ?err,
                ?token_url,
                ?client_id,
                "Unable to submit access token request"
            );
            OperationError::InvalidState
        })?;

    // Now depending on the result we have to choose how to proceed.
    if res.status() == reqwest::StatusCode::OK {
        res.json::<AccessTokenResponse>().await.map_err(|err| {
            error!(?err, "response was not a valid JSON access token response");
            OperationError::InvalidState
        })
    } else {
        error!(status = ?res.status(), "access token request failed");
        Err(OperationError::InvalidState)
    }
}

fn add_session_cookie(
    state: &ServerState,
    jar: CookieJar,
    session_context: &SessionContext,
) -> Result<CookieJar, OperationError> {
    cookies::make_signed(state, COOKIE_AUTH_SESSION_ID, session_context)
        .map(|mut cookie| {
            // Needs to be lax now for when we come back from an oauth2 trust
            cookie.set_same_site(SameSite::Lax);
            jar.add(cookie)
        })
        .ok_or(OperationError::InvalidSessionState)
}

async fn submit_userinfo_request(
    userinfo_url: Url,
    access_token: String,
) -> Result<serde_json::Value, OperationError> {
    let client = reqwest::ClientBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|err| {
            error!(?err, "Failed to build HTTP client for userinfo request");
            OperationError::InvalidState
        })?;

    let res = client
        .get(userinfo_url.as_str())
        .bearer_auth(&access_token)
        .header("User-Agent", "netidm/1.0")
        .send()
        .await
        .map_err(|err| {
            error!(?err, ?userinfo_url, "Userinfo request failed");
            OperationError::InvalidState
        })?;

    if res.status() == reqwest::StatusCode::OK {
        res.json::<serde_json::Value>().await.map_err(|err| {
            error!(?err, "Userinfo response was not valid JSON");
            OperationError::InvalidState
        })
    } else {
        error!(status = ?res.status(), "Userinfo request returned non-200 status");
        Err(OperationError::InvalidState)
    }
}

/// Fetch a provider's JWKS, verify the `id_token` signature and expiry, and return the
/// claims payload as a JSON string for further processing by the auth handler.
///
/// On key-not-found the JWKS is re-fetched once to handle provider key rotation.
///
/// # Errors
///
/// Returns [`OperationError::NotAuthenticated`] if the token cannot be verified (invalid
/// signature, unknown algorithm, expired, missing `sub`, or network failure).
async fn fetch_jwks(url: &Url) -> Result<JwkKeySet, OperationError> {
    let client = reqwest::ClientBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|err| {
            error!(?err, "Failed to build HTTP client for JWKS request");
            OperationError::NotAuthenticated
        })?;
    let res = client
        .get(url.as_str())
        .header("User-Agent", "netidm/1.0")
        .send()
        .await
        .map_err(|err| {
            error!(?err, ?url, "JWKS request failed");
            OperationError::NotAuthenticated
        })?;
    if res.status() == reqwest::StatusCode::OK {
        res.json::<JwkKeySet>().await.map_err(|err| {
            error!(?err, "JWKS response was not valid JSON");
            OperationError::NotAuthenticated
        })
    } else {
        error!(status = ?res.status(), "JWKS request returned non-200 status");
        Err(OperationError::NotAuthenticated)
    }
}

fn jwk_kid(jwk: &Jwk) -> Option<&str> {
    match jwk {
        Jwk::EC { kid, .. } => kid.as_deref(),
        Jwk::RSA { kid, .. } => kid.as_deref(),
    }
}

fn find_key_in_set<'a>(keyset: &'a JwkKeySet, token_kid: Option<&str>) -> Option<&'a Jwk> {
    keyset
        .keys
        .iter()
        .find(|jwk| match (token_kid, jwk_kid(jwk)) {
            (Some(tk), Some(jk)) => tk == jk,
            (None, _) => true,
            _ => false,
        })
}

async fn verify_oidc_id_token(
    jwks_url: &Url,
    id_token: &str,
    now_secs: i64,
) -> Result<String, OperationError> {
    let unverified = OidcUnverified::from_str(id_token).map_err(|err| {
        warn!(?err, "Failed to parse id_token as OidcUnverified");
        OperationError::NotAuthenticated
    })?;

    let token_kid = unverified.kid().map(str::to_owned);
    let token_alg = unverified.alg();

    let mut keyset = fetch_jwks(jwks_url).await?;
    let jwk = match find_key_in_set(&keyset, token_kid.as_deref()) {
        Some(k) => k.clone(),
        None => {
            // Key not found — re-fetch once to handle key rotation.
            keyset = fetch_jwks(jwks_url).await?;
            find_key_in_set(&keyset, token_kid.as_deref())
                .ok_or_else(|| {
                    warn!("id_token kid not found in JWKS after re-fetch");
                    OperationError::NotAuthenticated
                })?
                .clone()
        }
    };

    let exp_unverified = match token_alg {
        JwaAlg::ES256 => {
            let verifier = JwsEs256Verifier::try_from(&jwk).map_err(|err| {
                warn!(?err, "Failed to build ES256 verifier from JWK");
                OperationError::NotAuthenticated
            })?;
            verifier.verify(&unverified).map_err(|err| {
                warn!(?err, "ES256 id_token signature verification failed");
                OperationError::NotAuthenticated
            })?
        }
        JwaAlg::RS256 => {
            let verifier = JwsRs256Verifier::try_from(&jwk).map_err(|err| {
                warn!(?err, "Failed to build RS256 verifier from JWK");
                OperationError::NotAuthenticated
            })?;
            verifier.verify(&unverified).map_err(|err| {
                warn!(?err, "RS256 id_token signature verification failed");
                OperationError::NotAuthenticated
            })?
        }
        alg => {
            warn!(?alg, "Unsupported id_token signing algorithm");
            return Err(OperationError::NotAuthenticated);
        }
    };

    let token = exp_unverified.verify_exp(now_secs).map_err(|err| {
        warn!(?err, "id_token expiry verification failed");
        OperationError::NotAuthenticated
    })?;

    // Serialise the verified claims as JSON for the auth handler.
    serde_json::to_string(&token).map_err(|err| {
        error!(?err, "Failed to serialise verified id_token claims");
        OperationError::NotAuthenticated
    })
}

#[derive(Deserialize)]
pub struct ProvisionForm {
    username: String,
}

pub async fn view_login_provision_get(
    State(state): State<ServerState>,
    DomainInfo(domain_info): DomainInfo,
    Extension(_kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
) -> Response {
    let Some(cookie_data) =
        cookies::get_signed::<ProvisionCookieData>(&state, &jar, COOKIE_OAUTH2_PROVISION_REQ)
    else {
        return Redirect::to("/ui/login?reason=session_expired").into_response();
    };

    let display_ctx = LoginDisplayCtx {
        domain_info,
        oauth2: None,
        reauth: None,
        error: None,
        available_sso_providers: Vec::new(),
    };

    use netidmd_lib::idm::authsession::handler_oauth2_client::ExternalUserClaims;
    let claims = ExternalUserClaims {
        sub: cookie_data.sub.clone(),
        email: cookie_data.email.clone(),
        email_verified: cookie_data.email_verified,
        display_name: cookie_data.display_name.clone(),
        username_hint: cookie_data.username_hint.clone(),
        // ProvisionCookieData does not carry upstream groups; the claims
        // re-built from the cookie are used for JIT username derivation and
        // account linking. Reconciliation runs from the original claims
        // still in scope via the credential handler, not from the cookie.
        groups: Vec::new(),
    };

    let (proposed_username, username_notice) = match state
        .qe_w_ref
        .handle_derive_jit_username(claims, client_auth_info)
        .await
    {
        Ok(derived) => {
            let normalized_hint: String = cookie_data
                .username_hint
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .collect();
            let notice = if !normalized_hint.is_empty() && derived != normalized_hint {
                Some("Username already taken — we've suggested an alternative".to_string())
            } else {
                None
            };
            (derived, notice)
        }
        Err(_) => (
            cookie_data
                .username_hint
                .clone()
                .unwrap_or_else(|| "user".to_string()),
            None,
        ),
    };

    LoginProvisionView {
        display_ctx,
        provider_name: cookie_data.provider_uuid.to_string(),
        proposed_username,
        display_name: cookie_data.display_name.clone(),
        email: cookie_data.email.clone(),
        error: username_notice,
    }
    .into_response()
}

pub async fn view_login_provision_post(
    State(app_state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
    mut jar: CookieJar,
    Form(form): Form<ProvisionForm>,
) -> Response {
    let display_ctx = LoginDisplayCtx {
        domain_info,
        oauth2: None,
        reauth: None,
        error: None,
        available_sso_providers: Vec::new(),
    };

    let Some(cookie_data) =
        cookies::get_signed::<ProvisionCookieData>(&app_state, &jar, COOKIE_OAUTH2_PROVISION_REQ)
    else {
        return Redirect::to("/ui/login?reason=session_expired").into_response();
    };

    let username = form.username.trim().to_string();

    // T046: inline format validation (lowercase alphanumeric + hyphens, 2-64 chars)
    if username.is_empty() || username.len() < 2 || username.len() > 64 {
        return LoginProvisionView {
            display_ctx,
            provider_name: cookie_data.provider_uuid.to_string(),
            proposed_username: username,
            display_name: cookie_data.display_name.clone(),
            email: cookie_data.email.clone(),
            error: Some("Username must be between 2 and 64 characters.".to_string()),
        }
        .into_response();
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return LoginProvisionView {
            display_ctx,
            provider_name: cookie_data.provider_uuid.to_string(),
            proposed_username: username,
            display_name: cookie_data.display_name.clone(),
            email: cookie_data.email.clone(),
            error: Some(
                "Username may only contain lowercase letters, digits, hyphens, and underscores."
                    .to_string(),
            ),
        }
        .into_response();
    }

    use netidmd_lib::idm::authsession::handler_oauth2_client::ExternalUserClaims;
    let claims = ExternalUserClaims {
        sub: cookie_data.sub.clone(),
        email: cookie_data.email.clone(),
        email_verified: cookie_data.email_verified,
        display_name: cookie_data.display_name.clone(),
        username_hint: cookie_data.username_hint.clone(),
        // ProvisionCookieData does not carry upstream groups; the claims
        // re-built from the cookie are used for JIT username derivation and
        // account linking. Reconciliation runs from the original claims
        // still in scope via the credential handler, not from the cookie.
        groups: Vec::new(),
    };

    let result = app_state
        .qe_w_ref
        .handle_jit_provision_oauth2_account(
            cookie_data.provider_uuid,
            claims.clone(),
            username.clone(),
            kopid.eventid,
            client_auth_info.clone(),
        )
        .await;

    match result {
        Ok(_account_uuid) => {
            jar = cookies::destroy(jar, COOKIE_OAUTH2_PROVISION_REQ, &app_state);
            (jar, Redirect::to("/ui/login")).into_response()
        }
        // T045: username taken at POST time — re-derive a suggestion and re-render
        Err(OperationError::UniqueConstraintViolation) => {
            let suggestion = app_state
                .qe_w_ref
                .handle_derive_jit_username(claims, client_auth_info)
                .await
                .unwrap_or(username);
            LoginProvisionView {
                display_ctx,
                provider_name: cookie_data.provider_uuid.to_string(),
                proposed_username: suggestion,
                display_name: cookie_data.display_name.clone(),
                email: cookie_data.email.clone(),
                error: Some(
                    "That username is already taken — we've suggested an alternative.".to_string(),
                ),
            }
            .into_response()
        }
        Err(OperationError::InvalidAttribute(msg)) => LoginProvisionView {
            display_ctx,
            provider_name: cookie_data.provider_uuid.to_string(),
            proposed_username: username,
            display_name: cookie_data.display_name.clone(),
            email: cookie_data.email.clone(),
            error: Some(msg),
        }
        .into_response(),
        Err(err_code) => UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
            domain_info: display_ctx.domain_info,
        }
        .into_response(),
    }
}
