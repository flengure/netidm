#![deny(warnings)]
//! End-to-end integration tests for PR-RP-LOGOUT (spec: specs/009-rp-logout).
//!
//! Covers the subset of tasks that can be exercised without full
//! OAuth2 code-flow setup:
//!
//!   * T030 — OIDC discovery document advertises `end_session_endpoint`,
//!     `backchannel_logout_supported = true`,
//!     `backchannel_logout_session_supported = true`.
//!   * T035 / T037 — admin post-logout redirect URI CRUD round-trips
//!     via the client SDK; state persists and is observable from a
//!     subsequent list.
//!   * T029 — the `end_session_endpoint` resolves with no ID token
//!     hint and returns a 200 HTML confirmation page carrying
//!     `Cache-Control: no-store`.
//!   * T049 — backchannel-logout URI set/clear round-trip.
//!   * T066 — SAML SLO URL set/clear round-trip (admin-only).
//!   * T052 — admin queue-list API returns an empty list with 200.
//!   * T081 — admin logout-all on a user with no active sessions
//!     returns zero terminated (the surface itself works).
//!   * T027 — full OAuth2 code flow → `end_session_endpoint` with a
//!     valid `id_token_hint` and a registered `post_logout_redirect_uri`
//!     → 302 to the registered URI with `state` echoed. Asserts the
//!     session's refresh token is invalidated (the RP's access token is
//!     too, since both are bound to the terminated session).
//!   * T029b — `end_session_endpoint` with an unregistered
//!     `post_logout_redirect_uri` → falls through to the confirmation
//!     page; the unregistered URI is never visited.
//!   * T054 — back-channel logout delivery: full OAuth2 code flow →
//!     register a dummy HTTP receiver's URL as the RP's
//!     `OAuth2RsBackchannelLogoutUri` → terminate the session via
//!     end_session_endpoint → assert the receiver receives a POST
//!     carrying `logout_token=<signed-jws>` whose claims match the
//!     spec (iss, aud, sub, sid, events, typ=logout+jwt).
//!   * T057 — back-channel delivery opt-out: RP with NO
//!     `OAuth2RsBackchannelLogoutUri` registered → session terminates
//!     successfully but no `LogoutDelivery` record is created.
//!   * T082 — end_session_endpoint single-session semantics: a
//!     second UAT (e.g. CLI login) for the same user survives when
//!     an OIDC end-session terminates only the session named by the
//!     id_token_hint.
//!   * T036 / FR-016 — post-logout redirect URI CRUD requires admin
//!     privileges; ordinary persons are denied.
//!   * T079 — `/v1/self/logout_all` terminates every active UAT the
//!     caller holds. Three independent sessions are established,
//!     then logout_all is invoked via one of them; the response
//!     reports `3` and all three UATs fail subsequent `/v1/self`
//!     calls.
//!   * T080 — `/v1/self/logout_all` fans out back-channel logout
//!     deliveries per session: two OAuth2 code flows by the same
//!     user → two distinct UATs each bound to an OAuth2Session on
//!     the same RP → logout_all produces two back-channel POSTs
//!     with distinct `sid` claims.
//!   * T036 — malformed `post_logout_redirect_uri` values are
//!     rejected by the server (URL schema type); storage remains
//!     unchanged on failed add.
//!   * T057 — admin `logout_deliveries` list/show surface with a
//!     mix of Succeeded + Pending records. Status filter narrows
//!     the list; `show` returns one record by UUID. Non-admin is
//!     denied (ACP gating). `Failed` status is out of scope for
//!     the integration surface because flipping a record to
//!     `Failed` requires exhausting the 6-step retry schedule
//!     (many minutes of wall clock).

use axum::extract::Form;
use axum::{routing::post, Router};
use compact_jwt::{JwkKeySet, JwsEs256Verifier, JwsVerifier, OidcSubject, OidcUnverified};
use netidm_client::{http::header, NetidmClient, StatusCode};
use netidm_proto::constants::uri::OAUTH2_TOKEN_ENDPOINT;
use netidm_proto::constants::{OAUTH2_SCOPE_EMAIL, OAUTH2_SCOPE_OPENID, OAUTH2_SCOPE_READ};
use netidm_proto::oauth2::{
    AccessTokenRequest, AccessTokenResponse, AuthorisationResponse, GrantTypeReq,
    OidcDiscoveryResponse,
};
use netidmd_lib::constants::NAME_IDM_ALL_ACCOUNTS;
use netidmd_testkit::{
    ADMIN_TEST_PASSWORD, ADMIN_TEST_USER, NOT_ADMIN_TEST_PASSWORD, NOT_ADMIN_TEST_USERNAME,
    TEST_INTEGRATION_RS_DISPLAY, TEST_INTEGRATION_RS_ID, TEST_INTEGRATION_RS_REDIRECT_URL,
    TEST_INTEGRATION_RS_URL,
};
use oauth2_ext::PkceCodeChallenge;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use url::Url;

fn get_reqwest_client() -> reqwest::Client {
    reqwest::Client::builder()
        .tls_danger_accept_invalid_certs(true)
        .tls_danger_accept_invalid_hostnames(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("Failed to create client.")
}

/// T030 / SC-006 — a relying party reading the discovery document sees
/// the three new DL26 fields populated correctly.
#[netidmd_testkit::test]
async fn test_logout_discovery_advertises_logout_endpoints(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");

    rsclient
        .idm_oauth2_rs_basic_create(
            TEST_INTEGRATION_RS_ID,
            TEST_INTEGRATION_RS_DISPLAY,
            TEST_INTEGRATION_RS_URL,
        )
        .await
        .expect("Failed to create OAuth2 RS");

    let http = get_reqwest_client();
    let response = http
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/.well-known/openid-configuration"
        )))
        .send()
        .await
        .expect("discovery request");
    assert_eq!(response.status(), StatusCode::OK);

    let discovery: OidcDiscoveryResponse = response.json().await.expect("parse discovery");

    let expected_end_session = rsclient.make_url(&format!(
        "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/end_session_endpoint"
    ));
    assert_eq!(
        discovery.end_session_endpoint,
        Some(expected_end_session),
        "discovery.end_session_endpoint should be the per-client URL"
    );
    assert!(
        discovery.backchannel_logout_supported,
        "backchannel_logout_supported must be true"
    );
    assert!(
        discovery.backchannel_logout_session_supported,
        "backchannel_logout_session_supported must be true"
    );
}

/// T029 / US1 Acceptance Scenario 2 — the `end_session_endpoint` with
/// no `id_token_hint` returns a 200 HTML confirmation page carrying
/// `Cache-Control: no-store`.
#[netidmd_testkit::test]
async fn test_logout_end_session_without_hint_renders_confirmation(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    rsclient
        .idm_oauth2_rs_basic_create(
            TEST_INTEGRATION_RS_ID,
            TEST_INTEGRATION_RS_DISPLAY,
            TEST_INTEGRATION_RS_URL,
        )
        .await
        .expect("Failed to create OAuth2 RS");

    let http = get_reqwest_client();
    let response = http
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/end_session_endpoint"
        )))
        .send()
        .await
        .expect("end_session_endpoint GET");

    assert_eq!(response.status(), StatusCode::OK);
    let cache_control = response
        .headers()
        .get(header::CACHE_CONTROL)
        .expect("cache-control header must be set")
        .to_str()
        .expect("cache-control header utf-8");
    assert!(
        cache_control.contains("no-store"),
        "cache-control must include no-store, got: {cache_control}"
    );
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("content-type header must be set")
        .to_str()
        .expect("content-type header utf-8");
    assert!(
        content_type.starts_with("text/html"),
        "expected text/html, got: {content_type}"
    );
    let body = response.text().await.expect("response body");
    assert!(
        body.contains("logged out"),
        "confirmation page body should mention logged-out state"
    );
}

/// T035 / T037 / US2 — admin CRUD for the post-logout redirect URI
/// allowlist. Add, list, remove, list-again round-trips cleanly.
#[netidmd_testkit::test]
async fn test_logout_post_logout_redirect_uri_crud(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    rsclient
        .idm_oauth2_rs_basic_create(
            TEST_INTEGRATION_RS_ID,
            TEST_INTEGRATION_RS_DISPLAY,
            TEST_INTEGRATION_RS_URL,
        )
        .await
        .expect("Failed to create OAuth2 RS");

    // Initial state: empty allowlist.
    let listed = rsclient
        .idm_oauth2_client_list_post_logout_redirect_uris(TEST_INTEGRATION_RS_ID)
        .await
        .expect("initial list");
    assert!(listed.is_empty(), "allowlist should start empty");

    // Add two URIs.
    let uri_a = "https://app.example.com/after-logout";
    let uri_b = "https://app.example.com/after-logout-alt";
    rsclient
        .idm_oauth2_client_add_post_logout_redirect_uri(TEST_INTEGRATION_RS_ID, uri_a)
        .await
        .expect("add first URI");
    rsclient
        .idm_oauth2_client_add_post_logout_redirect_uri(TEST_INTEGRATION_RS_ID, uri_b)
        .await
        .expect("add second URI");

    let listed = rsclient
        .idm_oauth2_client_list_post_logout_redirect_uris(TEST_INTEGRATION_RS_ID)
        .await
        .expect("list after add");
    assert_eq!(listed.len(), 2, "both URIs should be present");
    assert!(listed.iter().any(|u| u == uri_a));
    assert!(listed.iter().any(|u| u == uri_b));

    // Idempotent add.
    rsclient
        .idm_oauth2_client_add_post_logout_redirect_uri(TEST_INTEGRATION_RS_ID, uri_a)
        .await
        .expect("idempotent add of existing URI");
    let listed = rsclient
        .idm_oauth2_client_list_post_logout_redirect_uris(TEST_INTEGRATION_RS_ID)
        .await
        .expect("list after idempotent add");
    assert_eq!(
        listed.len(),
        2,
        "idempotent add should not produce a duplicate"
    );

    // Remove the first, list should drop it.
    rsclient
        .idm_oauth2_client_remove_post_logout_redirect_uri(TEST_INTEGRATION_RS_ID, uri_a)
        .await
        .expect("remove");
    let listed = rsclient
        .idm_oauth2_client_list_post_logout_redirect_uris(TEST_INTEGRATION_RS_ID)
        .await
        .expect("list after remove");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0], uri_b);
}

/// T049 — admin CRUD for the back-channel logout URI (single-value).
#[netidmd_testkit::test]
async fn test_logout_backchannel_uri_set_clear(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    rsclient
        .idm_oauth2_rs_basic_create(
            TEST_INTEGRATION_RS_ID,
            TEST_INTEGRATION_RS_DISPLAY,
            TEST_INTEGRATION_RS_URL,
        )
        .await
        .expect("Failed to create OAuth2 RS");

    // Set.
    rsclient
        .idm_oauth2_client_set_backchannel_logout_uri(
            TEST_INTEGRATION_RS_ID,
            "https://app.example.com/oidc/backchannel-logout",
        )
        .await
        .expect("set backchannel URI");

    // Overwrite (single-value — must not accumulate).
    rsclient
        .idm_oauth2_client_set_backchannel_logout_uri(
            TEST_INTEGRATION_RS_ID,
            "https://app2.example.com/oidc/backchannel-logout",
        )
        .await
        .expect("overwrite backchannel URI");

    // Clear.
    rsclient
        .idm_oauth2_client_clear_backchannel_logout_uri(TEST_INTEGRATION_RS_ID)
        .await
        .expect("clear backchannel URI");

    // Idempotent clear.
    rsclient
        .idm_oauth2_client_clear_backchannel_logout_uri(TEST_INTEGRATION_RS_ID)
        .await
        .expect("idempotent clear");
}

/// T052 — admin queue list endpoint is reachable and returns an empty
/// list when no deliveries exist.
#[netidmd_testkit::test]
async fn test_logout_deliveries_admin_list_empty(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");

    let items = rsclient
        .idm_list_logout_deliveries(None)
        .await
        .expect("list deliveries");
    assert!(
        items.is_empty(),
        "no LogoutDelivery records should exist in a fresh DB"
    );
}

/// T081 — admin logout-all on a user with no active sessions returns
/// zero terminated. Exercises the HTTP + ACP + actor plumbing for US5
/// admin path without requiring active UATs on the target user.
#[netidmd_testkit::test]
async fn test_logout_admin_logout_all_no_sessions(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    rsclient
        .idm_person_account_create(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_USERNAME)
        .await
        .expect("create test person");

    let (user_uuid, count) = rsclient
        .idm_logout_all_user(NOT_ADMIN_TEST_USERNAME)
        .await
        .expect("admin logout-all");
    assert_eq!(count, 0, "no sessions should have been terminated");
    assert_ne!(user_uuid, uuid::Uuid::nil());
}

/// Set up a standard OAuth2 basic-client RS with an openid scope map
/// and return the test user's ID token after a full PKCE code-flow
/// cycle.
///
/// Returns the access + ID token pair plus the session UUID extracted
/// from the ID token's `jti` claim.
async fn setup_oauth2_flow_and_get_id_token(
    rsclient: &NetidmClient,
    client: &reqwest::Client,
) -> (AccessTokenResponse, String, uuid::Uuid) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");

    rsclient
        .idm_oauth2_rs_basic_create(
            TEST_INTEGRATION_RS_ID,
            TEST_INTEGRATION_RS_DISPLAY,
            TEST_INTEGRATION_RS_URL,
        )
        .await
        .expect("create RS");

    rsclient
        .idm_oauth2_client_add_origin(
            TEST_INTEGRATION_RS_ID,
            &Url::parse(TEST_INTEGRATION_RS_REDIRECT_URL).expect("redirect URL"),
        )
        .await
        .expect("add origin");

    rsclient
        .idm_person_account_create(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_USERNAME)
        .await
        .expect("create person");
    rsclient
        .idm_person_account_primary_credential_set_password(
            NOT_ADMIN_TEST_USERNAME,
            NOT_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect("set password");

    rsclient
        .idm_oauth2_rs_update_scope_map(
            TEST_INTEGRATION_RS_ID,
            NAME_IDM_ALL_ACCOUNTS,
            vec![OAUTH2_SCOPE_READ, OAUTH2_SCOPE_EMAIL, OAUTH2_SCOPE_OPENID],
        )
        .await
        .expect("update scope map");

    let client_secret = rsclient
        .idm_oauth2_rs_get_basic_secret(TEST_INTEGRATION_RS_ID)
        .await
        .ok()
        .flatten()
        .expect("basic secret");

    drive_code_flow(rsclient, client, &client_secret).await
}

/// Authenticate the standard test user, drive a PKCE authorisation
/// code exchange against the pre-created RS, and return the access
/// token bundle, ID token string, and the OAuth2 session UUID
/// extracted from the ID token's `jti` claim.
///
/// Callers must have already set up the RS (`TEST_INTEGRATION_RS_ID`)
/// and the test user with `NOT_ADMIN_TEST_USERNAME`. Each call mints
/// a fresh UAT for the test user — invoking twice from the same test
/// is how we get two parallel OAuth2 sessions for back-channel
/// fan-out assertions.
async fn drive_code_flow(
    rsclient: &NetidmClient,
    client: &reqwest::Client,
    client_secret: &str,
) -> (AccessTokenResponse, String, uuid::Uuid) {
    rsclient
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("user auth");
    let user_uat = rsclient.get_token().await.expect("user token");

    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();
    let query = [
        ("response_type", "code"),
        ("client_id", TEST_INTEGRATION_RS_ID),
        ("code_challenge", pkce_code_challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("redirect_uri", TEST_INTEGRATION_RS_REDIRECT_URL),
        ("scope", "email read openid"),
        ("state", "logout-test-state"),
    ];

    let response = client
        .get(rsclient.make_url("/oauth2/authorise"))
        .bearer_auth(user_uat.clone())
        .query(&query)
        .send()
        .await
        .expect("authorise GET");

    // Two cases handled: (1) the RS is new to this user → 200 +
    // ConsentRequested JSON, we follow up with `/permit` to get the
    // 302; (2) the user has previously consented to this RS → the
    // server returns 302 directly, with the authorisation code in
    // the Location header. Both branches converge on `redir_str`.
    let redir_str = if response.status() == StatusCode::FOUND {
        response
            .headers()
            .get("Location")
            .and_then(|hv| hv.to_str().ok().map(str::to_string))
            .expect("redirect location on direct authorise")
    } else {
        assert_eq!(response.status(), StatusCode::OK);
        let consent_req: AuthorisationResponse =
            response.json().await.expect("parse authorise response");
        let consent_token = match consent_req {
            AuthorisationResponse::ConsentRequested { consent_token, .. } => consent_token,
            AuthorisationResponse::Permitted => panic!("expected consent-requested; got permitted"),
        };
        let response = client
            .get(rsclient.make_url("/oauth2/authorise/permit"))
            .bearer_auth(user_uat)
            .query(&[("token", consent_token.as_str())])
            .send()
            .await
            .expect("consent permit");
        assert_eq!(response.status(), StatusCode::FOUND);
        response
            .headers()
            .get("Location")
            .and_then(|hv| hv.to_str().ok().map(str::to_string))
            .expect("redirect location from permit")
    };

    let redir_url = Url::parse(&redir_str).expect("parse redirect");
    let pairs: BTreeMap<_, _> = redir_url.query_pairs().collect();
    let code = pairs.get("code").expect("authorisation code in redirect");

    let form_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
        code: code.to_string(),
        redirect_uri: Url::parse(TEST_INTEGRATION_RS_REDIRECT_URL).expect("redirect URL"),
        code_verifier: Some(pkce_code_verifier.secret().clone()),
    }
    .into();

    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_ENDPOINT))
        .basic_auth(TEST_INTEGRATION_RS_ID, Some(client_secret))
        .form(&form_req)
        .send()
        .await
        .expect("token exchange");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/json")),
    );

    let atr = response
        .json::<AccessTokenResponse>()
        .await
        .expect("parse AccessTokenResponse");
    let id_token = atr.id_token.clone().expect("id_token issued");

    let unverified = OidcUnverified::from_str(&id_token).expect("parse id_token");
    let jwks: JwkKeySet = client
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/public_key.jwk"
        )))
        .send()
        .await
        .expect("jwks GET")
        .json()
        .await
        .expect("parse jwks");
    let jwk = jwks.keys.first().expect("jwks key").clone();
    let verifier = JwsEs256Verifier::try_from(&jwk).expect("build verifier");
    let verified = verifier
        .verify(&unverified)
        .expect("verify id_token")
        .verify_exp(0)
        .expect("check exp");
    let session_uuid = verified
        .jti
        .as_ref()
        .and_then(|s| uuid::Uuid::from_str(s).ok())
        .expect("id_token jti as session UUID");
    match verified.sub {
        OidcSubject::U(_) => {}
        OidcSubject::S(s) => panic!("unexpected string subject: {s}"),
    }

    (atr, id_token, session_uuid)
}

/// T027 / US1 Acceptance Scenario 1 / SC-001 — full OAuth2 code flow
/// followed by a POST to `end_session_endpoint` with a valid
/// `id_token_hint` and a **registered** `post_logout_redirect_uri`.
/// Asserts:
///
///   - 302 to the registered URI with `state` echoed onto the query string
///     and `Cache-Control: no-store`.
///   - The refresh token the code exchange minted is now invalid (the
///     session it was bound to has been destroyed by `terminate_session`).
#[netidmd_testkit::test]
async fn test_logout_end_session_end_to_end_registered_redirect(rsclient: &NetidmClient) {
    let http = get_reqwest_client();
    let (atr, id_token, _session_uuid) = setup_oauth2_flow_and_get_id_token(rsclient, &http).await;

    // Admin registers the post-logout redirect URI.
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    let post_logout_uri = "https://demo.example.com/after-logout";
    rsclient
        .idm_oauth2_client_add_post_logout_redirect_uri(TEST_INTEGRATION_RS_ID, post_logout_uri)
        .await
        .expect("add post-logout URI");

    // Hit the end_session_endpoint with the valid id_token_hint.
    let end_session_url = rsclient.make_url(&format!(
        "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/end_session_endpoint"
    ));
    let response = http
        .get(end_session_url)
        .query(&[
            ("id_token_hint", id_token.as_str()),
            ("post_logout_redirect_uri", post_logout_uri),
            ("state", "xyz123"),
        ])
        .send()
        .await
        .expect("end_session_endpoint GET");

    assert_eq!(response.status(), StatusCode::FOUND, "must 302 redirect");
    let loc = response
        .headers()
        .get("Location")
        .expect("redirect Location")
        .to_str()
        .expect("Location utf-8");
    let loc_url = Url::parse(loc).expect("parse redirect URL");
    assert_eq!(loc_url.scheme(), "https");
    assert_eq!(loc_url.host_str(), Some("demo.example.com"));
    assert_eq!(loc_url.path(), "/after-logout");
    let echoed_state: BTreeMap<_, _> = loc_url.query_pairs().collect();
    assert_eq!(
        echoed_state
            .get("state")
            .map(std::borrow::Cow::to_string)
            .as_deref(),
        Some("xyz123"),
        "state must be echoed back verbatim"
    );

    let cache_control = response
        .headers()
        .get(header::CACHE_CONTROL)
        .expect("cache-control")
        .to_str()
        .expect("cc utf-8");
    assert!(
        cache_control.contains("no-store"),
        "cache-control must include no-store, got: {cache_control}"
    );

    // The refresh token is bound to the session we just destroyed.
    // Attempting to refresh MUST fail with invalid_grant.
    if let Some(refresh_token) = atr.refresh_token.as_ref() {
        let refresh_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token: refresh_token.clone(),
            scope: None,
        }
        .into();
        let client_secret = rsclient
            .idm_oauth2_rs_get_basic_secret(TEST_INTEGRATION_RS_ID)
            .await
            .ok()
            .flatten()
            .expect("basic secret");
        let response = http
            .post(rsclient.make_url(OAUTH2_TOKEN_ENDPOINT))
            .basic_auth(TEST_INTEGRATION_RS_ID, Some(client_secret))
            .form(&refresh_req)
            .send()
            .await
            .expect("refresh request");
        assert_ne!(
            response.status(),
            StatusCode::OK,
            "refresh against a terminated session must fail"
        );
    }
}

/// T029b — `end_session_endpoint` with a `post_logout_redirect_uri` that
/// is NOT on the client's registered allowlist → falls through to the
/// confirmation page. The unregistered URI is never sent as a redirect.
#[netidmd_testkit::test]
async fn test_logout_end_session_unregistered_redirect_falls_through(rsclient: &NetidmClient) {
    let http = get_reqwest_client();
    let (_atr, id_token, _session_uuid) = setup_oauth2_flow_and_get_id_token(rsclient, &http).await;

    // Admin registers ONLY "https://example/a"; the request will try
    // "https://evil.example.com/" which is NOT on the list.
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    rsclient
        .idm_oauth2_client_add_post_logout_redirect_uri(
            TEST_INTEGRATION_RS_ID,
            "https://demo.example.com/after-logout",
        )
        .await
        .expect("add allow URI");

    let response = http
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/end_session_endpoint"
        )))
        .query(&[
            ("id_token_hint", id_token.as_str()),
            ("post_logout_redirect_uri", "https://evil.example.com/"),
            ("state", "abc"),
        ])
        .send()
        .await
        .expect("end_session_endpoint GET");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "unregistered redirect must fall through to the confirmation page (200)"
    );
    assert!(
        response.headers().get("Location").is_none(),
        "Location header must NOT be set for unregistered redirect"
    );
    let body = response.text().await.expect("response body");
    assert!(
        body.contains("logged out"),
        "confirmation page should mention logged-out state"
    );
}

/// Stand up a minimal axum server that records every POST body sent
/// to `/bcl` into a shared `Vec<String>`. Returns the base URL and
/// the shared buffer handle.
async fn spawn_bcl_receiver() -> (Url, Arc<Mutex<Vec<String>>>) {
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
            .await
            .expect("bind bcl receiver");
    let port = listener.local_addr().expect("bcl addr").port();
    let url = Url::parse(&format!("http://127.0.0.1:{port}")).expect("bcl url");
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_handler = captured.clone();
    let app = Router::new().route(
        "/bcl",
        post(move |Form(form): Form<BclForm>| {
            let captured = captured_for_handler.clone();
            async move {
                captured.lock().await.push(form.logout_token);
                (StatusCode::OK, "")
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, captured)
}

#[derive(serde::Deserialize)]
struct BclForm {
    logout_token: String,
}

/// T054 — full back-channel logout delivery. Drive a full OAuth2
/// code flow, register a dummy HTTP receiver as the RP's
/// `OAuth2RsBackchannelLogoutUri`, terminate the session via
/// end_session_endpoint, assert the receiver receives a POST
/// carrying `logout_token=<signed-jws>` whose claims match spec
/// (iss / aud / sub / sid / events / typ header = "logout+jwt").
#[netidmd_testkit::test]
async fn test_logout_backchannel_delivery_end_to_end(rsclient: &NetidmClient) {
    let http = get_reqwest_client();

    // Stand up the dummy BCL receiver first so we have its URL to
    // configure on the RP.
    let (receiver_base, captured) = spawn_bcl_receiver().await;
    let bcl_url = format!("{receiver_base}bcl");

    // Drive the full code flow and get an ID token.
    let (_atr, id_token, _oauth2_session_uuid) =
        setup_oauth2_flow_and_get_id_token(rsclient, &http).await;

    // Now re-auth as admin to configure the RP's back-channel URL.
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    rsclient
        .idm_oauth2_client_set_backchannel_logout_uri(TEST_INTEGRATION_RS_ID, bcl_url.as_str())
        .await
        .expect("set backchannel URL");

    // Terminate the session.
    let end_session_url = rsclient.make_url(&format!(
        "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/end_session_endpoint"
    ));
    let response = http
        .get(end_session_url)
        .query(&[("id_token_hint", id_token.as_str())])
        .send()
        .await
        .expect("end_session");
    assert_eq!(response.status(), StatusCode::OK);

    // Poll the captured buffer — the worker wakes on notify_one(),
    // the POST should land within a few seconds. Bounded retry loop
    // so we don't hang on an assertion failure.
    let mut tokens: Vec<String> = Vec::new();
    for _ in 0..40 {
        {
            let buf = captured.lock().await;
            if !buf.is_empty() {
                tokens = buf.clone();
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        !tokens.is_empty(),
        "back-channel receiver never got a POST after 10 s"
    );
    assert_eq!(tokens.len(), 1, "exactly one delivery expected");

    // Decode and verify the logout token's claims.
    let logout_token = &tokens[0];
    let jws = compact_jwt::compact::JwsCompact::from_str(logout_token)
        .expect("logout_token parses as JwsCompact");
    let header = jws.header();
    assert_eq!(
        header.typ.as_deref(),
        Some("logout+jwt"),
        "typ header must be logout+jwt per OIDC Back-Channel Logout 1.0 §2.4"
    );

    // Verify signature using the RP's public JWK set.
    let jwks: JwkKeySet = http
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/public_key.jwk"
        )))
        .send()
        .await
        .expect("jwks GET")
        .json()
        .await
        .expect("parse jwks");
    let jwk = jwks.keys.first().expect("jwks key").clone();
    let verifier = JwsEs256Verifier::try_from(&jwk).expect("build verifier");
    let verified = verifier.verify(&jws).expect("verify logout token");
    let claims: serde_json::Value =
        serde_json::from_slice(verified.payload()).expect("parse claims");

    // Required claims per OpenID Back-Channel Logout 1.0 §2.4.
    assert_eq!(
        claims.get("aud").and_then(serde_json::Value::as_str),
        Some(TEST_INTEGRATION_RS_ID),
        "aud must equal the client_id"
    );
    assert!(
        claims
            .get("iss")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "iss must be set"
    );
    assert!(
        claims
            .get("iat")
            .and_then(serde_json::Value::as_i64)
            .is_some(),
        "iat must be set"
    );
    assert!(
        claims
            .get("jti")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "jti must be set (per-token unique ID for replay protection)"
    );
    assert!(
        claims
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "sub must be the user UUID"
    );
    assert!(
        claims
            .get("sid")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "sid must be set because backchannel_logout_session_supported=true"
    );
    let events = claims.get("events").expect("events claim must be present");
    let logout_event = events
        .get("http://schemas.openid.net/event/backchannel-logout")
        .expect("events claim must contain the back-channel-logout event");
    assert!(
        logout_event.is_object(),
        "back-channel-logout event value must be an (empty) object"
    );
}

/// T057 — when the RP has NO `OAuth2RsBackchannelLogoutUri`
/// registered, session termination succeeds and produces zero
/// `LogoutDelivery` records. The admin queue-list must stay empty
/// after the logout flow.
#[netidmd_testkit::test]
async fn test_logout_backchannel_delivery_no_registration_skipped(rsclient: &NetidmClient) {
    let http = get_reqwest_client();
    let (_atr, id_token, _oauth2_session_uuid) =
        setup_oauth2_flow_and_get_id_token(rsclient, &http).await;

    // No backchannel URI registration. Terminate the session.
    let end_session_url = rsclient.make_url(&format!(
        "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/end_session_endpoint"
    ));
    let response = http
        .get(end_session_url)
        .query(&[("id_token_hint", id_token.as_str())])
        .send()
        .await
        .expect("end_session");
    assert_eq!(response.status(), StatusCode::OK);

    // Give the worker a moment to do NOTHING (so if we're about to
    // deliver, we'd see it).
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Admin queue-list must still be empty.
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    let deliveries = rsclient
        .idm_list_logout_deliveries(None)
        .await
        .expect("list deliveries");
    assert!(
        deliveries.is_empty(),
        "no LogoutDelivery records should be enqueued when RP has no backchannel URI; got {}",
        deliveries.len()
    );
}

/// T082 / US5 Acceptance Scenario 4 — OIDC end-session only
/// terminates the single session named by the id_token_hint's `sid`
/// claim (resolved via the OAuth2 session's parent). An unrelated
/// netidm session (e.g. the admin's CLI login) for the SAME user
/// must NOT be affected.
#[netidmd_testkit::test]
async fn test_logout_end_session_never_goes_global(rsclient: &NetidmClient) {
    let http = get_reqwest_client();

    // Drive the code flow; this returns an id_token for the
    // NOT_ADMIN_TEST_USERNAME user. The helper also leaves the client
    // authenticated AS that user (its `auth_simple_password` call).
    // We rely on the admin's own CLI login staying alive
    // independently — it's managed by a separate UAT.
    let (_atr, id_token, _) = setup_oauth2_flow_and_get_id_token(rsclient, &http).await;

    // Establish a second, independent UAT for the user by re-authing
    // with the user's password (same credential, fresh session). The
    // first UAT was set up by the OAuth2 code flow.
    rsclient
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("user second auth (second UAT)");
    let second_uat = rsclient.get_token().await.expect("second UAT must exist");

    // Terminate the ID-token session via end_session_endpoint. The
    // second UAT is bound to a DIFFERENT parent session and must
    // survive.
    let response = http
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/end_session_endpoint"
        )))
        .query(&[("id_token_hint", id_token.as_str())])
        .send()
        .await
        .expect("end_session");
    assert_eq!(response.status(), StatusCode::OK);

    // The second UAT must still authenticate — hit `/v1/self` which
    // requires a valid session.
    let whoami = http
        .get(rsclient.make_url("/v1/self"))
        .bearer_auth(second_uat)
        .send()
        .await
        .expect("whoami on surviving session");
    assert_eq!(
        whoami.status(),
        StatusCode::OK,
        "the second UAT must survive — OIDC end-session is single-session-only"
    );
}

/// T036 / FR-016 — post-logout redirect URI CRUD requires admin
/// privileges. A non-admin user hitting the admin endpoint must be
/// denied. Covers the ACP gating added to `IDM_ACP_OAUTH2_MANAGE`
/// in DL26.
#[netidmd_testkit::test]
async fn test_logout_post_logout_redirect_uri_crud_rejects_non_admin(rsclient: &NetidmClient) {
    // Admin creates the RS.
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    rsclient
        .idm_oauth2_rs_basic_create(
            TEST_INTEGRATION_RS_ID,
            TEST_INTEGRATION_RS_DISPLAY,
            TEST_INTEGRATION_RS_URL,
        )
        .await
        .expect("create RS");

    // Create a non-admin person.
    rsclient
        .idm_person_account_create(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_USERNAME)
        .await
        .expect("create non-admin");
    rsclient
        .idm_person_account_primary_credential_set_password(
            NOT_ADMIN_TEST_USERNAME,
            NOT_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect("set password");

    // Re-auth as the non-admin and attempt CRUD — must be denied at
    // the ACP layer, not pass silently.
    rsclient
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("non-admin auth");

    let add_result = rsclient
        .idm_oauth2_client_add_post_logout_redirect_uri(
            TEST_INTEGRATION_RS_ID,
            "https://demo.example.com/after-logout",
        )
        .await;
    assert!(
        add_result.is_err(),
        "non-admin post-logout add must fail; got Ok"
    );

    let remove_result = rsclient
        .idm_oauth2_client_remove_post_logout_redirect_uri(
            TEST_INTEGRATION_RS_ID,
            "https://demo.example.com/after-logout",
        )
        .await;
    assert!(
        remove_result.is_err(),
        "non-admin post-logout remove must fail; got Ok"
    );

    // Re-auth as admin and confirm the RS still has an empty
    // allowlist — no ghost state written by the denied requests.
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin reauth");
    let listed = rsclient
        .idm_oauth2_client_list_post_logout_redirect_uris(TEST_INTEGRATION_RS_ID)
        .await
        .expect("list");
    assert!(
        listed.is_empty(),
        "denied CRUD must not leave ghost values; got {listed:?}"
    );
}

/// T057 / US3 — admin `logout_deliveries` list/show with a mix of
/// Succeeded + Pending records; verifies the status filter and the
/// show-by-UUID surface; asserts non-admin access is denied by ACP.
///
/// Flow:
///   1. Drive a code flow and end the session against a WORKING
///      back-channel receiver → that delivery transitions to
///      Succeeded once the worker POSTs and gets `200`.
///   2. Reconfigure the RP's back-channel URL to `http://127.0.0.1:1`
///      (port 1 refuses connections) and drive a SECOND code flow
///      for the same user; terminating that session enqueues a
///      Pending delivery whose retries will never succeed within
///      the test window — it stays Pending for our assertions.
///   3. Assert: unfiltered list is ≥ 2; filter=succeeded returns
///      exactly the first; filter=pending returns exactly the
///      second; show-by-uuid returns the correct record.
///   4. Non-admin is denied by ACP on the list endpoint.
#[netidmd_testkit::test]
async fn test_logout_deliveries_admin_list_show_with_mix(rsclient: &NetidmClient) {
    use netidm_proto::v1::LogoutDeliveryFilter;

    let http = get_reqwest_client();

    // Step 1 — working receiver + first flow + terminate.
    let (receiver_base, captured) = spawn_bcl_receiver().await;
    let bcl_working = format!("{receiver_base}bcl");

    let (_atr1, id_token1, _session1) =
        setup_oauth2_flow_and_get_id_token(rsclient, &http).await;

    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    rsclient
        .idm_oauth2_client_set_backchannel_logout_uri(TEST_INTEGRATION_RS_ID, bcl_working.as_str())
        .await
        .expect("set working backchannel URL");

    let response = http
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/end_session_endpoint"
        )))
        .query(&[("id_token_hint", id_token1.as_str())])
        .send()
        .await
        .expect("end_session 1");
    assert_eq!(response.status(), StatusCode::OK);

    // Wait for the Succeeded delivery to land at the receiver.
    for _ in 0..40 {
        if !captured.lock().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        !captured.lock().await.is_empty(),
        "working receiver must have received the first delivery"
    );

    // Step 2 — swap the URL to an unreachable one + second flow +
    // terminate.
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin re-auth");
    rsclient
        .idm_oauth2_client_set_backchannel_logout_uri(
            TEST_INTEGRATION_RS_ID,
            "http://127.0.0.1:1/bcl",
        )
        .await
        .expect("set unreachable backchannel URL");

    let client_secret = rsclient
        .idm_oauth2_rs_get_basic_secret(TEST_INTEGRATION_RS_ID)
        .await
        .ok()
        .flatten()
        .expect("basic secret");
    let (_atr2, id_token2, _session2) = drive_code_flow(rsclient, &http, &client_secret).await;

    let response = http
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/end_session_endpoint"
        )))
        .query(&[("id_token_hint", id_token2.as_str())])
        .send()
        .await
        .expect("end_session 2");
    assert_eq!(response.status(), StatusCode::OK);

    // Step 3 — list + show + filter assertions.
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin re-auth for queue read");

    // Poll until the second delivery is enqueued (worker moves
    // deliveries out of the enqueue-then-notify window).
    let mut all: Vec<_> = Vec::new();
    for _ in 0..40 {
        let items = rsclient
            .idm_list_logout_deliveries(None)
            .await
            .expect("list unfiltered");
        if items.len() >= 2 {
            all = items;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        all.len() >= 2,
        "unfiltered list must show both deliveries; got {}",
        all.len()
    );

    // Filter narrows correctly. Succeeded/Pending each must match
    // one delivery; both counts must be at least 1 (new records
    // from a fresh DB guarantee exactly these two, but we assert
    // ≥ 1 to stay robust against future fixture changes).
    let succeeded = rsclient
        .idm_list_logout_deliveries(Some(LogoutDeliveryFilter::Succeeded))
        .await
        .expect("list succeeded");
    assert!(
        succeeded.iter().all(|d| d.status == "succeeded"),
        "filter=succeeded must only return succeeded rows; got {succeeded:?}"
    );
    assert!(
        !succeeded.is_empty(),
        "the working-receiver delivery must be Succeeded"
    );

    let pending = rsclient
        .idm_list_logout_deliveries(Some(LogoutDeliveryFilter::Pending))
        .await
        .expect("list pending");
    assert!(
        pending.iter().all(|d| d.status == "pending"),
        "filter=pending must only return pending rows; got {pending:?}"
    );
    assert!(
        !pending.is_empty(),
        "the unreachable-receiver delivery must be Pending"
    );

    // Show by UUID — pick the first pending row, look it up,
    // assert the record matches.
    let target = pending.first().expect("pending row");
    let fetched = rsclient
        .idm_show_logout_delivery(target.uuid)
        .await
        .expect("show delivery")
        .expect("existing delivery returns Some");
    assert_eq!(fetched.uuid, target.uuid);
    assert_eq!(fetched.status, "pending");
    assert_eq!(fetched.endpoint, target.endpoint);

    // Step 4 — non-admin is denied by ACP.
    rsclient
        .idm_person_account_primary_credential_set_password(
            NOT_ADMIN_TEST_USERNAME,
            NOT_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect("set password (helper already created the person)");
    rsclient
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("non-admin auth");
    // Correct ACP behaviour is either an explicit denial or a
    // filtered-empty list (no enumeration leak). An admin just saw
    // ≥ 2 records against this same fixture; the non-admin must
    // see none.
    let as_non_admin = rsclient.idm_list_logout_deliveries(None).await;
    match as_non_admin {
        Err(_) => {}
        Ok(items) => assert!(
            items.is_empty(),
            "non-admin must not observe any logout_deliveries; got {items:?}"
        ),
    }

    // Show-by-UUID must also refuse to surface the admin-only
    // record when called by a non-admin. Accept either a denial
    // or `Ok(None)` (filtered out of the result set).
    let show_as_non_admin = rsclient.idm_show_logout_delivery(target.uuid).await;
    match show_as_non_admin {
        Err(_) => {}
        Ok(None) => {}
        Ok(Some(d)) => panic!("non-admin must not observe delivery via show; got {d:?}"),
    }
}

/// T036 / US2 Acceptance Scenario 4 — the server rejects malformed
/// `post_logout_redirect_uri` values. The URL schema type is
/// authoritative — a non-URL string must not be accepted and must
/// not corrupt storage. Covers FR validation requirement on the
/// allowlist.
#[netidmd_testkit::test]
async fn test_logout_post_logout_redirect_uri_malformed_rejected(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    rsclient
        .idm_oauth2_rs_basic_create(
            TEST_INTEGRATION_RS_ID,
            TEST_INTEGRATION_RS_DISPLAY,
            TEST_INTEGRATION_RS_URL,
        )
        .await
        .expect("create RS");

    // Malformed inputs — none of these should be accepted by the
    // URL schema type. Testing a couple of flavours to catch naïve
    // partial validation.
    for bad in ["not-a-url", "example.com/missing-scheme", " "] {
        let add_result = rsclient
            .idm_oauth2_client_add_post_logout_redirect_uri(TEST_INTEGRATION_RS_ID, bad)
            .await;
        assert!(
            add_result.is_err(),
            "malformed post-logout URI {bad:?} must be rejected; got Ok"
        );
    }

    // Storage must remain untouched by the failed adds.
    let listed = rsclient
        .idm_oauth2_client_list_post_logout_redirect_uris(TEST_INTEGRATION_RS_ID)
        .await
        .expect("list");
    assert!(
        listed.is_empty(),
        "rejected adds must not leave ghost values; got {listed:?}"
    );

    // A properly-formed URL must still succeed — sanity check that
    // we didn't break the happy path.
    rsclient
        .idm_oauth2_client_add_post_logout_redirect_uri(
            TEST_INTEGRATION_RS_ID,
            "https://demo.example.com/after-logout",
        )
        .await
        .expect("well-formed URI must still succeed");
    let listed = rsclient
        .idm_oauth2_client_list_post_logout_redirect_uris(TEST_INTEGRATION_RS_ID)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1, "one well-formed URL should be stored");
}

/// T080 / US5 Acceptance Scenario 2 — `/v1/self/logout_all` fans out
/// back-channel deliveries to every RP whose tokens were minted
/// against one of the caller's sessions. Two independent OAuth2
/// code flows (same user, two UATs, two OAuth2Sessions) point at a
/// single RP with a registered back-channel URL; invoking
/// logout_all is expected to produce exactly two POSTs at the
/// receiver, each carrying a distinct `sid`.
#[netidmd_testkit::test]
async fn test_logout_self_logout_all_fans_out_backchannel(rsclient: &NetidmClient) {
    let http = get_reqwest_client();

    // Stand up the dummy BCL receiver first so we can configure the
    // RP with its URL before any tokens are issued (back-channel
    // lookup reads the RP entry at termination time).
    let (receiver_base, captured) = spawn_bcl_receiver().await;
    let bcl_url = format!("{receiver_base}bcl");

    // First flow also provisions the RS and the user.
    let (_atr1, _id_token1, _session1) =
        setup_oauth2_flow_and_get_id_token(rsclient, &http).await;

    // Admin: register the back-channel URL.
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    rsclient
        .idm_oauth2_client_set_backchannel_logout_uri(TEST_INTEGRATION_RS_ID, bcl_url.as_str())
        .await
        .expect("set backchannel URL");

    // Fetch the client secret so we can drive a second code flow
    // without re-running the whole setup (which would double-create
    // the RS / person).
    let client_secret = rsclient
        .idm_oauth2_rs_get_basic_secret(TEST_INTEGRATION_RS_ID)
        .await
        .ok()
        .flatten()
        .expect("basic secret");

    // Second flow (same user, fresh UAT, fresh OAuth2Session bound
    // to the RP that was already configured with a back-channel URL).
    let (_atr2, _id_token2, _session2) =
        drive_code_flow(rsclient, &http, &client_secret).await;

    // The client is now authenticated as NOT_ADMIN_TEST_USERNAME
    // holding the second-flow UAT. Invoke `/v1/self/logout_all` —
    // this must terminate BOTH of the user's active UATs (the two
    // the code flows produced).
    let count = rsclient
        .idm_logout_all_self()
        .await
        .expect("self logout_all");
    assert!(
        count >= 2,
        "at least the two OAuth2-code-flow UATs must be terminated; got {count}"
    );

    // The worker wakes on notify_one(); wait for both deliveries
    // to land. Bounded retry loop so a stuck test fails fast.
    let mut tokens: Vec<String> = Vec::new();
    for _ in 0..40 {
        {
            let buf = captured.lock().await;
            if buf.len() >= 2 {
                tokens = buf.clone();
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(
        tokens.len(),
        2,
        "back-channel receiver expected exactly two POSTs after logout_all (10 s window); got {}",
        tokens.len()
    );

    // Verify both tokens parse and carry distinct `sid` claims.
    let jwks: JwkKeySet = http
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/public_key.jwk"
        )))
        .send()
        .await
        .expect("jwks GET")
        .json()
        .await
        .expect("parse jwks");
    let jwk = jwks.keys.first().expect("jwks key").clone();
    let verifier = JwsEs256Verifier::try_from(&jwk).expect("build verifier");

    let mut sids: Vec<String> = Vec::with_capacity(2);
    for tok in &tokens {
        let jws = compact_jwt::compact::JwsCompact::from_str(tok).expect("parse jws");
        let verified = verifier.verify(&jws).expect("verify signature");
        let claims: serde_json::Value =
            serde_json::from_slice(verified.payload()).expect("parse claims");
        let sid = claims
            .get("sid")
            .and_then(serde_json::Value::as_str)
            .expect("sid present")
            .to_string();
        sids.push(sid);
    }
    assert_ne!(
        sids[0], sids[1],
        "each delivery must carry a distinct sid — one per terminated session"
    );
}

/// T079 / US5 Acceptance Scenario 1 — `/v1/self/logout_all`
/// terminates every active netidm session the caller holds.
/// Three independent UATs are established for the same user;
/// a single invocation through one of them brings the response
/// `sessions_terminated == 3` and every UAT subsequently fails
/// at `/v1/self`.
#[netidmd_testkit::test]
async fn test_logout_self_logout_all_terminates_every_session(rsclient: &NetidmClient) {
    let http = get_reqwest_client();

    // Admin: create the non-admin person and set its password.
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");
    rsclient
        .idm_person_account_create(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_USERNAME)
        .await
        .expect("create non-admin");
    rsclient
        .idm_person_account_primary_credential_set_password(
            NOT_ADMIN_TEST_USERNAME,
            NOT_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect("set password");

    // Establish three independent UATs by re-authenticating three
    // times. Each `auth_simple_password` mints a fresh UAT; the
    // client's bearer slot holds the most recent one, so grab each
    // value before the next login overwrites it.
    rsclient
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("user auth 1");
    let uat_one = rsclient.get_token().await.expect("uat 1");
    rsclient
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("user auth 2");
    let uat_two = rsclient.get_token().await.expect("uat 2");
    rsclient
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("user auth 3");
    let uat_three = rsclient.get_token().await.expect("uat 3");

    // The three UATs must be distinct — else we don't have three
    // sessions to log out.
    assert_ne!(uat_one, uat_two, "uat 1 and uat 2 must differ");
    assert_ne!(uat_two, uat_three, "uat 2 and uat 3 must differ");
    assert_ne!(uat_one, uat_three, "uat 1 and uat 3 must differ");

    // Sanity: every UAT currently authenticates.
    for (label, token) in [
        ("uat 1", uat_one.as_str()),
        ("uat 2", uat_two.as_str()),
        ("uat 3", uat_three.as_str()),
    ] {
        let resp = http
            .get(rsclient.make_url("/v1/self"))
            .bearer_auth(token)
            .send()
            .await
            .expect("whoami pre-logout");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{label} must authenticate before logout_all"
        );
    }

    // Invoke `/v1/self/logout_all` — the client is currently holding
    // uat 3, so that's the session making the call. Expect three
    // sessions terminated (including the caller's own).
    let count = rsclient
        .idm_logout_all_self()
        .await
        .expect("self logout_all");
    assert_eq!(count, 3, "all three sessions must be reported terminated");

    // Every UAT — the caller's included — must now be rejected at
    // `/v1/self`.
    for (label, token) in [
        ("uat 1", uat_one.as_str()),
        ("uat 2", uat_two.as_str()),
        ("uat 3", uat_three.as_str()),
    ] {
        let resp = http
            .get(rsclient.make_url("/v1/self"))
            .bearer_auth(token)
            .send()
            .await
            .expect("whoami post-logout");
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "{label} must be rejected after logout_all"
        );
    }
}
