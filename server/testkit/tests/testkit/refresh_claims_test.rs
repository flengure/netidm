#![deny(warnings)]
//! Integration tests for PR-REFRESH-CLAIMS (spec: specs/010-refresh-claims).
//!
//! Covers the must-land integration tests from the HANDOFF:
//!
//!   * T021 — end-to-end: upstream group mutation flows through connector
//!     dispatch to a new access token on refresh.
//!   * T024 — each `ConnectorRefreshError` variant causes the refresh
//!     endpoint to return `invalid_grant`.
//!   * T025 — a session with `upstream_connector = Some(unregistered_uuid)`
//!     returns `invalid_grant` because the registry lookup fails.
//!   * T032 — a pre-DL27 session (`upstream_connector = None`) takes the
//!     cached-claims path and returns a valid new access token.

use compact_jwt::dangernoverify::JwsDangerReleaseWithoutVerify;
use compact_jwt::{JwsVerifier, OidcUnverified};
use netidm_client::{NetidmClient, StatusCode};
use netidm_proto::constants::uri::OAUTH2_TOKEN_ENDPOINT;
use netidm_proto::constants::{OAUTH2_SCOPE_EMAIL, OAUTH2_SCOPE_OPENID, OAUTH2_SCOPE_READ};
use netidm_proto::oauth2::{
    AccessTokenRequest, AccessTokenResponse, AuthorisationResponse, ErrorResponse, GrantTypeReq,
};
use netidmd_lib::constants::NAME_IDM_ALL_ACCOUNTS;
use netidmd_lib::idm::oauth2::Oauth2Error as Oauth2LibError;
use netidmd_lib::modify::{Modify, ModifyList};
use netidmd_lib::prelude::{Attribute, QueryServerTransaction, Value, duration_from_epoch_now};
use netidmd_lib::value::{Oauth2Session, SessionState};
use netidmd_testkit::{
    AsyncTestEnvironment, ConnectorRefreshError, TestMockConnector, ADMIN_TEST_PASSWORD,
    ADMIN_TEST_USER, NOT_ADMIN_TEST_PASSWORD, NOT_ADMIN_TEST_USERNAME, TEST_INTEGRATION_RS_DISPLAY,
    TEST_INTEGRATION_RS_ID, TEST_INTEGRATION_RS_REDIRECT_URL, TEST_INTEGRATION_RS_URL,
};
use oauth2_ext::PkceCodeChallenge;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

// ── HTTP helpers ─────────────────────────────────────────────────────────────

fn http_client() -> reqwest::Client {
    #[allow(clippy::expect_used)]
    reqwest::Client::builder()
        .tls_danger_accept_invalid_certs(true)
        .tls_danger_accept_invalid_hostnames(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("failed to build reqwest client")
}

// ── OAuth2 flow helpers ───────────────────────────────────────────────────────

/// Create the test RS and the standard test user with a scope map.
/// Returns the RS basic secret. Caller is left authenticated as admin.
async fn setup_rs_and_user(rsclient: &NetidmClient) -> String {
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
        .expect("scope map");

    rsclient
        .idm_oauth2_rs_get_basic_secret(TEST_INTEGRATION_RS_ID)
        .await
        .ok()
        .flatten()
        .expect("basic secret")
}

/// Return the test person's netidm UUID. Re-authenticates as admin.
async fn person_uuid(rsclient: &NetidmClient) -> Uuid {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin re-auth for uuid lookup");

    let entry = rsclient
        .idm_person_account_get(NOT_ADMIN_TEST_USERNAME)
        .await
        .expect("person get")
        .expect("person exists");

    let uuid_str = entry
        .attrs
        .get("uuid")
        .and_then(|v| v.first())
        .expect("entry has uuid attr");

    Uuid::from_str(uuid_str).expect("parse uuid")
}

/// Authenticate as the test user and drive a full PKCE code flow.
///
/// Returns `(AccessTokenResponse, OAuth2 session UUID)`.  The session UUID is
/// the `jti` extracted from the ID token.
async fn drive_code_flow(
    rsclient: &NetidmClient,
    client: &reqwest::Client,
    client_secret: &str,
) -> (AccessTokenResponse, Uuid) {
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
        ("state", "refresh-claims-test"),
    ];

    let response = client
        .get(rsclient.make_url("/oauth2/authorise"))
        .bearer_auth(user_uat.clone())
        .query(&query)
        .send()
        .await
        .expect("authorise GET");

    let redir_str = if response.status() == StatusCode::FOUND {
        response
            .headers()
            .get("Location")
            .and_then(|hv| hv.to_str().ok().map(str::to_string))
            .expect("redirect location")
    } else {
        assert_eq!(response.status(), StatusCode::OK);
        let consent_req: AuthorisationResponse =
            response.json().await.expect("parse authorise response");
        let consent_token = match consent_req {
            AuthorisationResponse::ConsentRequested { consent_token, .. } => consent_token,
            AuthorisationResponse::Permitted => {
                panic!("expected consent-requested; got permitted")
            }
        };
        let resp = client
            .get(rsclient.make_url("/oauth2/authorise/permit"))
            .bearer_auth(user_uat)
            .query(&[("token", consent_token.as_str())])
            .send()
            .await
            .expect("consent permit");
        assert_eq!(resp.status(), StatusCode::FOUND);
        resp.headers()
            .get("Location")
            .and_then(|hv| hv.to_str().ok().map(str::to_string))
            .expect("redirect location from permit")
    };

    let redir_url = Url::parse(&redir_str).expect("parse redirect URL");
    let pairs: BTreeMap<_, _> = redir_url.query_pairs().collect();
    let code = pairs
        .get("code")
        .expect("authorisation code in redirect")
        .to_string();

    let form_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
        code,
        redirect_uri: Url::parse(TEST_INTEGRATION_RS_REDIRECT_URL).expect("redirect URL"),
        code_verifier: Some(pkce_code_verifier.secret().clone()),
    }
    .into();

    let resp = client
        .post(rsclient.make_url(OAUTH2_TOKEN_ENDPOINT))
        .basic_auth(TEST_INTEGRATION_RS_ID, Some(client_secret))
        .form(&form_req)
        .send()
        .await
        .expect("token exchange");

    assert_eq!(resp.status(), StatusCode::OK, "token exchange must succeed");

    let atr: AccessTokenResponse = resp.json().await.expect("parse AccessTokenResponse");

    // Extract session UUID from the ID token's `jti` claim without
    // re-fetching the JWKS for signature verification — the test environment
    // does not expose a stable signing key and we only need the UUID.
    let id_token_str = atr.id_token.as_deref().expect("id_token issued");
    let unverified = OidcUnverified::from_str(id_token_str).expect("parse id_token");
    let danger_verifier = JwsDangerReleaseWithoutVerify::default();
    let claims = danger_verifier
        .verify(&unverified)
        .expect("release id_token claims")
        .verify_exp(0)
        .expect("verify_exp");
    let jti_str = claims.jti.as_deref().expect("id_token has jti");
    let session_uuid = Uuid::from_str(jti_str).expect("jti is a UUID");

    (atr, session_uuid)
}

/// Send a refresh-token grant to the token endpoint.
async fn do_refresh(
    rsclient: &NetidmClient,
    client: &reqwest::Client,
    client_secret: &str,
    refresh_token: &str,
) -> reqwest::Response {
    let form_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
        refresh_token: refresh_token.to_string(),
        scope: None,
    }
    .into();

    client
        .post(rsclient.make_url(OAUTH2_TOKEN_ENDPOINT))
        .basic_auth(TEST_INTEGRATION_RS_ID, Some(client_secret))
        .form(&form_req)
        .send()
        .await
        .expect("refresh POST")
}

/// Stamp `upstream_connector = Some(connector_uuid)` onto the
/// `session_uuid` OAuth2 session belonging to `person_uuid`.
///
/// Uses a write transaction to bump the session's `ExpiresAt` by one second
/// so that `ValueSetOauth2Session::insert_checked`'s state-ordering conflict
/// resolution replaces the existing entry rather than silently discarding it.
async fn stamp_upstream_connector(
    test_env: &AsyncTestEnvironment,
    person_uuid: Uuid,
    session_uuid: Uuid,
    connector_uuid: Uuid,
) {
    let ct = duration_from_epoch_now();

    let mut proxy_read = test_env
        .idm_server
        .proxy_read()
        .await
        .expect("proxy_read");

    let entry = proxy_read
        .qs_read
        .internal_search_uuid(person_uuid)
        .expect("person not found");

    let existing = entry
        .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
        .and_then(|m| m.get(&session_uuid))
        .expect("session not found in entry")
        .clone();

    let new_state = match existing.state {
        SessionState::ExpiresAt(t) => SessionState::ExpiresAt(t + Duration::from_secs(1)),
        SessionState::NeverExpires => SessionState::NeverExpires,
        SessionState::RevokedAt(_) => panic!("cannot stamp a revoked session"),
    };

    let stamped = Oauth2Session {
        upstream_connector: Some(connector_uuid),
        upstream_refresh_state: Some(vec![]),
        state: new_state,
        ..existing
    };

    drop(proxy_read);

    let mut proxy_write = test_env
        .idm_server
        .proxy_write(ct)
        .await
        .expect("proxy_write");

    let session_value = Value::Oauth2Session(session_uuid, stamped);
    let modlist =
        ModifyList::new_list(vec![Modify::Present(Attribute::OAuth2Session, session_value)]);

    proxy_write
        .qs_write
        .internal_modify_uuid(person_uuid, &modlist)
        .expect("stamp modify failed");

    proxy_write.commit().expect("stamp commit failed");
}

// ── T032 — pre-DL27 session (upstream_connector = None) uses cached-claims ──

/// T032 / SC-DL27-none — a session whose `upstream_connector` is `None`
/// (pre-DL27 or locally-authenticated) takes the cached-claims path and
/// returns a new access + refresh token pair.
#[netidmd_testkit::test]
async fn test_refresh_no_connector_uses_cached_claims_path(rsclient: &NetidmClient) {
    let http = http_client();
    let secret = setup_rs_and_user(rsclient).await;

    let (atr, _session_uuid) = drive_code_flow(rsclient, &http, &secret).await;

    let refresh_token = atr.refresh_token.expect("refresh token issued");
    let resp = do_refresh(rsclient, &http, &secret, &refresh_token).await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "refresh on None-connector session must succeed"
    );

    let new_atr: AccessTokenResponse = resp.json().await.expect("parse new AccessTokenResponse");
    assert!(
        new_atr.access_token != atr.access_token,
        "new access token must differ from the original"
    );
}

// ── T021 — upstream group mutation flows to token via connector dispatch ──────

/// T021 / US1 — upstream mutation observed via connector dispatch.
///
/// Stamps `upstream_connector` onto the session, registers a mock connector,
/// drives a refresh, and asserts a new access token is issued.
#[netidmd_testkit::test(with_test_env = true)]
async fn test_refresh_dispatches_to_connector_when_bound(test_env: &AsyncTestEnvironment) {
    let http = http_client();
    let rsclient = &test_env.rsclient;
    let secret = setup_rs_and_user(rsclient).await;

    let puuid = person_uuid(rsclient).await;

    let connector_uuid = Uuid::new_v4();
    let mock = Arc::new(TestMockConnector::new(puuid.to_string()));
    mock.set_groups(vec!["upstream-group".to_string()]);

    test_env
        .connector_registry
        .register(connector_uuid, Arc::clone(&mock) as Arc<_>);

    let (atr, session_uuid) = drive_code_flow(rsclient, &http, &secret).await;
    stamp_upstream_connector(test_env, puuid, session_uuid, connector_uuid).await;

    let refresh_token = atr.refresh_token.expect("refresh token issued");
    let resp = do_refresh(rsclient, &http, &secret, &refresh_token).await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "refresh with bound connector must succeed"
    );

    let new_atr: AccessTokenResponse = resp.json().await.expect("parse new AccessTokenResponse");
    assert!(
        new_atr.access_token != atr.access_token,
        "new access token must differ from the original"
    );
    assert_eq!(
        mock.refresh_call_count(),
        1,
        "connector must have been called exactly once"
    );
}

// ── T024 — connector errors → invalid_grant ──────────────────────────────────

/// Shared body for T024 test variants: stamp the session, configure the mock
/// to return a specific error, drive a refresh, assert 400 + `invalid_grant`.
async fn run_connector_error_case(test_env: &AsyncTestEnvironment, error: ConnectorRefreshError) {
    let http = http_client();
    let rsclient = &test_env.rsclient;
    let secret = setup_rs_and_user(rsclient).await;

    let puuid = person_uuid(rsclient).await;

    let connector_uuid = Uuid::new_v4();
    let mock = Arc::new(TestMockConnector::new(puuid.to_string()));
    mock.set_error(Some(error));

    test_env
        .connector_registry
        .register(connector_uuid, Arc::clone(&mock) as Arc<_>);

    let (atr, session_uuid) = drive_code_flow(rsclient, &http, &secret).await;
    stamp_upstream_connector(test_env, puuid, session_uuid, connector_uuid).await;

    let refresh_token = atr.refresh_token.expect("refresh token issued");
    let resp = do_refresh(rsclient, &http, &secret, &refresh_token).await;

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "connector error must return 400"
    );
    let body: ErrorResponse = resp.json().await.expect("parse ErrorResponse");
    assert_eq!(
        body.error,
        Oauth2LibError::InvalidGrant.to_string(),
        "error field must be invalid_grant"
    );
}

/// T024a — `ConnectorRefreshError::TokenRevoked` → `invalid_grant`.
#[netidmd_testkit::test(with_test_env = true)]
async fn test_refresh_connector_error_token_revoked(test_env: &AsyncTestEnvironment) {
    run_connector_error_case(test_env, ConnectorRefreshError::TokenRevoked).await;
}

/// T024b — `ConnectorRefreshError::Network` → `invalid_grant`.
#[netidmd_testkit::test(with_test_env = true)]
async fn test_refresh_connector_error_network(test_env: &AsyncTestEnvironment) {
    run_connector_error_case(
        test_env,
        ConnectorRefreshError::Network("simulated timeout".into()),
    )
    .await;
}

/// T024c — `ConnectorRefreshError::UpstreamRejected` → `invalid_grant`.
#[netidmd_testkit::test(with_test_env = true)]
async fn test_refresh_connector_error_upstream_rejected(test_env: &AsyncTestEnvironment) {
    run_connector_error_case(test_env, ConnectorRefreshError::UpstreamRejected(401)).await;
}

/// T024d — `ConnectorRefreshError::Serialization` → `invalid_grant`.
#[netidmd_testkit::test(with_test_env = true)]
async fn test_refresh_connector_error_serialization(test_env: &AsyncTestEnvironment) {
    run_connector_error_case(
        test_env,
        ConnectorRefreshError::Serialization("bad blob".into()),
    )
    .await;
}

/// T024e — `ConnectorRefreshError::Other` → `invalid_grant`.
#[netidmd_testkit::test(with_test_env = true)]
async fn test_refresh_connector_error_other(test_env: &AsyncTestEnvironment) {
    run_connector_error_case(
        test_env,
        ConnectorRefreshError::Other("unexpected error".into()),
    )
    .await;
}

// ── T025 — missing connector → invalid_grant ─────────────────────────────────

/// T025 — session references a connector UUID not registered in the registry.
///
/// The refresh endpoint must return `invalid_grant` when the registry lookup
/// fails.
#[netidmd_testkit::test(with_test_env = true)]
async fn test_refresh_connector_missing_invalid_grant(test_env: &AsyncTestEnvironment) {
    let http = http_client();
    let rsclient = &test_env.rsclient;
    let secret = setup_rs_and_user(rsclient).await;

    let puuid = person_uuid(rsclient).await;

    // Use a connector UUID that is deliberately not registered.
    let unregistered_uuid = Uuid::new_v4();

    let (atr, session_uuid) = drive_code_flow(rsclient, &http, &secret).await;
    stamp_upstream_connector(test_env, puuid, session_uuid, unregistered_uuid).await;

    let refresh_token = atr.refresh_token.expect("refresh token issued");
    let resp = do_refresh(rsclient, &http, &secret, &refresh_token).await;

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "missing connector must return 400"
    );
    let body: ErrorResponse = resp.json().await.expect("parse ErrorResponse");
    assert_eq!(
        body.error,
        Oauth2LibError::InvalidGrant.to_string(),
        "error field must be invalid_grant"
    );
}
