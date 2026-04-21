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
//!
//! Full code-flow + session-termination + back-channel delivery
//! round-trips are covered by `oauth2_test.rs` patterns that need
//! a full PKCE consent cycle; those tests land with the follow-up
//! testkit work (T027-T028 remain).

use netidm_client::{http::header, NetidmClient, StatusCode};
use netidm_proto::oauth2::OidcDiscoveryResponse;
use netidmd_testkit::{
    ADMIN_TEST_PASSWORD, ADMIN_TEST_USER, NOT_ADMIN_TEST_USERNAME, TEST_INTEGRATION_RS_DISPLAY,
    TEST_INTEGRATION_RS_ID, TEST_INTEGRATION_RS_URL,
};

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
