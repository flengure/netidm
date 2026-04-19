#![deny(warnings)]
//! Integration tests for the OIDC upstream provider creation via discovery URL (US1).
//!
//! These tests spin up a tiny in-process axum HTTP server to serve mock discovery documents,
//! then exercise `idm_oauth2_client_create_oidc` against a real netidmd instance.

use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};

use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use url::Url;

use netidmd_testkit::{test, ADMIN_TEST_PASSWORD, ADMIN_TEST_USER};

/// Bind a listener on a random port and return it together with its base URL.
async fn bind_random() -> (tokio::net::TcpListener, Url) {
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
            .await
            .expect("Failed to bind mock server");
    let port = listener.local_addr().expect("no local addr").port();
    let url = Url::parse(&format!("http://127.0.0.1:{port}")).expect("invalid URL");
    (listener, url)
}

/// Serve `doc` forever from `listener` as the OIDC discovery endpoint.
fn serve_discovery(
    listener: tokio::net::TcpListener,
    doc: serde_json::Value,
) -> tokio::task::JoinHandle<()> {
    let app = Router::new().route(
        "/.well-known/openid-configuration",
        get(move || {
            let body = doc.clone();
            async move { Json(body).into_response() }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Mock discovery server error");
    })
}

/// Serve HTTP 404 for all requests.
fn serve_404(listener: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
    let app = Router::new().route(
        "/.well-known/openid-configuration",
        get(|| async { (StatusCode::NOT_FOUND, "Not Found").into_response() }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Mock 404 server error");
    })
}

/// (a) Valid discovery document → provider entry is created with the correct fields.
#[test]
async fn tk_test_idm_oauth2_client_create_oidc_success(rsclient: &netidm_client::NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin");

    let (listener, base) = bind_random().await;
    let doc = json!({
        "issuer": base.as_str().trim_end_matches('/'),
        "authorization_endpoint": format!("{base}oauth2/authorize"),
        "token_endpoint": format!("{base}oauth2/token"),
        "userinfo_endpoint": format!("{base}oauth2/userinfo"),
        "jwks_uri": format!("{base}.well-known/jwks.json"),
    });
    let _srv = serve_discovery(listener, doc);

    rsclient
        .idm_oauth2_client_create_oidc("test-oidc-ok", &base, "test-client-id", "test-secret")
        .await
        .expect("Failed to create OIDC provider");

    let entry = rsclient
        .idm_oauth2_client_get("test-oidc-ok")
        .await
        .expect("Failed to get provider entry")
        .expect("Provider entry not found");

    assert!(
        entry.attrs.contains_key("oauth2_authorisation_endpoint"),
        "Entry missing oauth2_authorisation_endpoint"
    );
    assert!(
        entry.attrs.contains_key("oauth2_token_endpoint"),
        "Entry missing oauth2_token_endpoint"
    );
    assert!(
        entry.attrs.contains_key("oauth2_issuer"),
        "Entry missing oauth2_issuer"
    );
    assert!(
        entry.attrs.contains_key("oauth2_jwks_uri"),
        "Entry missing oauth2_jwks_uri"
    );
}

/// (b) Discovery URL returns 404 → error returned, no entry created.
#[test]
async fn tk_test_idm_oauth2_client_create_oidc_discovery_404(
    rsclient: &netidm_client::NetidmClient,
) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin");

    let (listener, base) = bind_random().await;
    let _srv = serve_404(listener);

    let result = rsclient
        .idm_oauth2_client_create_oidc("test-oidc-404", &base, "client-id", "client-secret")
        .await;

    assert!(
        result.is_err(),
        "Expected error when discovery URL returns 404, got Ok"
    );
}

/// (c) Discovery doc missing `authorization_endpoint` → error returned.
#[test]
async fn tk_test_idm_oauth2_client_create_oidc_missing_auth_endpoint(
    rsclient: &netidm_client::NetidmClient,
) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin");

    let (listener, base) = bind_random().await;
    // authorization_endpoint is intentionally absent from the document.
    let doc = json!({
        "issuer": base.as_str().trim_end_matches('/'),
        "token_endpoint": format!("{base}oauth2/token"),
    });
    let _srv = serve_discovery(listener, doc);

    let result = rsclient
        .idm_oauth2_client_create_oidc("test-oidc-no-ep", &base, "client-id", "client-secret")
        .await;

    assert!(
        result.is_err(),
        "Expected error when discovery doc is missing authorization_endpoint, got Ok"
    );
}

/// (d) Discovery doc `issuer` field does not match requested issuer → error returned.
#[test]
async fn tk_test_idm_oauth2_client_create_oidc_issuer_mismatch(
    rsclient: &netidm_client::NetidmClient,
) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin");

    let (listener, base) = bind_random().await;
    // The issuer in the doc is a different domain than `base`.
    let doc = json!({
        "issuer": "https://evil.example.com",
        "authorization_endpoint": "https://evil.example.com/oauth2/authorize",
        "token_endpoint": "https://evil.example.com/oauth2/token",
    });
    let _srv = serve_discovery(listener, doc);

    let result = rsclient
        .idm_oauth2_client_create_oidc("test-oidc-mismatch", &base, "client-id", "client-secret")
        .await;

    assert!(
        result.is_err(),
        "Expected error when discovery doc issuer does not match requested issuer, got Ok"
    );
}
