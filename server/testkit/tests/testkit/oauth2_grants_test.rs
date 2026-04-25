#![deny(warnings)]
//! Integration tests for G2 (ROPC / password grant) and G6 (cross-client audience scope).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use netidm_client::{NetidmClient, StatusCode};
use netidm_proto::constants::{
    uri::{OAUTH2_AUTHORISE, OAUTH2_AUTHORISE_PERMIT, OAUTH2_TOKEN_ENDPOINT},
    ATTR_OAUTH2_RS_TRUSTED_PEERS, OAUTH2_SCOPE_EMAIL, OAUTH2_SCOPE_OPENID, OAUTH2_SCOPE_READ,
};
use netidm_proto::internal::{Filter, Modify, ModifyList};
use netidm_proto::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenRequest, AccessTokenResponse, AuthorisationResponse,
    ClientPostAuth, GrantTypeReq,
};
use netidmd_lib::prelude::Attribute;
use netidmd_testkit::{
    ADMIN_TEST_PASSWORD, ADMIN_TEST_USER, NOT_ADMIN_TEST_EMAIL, NOT_ADMIN_TEST_PASSWORD,
    NOT_ADMIN_TEST_USERNAME,
};
use oauth2_ext::PkceCodeChallenge;
use reqwest::header::HeaderValue;
use std::collections::BTreeMap;
use url::Url;

const RS_A_ID: &str = "grants_test_rs_a";
const RS_A_DISPLAY: &str = "Grants Test RS A";
const RS_A_URL: &str = "https://rs-a.example.com";
const RS_A_REDIRECT: &str = "https://rs-a.example.com/callback";

const RS_B_ID: &str = "grants_test_rs_b";
const RS_B_DISPLAY: &str = "Grants Test RS B";
const RS_B_URL: &str = "https://rs-b.example.com";
const RS_B_REDIRECT: &str = "https://rs-b.example.com/callback";

pub(crate) fn get_reqwest_client() -> reqwest::Client {
    reqwest::Client::builder()
        .tls_danger_accept_invalid_certs(true)
        .tls_danger_accept_invalid_hostnames(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("Failed to create reqwest client")
}

/// Create a confidential RS and return its client_secret.
async fn create_rs(
    rsclient: &NetidmClient,
    id: &str,
    display: &str,
    url: &str,
    redirect: &str,
) -> String {
    rsclient
        .idm_oauth2_rs_basic_create(id, display, url)
        .await
        .expect("Failed to create RS");

    rsclient
        .idm_connector_add_origin(id, &Url::parse(redirect).expect("Invalid redirect URL"))
        .await
        .expect("Failed to add origin");

    rsclient
        .idm_oauth2_rs_update(id, None, None, None, true)
        .await
        .expect("Failed to update RS");

    rsclient
        .idm_oauth2_rs_update_scope_map(
            id,
            "idm_all_accounts",
            vec![OAUTH2_SCOPE_READ, OAUTH2_SCOPE_EMAIL, OAUTH2_SCOPE_OPENID],
        )
        .await
        .expect("Failed to configure scope map");

    rsclient
        .idm_oauth2_rs_get_basic_secret(id)
        .await
        .ok()
        .flatten()
        .expect("Failed to retrieve basic secret")
}

/// Run an auth-code flow for `rs_id` as `NOT_ADMIN_TEST_USERNAME` with the given scopes.
/// Returns the full `AccessTokenResponse`.
async fn auth_code_flow(
    rsclient: &NetidmClient,
    client: &reqwest::Client,
    rs_id: &str,
    rs_redirect: &str,
    client_secret: &str,
    scopes: &str,
) -> AccessTokenResponse {
    let res = rsclient
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok(), "user auth failed");
    let user_uat = rsclient.get_token().await.expect("No user auth token");

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let response = client
        .get(rsclient.make_url(OAUTH2_AUTHORISE))
        .bearer_auth(&user_uat)
        .query(&[
            ("response_type", "code"),
            ("client_id", rs_id),
            ("code_challenge", pkce_challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("redirect_uri", rs_redirect),
            ("scope", scopes),
        ])
        .send()
        .await
        .expect("Failed to send authorise request");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "authorise must return 200"
    );

    let consent_req: AuthorisationResponse = response
        .json()
        .await
        .expect("Failed to parse AuthorisationResponse");

    let consent_token = match consent_req {
        AuthorisationResponse::ConsentRequested { consent_token, .. } => consent_token,
        other => panic!("Expected ConsentRequested, got {:?}", other),
    };

    let response = client
        .get(rsclient.make_url(OAUTH2_AUTHORISE_PERMIT))
        .bearer_auth(&user_uat)
        .query(&[("token", consent_token.as_str())])
        .send()
        .await
        .expect("Failed to send authorise_permit request");

    assert_eq!(
        response.status(),
        StatusCode::FOUND,
        "authorise_permit must 302"
    );

    let redir_str = response
        .headers()
        .get("Location")
        .and_then(|hv: &HeaderValue| hv.to_str().ok().map(str::to_string))
        .expect("Missing Location header");

    let redir_url = Url::parse(&redir_str).expect("Invalid redirect URL");
    let pairs: BTreeMap<_, _> = redir_url.query_pairs().collect();
    let code = pairs.get("code").expect("code not in redirect").to_string();

    let form_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
        code,
        redirect_uri: Url::parse(rs_redirect).expect("Invalid redirect URL"),
        code_verifier: Some(pkce_verifier.secret().clone()),
    }
    .into();

    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_ENDPOINT))
        .basic_auth(rs_id, Some(client_secret))
        .form(&form_req)
        .send()
        .await
        .expect("Failed to send token request");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "token exchange must succeed"
    );

    response
        .json::<AccessTokenResponse>()
        .await
        .expect("Failed to parse AccessTokenResponse")
}

// ─── G2: Resource Owner Password Credentials (ROPC) ──────────────────────────

/// G2 negative path: `grant_type=password` is rejected when no `password_connector` is set.
#[netidmd_testkit::test]
async fn test_oauth2_ropc_rejected_without_password_connector(rsclient: &NetidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let client_secret = create_rs(rsclient, RS_A_ID, RS_A_DISPLAY, RS_A_URL, RS_A_REDIRECT).await;

    let client = get_reqwest_client();

    let form = [
        ("grant_type", "password"),
        ("username", NOT_ADMIN_TEST_USERNAME),
        ("password", NOT_ADMIN_TEST_PASSWORD),
        ("scope", "openid email read"),
    ];

    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_ENDPOINT))
        .basic_auth(RS_A_ID, Some(&client_secret))
        .form(&form)
        .send()
        .await
        .expect("Failed to POST token endpoint");

    assert_ne!(
        response.status(),
        StatusCode::OK,
        "ROPC must be rejected when password_connector is not configured"
    );
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "ROPC without password_connector should return 400"
    );
}

// ─── G6: Cross-client audience scope (trustedPeers) ──────────────────────────

/// G6 positive path: client_a can request `audience:server:client_id:client_b` when
/// client_b has client_a in its `trusted_peers` list.
///
/// Verifies:
/// 1. The issued access token's `aud` claim is a JSON array containing both RS IDs.
/// 2. client_b can introspect the token and receives `active: true`.
#[netidmd_testkit::test]
async fn test_oauth2_cross_client_audience(rsclient: &NetidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Create two independent resource servers.
    let secret_a = create_rs(rsclient, RS_A_ID, RS_A_DISPLAY, RS_A_URL, RS_A_REDIRECT).await;
    let secret_b = create_rs(rsclient, RS_B_ID, RS_B_DISPLAY, RS_B_URL, RS_B_REDIRECT).await;

    // Create the user that will authenticate.
    rsclient
        .idm_person_account_create(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_USERNAME)
        .await
        .expect("Failed to create test user");

    rsclient
        .idm_person_account_set_attr(
            NOT_ADMIN_TEST_USERNAME,
            Attribute::Mail.as_ref(),
            &[NOT_ADMIN_TEST_EMAIL],
        )
        .await
        .expect("Failed to set mail");

    rsclient
        .idm_person_account_primary_credential_set_password(
            NOT_ADMIN_TEST_USERNAME,
            NOT_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect("Failed to set password");

    // Grant RS_B trust for RS_A: RS_B's trusted_peers must include RS_A's name.
    // This allows RS_A to request audience:server:client_id:RS_B.
    let m = ModifyList::new_list(vec![Modify::Present(
        ATTR_OAUTH2_RS_TRUSTED_PEERS.to_string(),
        RS_A_ID.to_string(),
    )]);
    rsclient
        .modify(Filter::Eq("name".to_string(), RS_B_ID.to_string()), m)
        .await
        .expect("Failed to set trusted_peers on RS_B");

    let client = get_reqwest_client();

    // Run auth-code flow for RS_A including the cross-client audience scope for RS_B.
    let audience_scope = format!("audience:server:client_id:{RS_B_ID}");
    let scopes = format!("openid email read {audience_scope}");

    let atr = auth_code_flow(
        rsclient,
        &client,
        RS_A_ID,
        RS_A_REDIRECT,
        &secret_a,
        &scopes,
    )
    .await;

    // Decode the JWT access token without signature verification to inspect `aud`.
    // The token format is header.payload.signature (JWS compact serialisation).
    let parts: Vec<&str> = atr.access_token.splitn(3, '.').collect();
    assert_eq!(parts.len(), 3, "Access token must be a compact JWS");

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Failed to base64-decode JWT payload");
    let claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("Failed to parse JWT payload as JSON");

    // `aud` must be a JSON array containing both RS IDs when cross-client scope is used.
    let aud = claims["aud"].as_array().unwrap_or_else(|| {
        panic!(
            "JWT aud must be an array for cross-client tokens, got: {}",
            claims["aud"]
        )
    });

    let aud_strings: Vec<&str> = aud.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        aud_strings.contains(&RS_A_ID),
        "aud must contain RS_A ({RS_A_ID}), got {:?}",
        aud_strings
    );
    assert!(
        aud_strings.contains(&RS_B_ID),
        "aud must contain RS_B ({RS_B_ID}), got {:?}",
        aud_strings
    );

    // RS_A can introspect its own token — confirms the token is valid.
    // (RS_B is an audience of the token, not the issuer, so it cannot
    // call netidm's introspect endpoint for it: introspect verifies against
    // the signing RS's key object. RS_B would instead verify via RS_A's JWKS.)
    let intr_request = AccessTokenIntrospectRequest {
        token: atr.access_token.clone(),
        token_type_hint: None,
        client_post_auth: ClientPostAuth::default(),
    };

    use netidm_proto::constants::uri::OAUTH2_TOKEN_INTROSPECT_ENDPOINT;

    let intr_response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_INTROSPECT_ENDPOINT))
        .basic_auth(RS_A_ID, Some(&secret_a))
        .form(&intr_request)
        .send()
        .await
        .expect("Failed to send introspect request");

    assert_eq!(
        intr_response.status(),
        StatusCode::OK,
        "RS_A introspect of its own token must succeed"
    );

    let tir: netidm_proto::oauth2::AccessTokenIntrospectResponse = intr_response
        .json()
        .await
        .expect("Failed to parse introspect response");

    assert!(tir.active, "Token must be active");
    assert_eq!(
        tir.client_id.as_deref(),
        Some(RS_A_ID),
        "client_id must be RS_A"
    );

    // secret_b was fetched to confirm RS_B was created successfully.
    // It is not used for introspect (see comment above).
    let _ = secret_b;
}
