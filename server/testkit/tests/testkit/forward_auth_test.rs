//! Integration tests for the forward auth gate.
//!
//! Covers [`/oauth2/auth`], [`/oauth2/proxy/userinfo`], and [`/oauth2/sign_out`].
//! Each test spins up a real netidmd instance via the testkit framework.

use netidm_client::NetidmClient;
use netidmd_lib::prelude::Attribute;
use netidmd_testkit::{
    ADMIN_TEST_PASSWORD, ADMIN_TEST_USER, NOT_ADMIN_TEST_EMAIL, NOT_ADMIN_TEST_PASSWORD,
    NOT_ADMIN_TEST_USERNAME,
};

fn anon_client() -> reqwest::Client {
    reqwest::Client::builder()
        .tls_danger_accept_invalid_certs(true)
        .tls_danger_accept_invalid_hostnames(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("Failed to build anonymous reqwest client")
}

// ---------------------------------------------------------------------------
// /oauth2/auth — forward auth gate
// ---------------------------------------------------------------------------

/// Unauthenticated request → redirect to /ui/login.
#[netidmd_testkit::test]
async fn test_oauth2_auth_unauthenticated_redirects_to_login(rsclient: &NetidmClient) {
    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/auth"))
        .send()
        .await
        .expect("Request failed");

    assert!(
        resp.status().is_redirection(),
        "Expected a redirect, got: {}",
        resp.status()
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.contains("ui/login"),
        "Expected Location to contain ui/login, got: {location}"
    );
}

/// Unauthenticated + `Accept: application/json` → 401 JSON `{"error":"unauthenticated"}`.
#[netidmd_testkit::test]
async fn test_oauth2_auth_unauthenticated_json_accept(rsclient: &NetidmClient) {
    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/auth"))
        .header("Accept", "application/json")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status(), 401);
    assert!(
        resp.headers().get("location").is_none(),
        "JSON 401 must not include Location header"
    );
    let body: serde_json::Value = resp.json().await.expect("Response is not JSON");
    assert_eq!(body["error"], "unauthenticated");
}

/// Valid bearer token → 202 with X-Auth-Request-User + X-Auth-Request-Preferred-Username +
/// X-Forwarded-User headers present; username must be the short name (no @domain).
#[netidmd_testkit::test]
async fn test_oauth2_auth_authenticated_returns_202_with_identity_headers(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");

    let token = rsclient
        .get_token()
        .await
        .expect("No bearer token after login");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/auth"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status(), 202);

    let h = resp.headers();
    assert!(
        h.get("x-auth-request-user").is_some(),
        "Missing X-Auth-Request-User"
    );
    assert!(
        h.get("x-auth-request-preferred-username").is_some(),
        "Missing X-Auth-Request-Preferred-Username"
    );
    assert!(
        h.get("x-forwarded-user").is_some(),
        "Missing X-Forwarded-User"
    );

    let user = h["x-auth-request-user"].to_str().unwrap();
    assert!(
        !user.contains('@'),
        "X-Auth-Request-User should be short name (no @domain), got: {user}"
    );
}

/// Valid token for a user with no email → `X-Auth-Request-Email` header absent.
#[netidmd_testkit::test]
async fn test_oauth2_auth_no_email_header_absent(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");

    let username = "noemail_user";
    let password = "xai3Ohhei0aigh2ooj8a";

    rsclient
        .idm_person_account_create(username, username)
        .await
        .expect("Failed to create test account");
    rsclient
        .idm_person_account_primary_credential_set_password(username, password)
        .await
        .expect("Failed to set password");

    let user_client = rsclient
        .new_session()
        .expect("Failed to create new session");
    user_client
        .auth_simple_password(username, password)
        .await
        .expect("Test user login failed");
    let token = user_client.get_token().await.expect("No token");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/auth"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status(), 202);
    assert!(
        resp.headers().get("x-auth-request-email").is_none(),
        "X-Auth-Request-Email should be absent when user has no email"
    );
}

/// When a user is added to a group, `X-Auth-Request-Groups` includes that group's short name.
#[netidmd_testkit::test]
async fn test_oauth2_auth_groups_header_present_when_member(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");

    let username = "groups_user";
    let password = "Ahhee6phaith0Pho3pha";
    let group_name = "test_forward_auth_group";

    rsclient
        .idm_person_account_create(username, username)
        .await
        .expect("Failed to create test account");
    rsclient
        .idm_person_account_primary_credential_set_password(username, password)
        .await
        .expect("Failed to set password");
    rsclient
        .idm_group_create(group_name, None)
        .await
        .expect("Failed to create group");
    rsclient
        .idm_group_add_members(group_name, &[username])
        .await
        .expect("Failed to add user to group");

    let user_client = rsclient
        .new_session()
        .expect("Failed to create new session");
    user_client
        .auth_simple_password(username, password)
        .await
        .expect("Test user login failed");
    let token = user_client.get_token().await.expect("No token");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/auth"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status(), 202);
    let groups = resp
        .headers()
        .get("x-auth-request-groups")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        groups.contains(group_name),
        "X-Auth-Request-Groups should contain {group_name}, got: {groups}"
    );
}

// ---------------------------------------------------------------------------
// /oauth2/proxy/userinfo — identity JSON
// ---------------------------------------------------------------------------

/// Unauthenticated → 401 JSON `{"error":"unauthenticated"}`.
#[netidmd_testkit::test]
async fn test_oauth2_userinfo_unauthenticated(rsclient: &NetidmClient) {
    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/proxy/userinfo"))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.expect("Response is not JSON");
    assert_eq!(body["error"], "unauthenticated");
}

/// Authenticated user with email → 200 JSON with user, email, groups, preferred_username.
#[netidmd_testkit::test]
async fn test_oauth2_userinfo_authenticated_full_body(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");

    rsclient
        .idm_person_account_create(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_USERNAME)
        .await
        .expect("Failed to create test account");
    rsclient
        .idm_person_account_set_attr(
            NOT_ADMIN_TEST_USERNAME,
            Attribute::Mail.as_ref(),
            &[NOT_ADMIN_TEST_EMAIL],
        )
        .await
        .expect("Failed to set email");
    rsclient
        .idm_person_account_primary_credential_set_password(
            NOT_ADMIN_TEST_USERNAME,
            NOT_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect("Failed to set password");

    let user_client = rsclient
        .new_session()
        .expect("Failed to create new session");
    user_client
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
        .await
        .expect("Test user login failed");
    let token = user_client.get_token().await.expect("No token");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/proxy/userinfo"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("Response is not JSON");

    assert!(body["user"].is_string(), "Missing user field");
    assert!(
        body["preferred_username"].is_string(),
        "Missing preferred_username field"
    );
    assert!(body["groups"].is_array(), "Missing groups array");
    assert_eq!(
        body["email"].as_str(),
        Some(NOT_ADMIN_TEST_EMAIL),
        "Email mismatch"
    );
}

/// Authenticated user with no email → `email` field absent from JSON.
#[netidmd_testkit::test]
async fn test_oauth2_userinfo_no_email_field_absent(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");

    let username = "userinfo_noemail";
    let password = "Eim3aeTh0aeph1Ahku4u";

    rsclient
        .idm_person_account_create(username, username)
        .await
        .expect("Failed to create test account");
    rsclient
        .idm_person_account_primary_credential_set_password(username, password)
        .await
        .expect("Failed to set password");

    let user_client = rsclient
        .new_session()
        .expect("Failed to create new session");
    user_client
        .auth_simple_password(username, password)
        .await
        .expect("Test user login failed");
    let token = user_client.get_token().await.expect("No token");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/proxy/userinfo"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("Response is not JSON");
    assert!(
        body.get("email").is_none(),
        "email field should be absent when user has no email, got: {:?}",
        body.get("email")
    );
}

// ---------------------------------------------------------------------------
// /oauth2/sign_out — session clear + redirect
// ---------------------------------------------------------------------------

/// No active session → sign-out still succeeds, redirects to /ui/login.
#[netidmd_testkit::test]
async fn test_oauth2_sign_out_no_session_is_safe(rsclient: &NetidmClient) {
    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/sign_out"))
        .send()
        .await
        .expect("Request failed");

    assert!(
        resp.status().is_redirection(),
        "Expected redirect, got: {}",
        resp.status()
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/ui/login");
}

/// `?rd=/some/path` → redirects to that relative path.
#[netidmd_testkit::test]
async fn test_oauth2_sign_out_relative_rd_accepted(rsclient: &NetidmClient) {
    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/sign_out?rd=%2Fsome%2Fpath"))
        .send()
        .await
        .expect("Request failed");

    assert!(resp.status().is_redirection());
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/some/path");
}

/// `?rd=https://evil.example.com` → rejected, redirects to /ui/login.
#[netidmd_testkit::test]
async fn test_oauth2_sign_out_absolute_rd_rejected(rsclient: &NetidmClient) {
    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/sign_out?rd=https%3A%2F%2Fevil.example.com%2Fsteal"))
        .send()
        .await
        .expect("Request failed");

    assert!(resp.status().is_redirection());
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/ui/login", "Absolute rd must be rejected");
}

/// `?rd=//evil.example.com` → rejected, redirects to /ui/login.
#[netidmd_testkit::test]
async fn test_oauth2_sign_out_protocol_relative_rd_rejected(rsclient: &NetidmClient) {
    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/sign_out?rd=%2F%2Fevil.example.com"))
        .send()
        .await
        .expect("Request failed");

    assert!(resp.status().is_redirection());
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/ui/login",
        "Protocol-relative rd must be rejected"
    );
}

/// Valid session + sign-out → bearer cookie cleared (`Max-Age=0`).
#[netidmd_testkit::test]
async fn test_oauth2_sign_out_clears_bearer_cookie(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");
    let token = rsclient.get_token().await.expect("No bearer token");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/sign_out"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");

    assert!(resp.status().is_redirection());

    let cookies: Vec<_> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();

    let bearer_cleared = cookies
        .iter()
        .any(|c| c.starts_with("bearer=") && (c.contains("Max-Age=0") || c.contains("max-age=0")));
    assert!(
        bearer_cleared,
        "Expected bearer cookie to be cleared, Set-Cookie headers: {cookies:?}"
    );
}

// ---------------------------------------------------------------------------
// /oauth2/auth — access token passthrough
// ---------------------------------------------------------------------------

/// 202 response always includes `X-Auth-Request-Access-Token` for authenticated requests.
#[netidmd_testkit::test]
async fn test_oauth2_auth_access_token_header_present(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");
    let token = rsclient.get_token().await.expect("No bearer token");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/auth"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status(), 202);
    assert!(
        resp.headers().get("x-auth-request-access-token").is_some(),
        "X-Auth-Request-Access-Token must be present in 202 response"
    );
    // The header value must be non-empty and contain at least two dots (JWT format).
    let token_val = resp
        .headers()
        .get("x-auth-request-access-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        token_val.contains('.'),
        "X-Auth-Request-Access-Token should look like a JWT, got: {token_val}"
    );
}

// ---------------------------------------------------------------------------
// /oauth2/auth — email domain allowlist
// ---------------------------------------------------------------------------

/// Email domain matches allowlist → 202 allowed through.
#[netidmd_testkit::test(forward_auth_allowed_email_domains = vec!["example.com".to_string()])]
async fn test_oauth2_auth_email_domain_allow(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");

    let username = "email_domain_allow_user";
    let password = "ahZ8gooN5ae2sha1Ahth";
    rsclient
        .idm_person_account_create(username, username)
        .await
        .expect("Failed to create user");
    rsclient
        .idm_person_account_primary_credential_set_password(username, password)
        .await
        .expect("Failed to set password");
    rsclient
        .idm_person_account_set_attr(username, "mail", &["alice@example.com"])
        .await
        .expect("Failed to set email");

    let user_client = rsclient.new_session().expect("new_session failed");
    user_client
        .auth_simple_password(username, password)
        .await
        .expect("Login failed");
    let token = user_client.get_token().await.expect("No token");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/auth"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        202,
        "User with allowed email domain should get 202"
    );
}

/// Email domain does NOT match allowlist → 401.
#[netidmd_testkit::test(forward_auth_allowed_email_domains = vec!["allowed.com".to_string()])]
async fn test_oauth2_auth_email_domain_deny(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");

    let username = "email_domain_deny_user";
    let password = "ahZ8gooN5ae2sha1Bhth";
    rsclient
        .idm_person_account_create(username, username)
        .await
        .expect("Failed to create user");
    rsclient
        .idm_person_account_primary_credential_set_password(username, password)
        .await
        .expect("Failed to set password");
    rsclient
        .idm_person_account_set_attr(username, "mail", &["alice@wrong.com"])
        .await
        .expect("Failed to set email");

    let user_client = rsclient.new_session().expect("new_session failed");
    user_client
        .auth_simple_password(username, password)
        .await
        .expect("Login failed");
    let token = user_client.get_token().await.expect("No token");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/auth"))
        .bearer_auth(&token)
        .header("Accept", "application/json")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "User with non-allowed email domain should get 401"
    );
}

// ---------------------------------------------------------------------------
// /oauth2/auth — group allowlist
// ---------------------------------------------------------------------------

/// User is a member of an allowed group → 202.
#[netidmd_testkit::test(forward_auth_allowed_groups = vec!["gateway_allowed".to_string()])]
async fn test_oauth2_auth_group_allow(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");

    let username = "group_allow_user";
    let password = "ahZ8gooN5ae2sha1Chth";
    let group_name = "gateway_allowed";
    rsclient
        .idm_person_account_create(username, username)
        .await
        .expect("Failed to create user");
    rsclient
        .idm_person_account_primary_credential_set_password(username, password)
        .await
        .expect("Failed to set password");
    rsclient
        .idm_group_create(group_name, None)
        .await
        .expect("Failed to create group");
    rsclient
        .idm_group_add_members(group_name, &[username])
        .await
        .expect("Failed to add user to group");

    let user_client = rsclient.new_session().expect("new_session failed");
    user_client
        .auth_simple_password(username, password)
        .await
        .expect("Login failed");
    let token = user_client.get_token().await.expect("No token");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/auth"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 202, "User in allowed group should get 202");
}

/// User is NOT a member of any allowed group → 401.
#[netidmd_testkit::test(forward_auth_allowed_groups = vec!["required_group".to_string()])]
async fn test_oauth2_auth_group_deny(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");

    let username = "group_deny_user";
    let password = "ahZ8gooN5ae2sha1Dhth";
    rsclient
        .idm_person_account_create(username, username)
        .await
        .expect("Failed to create user");
    rsclient
        .idm_person_account_primary_credential_set_password(username, password)
        .await
        .expect("Failed to set password");
    // User is NOT added to "required_group"

    let user_client = rsclient.new_session().expect("new_session failed");
    user_client
        .auth_simple_password(username, password)
        .await
        .expect("Login failed");
    let token = user_client.get_token().await.expect("No token");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/auth"))
        .bearer_auth(&token)
        .header("Accept", "application/json")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "User not in any allowed group should get 401"
    );
}

// ---------------------------------------------------------------------------
// /oauth2/auth — custom header injection
// ---------------------------------------------------------------------------

/// Configured attribute injection: `displayname` value appears as a custom header.
#[netidmd_testkit::test(forward_auth_inject_request_headers = vec!["X-User-Display: displayname".to_string()])]
async fn test_oauth2_auth_inject_header_from_attr(rsclient: &NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Admin login failed");

    let username = "inject_header_user";
    let password = "ahZ8gooN5ae2sha1Ehth";
    let display_name = "Inject Test User";
    rsclient
        .idm_person_account_create(username, display_name)
        .await
        .expect("Failed to create user");
    rsclient
        .idm_person_account_primary_credential_set_password(username, password)
        .await
        .expect("Failed to set password");

    let user_client = rsclient.new_session().expect("new_session failed");
    user_client
        .auth_simple_password(username, password)
        .await
        .expect("Login failed");
    let token = user_client.get_token().await.expect("No token");

    let client = anon_client();
    let resp = client
        .get(rsclient.make_url("/oauth2/auth"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status(), 202);
    let injected = resp
        .headers()
        .get("x-user-display")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        injected, display_name,
        "Injected header X-User-Display should contain the displayname"
    );
}
