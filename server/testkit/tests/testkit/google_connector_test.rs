#![deny(warnings)]
//! Integration tests for PR-CONNECTOR-GOOGLE (spec: specs/014-google-connector).
//!
//! Covers: HD restriction, groups via Directory API, refresh token rotation.
//! The mock Google server (`spawn_mock_google_server`) provides realistic
//! responses without hitting Google APIs.

use super::google_mock::{spawn_mock_google_server, MockGoogleUser};
use base64::{engine::general_purpose, Engine as _};
use compact_jwt::crypto::JwsRs256Signer;
use netidmd_lib::idm::connector::google::{GoogleConfig, GoogleConnector, ServiceAccountKey};
use netidmd_lib::idm::connector::traits::RefreshableConnector;
use url::Url;
use uuid::Uuid;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Generate a realistic service-account JSON string with a freshly-generated
/// RSA private key. The mock server never verifies the JWT signature, so this
/// key is only needed so that `JwsRs256Signer::from_rs256_der` inside the
/// connector doesn't fail at key-load time.
fn make_test_sa_json() -> String {
    #[allow(clippy::expect_used)]
    let signer = JwsRs256Signer::generate_rs256().expect("generate RS256 key");
    #[allow(clippy::expect_used)]
    let der = signer.private_key_to_der().expect("export DER");
    let b64 = general_purpose::STANDARD.encode(&*der);
    // Wrap in standard PEM format (PKCS8 header).
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        b64.chars()
            .collect::<Vec<_>>()
            .chunks(64)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    );
    format!(
        r#"{{"type":"service_account","client_email":"sa@test-project.iam.gserviceaccount.com","private_key":{}}}"#,
        serde_json::to_string(&pem).unwrap()
    )
}

fn make_test_config(mock: &super::google_mock::MockGoogle) -> GoogleConfig {
    let token_endpoint = format!("{}token", mock.base_url);
    let userinfo_endpoint = format!("{}userinfo", mock.base_url);
    let directory_api = format!("{}directory/groups", mock.base_url);

    #[allow(clippy::expect_used)]
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("netidm/test (connector-google)")
        .build()
        .expect("reqwest client");

    GoogleConfig {
        entry_uuid: Uuid::new_v4(),
        hosted_domain: None,
        service_account: None,
        admin_email: None,
        fetch_groups: false,
        client_id: "test-client-id".to_string(),
        client_secret: "test-client-secret".to_string(),
        redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
            .expect("test redirect_uri"),
        allow_jit_provisioning: false,
        http,
        // Override the hardcoded endpoints by storing them in fields we'll
        // check in the override below — but GoogleConnector uses compile-time
        // constants.  Instead, we use the override-able config approach via
        // special fields that point to the mock URLs.
        token_endpoint_override: Some(token_endpoint),
        userinfo_endpoint_override: Some(userinfo_endpoint),
        directory_api_override: Some(directory_api),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Basic callback: no HD restriction, no groups — returns sub, email, name.
#[tokio::test]
async fn test_google_fetch_callback_basic() {
    let mock = spawn_mock_google_server().await;
    mock.set_user(MockGoogleUser {
        sub: "google-uid-001".to_string(),
        email: "alice@gmail.com".to_string(),
        email_verified: true,
        name: "Alice Smith".to_string(),
        hosted_domain: None,
    })
    .await;

    let config = make_test_config(&mock);
    let connector = GoogleConnector::new(config);

    let claims = connector
        .fetch_callback_claims("mock-auth-code", None)
        .await
        .expect("fetch_callback_claims failed");

    assert_eq!(claims.sub, "google-uid-001");
    assert_eq!(claims.email.as_deref(), Some("alice@gmail.com"));
    assert_eq!(claims.display_name.as_deref(), Some("Alice Smith"));
    assert!(claims.groups.is_empty());
}

/// HD allow: configured domain matches `hd` claim → success.
#[tokio::test]
async fn test_google_fetch_callback_hd_allow() {
    let mock = spawn_mock_google_server().await;
    mock.set_user(MockGoogleUser {
        sub: "google-uid-002".to_string(),
        email: "bob@acme.com".to_string(),
        email_verified: true,
        name: "Bob Jones".to_string(),
        hosted_domain: Some("acme.com".to_string()),
    })
    .await;

    let mut config = make_test_config(&mock);
    config.hosted_domain = Some("acme.com".to_string());
    let connector = GoogleConnector::new(config);

    let claims = connector
        .fetch_callback_claims("mock-auth-code", None)
        .await
        .expect("fetch_callback_claims failed with matching HD");

    assert_eq!(claims.sub, "google-uid-002");
}

/// HD deny: configured domain does NOT match `hd` claim → AccessDenied.
#[tokio::test]
async fn test_google_fetch_callback_hd_deny() {
    let mock = spawn_mock_google_server().await;
    mock.set_user(MockGoogleUser {
        sub: "google-uid-003".to_string(),
        email: "charlie@other.com".to_string(),
        email_verified: true,
        name: "Charlie Brown".to_string(),
        hosted_domain: Some("other.com".to_string()),
    })
    .await;

    let mut config = make_test_config(&mock);
    config.hosted_domain = Some("acme.com".to_string());
    let connector = GoogleConnector::new(config);

    let result = connector
        .fetch_callback_claims("mock-auth-code", None)
        .await;

    assert!(
        matches!(
            result,
            Err(netidmd_lib::idm::connector::traits::ConnectorRefreshError::AccessDenied)
        ),
        "expected AccessDenied, got {result:?}"
    );
}

/// HD deny: HD is required but token has no `hd` claim.
#[tokio::test]
async fn test_google_fetch_callback_no_hd_claim() {
    let mock = spawn_mock_google_server().await;
    mock.set_user(MockGoogleUser {
        sub: "google-uid-004".to_string(),
        email: "dave@gmail.com".to_string(),
        email_verified: true,
        name: "Dave".to_string(),
        hosted_domain: None, // no hd claim
    })
    .await;

    let mut config = make_test_config(&mock);
    config.hosted_domain = Some("acme.com".to_string());
    let connector = GoogleConnector::new(config);

    let result = connector
        .fetch_callback_claims("mock-auth-code", None)
        .await;

    assert!(
        matches!(
            result,
            Err(netidmd_lib::idm::connector::traits::ConnectorRefreshError::AccessDenied)
        ),
        "expected AccessDenied for missing hd claim, got {result:?}"
    );
}

/// Groups: fetch_groups=true with service account → groups appear in claims.
#[tokio::test]
async fn test_google_fetch_callback_groups() {
    let mock = spawn_mock_google_server().await;
    mock.set_user(MockGoogleUser {
        sub: "google-uid-005".to_string(),
        email: "eve@acme.com".to_string(),
        email_verified: true,
        name: "Eve".to_string(),
        hosted_domain: Some("acme.com".to_string()),
    })
    .await;
    mock.set_groups(vec![
        "engineering@acme.com".to_string(),
        "all-staff@acme.com".to_string(),
    ])
    .await;

    let sa_json = make_test_sa_json();
    #[allow(clippy::expect_used)]
    let sa_key: ServiceAccountKey = serde_json::from_str(&sa_json).expect("parse SA JSON");

    let mut config = make_test_config(&mock);
    config.hosted_domain = Some("acme.com".to_string());
    config.service_account = Some(sa_key);
    config.admin_email = Some("admin@acme.com".to_string());
    config.fetch_groups = true;
    let connector = GoogleConnector::new(config);

    let claims = connector
        .fetch_callback_claims("mock-auth-code", None)
        .await
        .expect("fetch_callback_claims failed");

    assert!(claims.groups.contains(&"engineering@acme.com".to_string()));
    assert!(claims.groups.contains(&"all-staff@acme.com".to_string()));
}

/// Refresh: valid refresh_token → Updated outcome with rotated session state.
#[tokio::test]
async fn test_google_refresh_rotates_token() {
    let mock = spawn_mock_google_server().await;
    mock.set_user(MockGoogleUser {
        sub: "google-uid-006".to_string(),
        email: "frank@gmail.com".to_string(),
        email_verified: true,
        name: "Frank".to_string(),
        hosted_domain: None,
    })
    .await;

    let config = make_test_config(&mock);
    let connector = GoogleConnector::new(config);

    // First get claims so we have a "previous" sub.
    let initial_claims = connector
        .fetch_callback_claims("mock-auth-code", None)
        .await
        .expect("initial fetch failed");

    // Build a valid session state with the mock refresh token.
    let session_state = netidmd_lib::idm::connector::google::GoogleSessionState {
        format_version: netidmd_lib::idm::connector::google::GOOGLE_SESSION_STATE_FORMAT_VERSION,
        refresh_token: Some("mock-refresh-token".to_string()),
    };
    #[allow(clippy::expect_used)]
    let state_bytes = session_state.to_bytes().expect("serialise state");

    let outcome = connector
        .refresh(&state_bytes, &initial_claims)
        .await
        .expect("refresh failed");

    assert_eq!(outcome.claims.sub, "google-uid-006");
    assert!(outcome.new_session_state.is_some());
}
