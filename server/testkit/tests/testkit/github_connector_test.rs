#![deny(warnings)]
//! Integration tests for PR-CONNECTOR-GITHUB (spec: specs/012-github-connector).
//!
//! Covers T022: end-to-end GitHub SSO login, team→group mapping, and
//! claims propagation.  The mock GitHub server (`spawn_mock_github_server`)
//! provides realistic responses without hitting github.com.

use super::github_mock::{spawn_mock_github_server, MockGithubEmail};
use netidmd_lib::idm::github_connector::{GitHubConfig, GitHubConnector};
use netidmd_lib::idm::oauth2_connector::RefreshableConnector;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Build a minimal `GitHubConfig` that targets a running `MockGithub`.
/// The `entry_uuid` is a random new UUID per test so parallel tests
/// don't collide in the registry.
fn make_test_config(mock_base: &Url) -> GitHubConfig {
    let host = mock_base.clone();
    let mut api_base = mock_base.clone();
    api_base.set_path("/api/v3/");

    let mut default_headers = reqwest::header::HeaderMap::new();
    default_headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("application/vnd.github+json"),
    );
    default_headers.insert(
        reqwest::header::HeaderName::from_static("x-github-api-version"),
        reqwest::header::HeaderValue::from_static("2022-11-28"),
    );

    #[allow(clippy::expect_used)]
    let http = reqwest::Client::builder()
        .default_headers(default_headers)
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("netidm/test (connector-github)")
        .build()
        .expect("reqwest client");

    GitHubConfig {
        entry_uuid: Uuid::new_v4(),
        host,
        api_base,
        client_id: "test-client-id".to_string(),
        client_secret: "test-client-secret".to_string(),
        org_filter: Default::default(),
        allowed_teams: Default::default(),
        team_name_field: netidmd_lib::idm::github_connector::TeamNameField::Slug,
        load_all_groups: false,
        preferred_email_domain: None,
        allow_jit_provisioning: false,
        http,
    }
}

// ── T022: end-to-end callback claims + group mapping ─────────────────────────

/// T022 — `fetch_callback_claims` talks to the mock and assembles
/// `ExternalUserClaims` with the correct email + groups.
///
/// This test drives:
///  * T013 REST helpers (post_token, fetch_user, fetch_emails, fetch_orgs,
///    fetch_teams).
///  * T015 `render_team_names` via `team_name_field = Slug`.
///  * T021 pagination (two teams on the mock, one per page).
#[tokio::test]
async fn test_github_fetch_callback_claims_email_and_groups() {
    let mock = spawn_mock_github_server().await;

    // Register one user with verified email and two teams in two orgs.
    mock.set_user(
        42,
        "octocat",
        Some("Octo Cat"),
        vec![
            MockGithubEmail {
                email: "octocat@github.com".to_string(),
                primary: true,
                verified: true,
            },
            MockGithubEmail {
                email: "octocat@unverified.example".to_string(),
                primary: false,
                verified: false,
            },
        ],
    )
    .await;
    mock.set_orgs(42, vec!["core-org", "extra-org"]).await;
    mock.set_teams(
        42,
        vec![
            ("core-org", "eng", "Engineering"),
            ("extra-org", "ops", "Operations"),
        ],
    )
    .await;

    // Mint a code for this user.
    let code = mock.mint_token_for(42).await;

    let config = make_test_config(&mock.base);
    let connector = Arc::new(GitHubConnector::new(config));

    let claims = connector
        .fetch_callback_claims(&code)
        .await
        .expect("fetch_callback_claims");

    // Sub is the stable numeric GitHub ID.
    assert_eq!(claims.sub, "42");
    // Primary+verified email chosen.
    assert_eq!(claims.email.as_deref(), Some("octocat@github.com"));
    assert_eq!(claims.email_verified, Some(true));
    // Display name from /user.
    assert_eq!(claims.display_name.as_deref(), Some("Octo Cat"));
    // Login as username_hint.
    assert_eq!(claims.username_hint.as_deref(), Some("octocat"));

    // Groups are rendered as slug form (the default team_name_field).
    let mut groups = claims.groups.clone();
    groups.sort();
    assert_eq!(groups, vec!["core-org:eng", "extra-org:ops"]);
}

/// T022b — `fetch_callback_claims` with `load_all_groups = true` appends
/// bare org names alongside team slugs.
#[tokio::test]
async fn test_github_fetch_callback_claims_load_all_groups() {
    let mock = spawn_mock_github_server().await;

    mock.set_user(
        7,
        "alice",
        None,
        vec![MockGithubEmail {
            email: "alice@example.com".to_string(),
            primary: true,
            verified: true,
        }],
    )
    .await;
    mock.set_orgs(7, vec!["acme"]).await;
    mock.set_teams(
        7,
        vec![("acme", "devs", "Developers"), ("acme", "ops", "Ops")],
    )
    .await;

    let code = mock.mint_token_for(7).await;

    let mut config = make_test_config(&mock.base);
    config.load_all_groups = true;
    let connector = Arc::new(GitHubConnector::new(config));

    let claims = connector
        .fetch_callback_claims(&code)
        .await
        .expect("fetch_callback_claims");

    let mut groups = claims.groups.clone();
    groups.sort();
    // Team slugs + bare org
    assert_eq!(groups, vec!["acme", "acme:devs", "acme:ops"]);
}

/// T022c — `fetch_callback_claims` with `org_filter` only returns teams
/// from allowed orgs.
#[tokio::test]
async fn test_github_fetch_callback_claims_org_filter() {
    let mock = spawn_mock_github_server().await;

    mock.set_user(
        99,
        "bobbo",
        None,
        vec![MockGithubEmail {
            email: "bobbo@example.com".to_string(),
            primary: true,
            verified: true,
        }],
    )
    .await;
    mock.set_orgs(99, vec!["allowed-org", "other-org"]).await;
    mock.set_teams(
        99,
        vec![
            ("allowed-org", "backend", "Backend"),
            ("other-org", "frontend", "Frontend"),
        ],
    )
    .await;

    let code = mock.mint_token_for(99).await;

    let mut config = make_test_config(&mock.base);
    config
        .org_filter
        .insert("allowed-org".to_string());
    let connector = Arc::new(GitHubConnector::new(config));

    let claims = connector
        .fetch_callback_claims(&code)
        .await
        .expect("fetch_callback_claims");

    // Only the allowed org's team appears.
    assert_eq!(claims.groups, vec!["allowed-org:backend"]);
}

/// T033 — GitHub Enterprise host routing. All OAuth2 + REST traffic must
/// reach the configured host; the mock's per-host counter proves it.
///
/// `make_test_config` already uses GHE-style routing (api_base at /api/v3/)
/// which is exactly what `GitHubConfig::from_entry` derives for non-github.com
/// hosts. The mock mounts REST routes under both `/api/v3` and bare paths,
/// so this exercises the GHE code path end-to-end.
#[tokio::test]
async fn test_github_enterprise_host_routing() {
    let mock = spawn_mock_github_server().await;

    mock.set_user(
        1,
        "ghe-user",
        Some("GHE User"),
        vec![MockGithubEmail {
            email: "ghe@corp.example".to_string(),
            primary: true,
            verified: true,
        }],
    )
    .await;
    mock.set_orgs(1, vec!["corp"]).await;
    mock.set_teams(1, vec![("corp", "platform", "Platform")]).await;

    let code = mock.mint_token_for(1).await;
    // HTTP Host headers include the port ("127.0.0.1:PORT"); mock.addr gives the exact form.
    let host_str = mock.addr.to_string();

    // make_test_config sets api_base = mock_base/api/v3/ — matching the GHE
    // derivation in GitHubConfig::from_entry for non-github.com hosts.
    let config = make_test_config(&mock.base);
    let connector = Arc::new(GitHubConnector::new(config));

    let claims = connector
        .fetch_callback_claims(&code)
        .await
        .expect("GHE login");

    assert_eq!(claims.sub, "1");
    assert_eq!(claims.groups, vec!["corp:platform"]);

    // All requests must have landed on the configured mock host —
    // minimum 5: token + user + emails + orgs + teams.
    let count = mock.requests_on_host(&host_str).await;
    assert!(count >= 5, "expected ≥ 5 requests to mock host, got {count}");
}

// ── T022d: full end-to-end SSO login flow (Phase 4, expanded in T014) ────────
// TODO(T014): expand to full netidm server integration test once the
// 4-step linking chain is implemented. The connector-level tests above
// validate claims assembly; person linking and session minting are T014/T016.

// ── T025: team-based access gate (US2) ───────────────────────────────────────

/// T025a — `fetch_callback_claims` returns `AccessDenied` when the user's
/// teams don't intersect `allowed_teams`.
#[tokio::test]
async fn test_github_login_rejected_by_team_access_gate() {
    let mock = spawn_mock_github_server().await;

    mock.set_user(
        55,
        "denied-user",
        None,
        vec![MockGithubEmail {
            email: "denied@example.com".to_string(),
            primary: true,
            verified: true,
        }],
    )
    .await;
    mock.set_orgs(55, vec!["acme"]).await;
    mock.set_teams(55, vec![("acme", "ops", "Ops")]).await;

    let code = mock.mint_token_for(55).await;

    let mut config = make_test_config(&mock.base);
    // Only acme:eng is allowed; user is in acme:ops → denied.
    config.allowed_teams.insert("acme:eng".to_string());
    let connector = Arc::new(GitHubConnector::new(config));

    let result = connector.fetch_callback_claims(&code).await;
    assert!(
        matches!(
            result,
            Err(netidmd_lib::idm::oauth2_connector::ConnectorRefreshError::AccessDenied)
        ),
        "expected AccessDenied, got {result:?}"
    );
}

/// T025b — after adding the user to an allowed team the same connector
/// config (updated in-place) succeeds.
#[tokio::test]
async fn test_github_login_allowed_after_adding_to_allowed_team() {
    let mock = spawn_mock_github_server().await;

    mock.set_user(
        56,
        "future-member",
        None,
        vec![MockGithubEmail {
            email: "future@example.com".to_string(),
            primary: true,
            verified: true,
        }],
    )
    .await;
    mock.set_orgs(56, vec!["acme"]).await;
    // User is now in acme:eng — should pass.
    mock.set_teams(56, vec![("acme", "eng", "Engineering")]).await;

    let code = mock.mint_token_for(56).await;

    let mut config = make_test_config(&mock.base);
    config.allowed_teams.insert("acme:eng".to_string());
    let connector = Arc::new(GitHubConnector::new(config));

    let claims = connector
        .fetch_callback_claims(&code)
        .await
        .expect("fetch_callback_claims should succeed for allowed team");

    assert_eq!(claims.email.as_deref(), Some("future@example.com"));
    assert_eq!(claims.groups, vec!["acme:eng"]);
}

// ── T031: org_filter narrows groups without rejecting login (US4 / FR-005) ────

/// T031a — user in multiple orgs with org_filter set to one org: only that
/// org's teams appear in claims.groups; login succeeds.
#[tokio::test]
async fn test_github_org_filter_narrows_group_mapping_without_rejecting_login() {
    let mock = spawn_mock_github_server().await;

    mock.set_user(
        70,
        "multi-org-user",
        None,
        vec![MockGithubEmail {
            email: "multi@example.com".to_string(),
            primary: true,
            verified: true,
        }],
    )
    .await;
    mock.set_orgs(70, vec!["allowed-org", "other-org"]).await;
    mock.set_teams(
        70,
        vec![
            ("allowed-org", "backend", "Backend"),
            ("other-org", "frontend", "Frontend"),
        ],
    )
    .await;

    let code = mock.mint_token_for(70).await;

    let mut config = make_test_config(&mock.base);
    config.org_filter.insert("allowed-org".to_string());
    let connector = Arc::new(GitHubConnector::new(config));

    let claims = connector
        .fetch_callback_claims(&code)
        .await
        .expect("login must succeed even with org_filter");

    // FR-005: org_filter is NOT an access gate — login succeeds.
    assert_eq!(claims.sub, "70");
    // Only the allowed-org team appears in groups.
    assert_eq!(claims.groups, vec!["allowed-org:backend"]);
}

/// T031b — user with NO teams in the filtered org: login still succeeds with
/// an empty group list (org_filter ≠ access gate per FR-005).
#[tokio::test]
async fn test_github_org_filter_empty_match_login_succeeds_no_groups() {
    let mock = spawn_mock_github_server().await;

    mock.set_user(
        71,
        "outside-org-user",
        None,
        vec![MockGithubEmail {
            email: "outside@example.com".to_string(),
            primary: true,
            verified: true,
        }],
    )
    .await;
    mock.set_orgs(71, vec!["other-org"]).await;
    mock.set_teams(71, vec![("other-org", "staff", "Staff")]).await;

    let code = mock.mint_token_for(71).await;

    let mut config = make_test_config(&mock.base);
    // org_filter = allowed-org but user has no teams there.
    config.org_filter.insert("allowed-org".to_string());
    let connector = Arc::new(GitHubConnector::new(config));

    let claims = connector
        .fetch_callback_claims(&code)
        .await
        .expect("login must succeed: org_filter is not an access gate");

    assert_eq!(claims.sub, "71");
    assert!(
        claims.groups.is_empty(),
        "no groups from outside orgs, got {:?}",
        claims.groups
    );
}
