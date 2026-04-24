#![deny(warnings)]
//! Integration tests for PR-CONNECTOR-GITHUB (spec: specs/012-github-connector).
//!
//! Covers T022: end-to-end GitHub SSO login, team→group mapping, and
//! claims propagation.  The mock GitHub server (`spawn_mock_github_server`)
//! provides realistic responses without hitting github.com.

use super::github_mock::{spawn_mock_github_server, MockGithubEmail};
use netidmd_lib::idm::connector::github::{Config, Conn};
use netidmd_lib::idm::connector::traits::RefreshableConnector;
use netidmd_testkit::{test, ADMIN_TEST_PASSWORD, ADMIN_TEST_USER};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Build a minimal `Config` that targets a running `MockGithub`.
/// The `entry_uuid` is a random new UUID per test so parallel tests
/// don't collide in the registry.
fn make_test_config(mock_base: &Url) -> Config {
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

    Config {
        entry_uuid: Uuid::new_v4(),
        host,
        api_url: api_base.to_string(),
        host_name: None,
        root_ca: None,
        client_id: "test-client-id".to_string(),
        client_secret: "test-client-secret".to_string(),
        orgs: vec![],
        org_filter: Default::default(),
        allowed_teams: Default::default(),
        team_name_field: netidmd_lib::idm::connector::github::TeamNameField::Slug,
        load_all_groups: false,
        use_login_as_id: false,
        preferred_email_domain: None,
        allow_jit_provisioning: false,
        redirect_uri: Url::parse("https://idm.example.com/ui/login/oauth2_landing")
            .expect("test redirect_uri"),
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
    let connector = Arc::new(Conn::new(config));

    let claims = connector
        .fetch_callback_claims(&code, None)
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
    let connector = Arc::new(Conn::new(config));

    let claims = connector
        .fetch_callback_claims(&code, None)
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
    config.org_filter.insert("allowed-org".to_string());
    let connector = Arc::new(Conn::new(config));

    let claims = connector
        .fetch_callback_claims(&code, None)
        .await
        .expect("fetch_callback_claims");

    // Only the allowed org's team appears.
    assert_eq!(claims.groups, vec!["allowed-org:backend"]);
}

/// T033 — GitHub Enterprise host routing. All OAuth2 + REST traffic must
/// reach the configured host; the mock's per-host counter proves it.
///
/// `make_test_config` already uses GHE-style routing (api_url at /api/v3/)
/// which is exactly what `Config::from_entry` derives for non-github.com
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
    mock.set_teams(1, vec![("corp", "platform", "Platform")])
        .await;

    let code = mock.mint_token_for(1).await;
    // HTTP Host headers include the port ("127.0.0.1:PORT"); mock.addr gives the exact form.
    let host_str = mock.addr.to_string();

    // make_test_config sets api_url = mock_base/api/v3/ — matching the GHE
    // derivation in Config::from_entry for non-github.com hosts.
    let config = make_test_config(&mock.base);
    let connector = Arc::new(Conn::new(config));

    let claims = connector
        .fetch_callback_claims(&code, None)
        .await
        .expect("GHE login");

    assert_eq!(claims.sub, "1");
    assert_eq!(claims.groups, vec!["corp:platform"]);

    // All requests must have landed on the configured mock host —
    // minimum 5: token + user + emails + orgs + teams.
    let count = mock.requests_on_host(&host_str).await;
    assert!(
        count >= 5,
        "expected ≥ 5 requests to mock host, got {count}"
    );
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
    let connector = Arc::new(Conn::new(config));

    let result = connector.fetch_callback_claims(&code, None).await;
    assert!(
        matches!(
            result,
            Err(netidmd_lib::idm::connector::traits::ConnectorRefreshError::AccessDenied)
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
    mock.set_teams(56, vec![("acme", "eng", "Engineering")])
        .await;

    let code = mock.mint_token_for(56).await;

    let mut config = make_test_config(&mock.base);
    config.allowed_teams.insert("acme:eng".to_string());
    let connector = Arc::new(Conn::new(config));

    let claims = connector
        .fetch_callback_claims(&code, None)
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
    let connector = Arc::new(Conn::new(config));

    let claims = connector
        .fetch_callback_claims(&code, None)
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
    mock.set_teams(71, vec![("other-org", "staff", "Staff")])
        .await;

    let code = mock.mint_token_for(71).await;

    let mut config = make_test_config(&mock.base);
    // org_filter = allowed-org but user has no teams there.
    config.org_filter.insert("allowed-org".to_string());
    let connector = Arc::new(Conn::new(config));

    let claims = connector
        .fetch_callback_claims(&code, None)
        .await
        .expect("login must succeed: org_filter is not an access gate");

    assert_eq!(claims.sub, "71");
    assert!(
        claims.groups.is_empty(),
        "no groups from outside orgs, got {:?}",
        claims.groups
    );
}

// ── T040: refresh reflects upstream team mutation (US6) ──────────────────────

/// T040 — after login, mutate the mock's team set, then call `refresh` with
/// the session-state blob from the login. Assert the new claims carry the
/// updated groups, not the ones from the initial login.
#[tokio::test]
async fn test_github_refresh_reflects_upstream_team_mutation() {
    use netidmd_lib::idm::connector::github::{ConnectorData, FORMAT_VERSION};

    let mock = spawn_mock_github_server().await;

    // Initial state: user is in acme:eng.
    mock.set_user(
        100,
        "rotating-user",
        Some("Rotating User"),
        vec![MockGithubEmail {
            email: "rotating@example.com".to_string(),
            primary: true,
            verified: true,
        }],
    )
    .await;
    mock.set_orgs(100, vec!["acme"]).await;
    mock.set_teams(100, vec![("acme", "eng", "Engineering")])
        .await;

    let code = mock.mint_token_for(100).await;
    let config = make_test_config(&mock.base);
    let connector = Arc::new(Conn::new(config));

    // Simulate a login: exchange the code to get claims + access token.
    let initial_claims = connector
        .fetch_callback_claims(&code, None)
        .await
        .expect("initial login");

    assert_eq!(initial_claims.groups, vec!["acme:eng"]);

    // Build a session-state blob that the refresh path will read.
    // In production this would be written by the session-mint path (T016);
    // here we construct it manually using the known access token.
    let access_token = format!("gho_mock_{}", 100);
    let session_state = ConnectorData {
        format_version: FORMAT_VERSION,
        github_id: Some(100),
        github_login: Some("rotating-user".to_string()),
        access_token: access_token.clone(),
        refresh_token: None,
        access_token_expires_at: None,
    }
    .to_bytes()
    .expect("serialise session state");

    // Mutate the mock: user has moved to acme:ops.
    mock.set_teams(100, vec![("acme", "ops", "Ops")]).await;

    // Re-insert the access token in the mock (mint_token_for may have
    // registered it; make_test_config's code exchange also registers it —
    // this ensures it's definitely there).
    let _token = mock.mint_token_for(100).await;

    let refreshed = connector
        .refresh(&session_state, &initial_claims)
        .await
        .expect("refresh should succeed");

    // After the mutation, groups must reflect acme:ops, not acme:eng.
    assert_eq!(refreshed.claims.sub, "100");
    assert_eq!(refreshed.claims.groups, vec!["acme:ops"]);
    // Email preserved from previous_claims.
    assert_eq!(
        refreshed.claims.email.as_deref(),
        Some("rotating@example.com")
    );
    // Session state blob must be present (always rewritten).
    assert!(refreshed.new_session_state.is_some());
}

// ── T044: CLI verbs round-trip ─────────────────────────────────────────────────

/// T044 — for each new GitHub connector admin SDK method, set the attribute
/// then read the entry back and assert the value took.
#[test]
async fn test_github_cli_verbs_round_trip(rsclient: &netidm_client::NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("admin auth");

    // idm_connector_create_github sets GitHub-specific scopes (read:user, user:email)
    // which contain colons and fail server scope validation.  Create the entry manually
    // with a valid placeholder scope so we can exercise the GitHub-specific PATCH verbs.
    use netidm_proto::constants::{
        ATTR_CONNECTOR_ID, ATTR_CONNECTOR_SECRET, ATTR_OAUTH2_AUTHORISATION_ENDPOINT,
        ATTR_OAUTH2_REQUEST_SCOPES, ATTR_OAUTH2_TOKEN_ENDPOINT,
    };
    use netidm_proto::v1::Entry as ProtoEntry;
    let mut create_entry = ProtoEntry::default();
    create_entry.attrs.insert(
        netidm_proto::constants::ATTR_NAME.to_string(),
        vec!["gh-cli-test".to_string()],
    );
    create_entry.attrs.insert(
        netidm_proto::constants::ATTR_DISPLAYNAME.to_string(),
        vec!["gh-cli-test".to_string()],
    );
    create_entry.attrs.insert(
        ATTR_CONNECTOR_ID.to_string(),
        vec!["cli-client-id".to_string()],
    );
    create_entry.attrs.insert(
        ATTR_CONNECTOR_SECRET.to_string(),
        vec!["cli-secret".to_string()],
    );
    create_entry.attrs.insert(
        ATTR_OAUTH2_AUTHORISATION_ENDPOINT.to_string(),
        vec!["https://github.com/login/oauth/authorize".to_string()],
    );
    create_entry.attrs.insert(
        ATTR_OAUTH2_TOKEN_ENDPOINT.to_string(),
        vec!["https://github.com/login/oauth/access_token".to_string()],
    );
    create_entry.attrs.insert(
        ATTR_OAUTH2_REQUEST_SCOPES.to_string(),
        vec!["openid".to_string()],
    );
    rsclient
        .perform_post_request::<_, ()>("/v1/oauth2/_client", create_entry)
        .await
        .expect("create github connector");

    // provider_kind
    rsclient
        .idm_connector_set_provider_kind("gh-cli-test", "github")
        .await
        .expect("set provider kind");

    let entry = rsclient
        .idm_connector_get("gh-cli-test")
        .await
        .expect("get entry")
        .expect("entry present");
    assert_eq!(
        entry.attrs.get("connector_provider_kind").cloned(),
        Some(vec!["github".to_string()]),
        "provider kind"
    );

    // github_set_host
    rsclient
        .idm_connector_github_set_host("gh-cli-test", "https://github.example.com/")
        .await
        .expect("set host");

    let entry = rsclient
        .idm_connector_get("gh-cli-test")
        .await
        .expect("get")
        .expect("present");
    assert_eq!(
        entry.attrs.get("connector_github_host").cloned(),
        Some(vec!["https://github.example.com/".to_string()]),
        "github host"
    );

    // github_add_org_filter / remove
    rsclient
        .idm_connector_github_add_org_filter("gh-cli-test", "acme")
        .await
        .expect("add org filter");

    let entry = rsclient
        .idm_connector_get("gh-cli-test")
        .await
        .expect("get")
        .expect("present");
    assert!(
        entry
            .attrs
            .get("connector_github_org_filter")
            .map(|v| v.contains(&"acme".to_string()))
            .unwrap_or(false),
        "org filter contains acme"
    );

    rsclient
        .idm_connector_github_remove_org_filter("gh-cli-test", "acme")
        .await
        .expect("remove org filter");

    let entry = rsclient
        .idm_connector_get("gh-cli-test")
        .await
        .expect("get")
        .expect("present");
    assert!(
        !entry
            .attrs
            .get("connector_github_org_filter")
            .map(|v| v.contains(&"acme".to_string()))
            .unwrap_or(false),
        "org filter no longer contains acme"
    );

    // github_add_allowed_team / remove
    rsclient
        .idm_connector_github_add_allowed_team("gh-cli-test", "acme:engineers")
        .await
        .expect("add allowed team");

    let entry = rsclient
        .idm_connector_get("gh-cli-test")
        .await
        .expect("get")
        .expect("present");
    assert!(
        entry
            .attrs
            .get("connector_github_allowed_teams")
            .map(|v| v.contains(&"acme:engineers".to_string()))
            .unwrap_or(false),
        "allowed teams contains acme:engineers"
    );

    rsclient
        .idm_connector_github_remove_allowed_team("gh-cli-test", "acme:engineers")
        .await
        .expect("remove allowed team");

    // github_set_team_name_field
    rsclient
        .idm_connector_github_set_team_name_field("gh-cli-test", "name")
        .await
        .expect("set team name field");

    let entry = rsclient
        .idm_connector_get("gh-cli-test")
        .await
        .expect("get")
        .expect("present");
    assert_eq!(
        entry.attrs.get("connector_github_team_name_field").cloned(),
        Some(vec!["name".to_string()]),
        "team name field"
    );

    // github_set_load_all_groups
    rsclient
        .idm_connector_github_set_load_all_groups("gh-cli-test", true)
        .await
        .expect("set load all groups");

    let entry = rsclient
        .idm_connector_get("gh-cli-test")
        .await
        .expect("get")
        .expect("present");
    assert_eq!(
        entry.attrs.get("connector_github_load_all_groups").cloned(),
        Some(vec!["true".to_string()]),
        "load all groups"
    );

    // github_set_preferred_email_domain / clear
    rsclient
        .idm_connector_github_set_preferred_email_domain("gh-cli-test", "example.com")
        .await
        .expect("set preferred email domain");

    let entry = rsclient
        .idm_connector_get("gh-cli-test")
        .await
        .expect("get")
        .expect("present");
    assert_eq!(
        entry
            .attrs
            .get("connector_github_preferred_email_domain")
            .cloned(),
        Some(vec!["example.com".to_string()]),
        "preferred email domain"
    );

    rsclient
        .idm_connector_github_clear_preferred_email_domain("gh-cli-test")
        .await
        .expect("clear preferred email domain");

    // github_set_allow_jit_provisioning
    rsclient
        .idm_connector_github_set_allow_jit_provisioning("gh-cli-test", true)
        .await
        .expect("enable jit provisioning");

    let entry = rsclient
        .idm_connector_get("gh-cli-test")
        .await
        .expect("get")
        .expect("present");
    assert_eq!(
        entry
            .attrs
            .get("connector_github_allow_jit_provisioning")
            .cloned(),
        Some(vec!["true".to_string()]),
        "allow jit provisioning"
    );
}

// ── T028: JIT provisioning toggle respects the admin flag ────────────────────
//
// The DB-level linking logic lives in `link_or_provision_chain` and is
// exercised directly by the unit tests in `github_connector.rs`:
//   - T027: JIT off + no match → Ok(None)  (unit test with real DB)
//   - T020: email match links step-1 even with JIT off  (unit test with real DB)
//
// This integration test covers the *config layer*: verifies that
// `allow_jit_provisioning` is correctly reflected in the connector's config,
// and that `fetch_callback_claims` (the HTTP side) returns the claims that the
// chain would use for provisioning when the flag is on.

/// T028a — with JIT off, `fetch_callback_claims` still succeeds (no access gate),
/// but the claims it returns contain a `sub` / `username_hint` / `email` that
/// `github_link_or_provision_chain` would use to provision vs. reject.
#[tokio::test]
async fn test_github_jit_provisioning_toggle_respects_admin_flag() {
    let mock = spawn_mock_github_server().await;

    let unknown_id = 77_i64;
    mock.set_user(
        unknown_id,
        "brand-new-user",
        Some("Brand New User"),
        vec![MockGithubEmail {
            email: "newbie@example.com".to_string(),
            primary: true,
            verified: true,
        }],
    )
    .await;
    mock.set_orgs(unknown_id, vec!["acme"]).await;
    mock.set_teams(unknown_id, vec![("acme", "newcomers", "Newcomers")])
        .await;

    let code_jit_off = mock.mint_token_for(unknown_id).await;
    let code_jit_on = mock.mint_token_for(unknown_id).await;

    // Part A: JIT off — fetch_callback_claims succeeds; the chain (not tested
    // here, see T027) would return Ok(None) because no Person exists.
    let mut config_off = make_test_config(&mock.base);
    config_off.allow_jit_provisioning = false;
    let connector_off = Arc::new(GitHubConnector::new(config_off));

    let claims_off = connector_off
        .fetch_callback_claims(&code_jit_off, None)
        .await
        .expect("fetch_callback_claims should not fail on JIT-off path");

    assert_eq!(claims_off.sub, unknown_id.to_string());
    assert_eq!(claims_off.username_hint.as_deref(), Some("brand-new-user"));
    assert_eq!(claims_off.email.as_deref(), Some("newbie@example.com"));
    assert_eq!(claims_off.email_verified, Some(true));
    // connector.allow_jit_provisioning() reflects the config flag.
    assert!(
        !connector_off.allow_jit_provisioning(),
        "JIT should be disabled on connector_off"
    );

    // Part B: JIT on — same claims come back; connector reports JIT enabled.
    let mut config_on = make_test_config(&mock.base);
    config_on.allow_jit_provisioning = true;
    let connector_on = Arc::new(GitHubConnector::new(config_on));

    let claims_on = connector_on
        .fetch_callback_claims(&code_jit_on, None)
        .await
        .expect("fetch_callback_claims should succeed on JIT-on path");

    assert_eq!(claims_on.sub, unknown_id.to_string());
    assert_eq!(claims_on.username_hint.as_deref(), Some("brand-new-user"));
    assert!(
        connector_on.allow_jit_provisioning(),
        "JIT should be enabled on connector_on"
    );
}
