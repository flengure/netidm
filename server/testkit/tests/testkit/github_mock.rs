//! In-process mock GitHub / GitHub Enterprise server for integration tests
//! of the GitHub upstream connector (PR-CONNECTOR-GITHUB, T010).
//!
//! Stands up an `axum` server bound to a random localhost port and implements
//! the subset of GitHub's REST + OAuth2 surface the connector consumes (see
//! `specs/012-github-connector/contracts/github-api.md`):
//!
//! * `GET  /login/oauth/authorize` — user-agent redirect only; the browser
//!   follows it, the connector never hits this.
//! * `POST /login/oauth/access_token` — code exchange + refresh.
//! * `GET  /api/v3/user` — userinfo.
//! * `GET  /api/v3/user/emails` — verified-email list.
//! * `GET  /api/v3/user/orgs` — paginated.
//! * `GET  /api/v3/user/teams` — paginated.
//!
//! The `/api/v3/` prefix matches GHE behaviour; for `github.com` the connector
//! uses `https://api.github.com` so we mount both prefixes on this mock so
//! either `host` config exercises the same backing state. (The prefix is
//! stripped before dispatch so tests never need to know which one was hit.)
//!
//! Tests mutate the mock's in-memory state through the `MockGithub` mutator
//! methods (`set_user`, `set_orgs`, `set_teams`, `fail_next`). Pagination
//! kicks in once the stored list is longer than the requested `per_page`;
//! the mock emits RFC 5988 `Link: <...>; rel="next"` headers matching
//! GitHub's pattern so the connector's paginator is exercised in-band.
//!
//! Pattern precedent: `spawn_bcl_receiver` in `logout_test.rs`.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use hashbrown::HashMap;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;

/// Identifies one of the HTTP endpoints the mock serves, so tests can inject
/// a scoped failure via [`MockGithub::fail_next`]. Maps 1:1 to the HTTP route
/// set; adding a new endpoint means extending this enum AND the route set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum MockEndpoint {
    /// `POST /login/oauth/access_token` — code exchange + refresh.
    Token,
    /// `GET /user`.
    User,
    /// `GET /user/emails`.
    Emails,
    /// `GET /user/orgs`.
    Orgs,
    /// `GET /user/teams`.
    Teams,
}

/// One entry in the mock's verified-email list, matching the wire shape of
/// `GET /user/emails` so the connector's `GithubEmail` deserialises cleanly.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MockGithubEmail {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
}

/// One entry in the mock's team list. The mock expands this to
/// `{"slug": ..., "name": ..., "organization": {"login": <org>}}` at
/// response-render time; tests pass the simpler triple.
#[derive(Clone, Debug)]
pub struct MockGithubTeam {
    pub org: String,
    pub slug: String,
    pub name: String,
}

/// One registered user in the mock (keyed by GitHub numeric `id`). GitHub's
/// token endpoint hands out an access token bound to exactly one of these.
#[derive(Clone, Debug)]
struct MockUser {
    id: i64,
    login: String,
    name: Option<String>,
    emails: Vec<MockGithubEmail>,
    orgs: Vec<String>,
    teams: Vec<MockGithubTeam>,
}

impl MockUser {
    fn new(id: i64, login: &str, name: Option<String>) -> Self {
        MockUser {
            id,
            login: login.to_string(),
            name,
            emails: Vec::new(),
            orgs: Vec::new(),
            teams: Vec::new(),
        }
    }
}

/// Shared mutable state behind the Axum handlers.
#[derive(Default, Debug)]
struct State0 {
    /// GitHub numeric id -> user record.
    users: HashMap<i64, MockUser>,
    /// Mint token -> GitHub numeric id of the user it was issued for.
    tokens: HashMap<String, i64>,
    /// Single-use failure injections: the next request to the matching
    /// endpoint returns this status, then the entry is popped.
    fail_queue: HashMap<MockEndpoint, Vec<StatusCode>>,
    /// Monotonic counter so tests can assert requests happened against the
    /// configured host (useful for the GHE host-routing test, US5).
    requests_per_host: HashMap<String, u32>,
}

impl State0 {
    fn take_failure(&mut self, endpoint: MockEndpoint) -> Option<StatusCode> {
        let q = self.fail_queue.get_mut(&endpoint)?;
        let head = q.first().copied()?;
        q.remove(0);
        Some(head)
    }
}

/// Handle to a running mock server. Drop the handle to shut it down
/// (tokio-task-cancels the `axum::serve` future).
#[allow(dead_code)]
pub struct MockGithub {
    /// Base URL to point the connector's `ConnectorGithubHost` at.
    /// Mount-point-aware: REST paths live at `{base}/api/v3/...`; OAuth
    /// paths live at `{base}/login/oauth/...`. The real GitHub splits
    /// these across `github.com` and `api.github.com`, but on a single
    /// GHE host they share the same origin — we follow the GHE shape
    /// here.
    pub base: Url,
    /// The bound local address for tests that need it.
    pub addr: SocketAddr,
    state: Arc<Mutex<State0>>,
    _shutdown: tokio::task::JoinHandle<()>,
}

impl MockGithub {
    /// Register or replace a user. All REST endpoints key off `id`; the
    /// token endpoint binds an access token to this user at code-exchange
    /// time.
    pub async fn set_user(
        &self,
        id: i64,
        login: &str,
        name: Option<&str>,
        emails: Vec<MockGithubEmail>,
    ) {
        let mut st = self.state.lock().await;
        let user = st
            .users
            .entry(id)
            .or_insert_with(|| MockUser::new(id, login, name.map(str::to_string)));
        user.login = login.to_string();
        user.name = name.map(str::to_string);
        user.emails = emails;
    }

    /// Replace the user's org list.
    #[allow(dead_code)]
    pub async fn set_orgs(&self, id: i64, orgs: Vec<&str>) {
        let mut st = self.state.lock().await;
        if let Some(u) = st.users.get_mut(&id) {
            u.orgs = orgs.iter().map(|s| (*s).to_string()).collect();
        }
    }

    /// Replace the user's team list. Each entry is `(org, slug, name)`.
    #[allow(dead_code)]
    pub async fn set_teams(&self, id: i64, teams: Vec<(&str, &str, &str)>) {
        let mut st = self.state.lock().await;
        if let Some(u) = st.users.get_mut(&id) {
            u.teams = teams
                .into_iter()
                .map(|(org, slug, name)| MockGithubTeam {
                    org: org.to_string(),
                    slug: slug.to_string(),
                    name: name.to_string(),
                })
                .collect();
        }
    }

    /// Arrange for the next request to `endpoint` to return `status` instead
    /// of the normal response, exactly once. Multiple calls queue up. Maps
    /// to FR-012 error-handling coverage in the connector.
    #[allow(dead_code)]
    pub async fn fail_next(&self, endpoint: MockEndpoint, status: StatusCode) {
        let mut st = self.state.lock().await;
        st.fail_queue.entry(endpoint).or_default().push(status);
    }

    /// Total request count to this mock under the given host header. Used
    /// by the US5 (GHE host routing) test to assert zero leakage to
    /// `api.github.com` / `github.com`.
    #[allow(dead_code)]
    pub async fn requests_on_host(&self, host: &str) -> u32 {
        let st = self.state.lock().await;
        *st.requests_per_host.get(host).unwrap_or(&0)
    }

    /// Mint an access token bound to `id` and return it. Used by tests that
    /// bypass the OAuth code flow and feed the token directly to a connector
    /// helper under test.
    #[allow(dead_code)]
    pub async fn mint_token_for(&self, id: i64) -> String {
        let token = format!("gho_mock_{id}");
        let mut st = self.state.lock().await;
        st.tokens.insert(token.clone(), id);
        token
    }
}

/// Spawn a fresh mock bound to a random localhost port. The returned
/// `MockGithub` handle keeps the server alive; drop it to tear down.
#[allow(dead_code)]
pub async fn spawn_mock_github_server() -> MockGithub {
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
            .await
            .expect("bind mock github");
    let addr = listener.local_addr().expect("mock github addr");
    let base = Url::parse(&format!("http://{addr}")).expect("mock github url");

    let state: Arc<Mutex<State0>> = Arc::new(Mutex::new(State0::default()));

    // Mount the REST endpoints under BOTH `/api/v3` (GHE) and the bare path
    // (public api.github.com shape) so whichever form the connector
    // computes for `api_base` hits the same handlers.
    let rest = Router::new()
        .route("/user", get(handle_user))
        .route("/user/emails", get(handle_user_emails))
        .route("/user/orgs", get(handle_user_orgs))
        .route("/user/teams", get(handle_user_teams));

    let oauth = Router::new()
        .route("/login/oauth/authorize", get(handle_authorize))
        .route("/login/oauth/access_token", post(handle_access_token));

    let app = Router::new()
        .nest("/api/v3", rest.clone())
        .merge(rest)
        .merge(oauth)
        .with_state(state.clone());

    let shutdown = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    MockGithub {
        base,
        addr,
        state,
        _shutdown: shutdown,
    }
}

// ------------- Handlers -------------

/// `GET /login/oauth/authorize` — the browser-facing redirect target. The
/// connector itself never hits this (the user-agent does). Tests that drive
/// the full end-to-end flow through a real browser or a simulated one land
/// here and are redirected back to the netidm callback with a fixed mock
/// code and the `state` query parameter echoed.
async fn handle_authorize(Query(q): Query<AuthorizeQuery>) -> Response {
    let mut redirect = match Url::parse(&q.redirect_uri) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid redirect_uri").into_response(),
    };
    redirect
        .query_pairs_mut()
        .append_pair("code", "mock_auth_code_abc123")
        .append_pair("state", q.state.as_deref().unwrap_or(""));
    axum::response::Redirect::to(redirect.as_str()).into_response()
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    #[allow(dead_code)]
    client_id: String,
    redirect_uri: String,
    #[allow(dead_code)]
    scope: Option<String>,
    state: Option<String>,
    #[allow(dead_code)]
    response_type: Option<String>,
}

/// `POST /login/oauth/access_token` — accepts both the initial code-exchange
/// grant and the refresh grant. Returns a JSON body when `Accept:
/// application/json` was sent (matches the connector's behaviour and
/// research.md R8).
async fn handle_access_token(
    State(state): State<Arc<Mutex<State0>>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    record_host(&state, &headers).await;
    {
        let mut st = state.lock().await;
        if let Some(fail) = st.take_failure(MockEndpoint::Token) {
            return (fail, "injected failure").into_response();
        }
    }

    let want_json = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("application/json"))
        .unwrap_or(false);
    if !want_json {
        return (
            StatusCode::BAD_REQUEST,
            "mock requires Accept: application/json",
        )
            .into_response();
    }

    // Code-exchange path: bind a deterministic token to the first registered
    // user (typical test setup has exactly one). Tests with multiple mock
    // users should use `mint_token_for` instead.
    let st = state.lock().await;
    let uid = match form.grant_type.as_deref().unwrap_or("authorization_code") {
        "authorization_code" => st.users.keys().next().copied(),
        "refresh_token" => form
            .refresh_token
            .as_deref()
            .and_then(|rt| rt.strip_prefix("ghr_mock_"))
            .and_then(|rest| rest.parse::<i64>().ok()),
        _ => None,
    };
    let Some(uid) = uid else {
        return (StatusCode::BAD_REQUEST, "no mock user").into_response();
    };
    drop(st);

    let access_token = format!("gho_mock_{uid}");
    let refresh_token = format!("ghr_mock_{uid}");
    {
        let mut st = state.lock().await;
        st.tokens.insert(access_token.clone(), uid);
    }

    let body = json!({
        "access_token": access_token,
        "token_type": "bearer",
        "scope": "user:email,read:org",
        "refresh_token": refresh_token,
        "expires_in": 28800_u64,
    });
    Json(body).into_response()
}

#[derive(Deserialize)]
struct TokenForm {
    #[allow(dead_code)]
    client_id: Option<String>,
    #[allow(dead_code)]
    client_secret: Option<String>,
    #[allow(dead_code)]
    code: Option<String>,
    #[allow(dead_code)]
    redirect_uri: Option<String>,
    grant_type: Option<String>,
    refresh_token: Option<String>,
}

async fn handle_user(State(state): State<Arc<Mutex<State0>>>, headers: HeaderMap) -> Response {
    record_host(&state, &headers).await;
    let Some(uid) = token_to_uid(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, "Bad credentials").into_response();
    };

    {
        let mut st = state.lock().await;
        if let Some(fail) = st.take_failure(MockEndpoint::User) {
            return (fail, "injected failure").into_response();
        }
    }

    let st = state.lock().await;
    let Some(u) = st.users.get(&uid) else {
        return (StatusCode::NOT_FOUND, "user gone").into_response();
    };
    let body = json!({
        "id": u.id,
        "login": u.login,
        "name": u.name,
        "email": Value::Null,
    });
    Json(body).into_response()
}

async fn handle_user_emails(
    State(state): State<Arc<Mutex<State0>>>,
    headers: HeaderMap,
) -> Response {
    record_host(&state, &headers).await;
    let Some(uid) = token_to_uid(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, "Bad credentials").into_response();
    };

    {
        let mut st = state.lock().await;
        if let Some(fail) = st.take_failure(MockEndpoint::Emails) {
            return (fail, "injected failure").into_response();
        }
    }

    let st = state.lock().await;
    let body = st
        .users
        .get(&uid)
        .map(|u| u.emails.clone())
        .unwrap_or_default();
    Json(body).into_response()
}

async fn handle_user_orgs(
    State(state): State<Arc<Mutex<State0>>>,
    headers: HeaderMap,
    Query(page): Query<PageQuery>,
) -> Response {
    record_host(&state, &headers).await;
    let Some(uid) = token_to_uid(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, "Bad credentials").into_response();
    };

    {
        let mut st = state.lock().await;
        if let Some(fail) = st.take_failure(MockEndpoint::Orgs) {
            return (fail, "injected failure").into_response();
        }
    }

    let st = state.lock().await;
    let full = st
        .users
        .get(&uid)
        .map(|u| u.orgs.clone())
        .unwrap_or_default();
    let (slice, next_link) = paginate(&full, &page, "/user/orgs");
    let body: Vec<Value> = slice.iter().map(|s| json!({ "login": s })).collect();
    with_link_header(Json(body).into_response(), next_link)
}

async fn handle_user_teams(
    State(state): State<Arc<Mutex<State0>>>,
    headers: HeaderMap,
    Query(page): Query<PageQuery>,
) -> Response {
    record_host(&state, &headers).await;
    let Some(uid) = token_to_uid(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, "Bad credentials").into_response();
    };

    {
        let mut st = state.lock().await;
        if let Some(fail) = st.take_failure(MockEndpoint::Teams) {
            return (fail, "injected failure").into_response();
        }
    }

    let st = state.lock().await;
    let full = st
        .users
        .get(&uid)
        .map(|u| u.teams.clone())
        .unwrap_or_default();
    let (slice, next_link) = paginate(&full, &page, "/user/teams");
    let body: Vec<Value> = slice
        .iter()
        .map(|t| {
            json!({
                "slug": t.slug,
                "name": t.name,
                "organization": { "login": t.org },
            })
        })
        .collect();
    with_link_header(Json(body).into_response(), next_link)
}

#[derive(Deserialize, Default)]
struct PageQuery {
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_per_page")]
    per_page: usize,
}

fn default_page() -> usize {
    1
}
fn default_per_page() -> usize {
    30
}

fn paginate<T: Clone>(items: &[T], p: &PageQuery, path: &str) -> (Vec<T>, Option<String>) {
    let per = p.per_page.max(1);
    let page = p.page.max(1);
    let start = (page - 1).saturating_mul(per);
    if start >= items.len() {
        return (Vec::new(), None);
    }
    let end = items.len().min(start + per);
    let slice = items[start..end].to_vec();
    let next = if end < items.len() {
        Some(format!(
            "<{path}?page={}&per_page={per}>; rel=\"next\"",
            page + 1
        ))
    } else {
        None
    };
    (slice, next)
}

fn with_link_header(mut resp: Response, link: Option<String>) -> Response {
    if let Some(link) = link {
        if let Ok(v) = HeaderValue::from_str(&link) {
            resp.headers_mut().insert("link", v);
        }
    }
    resp
}

async fn token_to_uid(state: &Arc<Mutex<State0>>, headers: &HeaderMap) -> Option<i64> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))?;
    let st = state.lock().await;
    st.tokens.get(token).copied()
}

async fn record_host(state: &Arc<Mutex<State0>>, headers: &HeaderMap) {
    let Some(host) = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return;
    };
    let mut st = state.lock().await;
    *st.requests_per_host.entry(host).or_insert(0) += 1;
}

// ------------- Sanity test so T010 ships with live verification -------------

#[tokio::test]
async fn mock_github_server_responds_to_user() {
    let mock = spawn_mock_github_server().await;
    mock.set_user(
        42,
        "alice",
        Some("Alice"),
        vec![MockGithubEmail {
            email: "alice@example.com".into(),
            primary: true,
            verified: true,
        }],
    )
    .await;
    let token = mock.mint_token_for(42).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}api/v3/user", mock.base))
        .header("accept", "application/vnd.github+json")
        .bearer_auth(&token)
        .send()
        .await
        .expect("request /user");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["id"], 42);
    assert_eq!(body["login"], "alice");
}

// Silence the unused-import warning on a helper only a subset of the
// dispatched routes need yet.
#[allow(dead_code)]
fn _require_path_extractor(_: Path<String>) {}
