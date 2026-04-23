//! In-process mock Google server for integration tests of the Google upstream
//! connector (PR-CONNECTOR-GOOGLE, DL30).
//!
//! Stands up an `axum` server on a random localhost port and implements the
//! subset of Google's OAuth2 / userinfo / Admin SDK surface the connector
//! consumes:
//!
//! * `POST /token`           — code exchange, refresh token, and SA JWT exchange.
//! * `GET  /userinfo`        — OIDC userinfo.
//! * `GET  /directory/groups` — Admin SDK Directory API group listing.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;

/// Configurable user profile returned by the mock userinfo endpoint.
#[derive(Clone, Debug)]
pub struct MockGoogleUser {
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    pub name: String,
    /// `hd` (hosted domain) claim. `None` = omit the claim (non-Workspace account).
    pub hosted_domain: Option<String>,
}

/// Shared state behind the mock server.
struct MockState {
    user: Option<MockGoogleUser>,
    groups: Vec<String>,
    /// When true, /token returns 401 (simulates expired/revoked token).
    fail_token: bool,
}

/// Handle to the running mock server. Tests mutate state through `&self` methods.
pub struct MockGoogle {
    state: Arc<Mutex<MockState>>,
    pub base_url: Url,
}

impl MockGoogle {
    pub async fn set_user(&self, user: MockGoogleUser) {
        self.state.lock().await.user = Some(user);
    }

    pub async fn set_groups(&self, groups: Vec<String>) {
        self.state.lock().await.groups = groups;
    }

    #[allow(dead_code)]
    pub async fn set_fail_token(&self, fail: bool) {
        self.state.lock().await.fail_token = fail;
    }
}

/// Spawn the mock server and return a handle.
pub async fn spawn_mock_google_server() -> MockGoogle {
    let state = Arc::new(Mutex::new(MockState {
        user: None,
        groups: Vec::new(),
        fail_token: false,
    }));

    let router = Router::new()
        .route("/token", post(handle_token))
        .route("/userinfo", get(handle_userinfo))
        .route("/directory/groups", get(handle_directory_groups))
        .with_state(state.clone());

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind mock google server");
    let port = listener.local_addr().expect("local_addr").port();

    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("mock google server");
    });

    let base_url = Url::parse(&format!("http://127.0.0.1:{port}")).expect("base_url");

    MockGoogle { state, base_url }
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
    #[allow(dead_code)]
    assertion: Option<String>,
    #[allow(dead_code)]
    client_id: Option<String>,
    #[allow(dead_code)]
    client_secret: Option<String>,
}

async fn handle_token(
    State(state): State<Arc<Mutex<MockState>>>,
    Form(form): Form<TokenForm>,
) -> impl IntoResponse {
    let st = state.lock().await;
    if st.fail_token {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "token_revoked"})),
        );
    }

    let rt = match form.grant_type.as_str() {
        "authorization_code" => {
            // code exchange — code value is ignored
            if form.code.is_none() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "missing code"})),
                );
            }
            Some("mock-refresh-token")
        }
        "refresh_token" => {
            if form.refresh_token.as_deref() != Some("mock-refresh-token") {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "invalid_refresh_token"})),
                );
            }
            Some("mock-refresh-token")
        }
        "urn:ietf:params:oauth2:grant-type:jwt-bearer" => {
            // Service account JWT exchange — assertion is not verified by the mock.
            None
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "unsupported_grant_type"})),
            );
        }
    };

    let mut resp = json!({
        "access_token": "mock-access-token",
        "token_type": "Bearer",
    });

    if let Some(rt_val) = rt {
        resp["refresh_token"] = json!(rt_val);
    }

    (StatusCode::OK, Json(resp))
}

async fn handle_userinfo(State(state): State<Arc<Mutex<MockState>>>) -> impl IntoResponse {
    let st = state.lock().await;
    match &st.user {
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "no user configured in mock"})),
        ),
        Some(u) => {
            let mut obj = json!({
                "sub": u.sub,
                "email": u.email,
                "email_verified": u.email_verified,
                "name": u.name,
            });
            if let Some(hd) = &u.hosted_domain {
                obj["hd"] = json!(hd);
            }
            (StatusCode::OK, Json(obj))
        }
    }
}

#[derive(Deserialize)]
struct GroupsQuery {
    #[allow(dead_code)]
    #[serde(rename = "userKey")]
    user_key: Option<String>,
}

async fn handle_directory_groups(
    State(state): State<Arc<Mutex<MockState>>>,
    Query(_q): Query<GroupsQuery>,
) -> impl IntoResponse {
    let st = state.lock().await;
    let groups: Vec<_> = st
        .groups
        .iter()
        .map(|email| json!({"email": email, "kind": "admin#directory#group"}))
        .collect();
    (
        StatusCode::OK,
        Json(json!({"groups": groups, "kind": "admin#directory#groups"})),
    )
}
