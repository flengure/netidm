//! Forward auth gate — lets reverse proxies delegate authentication to netidm.
//!
//! Exposes three endpoints that reverse proxies call to protect upstream
//! applications that do not speak OIDC natively:
//!
//! - [`view_oauth2_auth_get`] — `GET /oauth2/auth` — forward auth gate
//! - [`view_oauth2_proxy_userinfo_get`] — `GET /oauth2/proxy/userinfo` — identity JSON
//! - [`view_oauth2_sign_out_get`] — `GET /oauth2/sign_out` — session clear + redirect
//!
//! # Compatibility
//!
//! Endpoint paths, status codes, and header names are compatible with the
//! oauth2-proxy convention so existing reverse-proxy configs work without
//! modification. This is a wire compatibility commitment, not an implementation
//! dependency — the internal logic is entirely netidm's own.
//!
//! # Route namespace
//!
//! `/oauth2/proxy/userinfo` is used instead of `/oauth2/userinfo` to avoid
//! ambiguity with the existing per-client OIDC userinfo endpoint at
//! `/oauth2/openid/:client_id/userinfo`.

use crate::https::{
    extractors::VerifiedClientInformation, middleware::KOpId, views::cookies, ServerState,
};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Extension, Json,
};
use axum_extra::extract::cookie::CookieJar;
use netidm_proto::internal::COOKIE_BEARER_TOKEN;
use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A compiled skip-auth rule that the forward auth gate checks before any
/// session validation.
///
/// Rules are specified as `METHOD=^/regex$` or `^/regex$` (any method).
/// When the incoming `X-Forwarded-Uri` path matches a rule the gate returns
/// `200 OK` immediately without checking authentication.
///
/// # Examples
///
/// ```rust
/// use netidmd_core::https::views::oauth2_proxy::SkipAuthRule;
///
/// // Match only GET /health
/// let rule = SkipAuthRule::parse("GET=^/health$").unwrap();
/// // Match any method on /metrics
/// let rule = SkipAuthRule::parse("^/metrics$").unwrap();
/// ```
#[derive(Debug)]
pub struct SkipAuthRule {
    /// When `Some`, the rule only matches requests with this HTTP method.
    pub method: Option<Method>,
    /// Compiled path regex.
    pub path: Regex,
}

impl SkipAuthRule {
    /// Parse a rule string of the form `METHOD=^/regex$` or `^/regex$`.
    ///
    /// Returns `None` and logs a warning when the regex fails to compile so
    /// callers can skip the invalid rule without panicking.
    pub fn parse(rule: &str) -> Option<Self> {
        let (method, pattern) = if let Some((m, p)) = rule.split_once('=') {
            let method = m.to_ascii_uppercase().parse::<Method>().ok().or_else(|| {
                warn!("skip_auth_rule: unknown HTTP method {m:?} in rule {rule:?}");
                None
            })?;
            (Some(method), p)
        } else {
            (None, rule)
        };

        match Regex::new(pattern) {
            Ok(re) => Some(SkipAuthRule { method, path: re }),
            Err(e) => {
                warn!(
                    ?e,
                    "skip_auth_rule: invalid regex {pattern:?} in rule {rule:?}, skipping"
                );
                None
            }
        }
    }

    /// Returns `true` when this rule matches the given request method and path.
    pub fn matches(&self, method: &Method, path: &str) -> bool {
        if let Some(ref m) = self.method {
            if m != method {
                return false;
            }
        }
        self.path.is_match(path)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Reconstruct the original request URL from trusted `X-Forwarded-*` headers.
///
/// Returns `None` when the required `x-forwarded-proto` or `x-forwarded-host`
/// headers are absent. The path defaults to `"/"` when `x-forwarded-uri` is
/// missing.
///
/// # Security
///
/// The caller is responsible for ensuring the request source IP is trusted
/// before using the reconstructed URL as a redirect target.
fn reconstruct_original_url(headers: &HeaderMap) -> Option<String> {
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())?;
    let host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())?;
    let uri = headers
        .get("x-forwarded-uri")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/");
    Some(format!("{proto}://{host}{uri}"))
}

/// Extract group short names from the `memberof` attribute of a whoami [`netidm_proto::v1::Entry`].
///
/// `memberof` values are SPNs of the form `group_name@domain`. This function
/// strips the `@domain` suffix and returns only the short names, matching the
/// convention used by [`netidm_proto::internal::UserAuthToken::name`].
fn group_names_from_entry(entry: &netidm_proto::v1::Entry) -> Vec<String> {
    entry
        .attrs
        .get("memberof")
        .map(|values| {
            values
                .iter()
                .map(|spn| {
                    spn.split_once('@')
                        .map(|(name, _)| name.to_string())
                        .unwrap_or_else(|| spn.clone())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Return an unauthenticated response.
///
/// For JSON clients (`Accept: application/json`): `401 Unauthorized` with
/// `{"error":"unauthenticated"}` and `WWW-Authenticate: Bearer`.
///
/// For browser clients: `302 Found` redirecting to the netidm login page.
/// The Location is an absolute URL (`{origin}/ui/login?next=<url>`) so that
/// Traefik forwardAuth correctly redirects the browser to netidm regardless
/// of which upstream host initiated the forward-auth check.
fn unauthenticated_response(
    headers: &HeaderMap,
    next_url: Option<String>,
    origin: &url::Url,
) -> Response {
    let wants_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("application/json"))
        .unwrap_or(false);

    if wants_json {
        (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(r#"Bearer realm="netidm""#),
            )],
            Json(serde_json::json!({"error": "unauthenticated"})),
        )
            .into_response()
    } else {
        let login_path = next_url
            .map(|url| format!("ui/login?next={}", percent_encode(url.as_bytes())))
            .unwrap_or_else(|| "ui/login".to_string());

        let location = origin
            .join(&login_path)
            .map(|u| u.to_string())
            .unwrap_or_else(|_| format!("{}ui/login", origin));

        (
            StatusCode::FOUND,
            [(
                header::LOCATION,
                HeaderValue::from_str(&location)
                    .unwrap_or_else(|_| HeaderValue::from_static("/ui/login")),
            )],
        )
            .into_response()
    }
}

/// Percent-encode a URL for use as a query parameter value.
fn percent_encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len());
    for &byte in input {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b':' => {
                output.push(byte as char);
            }
            _ => {
                output.push('%');
                output.push(
                    char::from_digit((byte >> 4) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                output.push(
                    char::from_digit((byte & 0xf) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    output
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Forward auth gate — `GET /oauth2/auth`.
///
/// Called by a reverse proxy on every request to a protected upstream. Returns
/// `202 Accepted` with identity headers when the request carries a valid
/// netidm session, or `401 Unauthorized` with a `Location` redirect to the
/// login page when it does not.
///
/// # Identity headers on 202
///
/// | Header | Value |
/// |--------|-------|
/// | `X-Auth-Request-User` | Short username (name part of SPN) |
/// | `X-Auth-Request-Email` | Primary email (omitted if not set) |
/// | `X-Auth-Request-Groups` | Comma-separated group short names (omitted if none) |
/// | `X-Auth-Request-Preferred-Username` | Display name |
/// | `X-Auth-Request-Access-Token` | Netidm bearer token (always set) |
/// | `X-Forwarded-User` | Same as `X-Auth-Request-User` |
/// | `X-Forwarded-Email` | Same as `X-Auth-Request-Email` |
/// | `X-Forwarded-Groups` | Same as `X-Auth-Request-Groups` |
///
/// Additional headers may be injected from user entry attributes via
/// `forward_auth_inject_request_headers` in the server config.
///
/// # Errors
///
/// Returns `401` when no credential is present or when the session is invalid,
/// expired, or belongs to a deleted or suspended account. Returns
/// `401 application/json` when the caller sends `Accept: application/json`.
///
/// # Examples
///
/// ```bash
/// # Unauthenticated — reverse proxy receives 401 + Location
/// curl -v -H "X-Forwarded-Proto: https" \
///      -H "X-Forwarded-Host: app.example.com" \
///      -H "X-Forwarded-Uri: /dashboard" \
///      http://netidm:8080/oauth2/auth
///
/// # Authenticated — reverse proxy receives 202 + identity headers
/// curl -v -H "Authorization: Bearer $TOKEN" \
///      http://netidm:8080/oauth2/auth
/// ```
pub async fn view_oauth2_auth_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    axum::extract::OriginalUri(original_uri): axum::extract::OriginalUri,
    headers: HeaderMap,
) -> Response {
    // Check skip-auth rules first — before any session validation or DB work.
    // Rules match against the X-Forwarded-Uri path (the original request URI that
    // the proxy is checking on behalf of), not the path of this endpoint itself.
    let forwarded_path = headers
        .get("x-forwarded-uri")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(original_uri.path());
    let forwarded_method = headers
        .get("x-forwarded-method")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<Method>().ok())
        .unwrap_or(Method::GET);
    if state
        .skip_auth_rules
        .iter()
        .any(|rule| rule.matches(&forwarded_method, forwarded_path))
    {
        return StatusCode::OK.into_response();
    }

    // Fast-fail: check that the pre-validated token is present before any DB work.
    if client_auth_info.pre_validated_uat().is_err() {
        // Only reconstruct the original URL when source headers are present.
        // No additional source-IP check needed here — the extractor already
        // handled trust via `trust_x_forward_for_ips` for the client IP, and
        // we build the `next` URL from headers that are only meaningful when
        // the proxy is trusted.
        let next_url = reconstruct_original_url(&headers);
        return unauthenticated_response(&headers, next_url, &state.origin);
    }

    // Capture the bearer token string before client_auth_info is moved into handle_whoami.
    let bearer_token_str = client_auth_info.bearer_token().map(|t| t.to_string());

    // Full validation + group lookup in a single DB transaction.
    // `handle_whoami` calls `validate_client_auth_info_to_ident` (checks the
    // session is not revoked and the account is active), then searches for the
    // user entry to populate `memberof`.
    match state
        .qe_r_ref
        .handle_whoami(client_auth_info, kopid.eventid)
        .await
    {
        Err(_) => {
            let next_url = reconstruct_original_url(&headers);
            unauthenticated_response(&headers, next_url, &state.origin)
        }
        Ok(whoami) => {
            let entry = &whoami.youare;

            // Extract identity fields from the Entry attributes.
            // SPN format is `name@domain`; strip the domain to get the short username.
            let username = entry
                .attrs
                .get("spn")
                .and_then(|v| v.first())
                .map(|spn| {
                    spn.split_once('@')
                        .map(|(name, _)| name.to_string())
                        .unwrap_or_else(|| spn.clone())
                })
                .unwrap_or_default();

            let displayname = entry
                .attrs
                .get("displayname")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let email = entry.attrs.get("mail").and_then(|v| v.first()).cloned();

            let groups = group_names_from_entry(entry);

            // Email domain allowlist check.
            if !state.forward_auth_allowed_email_domains.is_empty() {
                let domain_ok = email
                    .as_deref()
                    .and_then(|e| e.rsplit_once('@').map(|(_, d)| d))
                    .map(|d| {
                        state
                            .forward_auth_allowed_email_domains
                            .iter()
                            .any(|allowed| allowed.eq_ignore_ascii_case(d))
                    })
                    .unwrap_or(false);
                if !domain_ok {
                    return unauthenticated_response(&headers, None, &state.origin);
                }
            }

            // Group allowlist check.
            if !state.forward_auth_allowed_groups.is_empty() {
                let has_group = groups.iter().any(|g| {
                    state
                        .forward_auth_allowed_groups
                        .iter()
                        .any(|allowed| allowed == g)
                });
                if !has_group {
                    return unauthenticated_response(&headers, None, &state.origin);
                }
            }

            let groups_csv = if groups.is_empty() {
                None
            } else {
                Some(groups.join(","))
            };

            // Build 202 response with X-Auth-Request-* and X-Forwarded-* headers.
            let mut response_headers = vec![
                ("x-auth-request-user".to_string(), username.clone()),
                (
                    "x-auth-request-preferred-username".to_string(),
                    displayname.clone(),
                ),
                ("x-forwarded-user".to_string(), username),
            ];

            if let Some(ref em) = email {
                response_headers.push(("x-auth-request-email".to_string(), em.clone()));
                response_headers.push(("x-forwarded-email".to_string(), em.clone()));
            }

            if let Some(ref grps) = groups_csv {
                response_headers.push(("x-auth-request-groups".to_string(), grps.clone()));
                response_headers.push(("x-forwarded-groups".to_string(), grps.clone()));
            }

            let mut resp = StatusCode::ACCEPTED.into_response();
            for (name, value) in response_headers {
                if let (Ok(hname), Ok(hvalue)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(&value),
                ) {
                    resp.headers_mut().insert(hname, hvalue);
                }
            }

            // Pass the netidm bearer token through so upstream services can call
            // netidm APIs on behalf of the authenticated user.
            if let Some(ref token_str) = bearer_token_str {
                if let Ok(v) = HeaderValue::from_str(token_str) {
                    resp.headers_mut().insert("x-auth-request-access-token", v);
                }
            }

            // Inject custom headers from configured entry attribute mappings.
            for (header_name, attr_name) in state.forward_auth_inject_headers.as_ref() {
                if let Some(values) = entry.attrs.get(attr_name.as_str()) {
                    if let Some(val) = values.first() {
                        if let Ok(hvalue) = HeaderValue::from_str(val) {
                            resp.headers_mut().insert(header_name.clone(), hvalue);
                        }
                    }
                }
            }

            resp
        }
    }
}

/// Userinfo response body serialised as JSON.
#[derive(Serialize)]
struct UserinfoResponse {
    user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    groups: Vec<String>,
    preferred_username: String,
}

/// User identity JSON endpoint — `GET /oauth2/proxy/userinfo`.
///
/// Returns the authenticated user's identity as JSON. Compatible with the
/// oauth2-proxy `/oauth2/userinfo` endpoint contract.
///
/// The path `/oauth2/proxy/userinfo` is used (rather than `/oauth2/userinfo`)
/// to avoid ambiguity with the OIDC per-client userinfo endpoint at
/// `/oauth2/openid/:client_id/userinfo`.
///
/// # Response body (200)
///
/// ```json
/// {
///   "user": "alice",
///   "email": "alice@example.com",
///   "groups": ["admins", "developers"],
///   "preferred_username": "Alice Smith"
/// }
/// ```
///
/// `email` is omitted when not set. `groups` is an empty array when the user
/// has no group memberships.
///
/// # Errors
///
/// Returns `401 {"error":"unauthenticated"}` when no valid session is present.
///
/// # Examples
///
/// ```bash
/// curl -H "Authorization: Bearer $TOKEN" \
///      http://netidm:8080/oauth2/proxy/userinfo
/// ```
pub async fn view_oauth2_proxy_userinfo_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> Response {
    if client_auth_info.pre_validated_uat().is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthenticated"})),
        )
            .into_response();
    }

    match state
        .qe_r_ref
        .handle_whoami(client_auth_info, kopid.eventid)
        .await
    {
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthenticated"})),
        )
            .into_response(),
        Ok(whoami) => {
            let entry = &whoami.youare;

            let user = entry
                .attrs
                .get("spn")
                .and_then(|v| v.first())
                .map(|spn| {
                    spn.split_once('@')
                        .map(|(name, _)| name.to_string())
                        .unwrap_or_else(|| spn.clone())
                })
                .unwrap_or_default();

            let preferred_username = entry
                .attrs
                .get("displayname")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let email = entry.attrs.get("mail").and_then(|v| v.first()).cloned();

            let groups = group_names_from_entry(entry);

            (
                StatusCode::OK,
                Json(UserinfoResponse {
                    user,
                    email,
                    groups,
                    preferred_username,
                }),
            )
                .into_response()
        }
    }
}

/// Query parameters for the sign-out endpoint.
#[derive(Deserialize)]
pub struct SignOutQuery {
    /// Optional post-sign-out redirect URL. Must be a relative path (starting
    /// with `/`) to prevent open-redirect attacks.
    #[serde(default)]
    rd: Option<String>,
}

/// Session sign-out endpoint — `GET /oauth2/sign_out`.
///
/// Clears the session cookie and invalidates the server-side session record,
/// then redirects the user. Always succeeds — calling this endpoint without
/// an active session is safe.
///
/// # Redirect behaviour
///
/// | Condition | Redirect target |
/// |-----------|----------------|
/// | `?rd=/path` (relative) | `/path` |
/// | `?rd=https://…` (absolute) | `/ui/login` (rejected) |
/// | No `?rd` | `/ui/login` |
///
/// Only relative redirect targets (starting with `/`) are accepted to prevent
/// open-redirect attacks.
///
/// # Errors
///
/// This handler does not return errors — it always produces a `302` redirect.
///
/// # Examples
///
/// ```bash
/// # Sign out and redirect to login
/// curl -v --cookie "bearer=$SESSION" \
///      http://netidm:8080/oauth2/sign_out
///
/// # Sign out and redirect to a relative path
/// curl -v --cookie "bearer=$SESSION" \
///      "http://netidm:8080/oauth2/sign_out?rd=%2Fsome%2Fpath"
/// ```
pub async fn view_oauth2_sign_out_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Query(query): Query<SignOutQuery>,
    jar: CookieJar,
) -> Response {
    // Invalidate the server-side session record if one exists. We ignore the
    // error — sign-out must succeed even when there is no active session.
    if client_auth_info.pre_validated_uat().is_ok() {
        let _ = state
            .qe_w_ref
            .handle_logout(client_auth_info, kopid.eventid)
            .await;
    }

    // Always emit a removal cookie for COOKIE_BEARER_TOKEN so that browsers
    // clear their session cookie even when the token arrived via Authorization
    // header rather than a cookie (i.e., when the jar is empty).
    use axum_extra::extract::cookie::{Cookie, SameSite};
    let mut removal = Cookie::new(COOKIE_BEARER_TOKEN, "");
    removal.make_removal();
    removal.set_domain(state.domain.clone());
    removal.set_path("/");
    removal.set_secure(state.secure_cookies);
    removal.set_same_site(SameSite::Lax);
    removal.set_http_only(true);
    let jar = jar.add(removal);
    // Also remove from jar if cookie was present in the request.
    let jar = cookies::destroy(jar, COOKIE_BEARER_TOKEN, &state);

    // Validate the redirect target: only relative paths accepted to prevent
    // open-redirect attacks. Absolute URLs (including those with scheme://) are
    // rejected and fall back to the login page.
    let redirect_to = query
        .rd
        .as_deref()
        .filter(|rd| rd.starts_with('/') && !rd.starts_with("//"))
        .unwrap_or("/ui/login");

    (jar, Redirect::to(redirect_to)).into_response()
}

// ---------------------------------------------------------------------------
// Unit tests — pure helper functions only; handler tests live in testkit
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        h
    }

    // --- reconstruct_original_url ---

    #[test]
    fn test_reconstruct_url_full() {
        let h = headers_with(&[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "app.example.com"),
            ("x-forwarded-uri", "/dashboard?q=1"),
        ]);
        assert_eq!(
            reconstruct_original_url(&h),
            Some("https://app.example.com/dashboard?q=1".to_string())
        );
    }

    #[test]
    fn test_reconstruct_url_missing_proto() {
        let h = headers_with(&[
            ("x-forwarded-host", "app.example.com"),
            ("x-forwarded-uri", "/path"),
        ]);
        assert_eq!(reconstruct_original_url(&h), None);
    }

    #[test]
    fn test_reconstruct_url_missing_host() {
        let h = headers_with(&[("x-forwarded-proto", "https"), ("x-forwarded-uri", "/path")]);
        assert_eq!(reconstruct_original_url(&h), None);
    }

    #[test]
    fn test_reconstruct_url_no_uri_defaults_to_root() {
        let h = headers_with(&[
            ("x-forwarded-proto", "http"),
            ("x-forwarded-host", "host.internal"),
        ]);
        assert_eq!(
            reconstruct_original_url(&h),
            Some("http://host.internal/".to_string())
        );
    }

    // --- group_names_from_entry ---

    fn entry_with_memberof(values: &[&str]) -> netidm_proto::v1::Entry {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert(
            "memberof".to_string(),
            values.iter().map(|s| s.to_string()).collect(),
        );
        netidm_proto::v1::Entry { attrs }
    }

    #[test]
    fn test_group_names_strips_domain() {
        let entry = entry_with_memberof(&["admins@example.com", "developers@example.com"]);
        let names = group_names_from_entry(&entry);
        assert_eq!(names, vec!["admins", "developers"]);
    }

    #[test]
    fn test_group_names_no_domain_passthrough() {
        let entry = entry_with_memberof(&["plain-group"]);
        let names = group_names_from_entry(&entry);
        assert_eq!(names, vec!["plain-group"]);
    }

    #[test]
    fn test_group_names_empty_when_no_memberof() {
        let entry = netidm_proto::v1::Entry {
            attrs: std::collections::BTreeMap::new(),
        };
        let names = group_names_from_entry(&entry);
        assert!(names.is_empty());
    }

    // --- percent_encode ---

    #[test]
    fn test_percent_encode_unreserved_passthrough() {
        assert_eq!(percent_encode(b"abc-123.~"), "abc-123.~");
    }

    #[test]
    fn test_percent_encode_space() {
        assert_eq!(percent_encode(b"hello world"), "hello%20world");
    }

    #[test]
    fn test_percent_encode_slash_and_colon_passthrough() {
        assert_eq!(percent_encode(b"https://host/path"), "https://host/path");
    }

    #[test]
    fn test_percent_encode_query_string() {
        assert_eq!(percent_encode(b"?q=a b"), "%3Fq%3Da%20b");
    }

    // --- unauthenticated_response ---

    fn test_origin() -> url::Url {
        url::Url::parse("https://idm.example.com").unwrap()
    }

    #[tokio::test]
    async fn test_unauthenticated_response_html_redirect_with_next() {
        let h = headers_with(&[]);
        let origin = test_origin();
        let resp = unauthenticated_response(
            &h,
            Some("https://app.example.com/path".to_string()),
            &origin,
        );
        assert!(resp.status().is_redirection());
        let location = resp.headers().get(header::LOCATION).unwrap();
        let loc_str = location.to_str().unwrap();
        assert!(loc_str.contains("ui/login"));
        assert!(loc_str.contains("next="));
    }

    #[tokio::test]
    async fn test_unauthenticated_response_html_no_next() {
        let h = headers_with(&[]);
        let origin = test_origin();
        let resp = unauthenticated_response(&h, None, &origin);
        assert!(resp.status().is_redirection());
        let location = resp.headers().get(header::LOCATION).unwrap();
        assert!(location.to_str().unwrap().contains("ui/login"));
    }

    #[tokio::test]
    async fn test_unauthenticated_response_json_when_accept_json() {
        let h = headers_with(&[(header::ACCEPT.as_str(), "application/json")]);
        let origin = test_origin();
        let resp = unauthenticated_response(
            &h,
            Some("https://app.example.com/path".to_string()),
            &origin,
        );
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // JSON response has no Location header
        assert!(resp.headers().get(header::LOCATION).is_none());
    }

    // --- sign-out redirect safety ---

    #[test]
    fn test_sign_out_rd_relative_accepted() {
        let rd: Option<String> = Some("/some/path".to_string());
        let redirect_to = rd
            .as_deref()
            .filter(|rd| rd.starts_with('/') && !rd.starts_with("//"))
            .unwrap_or("/ui/login");
        assert_eq!(redirect_to, "/some/path");
    }

    #[test]
    fn test_sign_out_rd_absolute_rejected() {
        let rd: Option<String> = Some("https://evil.example.com/steal".to_string());
        let redirect_to = rd
            .as_deref()
            .filter(|rd| rd.starts_with('/') && !rd.starts_with("//"))
            .unwrap_or("/ui/login");
        assert_eq!(redirect_to, "/ui/login");
    }

    #[test]
    fn test_sign_out_rd_protocol_relative_rejected() {
        let rd: Option<String> = Some("//evil.example.com/steal".to_string());
        let redirect_to = rd
            .as_deref()
            .filter(|rd| rd.starts_with('/') && !rd.starts_with("//"))
            .unwrap_or("/ui/login");
        assert_eq!(redirect_to, "/ui/login");
    }

    #[test]
    fn test_sign_out_rd_none_defaults_to_login() {
        let rd: Option<String> = None;
        let redirect_to = rd
            .as_deref()
            .filter(|rd| rd.starts_with('/') && !rd.starts_with("//"))
            .unwrap_or("/ui/login");
        assert_eq!(redirect_to, "/ui/login");
    }

    // --- SkipAuthRule ---

    #[test]
    fn test_skip_auth_rule_get_health_matches() {
        let rule = SkipAuthRule::parse("GET=^/health$").unwrap();
        assert!(rule.matches(&Method::GET, "/health"));
    }

    #[test]
    fn test_skip_auth_rule_get_health_no_match_post() {
        let rule = SkipAuthRule::parse("GET=^/health$").unwrap();
        assert!(!rule.matches(&Method::POST, "/health"));
    }

    #[test]
    fn test_skip_auth_rule_any_method_matches_get_and_post() {
        let rule = SkipAuthRule::parse("^/metrics$").unwrap();
        assert!(rule.matches(&Method::GET, "/metrics"));
        assert!(rule.matches(&Method::POST, "/metrics"));
    }

    #[test]
    fn test_skip_auth_rule_invalid_regex_returns_none() {
        let result = SkipAuthRule::parse("GET=[invalid");
        assert!(result.is_none(), "Invalid regex should return None");
    }

    #[test]
    fn test_skip_auth_rule_regex_no_match() {
        let rule = SkipAuthRule::parse("^/health$").unwrap();
        assert!(!rule.matches(&Method::GET, "/healthz"));
        assert!(!rule.matches(&Method::GET, "/other"));
    }

    #[test]
    fn test_skip_auth_rule_prefix_match() {
        let rule = SkipAuthRule::parse("^/public/").unwrap();
        assert!(rule.matches(&Method::GET, "/public/logo.png"));
        assert!(rule.matches(&Method::GET, "/public/css/main.css"));
        assert!(!rule.matches(&Method::GET, "/private/secret"));
    }
}
