//! Shared URIs
//!
//! ⚠️  ⚠️   WARNING  ⚠️  ⚠️
//!
//! IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS EVERYWHERE
//!
//! SERIOUSLY... DO NOT CHANGE THEM!
//!
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS ⚠️  ⚠️
pub const OAUTH2_AUTHORISE: &str = "/oauth2/authorise";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS ⚠️  ⚠️
pub const OAUTH2_AUTHORISE_PERMIT: &str = "/oauth2/authorise/permit";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_AUTHORISE_REJECT: &str = "/oauth2/authorise/reject";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_AUTHORISE_DEVICE: &str = "/oauth2/device";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_TOKEN_ENDPOINT: &str = "/oauth2/token";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_TOKEN_INTROSPECT_ENDPOINT: &str = "/oauth2/token/introspect";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_TOKEN_REVOKE_ENDPOINT: &str = "/oauth2/token/revoke";

/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_DEVICE_LOGIN: &str = "/oauth2/device"; // starts with /ui

pub const V1_AUTH_VALID: &str = "/v1/auth/valid";

// Forward auth / proxy auth endpoints (oauth2-proxy compatibility)
/// Forward auth gate called by reverse proxies on every protected request.
pub const OAUTH2_PROXY_AUTH: &str = "/oauth2/auth";
/// Session identity JSON endpoint (namespaced to avoid collision with
/// `/oauth2/openid/:client_id/userinfo`).
pub const OAUTH2_PROXY_USERINFO: &str = "/oauth2/proxy/userinfo";
/// Session sign-out endpoint; clears the session cookie and redirects.
pub const OAUTH2_PROXY_SIGN_OUT: &str = "/oauth2/sign_out";
