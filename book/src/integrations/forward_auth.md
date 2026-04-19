# Forward Auth (Reverse Proxy Authentication)

Forward auth lets a reverse proxy delegate authentication to netidm for applications
that do not speak OIDC natively. Instead of each application handling login, the reverse
proxy intercepts every request and asks netidm "is this user authenticated?". If yes,
netidm responds with identity headers and the proxy forwards the request. If no, netidm
responds with a redirect to the login page.

**When to use forward auth vs. OIDC**

| Situation | Recommendation |
|-----------|---------------|
| App supports OIDC natively (e.g. Grafana, Gitea) | Use OIDC — full token lifecycle, logout, etc. |
| App has no auth at all (e.g. internal dashboards) | Use forward auth — zero app changes |
| App has its own basic auth you want to replace | Use forward auth |

---

## Endpoints

| Method | Path | Role |
|--------|------|------|
| `GET` | `/oauth2/auth` | Forward auth gate — called by the proxy on every request |
| `GET` | `/oauth2/proxy/userinfo` | Identity JSON — authenticated user details |
| `GET` | `/oauth2/sign_out` | Session sign-out + redirect |

All three endpoints are registered at the root level (not under `/ui`).

---

## Identity Headers

When `/oauth2/auth` returns `202 Accepted`, the following headers are set:

| Header | Value |
|--------|-------|
| `X-Auth-Request-User` | Short username (name part of SPN, no `@domain`) |
| `X-Auth-Request-Email` | Primary email address (omitted if not set) |
| `X-Auth-Request-Groups` | Comma-separated group short names (omitted if no memberships) |
| `X-Auth-Request-Preferred-Username` | Display name |
| `X-Forwarded-User` | Same as `X-Auth-Request-User` |
| `X-Forwarded-Email` | Same as `X-Auth-Request-Email` |
| `X-Forwarded-Groups` | Same as `X-Auth-Request-Groups` |

The upstream application can read these headers to identify the logged-in user.

---

## Userinfo JSON

`GET /oauth2/proxy/userinfo` returns the authenticated user's identity as JSON:

```json
{
  "user": "alice",
  "email": "alice@example.com",
  "groups": ["admins", "developers"],
  "preferred_username": "Alice Smith"
}
```

The `email` field is omitted when not set. `groups` is an empty array when the user has no
group memberships.

On failure: `401 {"error":"unauthenticated"}`.

---

## Sign-Out

`GET /oauth2/sign_out` clears the session cookie and redirects the user. Always safe to call
even without an active session.

Optional query parameter `rd` sets the post-sign-out redirect target. Only relative paths
(starting with `/` but not `//`) are accepted to prevent open-redirect attacks.

```
/oauth2/sign_out          → redirects to /ui/login
/oauth2/sign_out?rd=/app  → redirects to /app
/oauth2/sign_out?rd=https://evil.com  → rejected, redirects to /ui/login
```

---

## Proxy Configuration Examples

### Traefik

```yaml
# docker-compose.yml or traefik dynamic config
http:
  middlewares:
    netidm-auth:
      forwardAuth:
        address: "https://netidm.example.com/oauth2/auth"
        trustForwardHeader: true
        authResponseHeaders:
          - "X-Auth-Request-User"
          - "X-Auth-Request-Email"
          - "X-Auth-Request-Groups"
          - "X-Auth-Request-Preferred-Username"

  routers:
    my-app:
      rule: "Host(`app.example.com`)"
      middlewares:
        - netidm-auth
      service: my-app-service
```

Traefik automatically sends `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Uri`
headers so netidm can reconstruct the original URL for the `?next=` login redirect.

### Caddy

```caddy
app.example.com {
    forward_auth netidm.example.com {
        uri /oauth2/auth
        copy_headers X-Auth-Request-User X-Auth-Request-Email X-Auth-Request-Groups
    }

    reverse_proxy localhost:8080
}
```

### nginx

```nginx
location / {
    auth_request /oauth2/auth;
    auth_request_set $auth_user $upstream_http_x_auth_request_user;
    auth_request_set $auth_email $upstream_http_x_auth_request_email;
    proxy_set_header X-User $auth_user;
    proxy_set_header X-Email $auth_email;

    proxy_pass http://localhost:8080;
}

location = /oauth2/auth {
    internal;
    proxy_pass https://netidm.example.com;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Uri $request_uri;
}

error_page 401 = @error401;
location @error401 {
    return 302 https://netidm.example.com/ui/login?next=$scheme://$host$request_uri;
}
```

### Apache (mod_auth_request)

```apache
<Location "/">
    AuthType None
    Require all granted

    # Forward auth check
    AuthRequestHeader X-Forwarded-Proto "%{REQUEST_SCHEME}e"
    AuthRequestHeader X-Forwarded-Host "%{HTTP_HOST}e"
    AuthRequestHeader X-Forwarded-Uri "%{REQUEST_URI}e"
</Location>
```

Apache's `mod_auth_openidc` can redirect to netidm's OIDC endpoint; for pure forward auth,
use `mod_auth_request` pointing to `https://netidm.example.com/oauth2/auth`.

### HAProxy

```hacfg
frontend web
    bind *:443 ssl crt /etc/ssl/certs/cert.pem
    default_backend app

    http-request lua.auth-check
    http-request set-header X-Auth-User %[var(req.auth_user)] if { var(req.auth_ok) -m bool }

backend netidm-auth
    server netidm netidm.example.com:443 ssl verify required
```

Use a Lua script that calls `/oauth2/auth` and reads the response headers.

---

## Redirect After Login

When a user hits a protected URL without a session, netidm receives the original URL from
the `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Uri` headers and redirects
to:

```
/ui/login?next=https%3A%2F%2Fapp.example.com%2Fdashboard
```

After successful login, the user is redirected back to the original URL automatically.

This requires the reverse proxy to be trusted (i.e., it must send the `X-Forwarded-*`
headers). Configure `trust_x_forward_for_ips` in netidm's server config to include the
proxy's IP range.
