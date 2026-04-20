# Quickstart: Forward Auth & Proxy Auth

**Branch**: `004-forward-auth-endpoint`

## Prerequisites

- netidmd running locally (see repo README)
- A valid netidm user account + session token for testing

---

## Scenario 1: Forward Auth — Unauthenticated Request

```bash
# No session — expect 401 + Location header
curl -v \
  -H "X-Forwarded-Proto: https" \
  -H "X-Forwarded-Host: app.example.com" \
  -H "X-Forwarded-Uri: /dashboard" \
  http://localhost:8080/oauth2/auth

# Expected:
# < HTTP/1.1 401 Unauthorized
# < Location: /ui/login?next=https%3A%2F%2Fapp.example.com%2Fdashboard
# < WWW-Authenticate: Bearer realm="netidm"
```

---

## Scenario 2: Forward Auth — Authenticated Request

```bash
# Substitute a real bearer token from a login session
TOKEN="<your_bearer_token>"

curl -v \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Forwarded-Proto: https" \
  -H "X-Forwarded-Host: app.example.com" \
  -H "X-Forwarded-Uri: /dashboard" \
  http://localhost:8080/oauth2/auth

# Expected:
# < HTTP/1.1 202 Accepted
# < X-Auth-Request-User: alice
# < X-Auth-Request-Email: alice@example.com
# < X-Auth-Request-Groups: admins,developers
# < X-Auth-Request-Preferred-Username: Alice Smith
```

---

## Scenario 3: Userinfo Endpoint

```bash
TOKEN="<your_bearer_token>"

curl -v \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/oauth2/proxy/userinfo

# Expected:
# < HTTP/1.1 200 OK
# < Content-Type: application/json
# {"user":"alice","email":"alice@example.com","groups":["admins","developers"],"preferred_username":"Alice Smith"}
```

---

## Scenario 4: Sign-Out

```bash
# With cookie (browser session)
curl -v \
  --cookie "bearer=<session_cookie_value>" \
  "http://localhost:8080/oauth2/sign_out?rd=https%3A%2F%2Ftrusted.example.com"

# Expected:
# < HTTP/1.1 302 Found
# < Set-Cookie: bearer=; Max-Age=0; ...
# < Location: https://trusted.example.com
```

---

## Scenario 5: API Client (JSON 401)

```bash
curl -v \
  -H "Accept: application/json" \
  http://localhost:8080/oauth2/auth

# Expected:
# < HTTP/1.1 401 Unauthorized
# < Content-Type: application/json
# {"error":"unauthenticated"}
```

---

## Scenario 6: Skip-Auth Health Check

```bash
# Assuming skip-auth rule: GET=^/health$
# (No token — should pass through)
curl -v http://localhost:8080/health

# Expected: 200 (proxied through, no auth required)
```

---

## Traefik Configuration Example

```yaml
# traefik dynamic config
http:
  middlewares:
    netidm-auth:
      forwardAuth:
        address: "http://netidm:8080/oauth2/auth"
        trustForwardHeader: true
        authResponseHeaders:
          - "X-Auth-Request-User"
          - "X-Auth-Request-Email"
          - "X-Auth-Request-Groups"
          - "X-Auth-Request-Preferred-Username"
```

---

## Caddy Configuration Example

```
app.example.com {
    forward_auth netidm:8080 {
        uri /oauth2/auth
        copy_headers X-Auth-Request-User X-Auth-Request-Email X-Auth-Request-Groups
    }
    reverse_proxy app-backend:3000
}
```

---

## nginx Configuration Example

```nginx
location / {
    auth_request /oauth2/auth;
    auth_request_set $user $upstream_http_x_auth_request_user;
    auth_request_set $email $upstream_http_x_auth_request_email;
    proxy_set_header X-User $user;
    proxy_set_header X-Email $email;
    proxy_pass http://app-backend;
}

location = /oauth2/auth {
    internal;
    proxy_pass http://netidm:8080;
    proxy_set_header X-Forwarded-Uri $request_uri;
}
```
