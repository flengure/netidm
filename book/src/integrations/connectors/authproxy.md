# Auth Proxy Connector

The auth proxy connector trusts user identity information placed in HTTP request headers by
an upstream reverse proxy that has already performed authentication (for example Apache with
`mod_auth_gssapi`, `nginx` with LDAP auth, or oauth2-proxy in header-injection mode).

No OAuth2 redirect flow occurs — Netidm reads the nominated headers directly. The reverse
proxy is responsible for authenticating the user; Netidm must never be reachable without
passing through the proxy.

> **Security warning**: Place Netidm behind a firewall so that only the trusted reverse proxy
> can reach it. Any client that can reach Netidm directly can forge the identity headers.

## Prerequisites

Configure your reverse proxy to inject identity headers after successful authentication.
Common header names:

| Proxy | Username header | Email header | Groups header |
|---|---|---|---|
| oauth2-proxy | `X-Auth-Request-User` | `X-Auth-Request-Email` | `X-Auth-Request-Groups` |
| nginx auth_request | `X-Remote-User` | `X-Remote-Email` | — |
| Apache mod_auth | `REMOTE_USER` | — | — |

## Creating the connector

Specify the header that carries the authenticated username:

```bash
netidm system oauth2 create-authproxy \
    --name myproxy \
    --user-header X-Auth-Request-User
```

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name myproxy
```

## Optional headers

Set the email and groups headers via the REST API:

```bash
# PATCH /v1/oauth2/_client/myproxy
# {
#   "connector_authproxy_email_header":  "X-Auth-Request-Email",
#   "connector_authproxy_groups_header": "X-Auth-Request-Groups"
# }
```

When `connector_authproxy_groups_header` is set, its value is split on commas to produce the
list of group claims (e.g. `engineering,devops` → `["engineering", "devops"]`).

## nginx example

```nginx
location / {
    auth_request     /auth;
    auth_request_set $auth_user  $upstream_http_x_auth_request_user;
    auth_request_set $auth_email $upstream_http_x_auth_request_email;

    proxy_set_header X-Auth-Request-User  $auth_user;
    proxy_set_header X-Auth-Request-Email $auth_email;
    proxy_pass http://netidm-backend;
}
```

## Reference

| Attribute | Description |
|---|---|
| `connector_authproxy_user_header` | HTTP header carrying the authenticated username (required) |
| `connector_authproxy_email_header` | HTTP header carrying the user email (optional) |
| `connector_authproxy_groups_header` | HTTP header carrying comma-separated group names (optional) |
