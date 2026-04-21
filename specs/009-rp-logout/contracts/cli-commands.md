# CLI Command Contracts — PR-RP-LOGOUT

All verbs listed below are added to the `netidm` CLI by this PR. Existing verbs are unchanged.

---

## 1. OAuth2 client — post-logout redirect URI allowlist

### `netidm system oauth2-client add-post-logout-redirect-uri <name> <uri>`

Add a URI to the named OAuth2 client's `OAuth2RsPostLogoutRedirectUri` allowlist.

| Arg | Form | Description |
|---|---|---|
| `<name>` | string | OAuth2 client name or UUID. |
| `<uri>` | absolute URL | URI to add. MUST be absolute. |

**Exit codes**: `0` on success. `1` on validation error (not an absolute URL; URI already present). `2` on auth / ACP failure. `3` on client not found.

### `netidm system oauth2-client remove-post-logout-redirect-uri <name> <uri>`

Remove a URI from the allowlist. No-op (and `0` exit) if the URI is not present.

### `netidm system oauth2-client list-post-logout-redirect-uris <name>`

List all entries in the allowlist, one per line. Emits nothing (and `0` exit) if empty.

---

## 2. OAuth2 client — back-channel logout endpoint

### `netidm system oauth2-client set-backchannel-logout-uri <name> <uri>`

Replace the client's `OAuth2RsBackchannelLogoutUri` with `<uri>`. Single-value: only one endpoint is ever registered per client. Re-running replaces the previous value.

### `netidm system oauth2-client clear-backchannel-logout-uri <name>`

Clear the attribute. No-op (and `0` exit) if already unset.

---

## 3. SAML client — single logout service URL

### `netidm system saml-client set-slo-url <name> <url>`

Replace the SP's `SamlSingleLogoutServiceUrl` with `<url>`.

### `netidm system saml-client clear-slo-url <name>`

Clear the attribute.

---

## 4. Log-out-everywhere (US5)

### `netidm self logout-all`

Terminate every active netidm session for the CLI user (whoever holds the current CLI auth token). On success, the CLI auth token used for this very call is invalidated; subsequent commands will prompt for auth again.

Output:
```
Terminated 3 sessions.
```

Exit codes: `0` on success; `2` on auth failure.

### `netidm person logout-all <id>`

Admin-only. `<id>` is a person's name or UUID.

Output:
```
Terminated 5 sessions for alice (a1b2c3d4-…).
```

Exit codes: `0` on success; `2` on auth / ACP failure; `3` on user not found.

---

## 5. Delivery-queue inspection

### `netidm logout-deliveries list [--pending | --succeeded | --failed] [--rp <name>] [--limit <n>]`

Admin-only. Lists delivery records.

Default filter: all statuses, most recent first, `--limit 50`.

Output (one line per row, columns aligned):
```
UUID                                  STATUS      RP        ATTEMPTS  NEXT_ATTEMPT          CREATED
1a2b3c4d-…                            pending     portainer 2         2026-04-21T18:30:00Z  2026-04-21T17:00:00Z
5e6f7a8b-…                            succeeded   grafana   1         —                     2026-04-21T17:01:00Z
9c0d1e2f-…                            failed      forgejo   6         —                     2026-04-20T09:15:00Z
```

### `netidm logout-deliveries show <uuid>`

Admin-only. Show one delivery record in full, including the logout token's decoded claims (but NOT the raw JWT bytes).

Output:
```
UUID:         1a2b3c4d-...
RP:           portainer (uuid: ...)
Endpoint:     https://portainer.example/oidc/backchannel_logout
Status:       pending
Attempts:     2
Last attempt: 2026-04-21T18:25:00Z
Next attempt: 2026-04-21T18:30:00Z
Created:      2026-04-21T17:00:00Z

Logout token claims:
  iss:    https://netidm.example/oauth2/openid/portainer
  aud:    portainer
  sub:    <user uuid>
  sid:    <session uuid>
  iat:    2026-04-21T17:00:00Z
  jti:    <jti uuid>
  events: {"http://schemas.openid.net/event/backchannel-logout": {}}
```

Exit codes: `0` on success; `2` on auth / ACP failure; `3` on delivery not found.

---

## 6. Shared argument conventions

- `<name>` for OAuth2 / SAML clients accepts either the client's human-readable name or its UUID.
- `<id>` for persons accepts either the name or the UUID.
- `<uri>` / `<url>` must be absolute. HTTPS strongly preferred; HTTP permitted only for localhost/RFC-1918 per the same URL validator netidm uses elsewhere.
- Every new verb inherits the standard `--output json` and `--verbose` flags from the netidm CLI root.
- Every new verb is ACP-gated server-side; CLI-level errors surface server errors as they stand (no CLI-side authorisation logic).
