# CLI Command Contracts: Social Login with JIT Provisioning

**Branch**: `001-social-login-jit` | **Date**: 2026-04-16

These commands extend `netidm system oauth2` in `tools/cli/src/opt/netidm.rs`.

---

## New Commands

### `netidm system oauth2 create-github`

Register a GitHub social login provider with pre-filled endpoints and required scopes.

```
netidm system oauth2 create-github <name> <client_id> <client_secret> [OPTIONS]

Arguments:
  <name>           Provider name (Netidm iname, e.g. "github")
  <client_id>      GitHub OAuth App client ID
  <client_secret>  GitHub OAuth App client secret

Options:
  -H, --url <URL>  Netidm server URL
  -D, --name <NAME> Bind as this account

Pre-filled defaults:
  authorisation_endpoint: https://github.com/login/oauth/authorize
  token_endpoint:         https://github.com/login/oauth/access_token
  userinfo_endpoint:      https://api.github.com/user
  request_scopes:         user:email read:user
  jit_provisioning:       false  (must be explicitly enabled)
  claim_map_name:         login
  claim_map_displayname:  name
  claim_map_email:        email
```

**Success**: Prints `Successfully created GitHub provider 'github'`
**Error (name taken)**: `Error: A provider with name 'github' already exists`
**Error (invalid client_id)**: Client ID/secret are stored as-is; no validation at creation time

---

### `netidm system oauth2 create-google`

Register a Google social login provider with pre-filled OIDC endpoints.

```
netidm system oauth2 create-google <name> <client_id> <client_secret> [OPTIONS]

Arguments:
  <name>           Provider name (e.g. "google")
  <client_id>      Google OAuth2 client ID
  <client_secret>  Google OAuth2 client secret

Pre-filled defaults:
  authorisation_endpoint: https://accounts.google.com/o/oauth2/v2/auth
  token_endpoint:         https://oauth2.googleapis.com/token
  userinfo_endpoint:      (not set — Google uses id_token JWT, not userinfo endpoint)
  request_scopes:         openid email profile
  jit_provisioning:       false
  claim_map_name:         (not set — derived from email local-part)
  claim_map_displayname:  name
  claim_map_email:        email
```

**Success**: Prints `Successfully created Google provider 'google'`

---

### `netidm system oauth2 enable-jit-provisioning`

Enable Just-In-Time account provisioning for a social login provider.

```
netidm system oauth2 enable-jit-provisioning <name> [OPTIONS]

Arguments:
  <name>  Provider name to enable JIT provisioning on

Effect: Sets oauth2_jit_provisioning = true on the named provider entry
```

**Success**: Prints `JIT provisioning enabled for provider 'github'`
**Error (provider not found)**: `Error: No provider named 'github' found`
**Idempotent**: Enabling when already enabled is a no-op (no error)

---

### `netidm system oauth2 disable-jit-provisioning`

Disable JIT provisioning. New users will be denied; existing accounts are unaffected.

```
netidm system oauth2 disable-jit-provisioning <name> [OPTIONS]

Arguments:
  <name>  Provider name to disable JIT provisioning on
```

**Success**: Prints `JIT provisioning disabled for provider 'github'`
**Idempotent**: Disabling when already disabled is a no-op

---

### `netidm system oauth2 set-identity-claim-map`

Map a provider claim to a Netidm account attribute for JIT provisioning.

```
netidm system oauth2 set-identity-claim-map <name> <netidm_attr> <provider_claim> [OPTIONS]

Arguments:
  <name>            Provider name
  <netidm_attr>     Netidm attribute to populate. One of: name, displayname, email
  <provider_claim>  Provider claim name to read from (e.g. "login", "name", "email")

Examples:
  netidm system oauth2 set-identity-claim-map github name login
  netidm system oauth2 set-identity-claim-map github displayname name
  netidm system oauth2 set-identity-claim-map github email email
```

**Success**: Prints `Claim map updated: 'login' → name for provider 'github'`
**Error (invalid netidm_attr)**: `Error: 'foo' is not a valid identity claim attribute. Use: name, displayname, email`

---

## Unchanged Commands (context only)

The following existing commands are unchanged but are used in the setup workflow for social providers:

- `netidm system oauth2 add-redirect-url <name> <url>` — add the Netidm callback URL
- `netidm system oauth2 delete <name>` — remove a provider (disables new logins; existing sessions unaffected)
- `netidm system oauth2 get <name>` — show provider config including new JIT fields
