# Migrating from Dex

Netidm subsumes dex as a federation layer. If you have an existing dex deployment you can
migrate its state — connectors, OAuth2 clients, user identities, and active sessions — into
Netidm using the `netidm-dex-migrate` tool.

## What migrates

| Dex object | Netidm equivalent | Tool action |
|---|---|---|
| `connectors` | `Connector` entries | Create via API |
| `oauth2clients` | `OAuth2ResourceServer` entries | Create via API |
| `passwords` | `Person` entries + credential transplant | Internal API |
| `user_identities` | `ProviderIdentity` entries | Create via API |
| `offline_sessions` + `refresh_tokens` | `Oauth2Session` values on Person entries | Translate blob |
| `auth_requests`, `auth_codes` | Memory-only — **skipped** | — |
| `device_*` | Out of scope — **skipped** | — |
| `keys` | Netidm manages keys — **skipped**, regenerated | — |

## Before you begin

1. Ensure Netidm is running and reachable.
2. Obtain an admin bearer token for Netidm:
   ```bash
   netidm self auth --name admin | jq -r .token
   ```
3. Locate your dex SQLite database (typically `/var/dex/dex.db`).

## Running the migration

```bash
netidm-dex-migrate \
    --dex-db /var/dex/dex.db \
    --netidm-url https://idm.example.com \
    --token <ADMIN_BEARER_TOKEN>
```

Dry-run mode shows what would be created without making any changes:

```bash
netidm-dex-migrate --dry-run \
    --dex-db /var/dex/dex.db \
    --netidm-url https://idm.example.com \
    --token <ADMIN_BEARER_TOKEN>
```

Skip specific tables if you want to migrate in stages:

```bash
netidm-dex-migrate \
    --skip passwords \
    --skip sessions \
    ...
```

## After migration

1. **Verify connectors**: `netidm system oauth2 connector-list`
2. **Verify clients**: `netidm system oauth2 list`
3. **Update redirect URIs**: dex uses `/callback`; Netidm uses
   `/ui/login/oauth2_landing`. Update your OAuth2 clients at the provider side.
4. **Update issuer URLs**: point your OIDC relying parties to Netidm's issuer.
5. **Test a login** through each connector before decommissioning dex.

## Connector type mapping

Dex connector types map to Netidm connector create commands as follows:

| Dex type | Netidm command |
|---|---|
| `github` | `netidm system oauth2 create-github` |
| `gitlab` | `netidm system oauth2 create-gitlab` |
| `google` | `netidm system oauth2 create-google` |
| `microsoft` | `netidm system oauth2 create-microsoft` |
| `oidc` | `netidm system oauth2 create-oidc` |
| `ldap` | `netidm system oauth2 create-ldap` |
| `saml` | `netidm system saml-client create` |
| `bitbucketcloud` | `netidm system oauth2 create-bitbucket` |
| `openshift` | `netidm system oauth2 create-openshift` |
| `linkedin` | `netidm system oauth2 create-linkedin` |
| `authproxy` | `netidm system oauth2 create-authproxy` |
| `gitea` | `netidm system oauth2 create-gitea` |
| `keystone` | `netidm system oauth2 create-keystone` |
| `atlassiancrowd` | `netidm system oauth2 create-crowd` |

## Configuration differences

| Dex config | Netidm equivalent |
|---|---|
| `issuer` in `server.toml` | `origin` in `server.toml` |
| `oauth2.skipApprovalScreen` | `oauth2.skip_approval_screen` (planned) |
| `oauth2.responseTypes` | Always `code` |
| `expiry.idTokens` | Controlled by token policy |
| `web.http` / `web.https` | `bindaddress` in `server.toml` |
| `staticClients[].redirectURIs` | `oauth2_rs_origin` on each resource server |

## Callback URL change

Dex uses `/callback` as its callback path. Netidm uses `/ui/login/oauth2_landing`. You must
update the **Authorized Redirect URI** in every upstream OAuth2 provider (GitHub, Google,
etc.) after migration.

For SAML connectors the assertion consumer service URL changes from dex's
`/callback` to Netidm's `/ui/login/saml2_landing`.
