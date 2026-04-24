# Gitea Connector

The Gitea connector authenticates users via OAuth2 against a self-hosted Gitea instance.
It supports organisation and team-based access control using the Gitea API.

## Prerequisites

Create an OAuth2 application in Gitea:

1. Go to **User settings → Applications → Manage OAuth2 Applications**.
2. Set **Redirect URI** to:
   `https://<your-netidm-domain>/ui/login/oauth2_landing`
3. Note the **Client ID** and **Client Secret**.

## Creating the connector

```bash
netidm system oauth2 create-gitea \
    --name mygitea \
    --base-url https://gitea.internal.example.com \
    --client-id  <CLIENT_ID> \
    --client-secret <CLIENT_SECRET>
```

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name mygitea
```

## Restricting by organisation or team

To require membership in a specific organisation, set `connector_gitea_groups` to the
organisation name(s) via the REST API:

```bash
# PATCH /v1/oauth2/_client/mygitea
# { "connector_gitea_groups": ["my-org"] }
```

Team-level access is expressed as `org:team` strings:

```bash
# { "connector_gitea_groups": ["my-org:developers"] }
```

## Loading all groups

When no groups filter is configured, only the user's identity is fetched. Enable
`load_all_groups` to retrieve all org and team memberships:

```bash
# PATCH /v1/oauth2/_client/mygitea
# { "connector_gitea_load_all_groups": "true" }
```

## Use login name as stable ID

By default the connector uses the Gitea numeric user ID as the stable `sub` claim. To use
the Gitea username instead:

```bash
# PATCH /v1/oauth2/_client/mygitea
# { "connector_gitea_use_login_as_id": "true" }
```

## Custom CA certificate

For self-signed TLS:

```bash
# { "connector_gitea_root_ca": "<PEM certificate>" }
# or for development: { "connector_gitea_insecure_ca": "true" }
```

## Reference

| Attribute | Description |
|---|---|
| `connector_gitea_base_url` | Gitea instance base URL (default: `https://gitea.com`) |
| `connector_gitea_groups` | Required organisations or `org:team` pairs (multi-value) |
| `connector_gitea_load_all_groups` | Fetch all org/team memberships |
| `connector_gitea_use_login_as_id` | Use username as `sub` instead of numeric ID |
| `connector_gitea_insecure_ca` | Skip TLS certificate verification |
| `connector_gitea_root_ca` | PEM CA certificate for self-signed TLS |
