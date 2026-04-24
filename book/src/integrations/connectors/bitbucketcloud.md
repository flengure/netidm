# Bitbucket Cloud Connector

The Bitbucket Cloud connector authenticates users via Atlassian Bitbucket Cloud using OAuth2.
Users can be restricted to members of specific workspaces, and workspace-level permission
suffixes (`owner`, `member`) can be included in group claims.

## Prerequisites

Create an OAuth consumer in Bitbucket:

1. Go to **Workspace settings → OAuth consumers → Add consumer**.
2. Set **Callback URL** to:
   `https://<your-netidm-domain>/ui/login/oauth2_landing`
3. Grant the **Account: Read** and **Email: Read** permissions.
4. Note the **Key** (client ID) and **Secret** (client secret).

## Creating the connector

```bash
netidm system oauth2 create-bitbucket \
    --name mybitbucket \
    --client-id  <KEY> \
    --client-secret <SECRET>
```

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name mybitbucket
```

## Restricting by workspace membership

To require that a user belongs to at least one of a set of Bitbucket workspaces, set the
`connector_bitbucket_teams` attribute (multi-value) via the REST API:

```bash
# PATCH /v1/oauth2/_client/mybitbucket
# { "connector_bitbucket_teams": ["my-workspace", "another-workspace"] }
```

## Workspace permission suffixes

When `connector_bitbucket_get_workspace_permissions` is enabled, group claims include the
user's role as a suffix (`owner` or `member`):

```
my-workspace:owner
another-workspace:member
```

Enable via the REST API:

```bash
# PATCH /v1/oauth2/_client/mybitbucket
# { "connector_bitbucket_get_workspace_permissions": "true" }
```

## Reference

| Attribute | Description |
|---|---|
| `connector_bitbucket_teams` | Required workspaces (multi-value) |
| `connector_bitbucket_get_workspace_permissions` | Append `:owner`/`:member` suffix to workspace claims |
