# GitLab Connector

The GitLab connector lets users authenticate with their GitLab account on GitLab.com or a
self-hosted GitLab instance. Membership in GitLab groups can be required and surfaced as
claims.

## Prerequisites

Create an OAuth application in GitLab:

1. Go to **User settings → Applications** (or **Admin area → Applications** for instance-wide).
2. Set **Redirect URI** to:
   `https://<your-netidm-domain>/ui/login/oauth2_landing`
3. Grant the `read_user` and `openid` scopes.
4. Note the **Application ID** (client ID) and **Secret**.

## Creating the connector

```bash
netidm system oauth2 create-gitlab \
    --name mygitlab \
    --client-id  <APPLICATION_ID> \
    --client-secret <SECRET>
```

By default the connector targets GitLab.com. For a self-hosted instance pass `--base-url`:

```bash
netidm system oauth2 create-gitlab \
    --name mygitlab \
    --base-url https://gitlab.internal.example.com \
    --client-id  <APPLICATION_ID> \
    --client-secret <SECRET>
```

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name mygitlab
```

## Restricting by group membership

To require that a user belongs to at least one of a set of GitLab groups, add the groups
using the REST API (PATCH `/v1/oauth2/_client/mygitlab`) with the `connector_gitlab_groups`
attribute, or use the generic entry patch command.

## Use login name as stable ID

By default the connector uses the GitLab numeric user ID as the stable `sub` claim. To use
the GitLab username instead, patch the entry:

```bash
# Via REST API — set connector_gitlab_use_login_as_id = true
```

## Group permission suffixes

When `connector_gitlab_get_groups_permission` is set, group claims include the user's
permission level as a suffix (`owner`, `maintainer`, `developer`, etc.):

```
mygroup:owner
myteam:developer
```

## Reference

| Attribute | Description |
|---|---|
| `connector_gitlab_base_url` | GitLab instance URL (default: `https://gitlab.com`) |
| `connector_gitlab_groups` | Groups the user must belong to (multi-value) |
| `connector_gitlab_use_login_as_id` | Use username as `sub` instead of numeric ID |
| `connector_gitlab_get_groups_permission` | Append `:role` suffix to group claims |
| `connector_gitlab_root_ca` | PEM CA certificate for self-signed GitLab TLS |
