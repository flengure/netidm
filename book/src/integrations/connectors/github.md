# GitHub Connector

The GitHub connector lets users authenticate with their GitHub account. It supports both
GitHub.com and self-hosted GitHub Enterprise. Users can be filtered by organisation or team
membership; groups from all orgs are surfaced as Netidm group claims.

## Prerequisites

Create an OAuth App in GitHub:

1. Go to **Settings → Developer settings → OAuth Apps → New OAuth App**.
2. Set **Authorization callback URL** to:
   `https://<your-netidm-domain>/ui/login/oauth2_landing`
3. Note the **Client ID** and generate a **Client Secret**.

## Creating the connector

```bash
netidm system oauth2 create-github \
    --name mygithub \
    --client-id  <CLIENT_ID> \
    --client-secret <CLIENT_SECRET>
```

Enable JIT provisioning so first-time GitHub users get a Netidm account:

```bash
netidm system oauth2 enable-jit-provisioning --name mygithub
```

## GitHub Enterprise

For a self-hosted GitHub Enterprise instance set the hostname (without scheme or path):

```bash
netidm system oauth2 github-set-hostname \
    --name mygithub \
    --hostname github.internal.example.com
```

## Restricting access by organisation

Without org filtering any GitHub user can authenticate. To require membership in one or more
organisations add each one:

```bash
netidm system oauth2 github-add-org --name mygithub --org my-org
```

Remove an org:

```bash
netidm system oauth2 github-remove-org --name mygithub --org my-org
```

List configured orgs:

```bash
netidm system oauth2 github-list-orgs --name mygithub
```

## Loading all groups

When no org filter is configured the connector only fetches the authenticated user's verified
email. Enable `load-all-groups` to retrieve all orgs and teams instead:

```bash
netidm system oauth2 github-enable-load-all-groups  --name mygithub
netidm system oauth2 github-disable-load-all-groups --name mygithub
```

## Use login name as stable ID

By default the connector uses the GitHub numeric user ID as the stable `sub` claim. To use the
GitHub login (username) instead:

```bash
netidm system oauth2 github-enable-use-login-as-id  --name mygithub
netidm system oauth2 github-disable-use-login-as-id --name mygithub
```

> Using the login as ID means account identity changes if the user renames their GitHub account.

## Preferred email domain

If a user has multiple verified emails, Netidm selects the first one. To prefer a specific
domain (supports `*` wildcard):

```bash
netidm system oauth2 github-set-preferred-email-domain \
    --name mygithub \
    --domain "*.example.com"
```

## Reference

| Attribute | CLI flag / command | Description |
|---|---|---|
| `connector_github_host` | `github-set-hostname --hostname` | GitHub Enterprise hostname |
| `connector_github_org_filter` | `github-add-org / github-remove-org` | Allowed organisations |
| `connector_github_load_all_groups` | `github-enable-load-all-groups` | Load all orgs/teams |
| `connector_github_use_login_as_id` | `github-enable-use-login-as-id` | Use login as `sub` |
| `connector_github_preferred_email_domain` | `github-set-preferred-email-domain --domain` | Preferred email domain |
| `connector_github_allow_jit_provisioning` | `enable-jit-provisioning` | Create accounts on first login |
