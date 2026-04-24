# Upstream Identity Connectors

Netidm can act as a federation hub by connecting to external identity providers. When a user
authenticates through an upstream provider the connector retrieves their identity claims (name,
email, groups) and — if Just-In-Time (JIT) provisioning is enabled — automatically creates a
local account on first login.

## Connector types

| Connector | Provider | Auth flow | Group support |
|-----------|----------|-----------|---------------|
| [GitHub](github.md) | GitHub / GitHub Enterprise | OAuth2 | Orgs + Teams |
| [GitLab](gitlab.md) | GitLab.com / self-hosted | OAuth2 | Groups + permissions |
| [Google](google.md) | Google Workspace | OIDC | Directory groups |
| [Microsoft / Entra](microsoft.md) | Azure AD / Entra ID | OAuth2 | Security groups |
| [Generic OIDC](oidc.md) | Any OIDC provider | OIDC | Custom claim |
| [LDAP](ldap.md) | OpenLDAP, AD, etc. | Direct bind | Group search |
| [SAML 2.0](saml.md) | Any SAML 2.0 IdP | SAML POST | Assertion attribute |
| [Bitbucket Cloud](bitbucketcloud.md) | Atlassian Bitbucket Cloud | OAuth2 | Workspaces |
| [OpenShift](openshift.md) | OpenShift OAuth2 | OAuth2 | OpenShift groups |
| [LinkedIn](linkedin.md) | LinkedIn | OAuth2 | — |
| [Auth Proxy](authproxy.md) | Reverse proxy header | Header trust | Header groups |
| [Gitea](gitea.md) | Gitea (self-hosted) | OAuth2 | Orgs + Teams |
| [OpenStack Keystone](keystone.md) | OpenStack Keystone v3 | Password | Role assignments |
| [Atlassian Crowd](atlassiancrowd.md) | Atlassian Crowd | Password | Nested groups |

## Common concepts

### Connector name

Every connector is created with a short `--name`. This name appears in the login picker URL
(`/ui/sso/<name>`) and is used in all subsequent CLI operations.

### JIT provisioning

JIT provisioning creates a local Netidm account the first time a user authenticates via a
connector. Without it, only users with a pre-existing account can log in through a connector.

```bash
netidm system oauth2 enable-jit-provisioning --name <connector-name>
```

### Listing and deleting connectors

```bash
# List all configured connectors
netidm system oauth2 connector-list

# Delete a connector (irreversible — invalidates active sessions)
netidm system oauth2 connector-delete <connector-name>
```

### Group mapping

After a connector delivers group claims, you can map upstream group names to Netidm groups:

```bash
netidm system oauth2 update-scope-map \
    --name <connector-name> \
    --group <netidm-group> \
    <scope>
```

See the individual connector pages for provider-specific group configuration.
