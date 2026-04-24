# Atlassian Crowd Connector

The Crowd connector authenticates users against an Atlassian Crowd server using the Crowd
REST API. It presents a username/password prompt, delegates authentication to Crowd, and
resolves nested group memberships into group claims.

## Prerequisites

- A Crowd application configured to allow authentication for your users.
- The Crowd application name and password.
- The Crowd REST API base URL including the context path (e.g.
  `https://crowd.example.com/crowd`).

To create a Crowd application:

1. Log in to Crowd as an administrator.
2. Go to **Applications → Add application**.
3. Choose **Generic application**, give it a name and password.
4. Add the Netidm server IP/hostname to the **Remote addresses** allowlist.
5. On the **Directories** tab, select the directories whose users should be able to
   authenticate.

## Creating the connector

```bash
netidm system oauth2 create-crowd \
    --name mycrowd \
    --base-url https://crowd.example.com/crowd \
    --client-name netidm-app \
    --client-secret <APPLICATION_PASSWORD>
```

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name mycrowd
```

## Restricting by group

To allow only users who belong to specific Crowd groups, set `connector_crowd_groups`:

```bash
# PATCH /v1/oauth2/_client/mycrowd
# { "connector_crowd_groups": ["developers", "ops"] }
```

Group membership is resolved recursively (nested groups are expanded).

## Reference

| Attribute | Description |
|---|---|
| `connector_crowd_base_url` | Crowd REST API base URL including context path |
| `connector_crowd_client_name` | Crowd application login name |
| `connector_crowd_client_secret` | Crowd application password |
| `connector_crowd_groups` | Required Crowd groups (multi-value, nested groups expanded) |
