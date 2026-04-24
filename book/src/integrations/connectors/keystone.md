# OpenStack Keystone Connector

The Keystone connector authenticates users against an OpenStack Keystone v3 identity service.
It presents a username/password prompt, authenticates via the Keystone token API, and resolves
the user's project and role assignments into group claims.

An admin credential is required so Netidm can look up users and groups on behalf of the
authenticating account.

## Prerequisites

- A Keystone v3 endpoint reachable from the Netidm server.
- An admin user with permission to query `/v3/users` and `/v3/role_assignments`.

## Creating the connector

```bash
netidm system oauth2 create-keystone \
    --name mykeystone \
    --host https://keystone.example.com:5000
```

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name mykeystone
```

## Admin credentials and domain

The connector requires admin credentials to look up group memberships. Set these via the
REST API:

```bash
# PATCH /v1/oauth2/_client/mykeystone
# {
#   "connector_keystone_domain": "default",
#   "connector_keystone_admin_username": "admin",
#   "connector_keystone_admin_password": "secret"
# }
```

`connector_keystone_domain` may be a domain UUID or the name `default`. When it looks like a
UUID it is treated as a domain ID; otherwise it is resolved by name.

## Restricting by group

To allow only users who belong to specific Keystone groups or projects:

```bash
# PATCH /v1/oauth2/_client/mykeystone
# { "connector_keystone_groups": ["developers", "ops"] }
```

## TLS

For a Keystone endpoint with a self-signed certificate:

```bash
# { "connector_keystone_insecure_ca": "true" }
```

## Reference

| Attribute | Description |
|---|---|
| `connector_keystone_host` | Keystone v3 endpoint URL |
| `connector_keystone_domain` | Domain UUID or name for user lookup |
| `connector_keystone_groups` | Required groups / projects (multi-value) |
| `connector_keystone_insecure_ca` | Skip TLS certificate verification |
