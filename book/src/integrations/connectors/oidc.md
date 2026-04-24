# Generic OIDC Connector

The generic OIDC connector works with any provider that implements OpenID Connect discovery
(RFC 8414). Use this connector for providers that do not have a dedicated connector — Okta,
Auth0, Keycloak, Ping Identity, Dex itself, and many others.

## Prerequisites

In your OIDC provider:

1. Create a new **OAuth2 / OIDC application** of type *web*.
2. Set the **Redirect URI** to:
   `https://<your-netidm-domain>/ui/login/oauth2_landing`
3. Note the **issuer URL**, **client ID**, and **client secret**.

The issuer URL is the base of the `.well-known/openid-configuration` discovery document,
e.g. `https://accounts.example.com` (not the full discovery URL).

## Creating the connector

```bash
netidm system oauth2 create-oidc \
    --name myoidc \
    --issuer https://accounts.example.com \
    --client-id  <CLIENT_ID> \
    --client-secret <CLIENT_SECRET>
```

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name myoidc
```

## Group claims

Most OIDC providers do not include groups in the standard token by default. Enable group
claim parsing and specify the claim key:

```bash
# PATCH /v1/oauth2/_client/myoidc
# {
#   "connector_oidc_enable_groups": "true",
#   "connector_oidc_groups_key": "groups"
# }
```

Filter to allowed groups only:

```bash
# { "connector_oidc_allowed_groups": ["engineering", "devops"] }
```

## Userinfo endpoint

Some providers deliver additional claims only via the userinfo endpoint. Enable fetching:

```bash
# { "connector_oidc_get_user_info": "true" }
```

## Custom claim keys

Override which claims carry the user ID and display name:

```bash
# {
#   "connector_oidc_user_id_key": "sub",
#   "connector_oidc_user_name_key": "preferred_username"
# }
```

## Skipping email verification

Some providers do not set `email_verified: true` even for verified emails. Override:

```bash
# { "connector_oidc_skip_email_verified": "true" }
```

## Group name prefix / suffix

Add a prefix or suffix to all group names received from the provider:

```bash
# {
#   "connector_oidc_groups_prefix": "oidc-",
#   "connector_oidc_groups_suffix": ""
# }
```

## Reference

| Attribute | Description |
|---|---|
| `connector_oidc_enable_groups` | Parse group claims from the token |
| `connector_oidc_groups_key` | JWT claim key for groups (default: `groups`) |
| `connector_oidc_skip_email_verified` | Accept unverified emails |
| `connector_oidc_allowed_groups` | Only permit users in these groups (multi-value) |
| `connector_oidc_get_user_info` | Fetch additional claims from userinfo endpoint |
| `connector_oidc_user_id_key` | Claim key for stable user ID (default: `sub`) |
| `connector_oidc_user_name_key` | Claim key for display name (default: `name`) |
| `connector_oidc_override_claim_mapping` | Enforce custom claim mappings |
| `connector_oidc_groups_prefix` | Prefix added to every group name |
| `connector_oidc_groups_suffix` | Suffix added to every group name |
