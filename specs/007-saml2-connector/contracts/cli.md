# Contract: CLI Commands — SAML Provider Management

## New Command: `netidm system saml-client create`

Creates a new SAML 2.0 IdP configuration.

### Arguments

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--name` | string | Yes | Provider name (must match `[a-z][a-z0-9_-]*`) |
| `--displayname` | string | Yes | Human-readable name for the SSO button |
| `--sso-url` | URL | Yes | IdP's HTTP-POST SSO endpoint |
| `--idp-cert` | path or PEM string | Yes | IdP X.509 signing certificate (path to PEM file) |
| `--entity-id` | URL | Yes | SP entity ID (our issuer in AuthnRequests) |
| `--acs-url` | URL | Yes | Assertion Consumer Service URL (where IdP POSTs response) |
| `--nameid-format` | string | No | NameID format URI (default: `unspecified`) |
| `--email-attr` | string | No | SAML attribute name containing the user's email |
| `--displayname-attr` | string | No | SAML attribute name containing the user's display name |
| `--groups-attr` | string | No | SAML attribute name containing group membership values |
| `--jit-provisioning` | bool | No | Enable/disable JIT account creation (default: `true`) |

### Behaviour

1. Read PEM certificate from the provided path (or inline PEM string)
2. Validate: certificate is parseable as X.509
3. Validate: `--sso-url`, `--entity-id`, `--acs-url` are valid URLs
4. Create the `SamlClient` entry
5. Print success message showing the registered provider name

### Error Cases

| Error | Message |
|-------|---------|
| Certificate file not found | `error: cannot read certificate file: <path>: <reason>` |
| Certificate is not valid X.509 PEM | `error: invalid X.509 certificate: <reason>` |
| Invalid URL argument | `error: invalid URL for <flag>: <value>` |
| Provider name already exists | `error: provider name already in use` |
| Missing required argument | `error: missing required argument: <flag>` |

### Example

```sh
netidm system saml-client create \
  --name corp-adfs \
  --displayname "Corporate ADFS" \
  --sso-url https://adfs.corp.example/adfs/ls \
  --idp-cert /etc/netidm/adfs-signing.pem \
  --entity-id https://netidm.corp.example/saml/sp \
  --acs-url https://netidm.corp.example/ui/login/saml/corp-adfs/acs \
  --email-attr http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress \
  --displayname-attr http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname \
  --groups-attr http://schemas.xmlsoap.org/claims/Group
```

---

## New Command: `netidm system saml-client get`

### Arguments

| Argument | Description |
|----------|-------------|
| `<name>` | Provider name |

### Output

Displays all stored SAML provider attributes in tabular form.

---

## New Command: `netidm system saml-client list`

Lists all registered SAML providers: `name`, `display_name`, `sso_url`, `jit_provisioning`.

---

## New Command: `netidm system saml-client delete`

### Arguments

| Argument | Description |
|----------|-------------|
| `<name>` | Provider name to delete |

Removes the provider entry. Any subsequent SSO attempts via this provider will fail.

---

## New Command: `netidm system saml-client update-cert`

Updates the IdP signing certificate for an existing provider (certificate rotation).

### Arguments

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--name` | string | Yes | Provider name |
| `--idp-cert` | path | Yes | Path to new PEM certificate file |
