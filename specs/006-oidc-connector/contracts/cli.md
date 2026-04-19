# Contract: CLI Commands — OIDC Provider Management

## New Command: `netidm system oauth2-client create-oidc`

Creates a new OIDC upstream provider by fetching the discovery document from `--issuer`.

### Arguments

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--name` | string | Yes | Provider name (must match `[a-z][a-z0-9_-]*`) |
| `--issuer` | URL | Yes | OIDC issuer base URL (e.g., `https://dev-xxx.okta.com`) |
| `--client-id` | string | Yes | OAuth2 client ID from the provider |
| `--client-secret` | string | Yes | OAuth2 client secret from the provider |
| `--displayname` | string | No | Human-readable name for the SSO button (defaults to `--name`) |

### Behaviour

1. Fetch `<issuer>/.well-known/openid-configuration`
2. Validate: `authorization_endpoint` and `token_endpoint` MUST be present
3. Validate: response `issuer` MUST match the provided `--issuer` URL
4. Create entry with all discovered endpoints + `issuer` + `jwks_uri` (if present in discovery doc)
5. Print success or error with the specific discovery failure reason

### Error Cases

| Error | Message |
|-------|---------|
| Discovery URL unreachable | `error: failed to fetch OIDC discovery document from <url>: <reason>` |
| Missing `authorization_endpoint` | `error: discovery document missing required field: authorization_endpoint` |
| Missing `token_endpoint` | `error: discovery document missing required field: token_endpoint` |
| Issuer mismatch | `error: issuer in discovery document does not match provided issuer` |
| Provider name already exists | `error: provider name already in use` |

### Example

```sh
netidm system oauth2-client create-oidc \
  --name my-okta \
  --issuer https://dev-xxx.okta.com \
  --client-id 0oa1b2c3d4e5f6 \
  --client-secret s3cr3t
```

---

## Existing Commands (unchanged, verified compatible)

All existing `oauth2-client` subcommands (list, get, delete, enable/disable JIT, enable/disable email-link, set-claim-map, set-logo-uri) work on OIDC providers without modification since they operate on the `OAuth2Client` entry by name.

The `list` command shows OIDC providers in its output alongside GitHub/Google providers.
