# Social Login (JIT Provisioning)

Kanidm can act as an OAuth2 client to external identity providers such as GitHub and Google. When a
user authenticates via one of these providers for the first time, Kanidm can automatically create a
local account — this is called Just-In-Time (JIT) provisioning.

## Prerequisites

- A GitHub OAuth App or Google OAuth Client configured with the Kanidm callback URL:
  `https://<your-kanidm-domain>/ui/login/oauth2_landing`
- The `client_id` and `client_secret` from the provider.

## Configuring a GitHub Provider

```bash
kanidm system oauth2 create-github \
    --name mygithub \
    --client-id <YOUR_GITHUB_CLIENT_ID> \
    --client-secret <YOUR_GITHUB_CLIENT_SECRET>
```

Then enable JIT provisioning so that first-time GitHub users get a Kanidm account automatically:

```bash
kanidm system oauth2 enable-jit-provisioning --name mygithub
```

## Configuring a Google Provider

```bash
kanidm system oauth2 create-google \
    --name mygoogle \
    --client-id <YOUR_GOOGLE_CLIENT_ID> \
    --client-secret <YOUR_GOOGLE_CLIENT_SECRET>
```

Enable JIT provisioning:

```bash
kanidm system oauth2 enable-jit-provisioning --name mygoogle
```

## Mapping Identity Claims

By default, Kanidm uses the provider's standard claim names (`name`, `email`) to populate the new
account. You can override the claim names used for each Kanidm attribute:

```bash
# Map the provider's "display_name" claim to Kanidm's displayname attribute
kanidm system oauth2 set-identity-claim-map \
    --name mygithub \
    --kanidm-attr displayname \
    --provider-claim display_name
```

Supported `--kanidm-attr` values: `name`, `displayname`, `mail`.

## Disabling JIT Provisioning

```bash
kanidm system oauth2 disable-jit-provisioning --name mygithub
```

When JIT provisioning is disabled, only users with a pre-existing Kanidm account linked to the
provider can sign in via social login.

## Verifying the Configuration

```bash
kanidm system oauth2 get --name mygithub
```

The output includes `oauth2_jit_provisioning`, `oauth2_userinfo_endpoint`, and any configured
claim maps.
