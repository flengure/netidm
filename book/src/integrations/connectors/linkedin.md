# LinkedIn Connector

The LinkedIn connector authenticates users via LinkedIn using OAuth2. It retrieves the user's
profile name and primary email address. LinkedIn does not expose group or organisation
membership via its OAuth2 API so no group claims are available.

## Prerequisites

Create a LinkedIn application:

1. Go to [LinkedIn Developer Portal](https://www.linkedin.com/developers/apps/new) and create
   a new application.
2. Under **Auth**, add `https://<your-netidm-domain>/ui/login/oauth2_landing` as an
   **Authorized Redirect URL**.
3. Request the `r_liteprofile` and `r_emailaddress` product permissions (or `openid`,
   `profile`, `email` if using Sign In with LinkedIn v2).
4. Note the **Client ID** and **Client Secret**.

## Creating the connector

```bash
netidm system oauth2 create-linkedin \
    --name mylinkedin \
    --client-id  <CLIENT_ID> \
    --client-secret <CLIENT_SECRET>
```

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name mylinkedin
```

## Notes

- LinkedIn does not provide email verification status; Netidm treats all LinkedIn emails as
  verified.
- LinkedIn does not surface group or organisation data via its OAuth2 API. Group-based access
  control is not available with this connector.
