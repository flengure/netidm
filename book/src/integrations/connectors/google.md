# Google Connector

The Google connector authenticates users via Google's OpenID Connect provider. It supports
restricting access to specific Google Workspace (formerly G Suite) domains and can fetch
Google Workspace group memberships using the Admin Directory API.

## Prerequisites

1. Create a project in [Google Cloud Console](https://console.cloud.google.com/).
2. Enable the **Google Identity** API.
3. Under **APIs & Services → Credentials**, create an **OAuth 2.0 Client ID** of type
   *Web application*.
4. Add `https://<your-netidm-domain>/ui/login/oauth2_landing` as an authorised redirect URI.
5. Note the **Client ID** and **Client Secret**.

## Creating the connector

```bash
netidm system oauth2 create-google \
    --name mygoogle \
    --client-id  <CLIENT_ID> \
    --client-secret <CLIENT_SECRET>
```

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name mygoogle
```

## Restricting to a hosted domain

To allow only users from a specific Google Workspace domain, set the
`connector_google_hosted_domain` attribute (multi-value) via the REST API:

```bash
# PATCH /v1/oauth2/_client/mygoogle
# { "connector_google_hosted_domain": ["example.com"] }
```

## Fetching Google Workspace groups

To retrieve the user's Google Workspace group memberships, the connector needs a service
account with domain-wide delegation:

1. Create a **Service Account** in Google Cloud Console and download the JSON key file.
2. Grant the service account **domain-wide delegation** with scope
   `https://www.googleapis.com/auth/admin.directory.group.readonly`.
3. Set the service account JSON and the admin email used for impersonation:

```bash
# PATCH /v1/oauth2/_client/mygoogle
# {
#   "connector_google_service_account_json": "<contents of JSON key file>",
#   "connector_google_admin_email": "admin@example.com",
#   "connector_google_fetch_groups": "true"
# }
```

## Reference

| Attribute | Description |
|---|---|
| `connector_google_hosted_domain` | Allowed Google Workspace domains (multi-value) |
| `connector_google_service_account_json` | Service account JSON for Directory API access |
| `connector_google_admin_email` | Admin email for service account impersonation |
| `connector_google_fetch_groups` | Enable group membership fetching |
