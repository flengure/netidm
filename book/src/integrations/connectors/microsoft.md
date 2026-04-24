# Microsoft / Entra ID Connector

The Microsoft connector authenticates users via Azure Active Directory (Entra ID) using the
Microsoft identity platform. It supports single-tenant, multi-tenant, and consumer account
configurations and can retrieve security group memberships via the Microsoft Graph API.

## Prerequisites

1. Register an application in the [Azure portal](https://portal.azure.com/) under
   **Azure Active Directory → App registrations → New registration**.
2. Set the **Redirect URI** to:
   `https://<your-netidm-domain>/ui/login/oauth2_landing`
3. Under **Certificates & secrets**, create a **Client secret**.
4. Note the **Application (client) ID** and the **Directory (tenant) ID**.
5. Grant the `User.Read` Microsoft Graph permission (delegated).

## Creating the connector

```bash
netidm system oauth2 create-microsoft \
    --name myazure \
    --tenant <TENANT_ID_OR_common> \
    --client-id <CLIENT_ID> \
    --client-secret <CLIENT_SECRET>
```

Use `--tenant common` to allow any Microsoft account (personal or organisational).
Use the actual tenant ID (UUID) or the tenant domain name to restrict to one organisation.

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name myazure
```

## Security group membership

To fetch security group memberships, grant the `GroupMember.Read.All` Graph permission and
set the corresponding attribute:

```bash
# PATCH /v1/oauth2/_client/myazure
# { "connector_microsoft_only_security_groups": "true" }
```

By default group claims contain the group display name. To use the object ID instead:

```bash
# { "connector_microsoft_group_name_format": "id" }
```

## Filtering to specific groups

To allow only users who belong to certain groups:

```bash
# {
#   "connector_microsoft_groups": ["Engineering", "DevOps"],
#   "connector_microsoft_use_groups_as_whitelist": "true"
# }
```

## Reference

| Attribute | Description |
|---|---|
| `connector_microsoft_tenant` | Tenant ID, domain, `common`, `organizations`, or `consumers` |
| `connector_microsoft_only_security_groups` | Include only security groups |
| `connector_microsoft_groups` | Required groups (multi-value) |
| `connector_microsoft_group_name_format` | `name` (default) or `id` |
| `connector_microsoft_use_groups_as_whitelist` | Return only matched groups |
| `connector_microsoft_email_to_lowercase` | Normalise email to lowercase |
| `connector_microsoft_api_url` | Azure login URL (default: `https://login.microsoftonline.com`) |
| `connector_microsoft_graph_url` | Graph API URL (default: `https://graph.microsoft.com`) |
| `connector_microsoft_prompt_type` | OAuth `prompt` parameter |
| `connector_microsoft_domain_hint` | Azure `domain_hint` parameter |
| `connector_microsoft_scopes` | Additional OAuth scopes (default: `user.read`) |
| `connector_microsoft_preferred_username_field` | Field for preferred_username: `name`, `email`, `mailNickname`, `onPremisesSamAccountName` |
