#!/usr/bin/env bash
# Example: Microsoft Entra ID / Azure AD upstream connector
#
# Prerequisites:
#   Register an app at https://portal.azure.com > Azure Active Directory > App registrations
#   Redirect URI (Web): https://<your-netidm-domain>/ui/login/oauth2_landing
#   API permissions: Microsoft Graph > User.Read (delegated)

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=azure
TENANT=<YOUR_TENANT_ID>            # tenant UUID, or "common" for multi-tenant
CLIENT_ID=<YOUR_CLIENT_ID>
CLIENT_SECRET=<YOUR_CLIENT_SECRET>

$NETIDM system oauth2 create-microsoft \
    --name "$NAME" \
    --tenant "$TENANT" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET"

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

# Optional: restrict to security groups only and require specific groups
# NETIDM_URL=https://idm.example.com
# TOKEN=<ADMIN_BEARER_TOKEN>
# curl -s -X PATCH "$NETIDM_URL/v1/oauth2/_client/$NAME" \
#   -H "Authorization: Bearer $TOKEN" \
#   -H "Content-Type: application/json" \
#   -d '{"connector_microsoft_only_security_groups": "true",
#        "connector_microsoft_groups": ["Engineering", "DevOps"]}'

$NETIDM system oauth2 connector-list
