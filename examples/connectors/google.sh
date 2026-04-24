#!/usr/bin/env bash
# Example: Google Workspace upstream connector
#
# Prerequisites:
#   Create OAuth 2.0 credentials at https://console.cloud.google.com/apis/credentials
#   Application type: Web application
#   Authorised redirect URI: https://<your-netidm-domain>/ui/login/oauth2_landing

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=google
CLIENT_ID=<YOUR_GOOGLE_CLIENT_ID>
CLIENT_SECRET=<YOUR_GOOGLE_CLIENT_SECRET>
HOSTED_DOMAIN=example.com           # restrict to this Workspace domain
NETIDM_URL=https://idm.example.com
TOKEN=<ADMIN_BEARER_TOKEN>

$NETIDM system oauth2 create-google \
    --name "$NAME" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET"

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

# Restrict to a specific Google Workspace domain
curl -s -X PATCH "$NETIDM_URL/v1/oauth2/_client/$NAME" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"connector_google_hosted_domain\": [\"$HOSTED_DOMAIN\"]}"

# Optional: fetch Google Workspace group memberships via Admin Directory API
# Requires a service account with domain-wide delegation.
# SERVICE_ACCOUNT_JSON=$(cat /path/to/service-account.json)
# ADMIN_EMAIL=admin@example.com
# curl -s -X PATCH "$NETIDM_URL/v1/oauth2/_client/$NAME" \
#   -H "Authorization: Bearer $TOKEN" \
#   -H "Content-Type: application/json" \
#   -d "{\"connector_google_service_account_json\": \"$SERVICE_ACCOUNT_JSON\",
#        \"connector_google_admin_email\": \"$ADMIN_EMAIL\",
#        \"connector_google_fetch_groups\": \"true\"}"

$NETIDM system oauth2 connector-list
