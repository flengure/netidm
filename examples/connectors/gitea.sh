#!/usr/bin/env bash
# Example: Gitea upstream connector (self-hosted Gitea instance)
#
# Prerequisites:
#   Create an OAuth2 application in Gitea:
#   User Settings > Applications > Manage OAuth2 Applications
#   Redirect URI: https://<your-netidm-domain>/ui/login/oauth2_landing

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=gitea
BASE_URL=https://gitea.internal.example.com
CLIENT_ID=<YOUR_CLIENT_ID>
CLIENT_SECRET=<YOUR_CLIENT_SECRET>

$NETIDM system oauth2 create-gitea \
    --name "$NAME" \
    --base-url "$BASE_URL" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET"

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

# Optional: restrict to specific organisations or org:team pairs
# NETIDM_URL=https://idm.example.com
# TOKEN=<ADMIN_BEARER_TOKEN>
# curl -s -X PATCH "$NETIDM_URL/v1/oauth2/_client/$NAME" \
#   -H "Authorization: Bearer $TOKEN" \
#   -H "Content-Type: application/json" \
#   -d '{"connector_gitea_groups": ["my-org", "my-org:developers"]}'

$NETIDM system oauth2 connector-list
