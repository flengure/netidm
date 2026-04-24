#!/usr/bin/env bash
# Example: Bitbucket Cloud upstream connector
#
# Prerequisites:
#   Create an OAuth consumer in Bitbucket:
#   Workspace Settings > OAuth consumers > Add consumer
#   Callback URL: https://<your-netidm-domain>/ui/login/oauth2_landing
#   Permissions needed: Account: Read, Email: Read

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=bitbucket
CLIENT_ID=<CONSUMER_KEY>
CLIENT_SECRET=<CONSUMER_SECRET>

$NETIDM system oauth2 create-bitbucket \
    --name "$NAME" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET"

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

# Optional: restrict to specific workspaces
# NETIDM_URL=https://idm.example.com
# TOKEN=<ADMIN_BEARER_TOKEN>
# curl -s -X PATCH "$NETIDM_URL/v1/oauth2/_client/$NAME" \
#   -H "Authorization: Bearer $TOKEN" \
#   -H "Content-Type: application/json" \
#   -d '{"connector_bitbucket_teams": ["my-workspace"]}'

$NETIDM system oauth2 connector-list
