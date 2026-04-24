#!/usr/bin/env bash
# Example: Atlassian Crowd upstream connector
#
# Prerequisites:
#   Create a Crowd application (Admin > Applications > Add Application)
#   Application type: Generic application
#   Add the Netidm server to the Remote Addresses allowlist.

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=crowd
CROWD_BASE_URL=https://crowd.example.com/crowd
CLIENT_NAME=netidm-app
CLIENT_SECRET=<CROWD_APP_PASSWORD>

$NETIDM system oauth2 create-crowd \
    --name "$NAME" \
    --base-url "$CROWD_BASE_URL" \
    --client-name "$CLIENT_NAME" \
    --client-secret "$CLIENT_SECRET"

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

# Optional: restrict to specific Crowd groups
# NETIDM_URL=https://idm.example.com
# TOKEN=<ADMIN_BEARER_TOKEN>
# curl -s -X PATCH "$NETIDM_URL/v1/oauth2/_client/$NAME" \
#   -H "Authorization: Bearer $TOKEN" \
#   -H "Content-Type: application/json" \
#   -d '{"connector_crowd_groups": ["developers", "ops"]}'

$NETIDM system oauth2 connector-list
