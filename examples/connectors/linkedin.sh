#!/usr/bin/env bash
# Example: LinkedIn upstream connector
#
# Prerequisites:
#   Create an application at https://www.linkedin.com/developers/apps/new
#   Under Auth, add redirect URL: https://<your-netidm-domain>/ui/login/oauth2_landing
#   Request permissions: r_liteprofile, r_emailaddress (or openid, profile, email)

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=linkedin
CLIENT_ID=<YOUR_CLIENT_ID>
CLIENT_SECRET=<YOUR_CLIENT_SECRET>

$NETIDM system oauth2 create-linkedin \
    --name "$NAME" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET"

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

$NETIDM system oauth2 connector-list
