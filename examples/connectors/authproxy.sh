#!/usr/bin/env bash
# Example: Auth Proxy connector (trust headers from a reverse proxy)
#
# The reverse proxy (nginx, Apache, oauth2-proxy) must inject identity headers
# and Netidm must NOT be reachable without passing through the proxy.

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=myproxy
NETIDM_URL=https://idm.example.com
TOKEN=<ADMIN_BEARER_TOKEN>

# Create with the required username header
$NETIDM system oauth2 create-authproxy \
    --name "$NAME" \
    --user-header "X-Auth-Request-User"

# Set optional email and groups headers
curl -s -X PATCH "$NETIDM_URL/v1/oauth2/_client/$NAME" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"connector_authproxy_email_header":  "X-Auth-Request-Email",
       "connector_authproxy_groups_header": "X-Auth-Request-Groups"}'

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

$NETIDM system oauth2 connector-list
