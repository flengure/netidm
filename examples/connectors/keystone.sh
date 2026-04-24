#!/usr/bin/env bash
# Example: OpenStack Keystone v3 upstream connector

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=keystone
KEYSTONE_HOST=https://keystone.example.com:5000
NETIDM_URL=https://idm.example.com
TOKEN=<ADMIN_BEARER_TOKEN>

$NETIDM system oauth2 create-keystone \
    --name "$NAME" \
    --host "$KEYSTONE_HOST"

# Set Keystone domain and admin credentials
curl -s -X PATCH "$NETIDM_URL/v1/oauth2/_client/$NAME" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"connector_keystone_domain":           "default",
       "connector_keystone_admin_username":   "admin",
       "connector_keystone_admin_password":   "<ADMIN_PASSWORD>"}'

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

$NETIDM system oauth2 connector-list
