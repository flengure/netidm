#!/usr/bin/env bash
# Example: Generic OIDC upstream connector (Okta, Auth0, Keycloak, Dex, ...)
#
# Prerequisites:
#   Create an OAuth2 / OIDC web application in your provider.
#   Redirect URI: https://<your-netidm-domain>/ui/login/oauth2_landing
#   The ISSUER is the base of the /.well-known/openid-configuration URL.

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=myoidc
ISSUER=https://accounts.example.com
CLIENT_ID=<YOUR_CLIENT_ID>
CLIENT_SECRET=<YOUR_CLIENT_SECRET>

$NETIDM system oauth2 create-oidc \
    --name "$NAME" \
    --issuer "$ISSUER" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET"

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

# Optional: enable group claim parsing
# NETIDM_URL=https://idm.example.com
# TOKEN=<ADMIN_BEARER_TOKEN>
# curl -s -X PATCH "$NETIDM_URL/v1/oauth2/_client/$NAME" \
#   -H "Authorization: Bearer $TOKEN" \
#   -H "Content-Type: application/json" \
#   -d '{"connector_oidc_enable_groups": "true",
#        "connector_oidc_groups_key": "groups"}'

$NETIDM system oauth2 connector-list
