#!/usr/bin/env bash
# Example: OpenShift OAuth2 upstream connector
#
# Create the OAuthClient in OpenShift first:
#   oc apply -f - <<EOF
#   apiVersion: oauth.openshift.io/v1
#   kind: OAuthClient
#   metadata:
#     name: netidm
#   grantMethod: auto
#   redirectURIs:
#     - https://<your-netidm-domain>/ui/login/oauth2_landing
#   EOF

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=openshift
ISSUER=https://api.mycluster.example.com:6443
CLIENT_ID=netidm
CLIENT_SECRET=<OAUTHCLIENT_SECRET>

$NETIDM system oauth2 create-openshift \
    --name "$NAME" \
    --issuer "$ISSUER" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET"

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

# Optional: restrict to specific OpenShift groups
# NETIDM_URL=https://idm.example.com
# TOKEN=<ADMIN_BEARER_TOKEN>
# curl -s -X PATCH "$NETIDM_URL/v1/oauth2/_client/$NAME" \
#   -H "Authorization: Bearer $TOKEN" \
#   -H "Content-Type: application/json" \
#   -d '{"connector_openshift_groups": ["developers", "ops"]}'

$NETIDM system oauth2 connector-list
