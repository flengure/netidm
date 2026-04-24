#!/usr/bin/env bash
# Example: SAML 2.0 upstream connector
#
# Provide your IdP with:
#   SP Entity ID: https://<your-netidm-domain>
#   ACS URL:      https://<your-netidm-domain>/ui/login/saml2_landing
#
# Collect from your IdP:
#   SSO URL (HTTP-POST endpoint) and signing certificate (PEM)

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=corporate-sso
SSO_URL=https://idp.example.com/saml2/idp/SSO
IDP_CERT=/path/to/idp-signing.pem
ENTITY_ID=https://netidm.example.com
ACS_URL=https://netidm.example.com/ui/login/saml2_landing

$NETIDM system saml-client create \
    --name "$NAME" \
    --displayname "Corporate SSO" \
    --sso-url "$SSO_URL" \
    --idp-cert "$IDP_CERT" \
    --entity-id "$ENTITY_ID" \
    --acs-url "$ACS_URL" \
    --email-attr "email" \
    --displayname-attr "displayName" \
    --groups-attr "memberOf" \
    --jit-provisioning

# Map SAML group names to Netidm groups
$NETIDM system saml-client add-group-mapping \
    --name "$NAME" \
    --upstream-group "CN=Developers,OU=Groups,DC=corp,DC=example,DC=com" \
    --netidm-group developers

$NETIDM system saml-client list
