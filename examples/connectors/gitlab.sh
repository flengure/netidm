#!/usr/bin/env bash
# Example: GitLab upstream connector (GitLab.com or self-hosted)
#
# Prerequisites:
#   Register an Application at https://gitlab.com/-/user_settings/applications
#   or at Admin Area > Applications for instance-wide access.
#   Scopes needed: openid, read_user
#   Redirect URI: https://<your-netidm-domain>/ui/login/oauth2_landing

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=gitlab
CLIENT_ID=<YOUR_GITLAB_APP_ID>
CLIENT_SECRET=<YOUR_GITLAB_SECRET>
# BASE_URL defaults to https://gitlab.com; set for self-hosted instances:
# BASE_URL=https://gitlab.internal.example.com

$NETIDM system oauth2 create-gitlab \
    --name "$NAME" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET"
    # --base-url "$BASE_URL"    # uncomment for self-hosted

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

# Optional: restrict to specific GitLab groups (via REST API PATCH)
# curl -s -X PATCH "https://$NETIDM_URL/v1/oauth2/_client/$NAME" \
#   -H "Authorization: Bearer $TOKEN" \
#   -H "Content-Type: application/json" \
#   -d '{"connector_gitlab_groups": ["my-group"]}'

$NETIDM system oauth2 connector-list
