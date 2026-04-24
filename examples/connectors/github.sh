#!/usr/bin/env bash
# Example: GitHub upstream connector
#
# Creates a connector that authenticates users via GitHub (or GitHub Enterprise),
# restricted to members of a specific organisation, with JIT account provisioning.
#
# Prerequisites:
#   Register an OAuth App at https://github.com/settings/developers
#   Callback URL: https://<your-netidm-domain>/ui/login/oauth2_landing

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=github
CLIENT_ID=<YOUR_GITHUB_CLIENT_ID>
CLIENT_SECRET=<YOUR_GITHUB_CLIENT_SECRET>
ORG=my-github-org

# Create the connector
$NETIDM system oauth2 create-github \
    --name "$NAME" \
    --client-id "$CLIENT_ID" \
    --client-secret "$CLIENT_SECRET"

# Require members of a specific org (repeat for multiple orgs)
$NETIDM system oauth2 github-add-org --name "$NAME" --org "$ORG"

# Enable JIT provisioning: first-time users get a Netidm account automatically
$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

# Optional: use GitHub login name as stable ID instead of numeric user ID
# $NETIDM system oauth2 github-enable-use-login-as-id --name "$NAME"

# Optional: load all orgs/teams even when no org filter is set
# $NETIDM system oauth2 github-enable-load-all-groups --name "$NAME"

# Optional: prefer emails matching a domain (supports * wildcard)
# $NETIDM system oauth2 github-set-preferred-email-domain \
#     --name "$NAME" --domain "*.example.com"

# Optional: GitHub Enterprise hostname (without scheme)
# $NETIDM system oauth2 github-set-hostname \
#     --name "$NAME" --hostname github.internal.example.com

# Verify the connector
$NETIDM system oauth2 connector-list
