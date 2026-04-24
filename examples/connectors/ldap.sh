#!/usr/bin/env bash
# Example: LDAP upstream connector (OpenLDAP / Active Directory)

set -euo pipefail

NETIDM=${NETIDM:-netidm}
NAME=myldap
LDAP_HOST=ldap.example.com:636
BIND_DN="cn=svc-netidm,ou=service-accounts,dc=example,dc=com"
BIND_PW=<SERVICE_ACCOUNT_PASSWORD>
USER_BASE_DN="ou=people,dc=example,dc=com"
GROUP_BASE_DN="ou=groups,dc=example,dc=com"

$NETIDM system oauth2 create-ldap --name "$NAME"
$NETIDM system oauth2 ldap-set-host --name "$NAME" --host "$LDAP_HOST"
$NETIDM system oauth2 ldap-set-bind-dn --name "$NAME" --bind-dn "$BIND_DN"
$NETIDM system oauth2 ldap-set-bind-pw --name "$NAME" --bind-pw "$BIND_PW"

$NETIDM system oauth2 ldap-set-user-search-base-dn --name "$NAME" --base-dn "$USER_BASE_DN"
$NETIDM system oauth2 ldap-set-user-search-filter --name "$NAME" --filter "(objectClass=person)"
$NETIDM system oauth2 ldap-add-user-search-username --name "$NAME" --attr uid
$NETIDM system oauth2 ldap-set-user-id-attr --name "$NAME" --attr uid
$NETIDM system oauth2 ldap-set-user-email-attr --name "$NAME" --attr mail
$NETIDM system oauth2 ldap-set-user-name-attr --name "$NAME" --attr cn

$NETIDM system oauth2 ldap-set-group-search-base-dn --name "$NAME" --base-dn "$GROUP_BASE_DN"
$NETIDM system oauth2 ldap-set-group-search-filter --name "$NAME" --filter "(objectClass=groupOfNames)"
$NETIDM system oauth2 ldap-add-user-matcher --name "$NAME" --matcher "dn:member"

$NETIDM system oauth2 enable-jit-provisioning --name "$NAME"

# Active Directory variant — replace the above with:
# LDAP_HOST=dc.corp.example.com:636
# BIND_DN="CN=svc-netidm,OU=Service Accounts,DC=corp,DC=example,DC=com"
# USER_BASE_DN="OU=Users,DC=corp,DC=example,DC=com"
# GROUP_BASE_DN="OU=Groups,DC=corp,DC=example,DC=com"
# ldap-add-user-search-username --attr sAMAccountName
# ldap-set-user-id-attr --attr sAMAccountName
# ldap-set-group-search-filter --filter "(objectClass=group)"

$NETIDM system oauth2 connector-list
