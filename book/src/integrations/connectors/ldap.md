# LDAP Connector

The LDAP connector authenticates users directly against an LDAP or Active Directory server
using a bind operation. It can also resolve group memberships via configurable search filters.
Unlike OAuth2 connectors, LDAP presents a username/password prompt rather than an external
redirect.

## Creating the connector

The LDAP connector requires minimal initial parameters — connection and search details are
set individually after creation:

```bash
netidm system oauth2 create-ldap --name myldap
```

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name myldap
```

## Connection settings

```bash
# LDAP host and port (e.g. ldap.example.com:636 or ldaps://ldap.example.com)
netidm system oauth2 ldap-set-host --name myldap --host ldap.example.com:636

# Use StartTLS instead of LDAPS (port 389)
netidm system oauth2 ldap-enable-start-tls  --name myldap
netidm system oauth2 ldap-disable-start-tls --name myldap

# Skip TLS certificate verification (development only)
netidm system oauth2 ldap-enable-insecure-skip-verify  --name myldap
netidm system oauth2 ldap-disable-insecure-skip-verify --name myldap

# Service account credentials for directory lookups
netidm system oauth2 ldap-set-bind-dn --name myldap --bind-dn "cn=svc,dc=example,dc=com"
netidm system oauth2 ldap-set-bind-pw --name myldap --bind-pw "secret"
```

## User search

```bash
# Base DN for user search (required)
netidm system oauth2 ldap-set-user-search-base-dn \
    --name myldap --base-dn "ou=people,dc=example,dc=com"

# LDAP filter for users (default: all entries)
netidm system oauth2 ldap-set-user-search-filter \
    --name myldap --filter "(objectClass=person)"

# Attributes matched against the typed username (multi-value)
netidm system oauth2 ldap-add-user-search-username --name myldap --attr uid
netidm system oauth2 ldap-add-user-search-username --name myldap --attr mail

# Stable user ID attribute (default: uid)
netidm system oauth2 ldap-set-user-id-attr --name myldap --attr uid

# Email attribute (default: mail)
netidm system oauth2 ldap-set-user-email-attr --name myldap --attr mail

# Display name attribute
netidm system oauth2 ldap-set-user-name-attr --name myldap --attr cn

# Email suffix appended to ID when no email attr found
netidm system oauth2 ldap-set-user-email-suffix --name myldap --suffix "@example.com"
```

## Group search

```bash
# Base DN for group search (enables group sync)
netidm system oauth2 ldap-set-group-search-base-dn \
    --name myldap --base-dn "ou=groups,dc=example,dc=com"

# Group filter
netidm system oauth2 ldap-set-group-search-filter \
    --name myldap --filter "(objectClass=groupOfNames)"

# Group name attribute (default: cn)
netidm system oauth2 ldap-set-group-name-attr --name myldap --attr cn

# User→group matchers: user_attr:group_attr or user_attr:group_attr:recursion_attr
netidm system oauth2 ldap-add-user-matcher \
    --name myldap --matcher "dn:member"

netidm system oauth2 ldap-remove-user-matcher \
    --name myldap --matcher "dn:member"
```

## Active Directory example

```bash
netidm system oauth2 create-ldap --name myad
netidm system oauth2 ldap-set-host --name myad --host dc.corp.example.com:636
netidm system oauth2 ldap-set-bind-dn \
    --name myad --bind-dn "CN=svc-netidm,OU=Service Accounts,DC=corp,DC=example,DC=com"
netidm system oauth2 ldap-set-bind-pw --name myad --bind-pw "secret"
netidm system oauth2 ldap-set-user-search-base-dn \
    --name myad --base-dn "OU=Users,DC=corp,DC=example,DC=com"
netidm system oauth2 ldap-set-user-search-filter \
    --name myad --filter "(objectClass=person)"
netidm system oauth2 ldap-add-user-search-username --name myad --attr sAMAccountName
netidm system oauth2 ldap-set-user-id-attr --name myad --attr sAMAccountName
netidm system oauth2 ldap-set-user-email-attr --name myad --attr mail
netidm system oauth2 ldap-set-user-name-attr --name myad --attr displayName
netidm system oauth2 ldap-set-group-search-base-dn \
    --name myad --base-dn "OU=Groups,DC=corp,DC=example,DC=com"
netidm system oauth2 ldap-set-group-search-filter \
    --name myad --filter "(objectClass=group)"
netidm system oauth2 ldap-add-user-matcher --name myad --matcher "dn:member"
netidm system oauth2 enable-jit-provisioning --name myad
```

## Reference

| Attribute | Description |
|---|---|
| `connector_ldap_host` | LDAP server host:port |
| `connector_ldap_insecure_no_ssl` | Allow plain LDAP (port 389, no TLS) |
| `connector_ldap_insecure_skip_verify` | Skip TLS certificate verification |
| `connector_ldap_start_tls` | Use StartTLS upgrade |
| `connector_ldap_root_ca_data` | PEM CA certificate (base64) |
| `connector_ldap_client_cert` | Client certificate for mutual TLS |
| `connector_ldap_client_key` | Client private key for mutual TLS |
| `connector_ldap_bind_dn` | Service account distinguished name |
| `connector_ldap_bind_pw` | Service account password |
| `connector_ldap_username_prompt` | Login form label (default: Username) |
| `connector_ldap_user_search_base_dn` | User search base |
| `connector_ldap_user_search_filter` | User LDAP filter |
| `connector_ldap_user_search_username` | Attributes matched against typed username |
| `connector_ldap_user_search_id_attr` | Stable user ID attribute (default: uid) |
| `connector_ldap_user_search_email_attr` | Email attribute (default: mail) |
| `connector_ldap_user_search_name_attr` | Display name attribute |
| `connector_ldap_user_search_email_suffix` | Email suffix fallback |
| `connector_ldap_group_search_base_dn` | Group search base |
| `connector_ldap_group_search_filter` | Group LDAP filter |
| `connector_ldap_group_search_name_attr` | Group name attribute (default: cn) |
| `connector_ldap_group_search_user_matchers` | user_attr:group_attr matcher rules |
