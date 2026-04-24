# SAML 2.0 Connector

The SAML 2.0 connector lets users authenticate via a SAML Identity Provider (IdP) using the
HTTP-POST binding. Netidm acts as a SAML Service Provider (SP). Group memberships are read
from a configurable assertion attribute.

## Prerequisites

You will need from your SAML IdP:

- The **SSO endpoint URL** (HTTP-POST binding).
- The **IdP signing certificate** (PEM format).
- The **entity ID** of the IdP.

You will provide to your SAML IdP:

- **SP entity ID**: typically your Netidm origin URL.
- **ACS URL** (Assertion Consumer Service): `https://<your-netidm-domain>/ui/login/saml2_landing`.

## Creating the connector

```bash
netidm system saml-client create \
    --name mysaml \
    --displayname "Corporate SSO" \
    --sso-url https://idp.example.com/saml2/idp/SSO \
    --idp-cert /path/to/idp-signing.pem \
    --entity-id https://netidm.example.com \
    --acs-url https://netidm.example.com/ui/login/saml2_landing
```

Optional initial parameters:

```bash
    --email-attr       "email"              # SAML attribute carrying email
    --displayname-attr "displayName"        # SAML attribute for display name
    --groups-attr      "memberOf"           # SAML attribute for groups
    --nameid-format    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    --sso-issuer       "https://idp.example.com"   # Expected <Issuer> string
    --jit-provisioning                              # Create accounts on first login
```

## Listing and inspecting

```bash
netidm system saml-client list
netidm system saml-client get --name mysaml
```

## Group mapping

Map upstream SAML group names to Netidm groups:

```bash
netidm system saml-client add-group-mapping \
    --name mysaml \
    --upstream-group "CN=Developers,OU=Groups,DC=corp,DC=example,DC=com" \
    --netidm-group developers

netidm system saml-client remove-group-mapping \
    --name mysaml \
    --upstream-group "CN=Developers,OU=Groups,DC=corp,DC=example,DC=com"

netidm system saml-client list-group-mappings --name mysaml
```

## Multi-value groups delimiter

Some IdPs encode multiple groups as a single delimited string. Set the delimiter:

```bash
netidm system saml-client set-groups-delim --name mysaml ","
netidm system saml-client clear-groups-delim --name mysaml
```

## Filtering to allowed groups

Restrict login to users belonging to specific upstream groups:

```bash
netidm system saml-client add-allowed-group    --name mysaml --group "Developers"
netidm system saml-client remove-allowed-group --name mysaml --group "Developers"
netidm system saml-client list-allowed-groups  --name mysaml

# Enable the filter (groups-attr must also be set)
netidm system saml-client set-filter-groups --name mysaml --enable true
```

## Reference

| Attribute | Description |
|---|---|
| `connector_saml_sso_url` | IdP HTTP-POST SSO endpoint |
| `connector_saml_idp_cert` | IdP signing certificate (PEM) |
| `connector_saml_entity_id` | SP entity ID |
| `connector_saml_acs_url` | SP assertion consumer service URL |
| `connector_saml_email_attr` | SAML attribute for user email |
| `connector_saml_displayname_attr` | SAML attribute for display name |
| `connector_saml_groups_attr` | SAML attribute for group memberships |
| `connector_saml_groups_delim` | Delimiter for single-string group values |
| `connector_saml_allowed_groups` | Groups that may log in (multi-value) |
| `connector_saml_filter_groups` | Reject logins outside allowed groups |
| `connector_saml_nameid_format` | Requested NameID format |
| `connector_saml_sso_issuer` | Expected `<Issuer>` in IdP responses |
