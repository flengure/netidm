# Data Model: SAML 2.0 Upstream Connector

## Entity: SamlClientProvider (new)

New struct in `server/lib/src/idm/saml_client.rs`, analogous to `OAuth2ClientProvider`.

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `String` | Yes | Provider name (spn / iname) — slug-safe identifier |
| `display_name` | `String` | Yes | Human-readable name for the SSO button |
| `uuid` | `Uuid` | Yes | Entry UUID |
| `entity_id` | `Url` | Yes | SP entity ID (also used as `Issuer` in AuthnRequests) |
| `idp_sso_url` | `Url` | Yes | IdP's HTTP-POST SSO endpoint |
| `idp_certificate` | `String` | Yes | IdP's X.509 signing certificate in PEM format |
| `acs_url` | `Url` | Yes | Assertion Consumer Service URL (stored; derived from base URL at entry creation) |
| `name_id_format` | `Option<String>` | No | NameID format URI; defaults to `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` |
| `attr_map_email` | `Option<String>` | No | SAML assertion attribute name that maps to user email |
| `attr_map_displayname` | `Option<String>` | No | SAML assertion attribute name that maps to display name |
| `attr_map_groups` | `Option<String>` | No | SAML assertion attribute name that maps to group membership |
| `jit_provisioning` | `bool` | Yes | Whether to auto-create accounts on first login (default: `true`) |

---

## Entity: SamlAuthRequest (transient, in-memory)

Not persisted. Lives in a short-lived map keyed by relay state (TTL ≈ 5 minutes). Dropped after ACS response received or TTL expires.

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | `String` | Generated `ID` attribute of the AuthnRequest (prefixed `_`) |
| `provider_name` | `String` | Name of the SAML provider that issued this request |
| `issued_at` | `SystemTime` | Used to enforce TTL |

---

## Schema Attributes (DL22)

### `Attribute::SamlIdpSsoUrl`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff0000024b` |
| Syntax | `SyntaxType::Url` |
| Multivalue | `false` |
| Schema class | `systemmust` on `EntryClass::SamlClient` |
| Description | IdP HTTP-POST SSO endpoint URL |

### `Attribute::SamlIdpCertificate`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff0000024c` |
| Syntax | `SyntaxType::Utf8String` |
| Multivalue | `false` |
| Schema class | `systemmust` on `EntryClass::SamlClient` |
| Description | IdP X.509 signing certificate (PEM-encoded) |

### `Attribute::SamlEntityId`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff0000024d` |
| Syntax | `SyntaxType::Url` |
| Multivalue | `false` |
| Schema class | `systemmust` on `EntryClass::SamlClient` |
| Description | SP entity ID (our issuer in AuthnRequests; must be globally unique) |

### `Attribute::SamlAcsUrl`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff0000024e` |
| Syntax | `SyntaxType::Url` |
| Multivalue | `false` |
| Schema class | `systemmust` on `EntryClass::SamlClient` |
| Description | Assertion Consumer Service URL — where the IdP POSTs SAML Responses |

### `Attribute::SamlNameIdFormat`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff0000024f` |
| Syntax | `SyntaxType::Utf8String` |
| Multivalue | `false` |
| Schema class | `systemmay` on `EntryClass::SamlClient` |
| Description | Requested NameID format URI; absent means `unspecified` |

### `Attribute::SamlAttrMapEmail`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff00000250` |
| Syntax | `SyntaxType::Utf8String` |
| Multivalue | `false` |
| Schema class | `systemmay` on `EntryClass::SamlClient` |
| Description | Assertion attribute name whose value is the user's email address |

### `Attribute::SamlAttrMapDisplayname`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff00000251` |
| Syntax | `SyntaxType::Utf8String` |
| Multivalue | `false` |
| Schema class | `systemmay` on `EntryClass::SamlClient` |
| Description | Assertion attribute name whose value is the user's display name |

### `Attribute::SamlAttrMapGroups`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff00000252` |
| Syntax | `SyntaxType::Utf8String` |
| Multivalue | `false` |
| Schema class | `systemmay` on `EntryClass::SamlClient` |
| Description | Assertion attribute name whose values are the user's group names |

### `Attribute::SamlJitProvisioning`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff00000253` |
| Syntax | `SyntaxType::Boolean` |
| Multivalue | `false` |
| Schema class | `systemmay` on `EntryClass::SamlClient` |
| Description | Whether to auto-create accounts for first-time SAML users (default: `true`) |

---

## Schema Class (DL22)

### `EntryClass::SamlClient`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-ffff00000090` |
| systemmust | `SamlIdpSsoUrl`, `SamlIdpCertificate`, `SamlEntityId`, `SamlAcsUrl`, `DisplayName` |
| systemmay | `SamlNameIdFormat`, `SamlAttrMapEmail`, `SamlAttrMapDisplayname`, `SamlAttrMapGroups`, `SamlJitProvisioning` |
| Description | A SAML 2.0 Identity Provider configuration used for SP-initiated SSO |

---

## Access Control (DL22)

### Group: `idm_saml_client_admins`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-000000000057` |
| Description | Members can manage SAML provider entries |
| Members | (none by default — admin assigns) |

### ACP: `UUID_IDM_ACP_SAML_CLIENT_ADMIN`

| Property | Value |
|----------|-------|
| UUID | `00000000-0000-0000-0000-000000000082` |
| Receiver | `idm_saml_client_admins` |
| Target | Entries with class `SamlClient` |
| Permissions | `create`, `read`, `modify`, `delete` |
| create_classes | `Object`, `SamlClient` |
| create_attrs | All SAML schema attributes + `Name`, `DisplayName`, `Class`, `Uuid` |

---

## Entity: SamlAssertionNonce (persisted)

Follows the existing `AssertionNonce` pattern in `server/lib/src/server/assert.rs`. Stores a SHA-256 hash of the SAML assertion `ID` to prevent replay attacks.

| Field | Attribute | Notes |
|-------|-----------|-------|
| `id` | `Attribute::AssertionNonce` | SHA-256 hex digest of the SAML `saml:Assertion/@ID` |
| `expires` | `Attribute::DeleteAfter` | Set to `NotOnOrAfter` from the assertion conditions |

Purged by the existing tombstone/recycle purge task when `DeleteAfter` is reached.
