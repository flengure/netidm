# Contract: SAML 2.0 Authentication Flow

## SP-Initiated SSO Flow

```
Browser                server/core              server/lib                IdP (Okta/ADFS/etc.)
  |                        |                        |                           |
  |-- GET /ui/sso/:name -->|                        |                           |
  |                        |-- handle_auth(InitSamlProvider { name }) -->       |
  |                        |<-- External(SamlAuthnRequest { sso_url, saml_request, relay_state })
  |                        |   [store relay_state → request_id in memory map]  |
  |<-- 302 to IdP SSO URL--|                        |                           |
  |   (with SAMLRequest + RelayState query params)  |                           |
  |                                                 |                           |
  |-- [user authenticates at IdP] ------------------------------------------------>
  |<-- POST /ui/login/saml/:name/acs -----------------------------------------------
  |     (SAMLResponse base64, RelayState)           |                           |
  |                        |                        |                           |
  |                        |-- handle_auth(SamlAcsResponse { saml_response, relay_state }) -->
  |                        |                        |  [validate InResponseTo vs memory map]
  |                        |                        |  [decode + verify XML signature]
  |                        |                        |  [check NotBefore/NotOnOrAfter ±5min]
  |                        |                        |  [store assertion nonce in DB]
  |                        |                        |  [JIT provision if needed]
  |                        |<-- Success(uat) --      |                           |
  |<-- 302 /ui/ + session cookie ---|               |                           |
```

## HTTP Endpoints

### `GET /ui/sso/:name`

Initiates SP-initiated SSO for the named SAML provider.

**Request**: `name` = provider `iname` attribute

**Response on success**: HTTP 302
- `Location`: `<sso_url>?SAMLRequest=<deflated+b64>&RelayState=<opaque>`
- No session cookie yet

**Response on unknown provider**: HTTP 404

---

### `POST /ui/login/saml/:name/acs`

Assertion Consumer Service — receives the SAML Response from the IdP.

**Request**: `application/x-www-form-urlencoded` body
- `SAMLResponse`: base64-encoded SAML Response XML
- `RelayState`: opaque string returned unmodified from the AuthnRequest

**Response on success**: HTTP 302
- `Location`: original destination URL (from `RelayState` or `/ui/`)
- Sets bearer token cookie (`COOKIE_BEARER_TOKEN`)

**Response on validation failure**: HTTP 200 with login error page
- Signature invalid
- Assertion expired
- Replay (nonce already used)
- No existing account and JIT provisioning disabled
- `InResponseTo` mismatch (unknown or expired relay state)

---

## AuthnRequest Generation

The SP generates an AuthnRequest XML document:

```xml
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_<random-uuid>"
  Version="2.0"
  IssueInstant="<RFC3339>"
  AssertionConsumerServiceURL="<acs_url>"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <entity_id>
  </saml:Issuer>
  <samlp:NameIDPolicy Format="<name_id_format>" AllowCreate="true"/>
</samlp:AuthnRequest>
```

Delivered to IdP via HTTP-Redirect binding:
- Deflate-compress the AuthnRequest XML
- Base64-encode
- URL-encode as `SAMLRequest` query parameter
- Append `RelayState=<opaque>` (used to correlate the response)

AuthnRequest is NOT signed (signature optional in HTTP-Redirect binding; not required by major IdPs).

---

## SAML Response Validation

Steps performed in `handler_saml_client.rs` in order:

1. **Base64 decode** `SAMLResponse`
2. **XML parse** via `samael`
3. **Issuer check**: `Response/Issuer` or `Assertion/Issuer` MUST match expected `idp_entity_id` (if the provider stores one; otherwise skipped)
4. **InResponseTo check**: `Response/@InResponseTo` MUST match an outstanding `request_id` in the in-memory map for this `provider_name`; map entry is consumed (one-use)
5. **XML signature verification**: `samael::verify_response_signature(&idp_cert, &response)` — validates the XML signature on either the `<Response>` or the `<Assertion>` element
6. **Conditions check**: `NotBefore` ≤ now ≤ `NotOnOrAfter` with ±5 minute clock skew tolerance
7. **Nonce check**: `Assertion/@ID` SHA-256 hash MUST NOT exist in `server/lib/src/server/assert.rs` nonce store
8. **NameID**: extracted as the unique user identifier; absent `NameID` → rejected
9. **Attribute mapping**: extract email, display_name, groups from assertion attributes per provider config
10. **JIT provision or lookup**: find existing account by external UID or provision new one
11. **Store nonce**: write `SamlAssertionNonce` entry with `DeleteAfter = NotOnOrAfter`
12. **Return** `CredState::Success { auth_type: AuthType::SamlFederated }`

---

## Error Paths

| Condition | Handler response | User sees |
|-----------|-----------------|-----------|
| Unknown provider name in ACS URL | 404 | "Not found" |
| `InResponseTo` not in memory map (expired or unknown) | `CredState::Denied` | "Authentication failed" |
| XML signature invalid | `CredState::Denied` | "Authentication failed" |
| Assertion expired | `CredState::Denied` | "Authentication failed" |
| Assertion ID already used (replay) | `CredState::Denied` | "Authentication failed" |
| `NameID` absent | `CredState::Denied` | "Authentication failed" |
| JIT disabled, user has no account | `CredState::Denied` | "Authentication failed" |

---

## New AuthExternal Variant

```rust
/// Carry the SAML AuthnRequest redirect data back to server/core.
SamlAuthnRequest {
    sso_url: Url,
    saml_request: String,   // deflated + base64-encoded AuthnRequest
    relay_state: String,    // opaque correlation value
},
```

## New AuthCredential Variant

```rust
/// ACS POST body from the IdP.
SamlAcsResponse {
    saml_response: String,  // base64-encoded SAML Response XML
    relay_state: String,
    provider_name: String,
},
```

## New AuthType Variant

```rust
SamlFederated,  // analogous to AuthType::OAuth2
```
