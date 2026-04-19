# Quickstart: SAML 2.0 Connector Test Scenarios

## Integration Test Setup

Tests run against a real in-process netidmd instance via `server/testkit`. No mocks for the netidm side.

The external IdP is simulated by a minimal in-process HTTP server (using `axum` or `tokio` directly) that:
1. Generates a real RSA/EC key pair for signing
2. Accepts an AuthnRequest redirect (captures `SAMLRequest` + `RelayState`)
3. Returns a signed SAML Response XML when triggered
4. Provides a predictable certificate for verification

The `samael` crate is used directly in test helpers to build and sign test assertions.

---

## Scenario 1: Provider Created via CLI SDK

**Setup**: Running netidmd, admin user with `idm_saml_client_admins` membership.

**Action**:
```rust
let result = client.idm_saml_client_create(
    "corp-adfs",
    "Corporate ADFS",
    "https://adfs.corp.example/adfs/ls",
    PEM_CERT,
    "https://netidm.corp.example/saml/sp",
    "https://netidm.corp.example/ui/login/saml/corp-adfs/acs",
).await;
```

**Verify**:
- `result` is `Ok(())`
- Provider entry exists with `name = "corp-adfs"`
- `SamlIdpSsoUrl` matches supplied SSO URL
- `SamlEntityId` matches supplied entity ID
- `SamlAcsUrl` matches supplied ACS URL

---

## Scenario 2: Full Login Flow — Signed SAML Response

**Setup**: Provider from Scenario 1. Test key pair generated. Certificate registered.

**Action**: Simulate complete auth flow:
1. `InitSamlProvider { name: "corp-adfs" }` → get `AuthExternal::SamlAuthnRequest { sso_url, saml_request, relay_state }`
2. Decode + parse `saml_request` → confirm valid AuthnRequest XML with correct `AssertionConsumerServiceURL`
3. Simulate IdP: build SAML Response XML with `InResponseTo` = extracted request `ID`, sign with test key
4. `SamlAcsResponse { saml_response, relay_state, provider_name }` → expect `CredState::Success`

**Verify**:
- `AuthState::Success` returned (via JIT provision confirm)
- JIT-provisioned account exists with `SamlExternalId = <NameID>`
- Session token can be used to authenticate subsequent requests

---

## Scenario 3: Invalid Signature Rejected

**Setup**: Provider from Scenario 1. SAML Response signed with a different (wrong) key.

**Action**: Submit ACS response with wrong signature.

**Verify**:
- `CredState::Denied` returned
- No account provisioned
- Nonce not stored

---

## Scenario 4: Expired Assertion Rejected

**Setup**: Provider from Scenario 1. SAML Response with `NotOnOrAfter` 10 minutes in the past.

**Verify**: `CredState::Denied` returned.

---

## Scenario 5: Replay Attack Rejected

**Setup**: Provider from Scenario 1. Valid SAML Response processed once successfully.

**Action**: Submit the same `SAMLResponse` base64 string a second time.

**Verify**:
- Second submission returns `CredState::Denied`
- Log contains nonce-already-used indicator

---

## Scenario 6: InResponseTo Mismatch Rejected

**Setup**: Provider from Scenario 1.

**Action**: Submit SAML Response with `InResponseTo` referencing an ID that was never issued (or already consumed).

**Verify**: `CredState::Denied` returned.

---

## Scenario 7: JIT Provisioning Disabled — Unknown User Rejected

**Setup**: Provider created with `jit_provisioning = false`. User has no existing account.

**Action**: Complete auth flow with valid SAML Response for unknown user.

**Verify**: `CredState::Denied` returned. No new account created.

---

## Scenario 8: Attribute Mapping — Email Populated

**Setup**: Provider with `attr_map_email = "email"`. SAML Response contains:
```xml
<saml:Attribute Name="email">
  <saml:AttributeValue>alice@corp.example</saml:AttributeValue>
</saml:Attribute>
```

**Action**: Complete auth flow (first-time user, JIT enabled).

**Verify**:
- Provisioned account has `mail = "alice@corp.example"`

---

## Scenario 9: Group Mapping — Group Membership Applied

**Setup**: Provider with `attr_map_groups = "memberOf"`. Group `corp-engineers` exists in netidm. SAML Response contains `memberOf = ["corp-engineers", "unknown-group"]`.

**Action**: Complete auth flow (first-time user).

**Verify**:
- Provisioned account is a member of `corp-engineers`
- `unknown-group` (no matching netidm group) is silently ignored

---

## Scenario 10: CLI Round-Trip

```sh
# Create
netidm system saml-client create \
  --name corp-adfs \
  --displayname "Corporate ADFS" \
  --sso-url https://adfs.corp.example/adfs/ls \
  --idp-cert /tmp/test-cert.pem \
  --entity-id https://netidm.example/saml/sp \
  --acs-url https://netidm.example/ui/login/saml/corp-adfs/acs

# List (verify appears)
netidm system saml-client list

# Get (verify attributes)
netidm system saml-client get corp-adfs

# Delete
netidm system saml-client delete corp-adfs

# List again (verify gone)
netidm system saml-client list
```

---

## Scenario 11: Login Page Shows SAML Button

**Setup**: Provider `corp-adfs` registered.

**Action**: `GET /ui/login`

**Verify**:
- Response HTML contains a link/button with text "Corporate ADFS" (the display name)
- Link href is `/ui/sso/corp-adfs`

---

## Scenario 12: Clock Skew Tolerance

**Setup**: Provider from Scenario 1. SAML Response with `NotBefore` = now + 3 minutes (within ±5 min window).

**Verify**: Auth succeeds (clock skew tolerance applied).

**Setup**: Response with `NotBefore` = now + 6 minutes (outside window).

**Verify**: `CredState::Denied` returned.
