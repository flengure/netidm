# Feature Specification: SAML 2.0 Upstream Connector

**Feature Branch**: `007-saml2-connector`
**Created**: 2026-04-19
**Status**: Draft

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Register a SAML IdP and Log In (Priority: P1)

An administrator registers an enterprise identity provider (e.g. Okta, ADFS, Azure AD, Shibboleth) by supplying a small number of IdP details. End users can then sign in to netidm-protected applications using their corporate credentials via that IdP, without needing a separate netidm password.

**Why this priority**: This is the entire reason for the feature. Without it nothing else is useful.

**Independent Test**: Configure a mock SAML IdP, register it in netidm, trigger a login, receive a valid SAML Response, and confirm the user session is established with the correct identity attributes.

**Acceptance Scenarios**:

1. **Given** an admin has registered a SAML IdP with a valid SSO URL and signing certificate, **When** a user clicks "Login with [IdP name]" on the netidm login page, **Then** the user is redirected to the IdP's login page.
2. **Given** the user authenticates successfully at the IdP, **When** the IdP POSTs a signed SAML Response to netidm's Assertion Consumer Service URL, **Then** the user is granted a netidm session and redirected to the original destination.
3. **Given** the IdP returns a SAML Response with an invalid or tampered signature, **When** netidm processes it, **Then** the login is rejected and the user sees an error message.
4. **Given** the SAML Response contains an expired `NotOnOrAfter` assertion, **When** netidm processes it, **Then** the login is rejected.
5. **Given** a user has no existing netidm account, **When** they authenticate via SAML for the first time, **Then** a new account is automatically provisioned with attributes mapped from the SAML assertion.

---

### User Story 2 — Manage SAML IdP Providers via CLI (Priority: P2)

An administrator can create, list, get, and delete SAML IdP configurations using the netidm command-line tool, without needing direct database access.

**Why this priority**: Operators need a repeatable, scriptable way to configure IdPs in production. Without CLI support the feature can only be used by developers with DB access.

**Independent Test**: Run `netidm system saml-client create ...` with valid arguments, then `netidm system saml-client get <name>` and confirm the stored configuration matches the inputs.

**Acceptance Scenarios**:

1. **Given** valid IdP parameters are supplied, **When** the admin runs the create command, **Then** the provider is stored and subsequent get/list commands show it.
2. **Given** an existing SAML provider, **When** the admin runs the delete command, **Then** the provider is removed and login via that IdP is no longer possible.
3. **Given** invalid or missing required parameters, **When** the admin runs the create command, **Then** a clear error message is displayed and nothing is stored.

---

### User Story 3 — Attribute Mapping and JIT Provisioning (Priority: P3)

An administrator can configure which SAML assertion attributes map to netidm user attributes (display name, email, group membership). On first login, accounts are automatically created ("just-in-time provisioned") with those mapped attributes.

**Why this priority**: Without attribute mapping, provisioned accounts carry no useful identity information and cannot be used for group-based authorisation.

**Independent Test**: Configure an email attribute mapping, trigger a first-time login with a SAML assertion containing that attribute, and confirm the provisioned account has the correct email address stored.

**Acceptance Scenarios**:

1. **Given** an email attribute mapping is configured on a SAML provider, **When** a user logs in for the first time with an assertion containing that attribute, **Then** the provisioned account has the correct email address.
2. **Given** a groups attribute mapping is configured, **When** the SAML assertion lists the user as a member of a group that exists in netidm, **Then** the provisioned account is added to that group.
3. **Given** no attribute mapping is configured, **When** a user logs in, **Then** an account is provisioned using the SAML `NameID` as the unique identifier, and all other attributes are left blank.

---

### Edge Cases

- What happens when the IdP's signing certificate expires or is rotated?
- How does the system handle a SAML Response that is valid but contains no `NameID`?
- What happens when two different SAML providers assert the same `NameID`?
- How does the system behave when the IdP is unreachable during the redirect phase?
- What happens when JIT provisioning is disabled and the user has no existing account?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Administrators MUST be able to register a SAML 2.0 IdP by providing: a display name, the IdP's HTTP-POST SSO URL, the IdP's X.509 signing certificate (PEM), and an entity issuer identifier.
- **FR-002**: Netidm MUST act as a SAML 2.0 Service Provider, generating a signed `AuthnRequest` and redirecting users to the IdP's SSO URL.
- **FR-003**: Netidm MUST expose an Assertion Consumer Service (ACS) endpoint that receives and validates HTTP-POST SAML Responses from the IdP.
- **FR-004**: The system MUST validate SAML Response XML signatures against the registered IdP signing certificate.
- **FR-005**: The system MUST reject assertions with expired `NotOnOrAfter` or `NotBefore` conditions outside an acceptable clock-skew window (default ±5 minutes).
- **FR-006**: On successful SAML authentication, the system MUST establish a netidm user session equivalent to a password login session.
- **FR-007**: The system MUST support just-in-time account provisioning for users authenticating via SAML for the first time.
- **FR-008**: Administrators MUST be able to configure attribute mappings from SAML assertion attributes to netidm user attributes (at minimum: email, display name, group membership).
- **FR-009**: JIT provisioning MUST be configurable per SAML provider (enabled/disabled).
- **FR-010**: The SAML provider configuration MUST be manageable via the CLI (`create`, `get`, `list`, `delete`).
- **FR-011**: The netidm login page MUST display a "Login with [provider display name]" button for each active SAML provider.
- **FR-012**: The system MUST prevent replay attacks by tracking and rejecting previously used SAML assertion IDs within their validity window.

### Key Entities

- **SAML Provider**: A registered enterprise IdP. Key attributes: name, display name, SSO URL, entity issuer, signing certificate (PEM), ACS URL (derived), attribute mappings, JIT provisioning flag.
- **SAML Assertion**: The authentication statement returned by the IdP. Contains: NameID, conditions (validity window), attribute statements, XML signature.
- **Attribute Mapping**: A rule linking a SAML assertion attribute name to a netidm user attribute (email, display name, group).
- **Assertion ID Cache**: A short-lived record of processed assertion IDs used to prevent replay attacks.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A new SAML provider can be registered and a first login completed in under 5 minutes of configuration time.
- **SC-002**: The full SSO redirect-and-callback round-trip completes in under 3 seconds under normal network conditions.
- **SC-003**: 100% of SAML Responses with invalid signatures or expired conditions are rejected.
- **SC-004**: JIT-provisioned accounts are created with all mapped attributes populated within the same request that completes the login.
- **SC-005**: All SAML provider management operations (create, get, list, delete) complete via CLI without requiring direct database access.

## Assumptions

- The IdP supports SAML 2.0 HTTP-POST binding for the SSO response (the most widely supported binding; HTTP-Redirect for the AuthnRequest is also standard).
- SAML metadata XML import (automatic endpoint discovery from a metadata URL) is out of scope for the initial version; admins supply the SSO URL and certificate directly.
- Only a single signing certificate per IdP is supported initially; certificate rotation requires updating the stored certificate via the management commands.
- The `samael` Rust crate (or equivalent) provides SAML 2.0 parsing and signature verification; no new C library bindings are introduced.
- Group membership synchronisation on every login (not just first login) is out of scope for the initial version.
- SP-initiated SSO only; IdP-initiated SSO (unsolicited SAML Responses) is out of scope.
- Encrypted SAML assertions are out of scope for the initial version; only signed assertions are required.
