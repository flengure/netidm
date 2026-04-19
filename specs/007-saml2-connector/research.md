# Research: SAML 2.0 Upstream Connector

## Decision 1: SAML Crate — `samael`

**Decision**: Use `samael` 0.0.20 with the `xmlsec` feature enabled.

**Rationale**: It is the only actively maintained Rust SAML 2.0 crate that covers the full SP role:
AuthnRequest generation (HTTP-Redirect binding), HTTP-POST ACS response parsing, and XML
signature verification. Pure-Rust alternatives do not exist for the cryptographic operations
required by xmldsig.

**Alternatives considered**:
- `saml-rs` — older, less maintained, incomplete SP support.
- Hand-rolled XML parsing with `quick-xml` + OpenSSL — would replicate large parts of samael with
  higher risk of subtle security bugs. Rejected.

**Implication**: `xmlsec` requires native libraries at build time: `libxml2`, `libxslt`, `xmlsec1`,
`openssl`, `pkg-config`. These are standard system packages on Linux and available in CI. The
constitution prohibits `#[allow(...)]` suppressions but does not prohibit native deps — this is
acceptable.

---

## Decision 2: Domain Level — DL22

**Decision**: DL22 is the correct next migration level (current target is DL21).

**Rationale**: Each new entry-type family gets its own DL. DL21 introduced the OIDC connector
(OAuth2Issuer, OAuth2JwksUri). DL22 will introduce the SAML client entry class and its attributes.

**Pattern**: Copy the DL21 structure exactly — `schema.rs`, `access.rs`, `mod.rs` — delegating all
phases to `super::dl21` except phases 1, 2, 6, and 7 where new entries are added.

---

## Decision 3: SAML Admin Group — new `idm_saml_client_admins`

**Decision**: Create a dedicated group `idm_saml_client_admins` with UUID
`00000000-0000-0000-0000-000000000057`.

**Rationale**: OAuth2 client admins manage OAuth2 providers; SAML providers are a distinct trust
boundary. Separating them follows the principle of least privilege and mirrors every other admin
group in the system.

**Alternatives considered**: Reusing `UUID_IDM_OAUTH2_CLIENT_ADMINS` — rejected because it conflates
two distinct responsibilities and can't be independently delegated.

---

## Decision 4: Replay Attack Prevention — in-memory per-request deduplication + DB nonce

**Decision**: Two-layer approach:
1. On every SAML Response receive, check `InResponseTo` against a short-lived in-memory map of
   outstanding AuthnRequest IDs (keyed by relay state, TTL = assertion validity window ≈ 5 min).
2. Store the processed assertion ID as a `SamlAssertionNonce` entry (SHA-256 hash) in the DB,
   following the existing `AssertionNonce` pattern in `server/lib/src/server/assert.rs`. Purge via
   the existing tombstone/recycle purge task using a `DeleteAfter` attribute.

**Rationale**: The in-memory map handles the common case within a single instance. The DB nonce
survives restarts and multi-node deployments.

---

## Decision 5: Session Creation — reuse CredState::Success via existing auth machinery

**Decision**: After SAML Response validation and JIT provisioning, the SAML handler returns
`CredState::Success { auth_type: AuthType::SamlFederated, ... }` — identical to how
`handler_oauth2_client.rs` returns success. The existing `AuthSession::issue_uat()` path is
unchanged.

**Rationale**: Keeps the auth session path single-sourced. Avoids creating a parallel session-
creation mechanism that would be hard to audit.

**New `AuthType` variant required**: `SamlFederated` — analogous to `AuthType::OAuth2` already
present for the upstream OAuth2 connector.

---

## Decision 6: ACS URL structure

**Decision**: `GET/POST /ui/login/saml/<provider-name>/acs`

**Rationale**: Consistent with the existing OAuth2 callback path
(`/ui/login/oauth2/<provider-name>/callback`). Provider name is slug-safe (iname attribute).
`<provider-name>` is the netidm name attribute of the SAML client entry.

---

## Decision 7: AuthnRequest binding — HTTP-Redirect for request, HTTP-POST for response

**Decision**: Use HTTP-Redirect binding for the outgoing AuthnRequest (SP → IdP) and HTTP-POST
binding for the incoming SAML Response (IdP → SP ACS).

**Rationale**: This is the SAML 2.0 Web SSO Browser Profile standard combination and what all
major IdPs (Okta, ADFS, Azure AD, Shibboleth) expect by default. Samael supports both.

---

## Schema Attribute UUIDs (reserved)

| Attribute | UUID |
|---|---|
| `saml_idp_sso_url` | `00000000-0000-0000-0000-ffff0000024b` |
| `saml_idp_certificate` | `00000000-0000-0000-0000-ffff0000024c` |
| `saml_entity_id` | `00000000-0000-0000-0000-ffff0000024d` |
| `saml_acs_url` | `00000000-0000-0000-0000-ffff0000024e` |
| `saml_name_id_format` | `00000000-0000-0000-0000-ffff0000024f` |
| `saml_attr_map_email` | `00000000-0000-0000-0000-ffff00000250` |
| `saml_attr_map_displayname` | `00000000-0000-0000-0000-ffff00000251` |
| `saml_attr_map_groups` | `00000000-0000-0000-0000-ffff00000252` |
| `saml_jit_provisioning` | `00000000-0000-0000-0000-ffff00000253` |
| `SCHEMA_CLASS_SAML_CLIENT` | `00000000-0000-0000-0000-ffff00000090` |
| `UUID_IDM_ACP_SAML_CLIENT_ADMIN` | `00000000-0000-0000-0000-000000000082` |
| `UUID_IDM_SAML_CLIENT_ADMINS` group | `00000000-0000-0000-0000-000000000057` |
