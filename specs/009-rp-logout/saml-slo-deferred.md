# SAML Single Logout — architectural gap, design note

**Status**: US4 scaffolding landed in PR-RP-LOGOUT; the end-to-end SLO
handler is deferred to a follow-up PR because it depends on IdP-side
SAML infrastructure that does not exist in netidm today.

## The gap

Spec §US4 describes netidm acting as a **SAML Identity Provider (IdP)**:
a registered service provider (SP) sends an inbound `<LogoutRequest>`
signed with its own key; netidm verifies the signature against the SP's
registered signing certificate, correlates to a `SamlSession`,
terminates the netidm session, and returns a signed `<LogoutResponse>`.

Netidm's existing SAML infrastructure (`idm::saml_client::SamlClientProvider`)
is **SP-side**. The fields on the `SamlClient` entry class are all
upstream-facing — `SamlIdpSsoUrl`, `SamlIdpCertificate`, `SamlEntityId`
(our SP entity ID), `SamlAcsUrl` (our ACS URL). These belong to a model
where netidm federates to an external SAML IdP to authenticate its
own users. They are the wrong shape for acting as an IdP.

## What this PR did land

- `EntryClass::SamlSession` + its attrs (`SamlSessionUser`,
  `SamlSessionSp`, `SamlSessionIndex`, `SamlSessionUatUuid`,
  `SamlSessionCreated`) via DL26.
- `Attribute::SamlSingleLogoutServiceUrl` on `EntryClass::SamlClient`
  via DL26 + ACP coverage + admin CLI CRUD.
- DB-layer CRUD helpers in `idm::saml_session`:
  `create_saml_session`, `find_saml_session_by_index`,
  `find_saml_sessions_by_user_sp`, `delete_saml_session`.
- `backfill_saml_session_indices` migration stub (no-op — populated
  once SessionIndex emission has a real upstream path).

Everything above is architecturally neutral. It is useful scaffolding
for whichever future PR introduces IdP-side SAML.

## What a follow-up SAML IdP PR would need to add

1. **A new `SamlIdpClient` class** (or an IdP-mode flag + IdP-specific
   attributes on the existing `SamlClient`) carrying at minimum:
    - `SamlSpSigningCertificate` — PEM for verifying inbound requests.
    - `SamlSpEntityId` — the SP's entity ID.
    - `SamlSpAcsUrl` — where netidm-as-IdP POSTs assertions.
    - A separate IdP signing key (distinct from OIDC signing key, or
      an explicit policy decision to share).
   This is a new schema migration — call it DL27.
2. **IdP-side SAML auth response minting** — netidm issues its own
   `<samlp:Response>` containing a signed `<saml:Assertion>` with
   `<saml:AuthnStatement SessionIndex="...">`. Mirrors the shape of
   how netidm issues OIDC ID tokens today. Driven from the existing
   web-auth flow: after a user authenticates, if the request came
   from an SAML SP, emit an assertion. Uses `samael::idp` helpers.
3. **`<SessionIndex>` emission integrated with `SamlSession`
   creation**. At assertion time, call
   `idm::saml_session::create_saml_session(qs_write, user_uuid,
   sp_uuid, uat_uuid, now)` to get a fresh `SessionIndex`, embed it
   in the outgoing `<AuthnStatement>`. This is spec §FR-011b.
4. **Inbound `<LogoutRequest>` handler** per spec §FR-011a:
    - HTTP routes `POST /saml/{sp_name}/slo/soap` (SOAP binding) and
      `GET /saml/{sp_name}/slo/redirect` (HTTP-Redirect binding).
    - Parse with `samael`; verify signature against the SP's
      registered signing cert (above).
    - If `<SessionIndex>` present: `find_saml_session_by_index` →
      `terminate_session` + `delete_saml_session`. Single-session
      SLO per Q3/B.
    - If `<SessionIndex>` absent: `find_saml_sessions_by_user_sp` →
      iterate, `terminate_session` + `delete_saml_session` for each.
      All-sessions-at-SP per Q3/B.
    - Sign the outgoing `<LogoutResponse>` with netidm's IdP signing
      key and POST to the SP's `SamlSingleLogoutServiceUrl`.
5. **IdP metadata extension** exposing the SLO endpoints at
   `/saml/metadata.xml` alongside the SSO endpoints, per spec §FR-013.
6. **Backfill implementation** for
   `backfill_saml_session_indices` (research §R6 Stage 2) iterating
   active UATs and populating `SamlSession` rows where SAML
   provenance can be established.

## Why this can't ship as a one-commit addition to PR-RP-LOGOUT

- Item 1 is a schema migration (new DL + ACPs).
- Item 2 introduces a new authn flow; it touches the web auth path.
- Items 1 + 2 + 3 together are net-new IdP infrastructure. The SLO
  handler (item 4) cannot be tested end-to-end without at least a
  minimal assertion-minting path (item 2) to generate the sessions
  it's supposed to terminate.

Shipping items 4 + 5 in isolation would give you an HTTP endpoint
that handles `<LogoutRequest>` messages for sessions that cannot be
created — dead code by construction. Not a useful landing.

## Tasks in `tasks.md` carried to the follow-up PR

- **T059** — SessionIndex emission on SAML auth response.
- **T060** — unit test for SessionIndex emission.
- **T061** — `handle_saml_logout_request` end-to-end.
- **T062** — SLO routes + handlers.
- **T063** — IdP metadata extension.
- **T067–T073** — SAML SLO testkit integration tests.

Marking these as **deferred** (rather than incomplete) so future-me
doesn't mistake them for normal TODOs. The deferral is architectural,
not scope-cut.
