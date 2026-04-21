# HTTP Endpoint Contracts — PR-RP-LOGOUT

All routes listed below are added by this PR. Contracts are external (RP-facing or admin-facing); internal handler shapes are not covered here.

---

## 1. OIDC end-session endpoint — per-client

### `GET | POST /oauth2/openid/{client_id}/end_session_endpoint`

**Request parameters** (query string for GET, `application/x-www-form-urlencoded` body for POST):

| Name | Required | Source | Description |
|---|---|---|---|
| `id_token_hint` | Recommended | OIDC spec | Previously-issued ID token. Used to identify the session (`sid` claim) and the client (`aud` claim). |
| `post_logout_redirect_uri` | No | OIDC spec | URI to redirect the user-agent to after logout. MUST exactly match one of the client's registered `OAuth2RsPostLogoutRedirectUri` entries. |
| `state` | No | OIDC spec | Opaque value echoed back as `?state=` on the redirect. |
| `client_id` | No | OIDC spec | Allowed but redundant with `id_token_hint.aud`; if both present and mismatched, the endpoint renders the confirmation page. |
| `logout_hint` | No | OIDC spec | Hint about who to log out. Netidm currently ignores this (no multi-user-per-agent UI). |
| `ui_locales` | No | OIDC spec | Space-separated BCP47 tags. Used to select the confirmation-page locale when rendered. |

**Behaviour matrix**:

| Condition | Outcome |
|---|---|
| Valid `id_token_hint`, `post_logout_redirect_uri` is in the RP's allowlist | Terminate the session named by the token's `sid`; revoke in-scope refresh tokens; enqueue back-channel deliveries; 302 redirect to the URI with `state` appended if supplied. |
| Valid `id_token_hint`, `post_logout_redirect_uri` is absent OR not in allowlist | Terminate the session; enqueue back-channel deliveries; 200 render `logged_out.html`. |
| `id_token_hint` missing, expired, or unverifiable | Terminate the browser's current netidm session if one is present (cookie-based); render `logged_out.html`. No redirect regardless of `post_logout_redirect_uri`. |
| `id_token_hint` present but `aud` is not a known client | Render `logged_out.html` without terminating any session. |
| `client_id` path param doesn't match `aud` in token | Render `logged_out.html` without terminating any session. |

**Response**:
- On redirect: `HTTP/1.1 302 Found` with `Location: <post_logout_redirect_uri>[?state=<state>]`.
- On render: `HTTP/1.1 200 OK` with `Content-Type: text/html`, body from the askama `logged_out.html` template.

**Caching**: Response MUST carry `Cache-Control: no-store` and `Pragma: no-cache`.

---

## 2. OIDC end-session endpoint — global fallback

### `GET | POST /oauth2/openid/end_session_endpoint`

Same request parameters and behaviour as the per-client route, except:
- No `client_id` path segment.
- The handler derives the target client from `id_token_hint.aud`. If `id_token_hint` is absent, the handler can still terminate the browser's current netidm session and render the confirmation page; it just won't know which client to attribute the logout to for back-channel delivery selection — in that case, back-channel deliveries fan out to every RP whose back-channel endpoint registered against the session's UAT.

This route exists as a fallback for RPs that hard-code a logout URL without consulting discovery. RPs SHOULD prefer the per-client route from the discovery document.

---

## 3. Discovery document additions

### `GET /oauth2/openid/{client_id}/.well-known/openid-configuration`

The existing document gains three new fields:

```json
{
  "end_session_endpoint": "{origin}/oauth2/openid/{client_id}/end_session_endpoint",
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true
}
```

No existing fields removed. No renames. Existing consumers unaffected.

---

## 4. OIDC Back-Channel Logout — outbound from netidm

### `POST {OAuth2RsBackchannelLogoutUri}`

Netidm — not an RP — is the client for this call. Contract listed here for RP implementers.

**Headers**:
- `Content-Type: application/x-www-form-urlencoded`
- `Cache-Control: no-store`
- `User-Agent: netidm/<version> (backchannel-logout)`

**Body**:
```
logout_token=<signed-jws>
```

The JWS is a compact-serialised JWT with `typ: "logout+jwt"` and the claim set specified in `research.md` R2.

**Expected response**:
- `HTTP 2xx` — delivery marked `succeeded`; no retry.
- Any other response (including no response / network failure / timeout) — delivery retried per `research.md` R1.

**Retry budget**: 6 attempts over ~24 h (0, +1 min, +5 min, +30 min, +2 h, +8 h). Per-request timeout: 5 s.

---

## 5. SAML Single Logout — SOAP binding

### `POST /saml/{sp_name}/slo/soap`

**Request**:
- `Content-Type: text/xml` (or `application/soap+xml`).
- Body is a SOAP envelope wrapping a signed `<samlp:LogoutRequest>`.
- The `<LogoutRequest>` MUST carry a valid XML Digital Signature using the SP's registered signing certificate (as recorded on the `SamlClient` entry).

**Required elements of the `<LogoutRequest>`**:
- `<saml:Issuer>` — MUST match `sp_name` (or the SP's entity ID recorded on the entry).
- `<saml:NameID>` — identifies the user whose session(s) should end.
- `<samlp:SessionIndex>` — optional. Governs single-session vs SP-wide-all-sessions termination per FR-011a.

**Response**:
- `HTTP/1.1 200 OK`, `Content-Type: text/xml`.
- Body is a SOAP envelope wrapping a signed `<samlp:LogoutResponse>`.

**Status codes**:
- `urn:oasis:names:tc:SAML:2.0:status:Success` — the session(s) matched by the rule in FR-011a were terminated. If no `SamlSession` entries matched (e.g. session already ended, or SessionIndex unknown), still `Success` — idempotent.
- `urn:oasis:names:tc:SAML:2.0:status:Requester` — malformed request, unrecognised `<Issuer>`, or no matching SP.
- `urn:oasis:names:tc:SAML:2.0:status:Responder` — signature verification failure, or internal error.

---

## 6. SAML Single Logout — HTTP-Redirect binding

### `GET /saml/{sp_name}/slo/redirect`

**Request parameters** (query string):
- `SAMLRequest` — deflate-compressed, base64-encoded `<LogoutRequest>`.
- `SigAlg` — signature algorithm URI.
- `Signature` — base64-encoded signature over the URL-encoded `SAMLRequest`, `SigAlg`, and `RelayState` if present.
- `RelayState` — optional opaque value.

**Behaviour**: Same logout semantics as the SOAP binding. After termination:
- If `RelayState` is a safe value (URL on the SP's own origin or absent), redirect to it.
- Otherwise render `logged_out.html`.

**Response**: `HTTP/1.1 302 Found` to `RelayState` on redirect, or `200 OK` with the confirmation page, or a signed `<LogoutResponse>` in a `SAMLResponse` query parameter on redirect back to the SP's SLO return URL (standard SAML HTTP-Redirect SLO response shape).

---

## 7. SAML IdP metadata extension

### `GET /saml/metadata.xml` (or the existing IdP metadata route)

The existing IdP metadata document gains `<SingleLogoutService>` elements alongside the existing `<SingleSignOnService>`:

```xml
<md:SingleLogoutService
    Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
    Location="{origin}/saml/{sp_name}/slo/soap"/>
<md:SingleLogoutService
    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    Location="{origin}/saml/{sp_name}/slo/redirect"/>
```

No existing elements removed or renamed.

---

## 8. US5 log-out-everywhere routes

### `POST /v1/self/logout_all`

**Auth**: Authenticated user (any valid UAT).
**Request body**: empty.
**Behaviour**: Terminate every active netidm session (UAT) belonging to the authenticated user. Each termination runs through `terminate_session`, so refresh-token revocation and back-channel enqueue fire per session.
**Response**: `200 OK` with a JSON summary `{"sessions_terminated": N}`.

### `POST /v1/person/{id}/logout_all`

**Auth**: System administrator (ACP `idm_admins` or equivalent).
**Path**: `{id}` = user's name or UUID.
**Request body**: empty.
**Behaviour**: Same as `/v1/self/logout_all` but targeting the named user.
**Response**: `200 OK` with `{"user": "<uuid>", "sessions_terminated": N}`. `404` if the user does not exist.

---

## 9. Admin delivery-queue read API

### `GET /v1/logout_deliveries`

**Auth**: System administrator.
**Query parameters**:
- `status` — optional; one of `pending`, `succeeded`, `failed`.
- `rp` — optional; OAuth2Client name or UUID to filter by.
- `limit` — default 100, max 1000.
- `cursor` — opaque continuation token.

**Response**: `200 OK`
```json
{
  "items": [
    {
      "uuid": "…",
      "rp": "portainer",
      "endpoint": "https://portainer.example/oidc/backchannel_logout",
      "status": "pending",
      "attempts": 2,
      "next_attempt": "2026-04-21T18:30:00Z",
      "last_attempt": "2026-04-21T18:25:00Z",
      "created": "2026-04-21T17:00:00Z"
    }
  ],
  "next_cursor": null
}
```

### `GET /v1/logout_deliveries/{uuid}`

Returns one item in the same shape as list items, plus a `logout_token_claims` field containing the decoded (but NOT the raw) token claims for admin inspection.
