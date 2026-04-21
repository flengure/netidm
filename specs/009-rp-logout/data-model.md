# Phase 1 — Data Model: PR-RP-LOGOUT

All new schema elements landed in DL26. Uses `server/lib/src/constants/uuids.rs` slot range `…ffff00000259` through `…ffff0000026A` — reserved by this PR. The first DL25 slot was `…ffff00000256`; DL26 begins immediately after DL25's last slot (`…ffff00000258`).

## 1. New attributes on existing classes

### 1.1 `OAuth2Client` gains:

| Attribute | Syntax | Multi-value | UUID slot | Description |
|---|---|---|---|---|
| `OAuth2RsPostLogoutRedirectUri` | Url | Yes | `…0259` | Allowlist of URIs the RP may name as `post_logout_redirect_uri` in an OIDC RP-initiated logout request. Exact-match semantics (see R7). |
| `OAuth2RsBackchannelLogoutUri` | Url | **No** | `…025A` | Endpoint netidm POSTs a signed logout token to when a session bound to this RP terminates. Absence = RP opts out of back-channel logout. |

Both added to `systemmay` on `OAuth2Client`. Neither is required.

### 1.2 `SamlClient` gains:

| Attribute | Syntax | Multi-value | UUID slot | Description |
|---|---|---|---|---|
| `SamlSingleLogoutServiceUrl` | Url | **No** | `…025B` | The SP's Single Logout Service endpoint (either SOAP or HTTP-Redirect binding; binding inferred from URL / advertised metadata). Absence = SLO not configured for this SP; inbound `<LogoutRequest>` signed by a recognised key is still honoured because SLO is a profile of the SP-to-IdP relationship. |

Added to `systemmay`. Not required.

## 2. New classes

### 2.1 `LogoutDelivery`

One entry per pending / succeeded / failed back-channel logout delivery.

| Attribute | Syntax | Multi-value | UUID slot | Description |
|---|---|---|---|---|
| `LogoutDeliveryEndpoint` | Url | No | `…025C` | Target URL (copy of the RP's `OAuth2RsBackchannelLogoutUri` at enqueue time — frozen so re-config doesn't change in-flight deliveries). |
| `LogoutDeliveryToken` | Utf8String | No | `…025D` | The signed logout token (JWS compact form) to POST. |
| `LogoutDeliveryStatus` | Utf8String | No | `…025E` | One of `pending`, `succeeded`, `failed`. Parsed by `LogoutDeliveryStatus::from_str`. |
| `LogoutDeliveryAttempts` | Uint32 | No | `…025F` | Count of attempts made so far (0 on enqueue). |
| `LogoutDeliveryNextAttempt` | DateTime | No | `…0260` | When the worker should next attempt this delivery. On enqueue = `now()`. |
| `LogoutDeliveryCreated` | DateTime | No | `…0261` | Enqueue time. Immutable. |
| `LogoutDeliveryRp` | Uuid (ref to `OAuth2Client`) | No | `…0262` | For admin filtering and debug; source of truth is the JWT `aud`. |

Class UUID slot: `…0265`.

ACP: admin-read-only (no write). Entries are inserted, updated, and eventually marked `succeeded`/`failed` only by the server. Admins can `list` and `show`, never modify.

Indexing: `LogoutDeliveryStatus` + `LogoutDeliveryNextAttempt` (composite; drives the worker's "due-now" query).

### 2.2 `SamlSession`

One entry per (user, SP, authentication) tuple — the per-SP session index referenced in FR-011a.

| Attribute | Syntax | Multi-value | UUID slot | Description |
|---|---|---|---|---|
| `SamlSessionUser` | Uuid (ref to `Person`) | No | `…0263` | The authenticated user's UUID. |
| `SamlSessionSp` | Uuid (ref to `SamlClient`) | No | `…0264` | The SP this session was created for. `nil` only for fallback-backfilled entries (see research R6). |
| `SamlSessionIndex` | Utf8String | No | `…0266` | UUID-v4 string, opaque to the SP. Emitted as `SessionIndex` on the matching `<AuthnStatement>`. Unique when combined with `SamlSessionSp`. |
| `SamlSessionUatUuid` | Uuid | No | `…0267` | Reference to the netidm UAT that backs this SAML session. When an inbound `<LogoutRequest>` matches, `terminate_session(uat_uuid)` is called. |
| `SamlSessionCreated` | DateTime | No | `…0268` | Emission time. |

Class UUID slot: `…0269`.

ACP: admin-read-all; self-read for entries where `SamlSessionUser == own_uuid`; no write ACP (server-only).

Indexing: `SamlSessionSp` + `SamlSessionIndex` (composite; drives the "SessionIndex present" SLO lookup). `SamlSessionSp` + `SamlSessionUser` (drives the "SessionIndex absent" SLO lookup).

## 3. UUID allocation summary

Next-free slot after DL25 is `…ffff00000259`. This PR consumes the following:

| Slot | Purpose |
|---|---|
| `…0259` | `OAuth2RsPostLogoutRedirectUri` attr |
| `…025A` | `OAuth2RsBackchannelLogoutUri` attr |
| `…025B` | `SamlSingleLogoutServiceUrl` attr |
| `…025C` | `LogoutDeliveryEndpoint` attr |
| `…025D` | `LogoutDeliveryToken` attr |
| `…025E` | `LogoutDeliveryStatus` attr |
| `…025F` | `LogoutDeliveryAttempts` attr |
| `…0260` | `LogoutDeliveryNextAttempt` attr |
| `…0261` | `LogoutDeliveryCreated` attr |
| `…0262` | `LogoutDeliveryRp` attr |
| `…0263` | `SamlSessionUser` attr |
| `…0264` | `SamlSessionSp` attr |
| `…0265` | `LogoutDelivery` class |
| `…0266` | `SamlSessionIndex` attr |
| `…0267` | `SamlSessionUatUuid` attr |
| `…0268` | `SamlSessionCreated` attr |
| `…0269` | `SamlSession` class |

First slot available for the next feature: `…ffff0000026A`.

Four new ACP UUIDs in the `UUID_IDM_ACP_*` block (allocated from the existing ACP range; exact slots decided during implementation). ACP purposes:

- `acp_oauth2_post_logout_redirect_uri_manage` — admin CRUD on `OAuth2RsPostLogoutRedirectUri` on OAuth2Client entries.
- `acp_oauth2_backchannel_logout_uri_manage` — admin CRUD on `OAuth2RsBackchannelLogoutUri` on OAuth2Client entries.
- `acp_saml_slo_url_manage` — admin CRUD on `SamlSingleLogoutServiceUrl` on SamlClient entries.
- `acp_logout_delivery_read` — admin read-only on `LogoutDelivery` entries.

## 4. State transitions

### 4.1 `LogoutDelivery` lifecycle

```
           enqueue
  (nothing) ────────▶ Pending ──── worker attempt success ───▶ Succeeded (terminal)
                          │
                          └─── worker attempt failure ───▶ Pending (next_attempt pushed back)
                          │                                    │
                          │                                    └─── RETRY_SCHEDULE.len() hits ───▶ Failed (terminal)
                          │
                          └─── admin inspects (read-only) ───▶ (no state change)
```

No admin write transition. Both terminal states (`Succeeded`, `Failed`) are permanent — no automatic re-enqueue.

### 4.2 `SamlSession` lifecycle

```
               SAML auth response minted
    (nothing) ──────────────────────────▶ Active
                                            │
                                            ├──── LogoutRequest (SessionIndex present) ─▶ deleted
                                            ├──── LogoutRequest (SessionIndex absent, SP match) ─▶ deleted
                                            ├──── UAT deletion (any cause) ────────────▶ deleted
                                            └──── DL26 migration (Stage 2 path) ───────▶ Active (SP = nil)
```

Entry is always deleted at session end (not soft-flagged), in line with constitution §Security Standards "Account deletion MUST be a true deletion".

## 5. Relationship diagram

```
Person ───────┐
              │ is subject of
              ▼
           UAT (existing) ◀──── SamlSessionUatUuid ──── SamlSession ──── SamlSessionSp ───▶ SamlClient
              │
              │ produced tokens for
              ▼
       OAuth2Client ────OAuth2RsBackchannelLogoutUri───▶ (endpoint URL)
                              │
                              │ enqueue on session end
                              ▼
                       LogoutDelivery ──── LogoutDeliveryRp ───▶ OAuth2Client
```

## 6. Validation rules

- `LogoutDeliveryStatus` MUST be one of `pending | succeeded | failed` — any other value is a schema constraint violation.
- `LogoutDeliveryAttempts` MUST be ≤ `RETRY_SCHEDULE.len()` (= 6). A value equal to `RETRY_SCHEDULE.len()` is only valid when `LogoutDeliveryStatus == failed`.
- `SamlSessionIndex` MUST parse as a UUID (any version). Legacy backfill values and freshly-emitted values both conform.
- `(SamlSessionSp, SamlSessionIndex)` is unique when `SamlSessionSp` is non-nil — enforced by a uniqueness constraint at the schema level.
- `LogoutDeliveryEndpoint` MUST be an absolute URL with `https` scheme (exception: `http` permitted only to RFC 1918 loopback hosts, for local dev/testing — same rule netidm uses elsewhere).
- `OAuth2RsPostLogoutRedirectUri` MUST be an absolute URL; no scheme restriction (apps may legitimately use `myapp://` mobile redirects).

## 7. Migration notes

- DL25 → DL26 is backward-compatible for every pre-existing class: `OAuth2Client` and `SamlClient` only gain `systemmay` attributes.
- The two new classes (`LogoutDelivery`, `SamlSession`) do not replace any existing data.
- The backfill phase (research R6) is the only phase with a data write; it is idempotent — re-running it on a DB that already has `SamlSession` entries is a no-op at the (UAT, SP) level.
