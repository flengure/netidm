# Implementation Plan: RP-Initiated Logout (PR-RP-LOGOUT)

**Branch**: `009-rp-logout` | **Date**: 2026-04-21 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/009-rp-logout/spec.md`

## Summary

Add RP-initiated logout across netidm's OIDC and SAML surfaces. Three discrete wire contracts:
(1) **OIDC RP-Initiated Logout 1.0** — a per-client `end_session_endpoint` plus a global fallback route, both sharing one handler; verifies the ID token hint, terminates the single netidm session named by the token's `sid` claim, revokes the in-scope refresh tokens, redirects to a registered `post_logout_redirect_uri` (echoing `state`) or renders a confirmation page.
(2) **OIDC Back-Channel Logout 1.0** — at session termination, enqueue one persisted `LogoutDelivery` record per registered back-channel endpoint; a background worker attempts each with bounded timeout and exponential-backoff retry budget, surviving restart; admins list pending/succeeded/failed via CLI. (Intentional netidm extension beyond dex's fire-and-forget model.)
(3) **SAML Single Logout** — SOAP + HTTP-Redirect bindings on each `SamlClient`; spec-strict `<SessionIndex>` handling (single-session with index present; all-sessions-at-SP when absent); emits `<SessionIndex>` on every new SAML auth response; DL26 migration backfills synthetic `<SessionIndex>` values onto all active SAML sessions so every session is single-session-addressable at ship.

All termination paths (OIDC end-session, SAML SLO, netidm expiry/revoke, new US5 "log out everywhere" surface) converge on one internal routine (`idm::logout::terminate_session`) that ends the netidm session, revokes in-scope refresh tokens, and enqueues back-channel deliveries — so no termination path skips steps. DL26 adds attributes on `OAuth2Client` and `SamlClient`, two new classes (`LogoutDelivery`, `SamlSession`), and ACPs. CLI + client SDK gain CRUD verbs for the new attributes and read verbs for the delivery queue.

## Technical Context

**Language/Version**: Rust stable (see `rust-toolchain.toml`)
**Primary Dependencies**: Existing — `netidmd_lib` (MVCC entry DB, schema/migration framework), `netidm_proto` (Attribute / EntryClass / constants), `compact_jwt` (JWS signing for the logout token, already used for OIDC), `samael` 0.0.20 (already vendored with `xmlsec` feature — used for SAML XML signing/verification since 007-saml2-connector), `reqwest` (HTTP client for back-channel delivery, already in `server/core`), `askama` (confirmation page template, already in use), `axum` / `axum-extra` (routing + cookies, already present). No new workspace deps.
**New Dependencies**: None.
**Storage**: Netidm MVCC entry database. DL26 migration adds:
- Three new attributes on existing classes (`OAuth2RsPostLogoutRedirectUri`, `OAuth2RsBackchannelLogoutUri`, `SamlSingleLogoutServiceUrl`).
- Two new entry classes (`LogoutDelivery`, `SamlSession`) plus their attributes (`LogoutDeliveryEndpoint`, `LogoutDeliveryToken`, `LogoutDeliveryStatus`, `LogoutDeliveryAttempts`, `LogoutDeliveryNextAttempt`, `LogoutDeliveryCreated`, `SamlSessionUser`, `SamlSessionSp`, `SamlSessionIndex`, `SamlSessionUatUuid`, `SamlSessionCreated`).
- New ACP entries for admin-only access to the new configuration attributes and read-only listing of `LogoutDelivery` records.
- A migration phase that scans all active-session UATs created by the SAML auth path and backfills a synthetic `SessionIndex` (UUID v4 string) into a new `SamlSession` entry per (user, SP, UAT) tuple.

**Testing**: `cargo test` via `server/testkit` integration infrastructure (real in-process netidmd); unit tests co-located in the new modules. HTTP-level tests for the new `end_session_endpoint` and SLO routes via testkit. Dummy HTTP receiver for back-channel delivery (spun up inside the test process, not an external service).
**Target Platform**: Linux server (same as rest of netidm).
**Project Type**: Library + HTTP service + CLI tool (tri-crate: `server/lib`, `server/core`, `tools/cli`).
**Performance Goals**: End-session handler returns in the same latency band as `/oauth2/token` (well under 100 ms under normal load — token verification + one write txn). Back-channel delivery does not contribute to user-visible latency (enqueue only; worker runs out-of-band). Worker poll interval 30 s; wake-up trigger on enqueue for immediate first-attempt latency.
**Constraints**:
- All new doc comments per constitution §Documentation Standards.
- `cargo clippy --all-features -- -D warnings` must remain clean.
- `cargo test` (default features) must pass — no `--all-features` for tests (dhat profiler singleton conflicts with parallel harness, per project memory).
- Back-channel delivery worker MUST run entirely in-process in `netidmd`; no external queue (Redis, RabbitMQ) — constitution §Correct & Simple.
- SAML signature verification MUST go through `samael` with the `xmlsec` feature; no hand-rolled XML-DSig.
- Rust identifier `end_session` is already taken by `authsession::AuthSessionData::end_session` at `server/lib/src/idm/authsession/mod.rs:1761`; the new OIDC handler is named `handle_oauth2_rp_initiated_logout` to avoid the clash.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Ethics & Human Rights | PASS | No new PII fields. `LogoutDelivery` records contain the logout token (JWS) which carries the target user's UUID and session UUID — these are already observable in existing audit logs. `SamlSession` entries carry (user, SP, SessionIndex) — all derivable from the existing SAML flow. Users retain self-control: US5 gives end users a self-service "log out everywhere" surface, which is the single way to kill all their sessions at once. |
| II. Humans First | PASS | Admin CLI accepts OAuth2 and SAML client by `name` or UUID — matches prior PR conventions. Confirmation page on logout is non-blocking; fallback path when ID token is missing/expired still clears the session and reaches a visible landing page (not a 400/500). Error responses on SAML SLO use `<StatusCode>` values the SP library will render cleanly. |
| III. Correct & Simple | PASS | `cargo test` remains self-contained — dummy HTTP receiver for back-channel tests is spun up by `testkit` inside the test process. Background worker runs inside `netidmd` — no external queue. Delivery records persist in the same MVCC DB — no second storage engine. |
| IV. Clippy & Zero Warnings | PASS | No `#[allow(...)]` planned. `hashbrown::HashSet` used where sets are needed; std `HashSet` banned by project clippy config. `async-trait` only where an existing trait requires it. |
| V. Security by Hierarchy | PASS | Elimination: SAML `<LogoutRequest>` with missing/invalid signature NEVER ends a session (FR-012) — not "warn and proceed". Engineering Control: central `terminate_session` routine means no termination path can skip refresh-token revocation or back-channel enqueue (FR-015). Administrative Control: admin-visible delivery-queue CLI so permanently-failed deliveries surface in ops view, not silently lost. |
| Security Standards | PASS | Authentication flows deny on validation failure (FR-003, FR-012). Secrets: logout tokens are signed, not encrypted; signing key is the existing netidm OIDC signing key, not a new one. Logs: delivery failure logs include endpoint URL and HTTP status but NOT the logout token body (contains `sub` + `sid` which are session-scoped but still sensitive). Post-logout redirect URIs use exact-match allowlisting — no open redirect vulnerability. |
| Documentation Standards | REQUIRED | Doc comments on every new `pub` item: `terminate_session`, `LogoutDelivery` / `SamlSession` types and their constructors, CLI verbs, client SDK methods, new HTTP handlers. `# Errors` on every `Result`-returning `pub fn`. `# Examples` on new public handlers and CLI verbs. |
| Testing Standards | REQUIRED | Unit tests for logout-token JWT claim shape, `<LogoutRequest>` parsing + signature verification, `SamlSession` lookup by (SP, SessionIndex), `LogoutDelivery` state transitions. Integration tests (testkit) for each user story's primary success and failure path. Dummy receiver for back-channel delivery. |
| DL Migration | REQUIRED | DL26 migration introduced; round-trip test in `migrations.rs` asserts new attributes, classes, and ACPs exist after DL25→DL26 upgrade. Backfill phase tested with a pre-seeded DL25 DB that has active SAML sessions. |

No constitution violations. No Complexity Tracking entries required.

## Project Structure

### Documentation (this feature)

```text
specs/009-rp-logout/
├── plan.md              # This file
├── research.md          # Design decisions + alternatives (Phase 0)
├── data-model.md        # Entity model (Phase 1)
├── quickstart.md        # Test scenarios (Phase 1)
├── contracts/
│   ├── http-endpoints.md  # OIDC + SAML HTTP contract
│   └── cli-commands.md    # CLI command contract
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Generated by /speckit.tasks
```

### Source Code Changes

```text
proto/src/
├── attribute.rs                                # + OAuth2RsPostLogoutRedirectUri,
│                                                 OAuth2RsBackchannelLogoutUri,
│                                                 SamlSingleLogoutServiceUrl,
│                                                 LogoutDeliveryEndpoint, LogoutDeliveryToken,
│                                                 LogoutDeliveryStatus, LogoutDeliveryAttempts,
│                                                 LogoutDeliveryNextAttempt, LogoutDeliveryCreated,
│                                                 SamlSessionUser, SamlSessionSp, SamlSessionIndex,
│                                                 SamlSessionUatUuid, SamlSessionCreated
│                                                 (Attribute enum + as_str + FromStr)
└── constants.rs                                # + ATTR_* const strings (one per new attribute)
                                                  + ENTRY_CLASS_LOGOUT_DELIVERY,
                                                    ENTRY_CLASS_SAML_SESSION

server/lib/src/
├── constants/
│   ├── mod.rs                                  # DOMAIN_LEVEL_26; bump TGT/MAX; PREVIOUS follows
│   └── uuids.rs                                # UUID_SCHEMA_ATTR_* (12 new, ...0259–0264 for
│                                                 attrs; ...0265–0266 for classes)
│                                                 UUID_SCHEMA_CLASS_LOGOUT_DELIVERY,
│                                                 UUID_SCHEMA_CLASS_SAML_SESSION
│                                                 UUID_IDM_ACP_* additions for new attributes
├── idm/
│   ├── logout.rs                               # NEW: terminate_session, LogoutTokenClaims,
│   │                                                 logout_token_for_rp, unit tests
│   ├── logout_delivery.rs                      # NEW: LogoutDelivery model, worker task, retry
│   │                                                 schedule, unit tests
│   ├── mod.rs                                  # + pub mod logout; pub mod logout_delivery;
│   ├── oauth2.rs                               # + handle_oauth2_rp_initiated_logout;
│   │                                             discovery doc additions:
│   │                                               end_session_endpoint,
│   │                                               backchannel_logout_supported = true,
│   │                                               backchannel_logout_session_supported = true
│   │                                             logout_token minting helper
│   ├── saml_client.rs                          # + SessionIndex emission on AuthnStatement
│   │                                             + handle_saml_logout_request (SessionIndex
│   │                                                 present / absent branches)
│   │                                             + SamlSession entry read/write helpers
│   ├── session.rs OR authsession/mod.rs        # Hook terminate_session from existing
│   │                                             expiry/revoke paths (all end-of-session
│   │                                             paths converge — FR-015)
│   └── server.rs                               # + IdmServerProxyWriteTransaction:
│                                                   terminate_session_for_uat(uat_uuid),
│                                                   enqueue_logout_deliveries(session_uuid),
│                                                   backfill_saml_session_indices (DL26 use)
├── migration_data/
│   ├── mod.rs                                  # + dl26 module; flip latest alias
│   └── dl26/
│       ├── mod.rs                              # DL26 phase functions (delegate to dl25 except
│       │                                         phases 1–3: schema attrs, classes, and
│       │                                         Phase N: SAML-session backfill)
│       ├── schema.rs                           # SCHEMA_ATTR_*_DL26, SCHEMA_CLASS_*_DL26
│       │                                         (OAuth2Client + SamlClient gain systemmay
│       │                                         entries for the new URL attrs;
│       │                                         LogoutDelivery + SamlSession full class defs)
│       └── access.rs                           # New ACPs: admin CRUD for the new URL attrs;
│                                                 admin read-only for LogoutDelivery entries;
│                                                 self-read for SamlSession entries belonging
│                                                 to the authenticated user (for "list my
│                                                 sessions" UX used by US5 self-service)
└── server/
    ├── migrations.rs                           # migrate_domain_25_to_26() method
    │                                             (mirrors migrate_domain_24_to_25 structurally);
    │                                             backfill_saml_session_indices phase at the end
    └── mod.rs                                  # DL25→26 upgrade block; const assert
                                                  DOMAIN_MAX_LEVEL == DOMAIN_LEVEL_26

server/core/src/
├── actors/
│   ├── v1_read.rs                              # handle_list_logout_deliveries (admin query)
│   └── v1_write.rs                             # handle_oauth2_client_add_post_logout_uri /
│                                                 _remove_ / _list_ (per-attribute CRUD)
│                                                 handle_oauth2_client_set_backchannel_uri /
│                                                 _clear_
│                                                 handle_saml_client_set_slo_url / _clear_
│                                                 handle_user_logout_all_sessions (US5 self)
│                                                 handle_admin_logout_all_sessions (US5 admin)
├── https/
│   ├── oauth2.rs                               # Route registration:
│   │                                             /oauth2/openid/{client_id}/end_session_endpoint
│   │                                             /oauth2/openid/end_session_endpoint (global)
│   │                                             both → oauth2_rp_initiated_logout
│   ├── v1_oauth2.rs                            # Per-attribute CRUD routes for post_logout_uri,
│   │                                             backchannel_logout_uri
│   ├── v1_saml.rs                              # Route registration:
│   │                                             /saml/{sp_name}/slo/soap (POST)
│   │                                             /saml/{sp_name}/slo/redirect (GET)
│   │                                             both → saml_slo_handler
│   │                                             metadata handler extension to advertise SLO
│   ├── v1.rs                                   # GET /v1/logout_deliveries (admin)
│   │                                             POST /v1/self/logout_all (self)
│   │                                             POST /v1/person/{id}/logout_all (admin)
│   └── views/
│       ├── logout.rs                           # NEW: logged-out confirmation page
│       │                                            (askama template)
│       └── login.rs                            # No changes expected (existing login flow
│                                                 unaffected by logout path)
└── lib.rs                                      # Spawn back-channel delivery worker on startup
                                                  (one task per netidmd instance, terminates
                                                  on shutdown signal)

server/core/templates/
└── logged_out.html                             # NEW: askama template for the confirmation page

libs/client/src/
├── oauth.rs                                    # + idm_oauth2_client_add_post_logout_redirect_uri
│                                                 + idm_oauth2_client_remove_post_logout_redirect_uri
│                                                 + idm_oauth2_client_list_post_logout_redirect_uris
│                                                 + idm_oauth2_client_set_backchannel_logout_uri
│                                                 + idm_oauth2_client_clear_backchannel_logout_uri
├── saml.rs                                     # + idm_saml_client_set_slo_url
│                                                 + idm_saml_client_clear_slo_url
└── session.rs OR new module                    # + idm_logout_all_self
                                                  + idm_logout_all_user (admin)
                                                  + idm_list_logout_deliveries (admin)

tools/cli/src/
├── opt/
│   ├── netidm.rs                               # + AddPostLogoutRedirectUri,
│   │                                             RemovePostLogoutRedirectUri,
│   │                                             ListPostLogoutRedirectUris,
│   │                                             SetBackchannelLogoutUri,
│   │                                             ClearBackchannelLogoutUri on OAuth2Opt
│   │                                           + SetSloUrl, ClearSloUrl on SamlClientOpt
│   │                                           + LogoutAll on PersonOpt (admin form)
│   │                                           + LogoutAll on SelfOpt (self form)
│   │                                           + LogoutDeliveries (top-level admin verb)
│   └── logout.rs                               # NEW: subcommand group for delivery-queue
│                                                      inspection (list, show, filter)
└── cli/
    ├── oauth2.rs                               # Command handlers for new URL attrs
    ├── saml.rs                                 # Command handlers for SLO URL
    ├── person.rs                               # logout-all (admin) handler
    ├── self_cli.rs OR equivalent               # logout-all (self) handler
    └── logout.rs                               # NEW: delivery-queue inspection handlers
```

## Implementation Notes by Layer

### Layer 1: Protocol (`proto/`)

**`proto/src/constants.rs`** — new const strings (one per new attribute and class):
```rust
pub const ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI: &str = "oauth2_rs_post_logout_redirect_uri";
pub const ATTR_OAUTH2_RS_BACKCHANNEL_LOGOUT_URI: &str = "oauth2_rs_backchannel_logout_uri";
pub const ATTR_SAML_SINGLE_LOGOUT_SERVICE_URL: &str = "saml_single_logout_service_url";
pub const ATTR_LOGOUT_DELIVERY_ENDPOINT: &str = "logout_delivery_endpoint";
// ... (see data-model.md for full set)
pub const ENTRY_CLASS_LOGOUT_DELIVERY: &str = "logout_delivery";
pub const ENTRY_CLASS_SAML_SESSION: &str = "saml_session";
```

**`proto/src/attribute.rs`** — `Attribute` enum gains 12 new variants; both `as_str` and `FromStr` match arms updated.

### Layer 2: Schema constants (`server/lib/src/constants/`)

- `DOMAIN_LEVEL_26` added; `DOMAIN_TGT_LEVEL`, `DOMAIN_MAX_LEVEL`, `DOMAIN_MINIMUM_REPLICATION_LEVEL`, `DOMAIN_MAXIMUM_REPLICATION_LEVEL` bumped. `DOMAIN_PREVIOUS_TGT_LEVEL` follows.
- `uuids.rs` — allocate from the next free slot. Current highest is `…ffff00000258` (`UUID_SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP` from DL25). Block for DL26 begins at `…ffff00000259` and continues through the twelve attr UUIDs plus two class UUIDs.
- ACP UUIDs in the `UUID_IDM_ACP_*` block for the new admin-facing ACPs.

### Layer 3: `terminate_session` central routine (`server/lib/src/idm/logout.rs`)

```rust
//! Central session-termination routine plus logout-token minting.
//!
//! Every end-of-session path in netidm — OIDC `end_session_endpoint`,
//! SAML `<LogoutRequest>`, session expiry, administrator revoke, and the
//! US5 "log out everywhere" surface — calls [`terminate_session`]. This
//! routine ends the netidm session, revokes the refresh tokens issued
//! against it, and enqueues back-channel-logout deliveries for every
//! relying party that has a [`Attribute::OAuth2RsBackchannelLogoutUri`].
//! There is no other termination path in the codebase — a project-wide
//! grep MUST return exactly one definition of this function.

pub struct LogoutTokenClaims { /* sub, sid, iss, aud, iat, jti, events */ }

/// Terminate a single netidm session and enqueue any back-channel deliveries.
///
/// # Errors
/// Returns any `OperationError` from the underlying entry-DB write or
/// enqueue transaction. Back-channel enqueue failures propagate; the
/// caller is responsible for rolling the enclosing txn back if the session
/// termination itself should be reversed.
pub fn terminate_session(
    qs_write: &mut QueryServerWriteTransaction,
    uat_uuid: Uuid,
) -> Result<(), OperationError> { ... }

/// Mint a signed logout token targeted at one relying party.
///
/// # Errors
/// Returns `OperationError::Jws*` variants if signing fails.
pub fn logout_token_for_rp(
    idms: &IdmServerProxyWriteTransaction<'_>,
    rp_uuid: Uuid,
    user_uuid: Uuid,
    session_uuid: Uuid,
) -> Result<String, OperationError> { ... }
```

Algorithm for `terminate_session`:
1. Read the UAT entry; extract `user_uuid`, list of `rp_uuid`s that minted tokens against it (from existing `OAuth2AccountCredential` linkage), and SAML `SamlSession` records linked to this UAT.
2. Revoke each linked `OAuth2AccountCredential` with in-scope refresh tokens (existing `IdmServerProxyWriteTransaction::expire_account_session` shape).
3. For each `rp_uuid` that has a `OAuth2RsBackchannelLogoutUri`, build a `LogoutTokenClaims`, sign it with the netidm OIDC signing key, and insert one `LogoutDelivery` entry (status = `pending`, `next_attempt = now()`).
4. For each linked SAML session (via `SamlSession` entries), delete those entries.
5. Delete the UAT.
6. Signal the delivery worker (a `tokio::sync::Notify` instance) to wake up for an immediate first attempt of the newly-enqueued records. Worker path described in Layer 4.

### Layer 4: Back-channel delivery worker (`server/lib/src/idm/logout_delivery.rs`)

```rust
//! Persistent back-channel logout delivery worker.
//!
//! At `terminate_session` time, one [`LogoutDelivery`] entry is inserted per
//! registered endpoint. This module defines the entry shape and the
//! long-running worker that drives deliveries.

pub struct LogoutDelivery {
    pub uuid: Uuid,
    pub endpoint: Url,
    pub logout_token: String,   // signed JWT
    pub status: LogoutDeliveryStatus,
    pub attempts: u32,
    pub next_attempt: OffsetDateTime,
    pub last_attempt: Option<OffsetDateTime>,
    pub created: OffsetDateTime,
}

pub enum LogoutDeliveryStatus { Pending, Succeeded, Failed }

/// Retry schedule — 6 attempts totalling ~24 h:
/// attempt #:  0  1    2    3    4   5
/// delay:      0  1m   5m   30m  2h  8h
const RETRY_SCHEDULE: [Duration; 6] = [
    Duration::ZERO,
    Duration::from_secs(60),
    Duration::from_secs(300),
    Duration::from_secs(1800),
    Duration::from_secs(7200),
    Duration::from_secs(28800),
];

pub async fn run_worker(
    idms: Arc<IdmServer>,
    http: reqwest::Client,         // 5s per-request timeout
    notify: Arc<tokio::sync::Notify>,
) -> ! { ... }
```

Worker behaviour:
- On startup, scan for `LogoutDelivery { status: Pending }` entries; for each, if `next_attempt > now()`, schedule a wake-up; if `<= now()`, attempt immediately.
- Loop: `select!` over a 30 s poll timer, the `Notify` signal, and a shutdown signal. On each tick, read all `Pending` entries whose `next_attempt <= now()`.
- Per attempt: POST the stored `logout_token` as `application/jwt` with a 5 s request timeout to `endpoint`. On 2xx → `status = Succeeded`. On any other response (non-2xx / network error / timeout) → increment `attempts`; if `attempts == RETRY_SCHEDULE.len()` → `status = Failed`; else set `next_attempt = now() + RETRY_SCHEDULE[attempts]`.
- Logs: info on success, warn on retry scheduled, error on permanent failure. Logs include endpoint URL + HTTP status but NOT the JWT body.

### Layer 5: OIDC end-session endpoint (`server/lib/src/idm/oauth2.rs`, `server/core/src/https/oauth2.rs`)

Route registration — both routes share one handler (existing OIDC router at `server/core/src/https/oauth2.rs:763`):
```rust
.route(
    "/oauth2/openid/{client_id}/end_session_endpoint",
    get(oauth2_rp_initiated_logout).post(oauth2_rp_initiated_logout),
)
.route(
    "/oauth2/openid/end_session_endpoint",
    get(oauth2_rp_initiated_logout_global).post(oauth2_rp_initiated_logout_global),
)
```

Handler flow (`handle_oauth2_rp_initiated_logout` in `server/lib/src/idm/oauth2.rs`):
1. Parse request parameters (`id_token_hint`, `post_logout_redirect_uri`, `state`, `client_id`, `logout_hint`, `ui_locales`).
2. Verify `id_token_hint` via `compact_jwt::OidcUnverified` → `compact_jwt::OidcVerified` using the client's known signing material. On failure → fall through to confirmation page.
3. Extract `sid` (session UUID) and `aud` (client UUID) from the verified token.
4. Begin write txn. Call `logout::terminate_session(qs_write, sid_uat_uuid)`.
5. Evaluate `post_logout_redirect_uri`:
    - If present AND in the client's `Attribute::OAuth2RsPostLogoutRedirectUri` allowlist → emit 302 to the URI with `state` appended.
    - Else → render `logged_out.html` askama template with HTTP 200.

Discovery doc extensions (`oauth2_openid_discovery_get` handler used at `server/core/src/https/oauth2.rs:769`):
```json
{
  "end_session_endpoint": "…/oauth2/openid/{client_id}/end_session_endpoint",
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true
}
```

### Layer 6: SAML SLO (`server/lib/src/idm/saml_client.rs`, `server/core/src/https/v1_saml.rs`)

Two new routes:
```rust
// server/core/src/https/v1_saml.rs
.route("/saml/{sp_name}/slo/soap",     post(saml_slo_soap))
.route("/saml/{sp_name}/slo/redirect", get(saml_slo_redirect))
```

Both hand off to `handle_saml_logout_request`, which:
1. Uses `samael` to parse and verify the signature on the `<LogoutRequest>`. Invalid / missing → build a signed `<LogoutResponse>` with `StatusCode = saml:status:Responder` and return.
2. Read `<NameID>` and (if present) `<SessionIndex>`.
3. **SessionIndex present**: `qs_write.search` for `SamlSession` where `SamlSessionSp == sp_uuid && SamlSessionIndex == sessionindex`. Match → verify `SamlSessionUser == nameid_user_uuid`. Call `logout::terminate_session(qs_write, session_record.uat_uuid)`. Delete the `SamlSession` entry. Build `Status::Success` response.
4. **SessionIndex absent**: `qs_write.search` for all `SamlSession` where `SamlSessionSp == sp_uuid && SamlSessionUser == nameid_user_uuid`. For each match, `terminate_session` + delete. Build `Status::Success`.
5. Sign `<LogoutResponse>` via `samael` using the existing SAML signing key.
6. On HTTP-Redirect binding, also render a confirmation page (same template as OIDC) or honour `RelayState` if supplied and safe.

SAML `<SessionIndex>` emission — in `saml_client.rs`'s authn-response builder: when minting `<AuthnStatement>`, include `SessionIndex="<uuid>"` and create a `SamlSession` entry tying `(user_uuid, sp_uuid, session_index, uat_uuid)`. UAT UUID comes from the current auth context.

### Layer 7: US5 — log-out-everywhere surface (`server/core/src/https/v1.rs`)

Two HTTP routes:
- `POST /v1/self/logout_all` — self-service path. Authenticated user only. Enumerate all UATs for the authenticated principal and call `terminate_session` on each.
- `POST /v1/person/{id}/logout_all` — admin path. ACP-gated to system administrators. Same enumerate-and-terminate, but on behalf of the named user.

Both routes call into `handle_user_logout_all_sessions` / `handle_admin_logout_all_sessions` on `v1_write.rs`.

### Layer 8: DL26 migration (`server/lib/src/migration_data/dl26/`)

`schema.rs`:
```rust
pub static SCHEMA_ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI_DL26: LazyLock<SchemaAttribute> = LazyLock::new(|| {
    SchemaAttribute {
        name: Attribute::OAuth2RsPostLogoutRedirectUri,
        uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI,
        description: "Allowlist of post-logout redirect URIs the relying party \
                      may name in an end_session_endpoint request.".to_string(),
        multivalue: true,
        syntax: SyntaxType::Url,
        ..Default::default()
    }
});

// Analogous blocks for the other 11 new attributes and the two new classes.
// OAuth2Client + SamlClient gain the new URL attrs in systemmay.
// LogoutDelivery + SamlSession are full standalone class definitions.
```

`mod.rs` — phase functions delegate to `super::dl25` except:
- Phase 1 (schema attrs): register all 12 new attrs.
- Phase 2 (schema classes): register the two new classes and the modified OAuth2Client / SamlClient.
- Phase 3 (ACPs): register the new admin-only ACPs.
- Phase 4 (backfill): enumerate active UATs produced by a SAML auth (see research.md — detection strategy depends on whether DL25 session metadata records provenance; fallback is "backfill every active UAT; SLO correlation ignores non-SAML rows" with `SamlSessionSp = nil`). Produce one `SamlSession` entry per match with a freshly-generated SessionIndex.

`server/lib/src/server/migrations.rs` — `migrate_domain_25_to_26()` mirrors `migrate_domain_24_to_25()` structurally; backfill phase runs after schema + ACPs land.

### Layer 9: Client SDK (`libs/client/src/oauth.rs`, `saml.rs`, `session.rs`)

Signatures mirror the shape of `idm_oauth2_client_add_group_mapping` from PR-GROUPS-PIPELINE:
```rust
pub async fn idm_oauth2_client_add_post_logout_redirect_uri(
    &self, id: &str, uri: &str,
) -> Result<(), ClientError>;
pub async fn idm_oauth2_client_remove_post_logout_redirect_uri(
    &self, id: &str, uri: &str,
) -> Result<(), ClientError>;
pub async fn idm_oauth2_client_list_post_logout_redirect_uris(
    &self, id: &str,
) -> Result<Vec<String>, ClientError>;
pub async fn idm_oauth2_client_set_backchannel_logout_uri(
    &self, id: &str, uri: &str,
) -> Result<(), ClientError>;
pub async fn idm_oauth2_client_clear_backchannel_logout_uri(
    &self, id: &str,
) -> Result<(), ClientError>;

pub async fn idm_saml_client_set_slo_url(
    &self, id: &str, url: &str,
) -> Result<(), ClientError>;
pub async fn idm_saml_client_clear_slo_url(
    &self, id: &str,
) -> Result<(), ClientError>;

pub async fn idm_logout_all_self(&self) -> Result<(), ClientError>;
pub async fn idm_logout_all_user(&self, id: &str) -> Result<(), ClientError>;
pub async fn idm_list_logout_deliveries(
    &self, filter: LogoutDeliveryFilter,
) -> Result<Vec<LogoutDeliveryDto>, ClientError>;
```

### Layer 10: CLI (`tools/cli/src/`)

New verbs on `OAuth2Opt`:
```rust
AddPostLogoutRedirectUri { name: String, uri: String },
RemovePostLogoutRedirectUri { name: String, uri: String },
ListPostLogoutRedirectUris { name: String },
SetBackchannelLogoutUri { name: String, uri: String },
ClearBackchannelLogoutUri { name: String },
```

New verbs on `SamlClientOpt`:
```rust
SetSloUrl { name: String, url: String },
ClearSloUrl { name: String },
```

US5 surface:
- `netidm person logout-all <id>` (admin)
- `netidm self logout-all` (self-service)

Delivery queue inspection (top-level admin subcommand):
- `netidm logout-deliveries list [--pending | --succeeded | --failed]`
- `netidm logout-deliveries show <uuid>`

## Complexity Tracking

No constitution violations. No entries required.

**Notes on intentional complexity** (documented in `research.md` for future reference):
- **Back-channel delivery is persisted, not fire-and-forget.** Dex's fire-and-forget model was rejected per spec Q2/D because operators reported losing back-channel notifications across restarts in comparable deployments. Flagged as "netidm extension beyond dex feature set" (same category as PR-LINKBY).
- **SAML SessionIndex backfill migration.** Without it, SAML sessions created before the migration lands could only be logged out via the "no SessionIndex" branch, which is a footgun for admins who'd expect single-session SLO to work for all sessions on day one (spec Q5/C). Backfill runs once during DL26 upgrade.
- **`SamlSession` as a standalone entry class.** Alternatives rejected:
  - Multi-value attribute on `Person` — awkward to index for the (SP, SessionIndex) lookup and loses per-attempt metadata.
  - Overload the existing UAT entry — UAT is OIDC/native-session-oriented and adding SAML-specific fields pollutes it.
  - Separate index file outside the MVCC DB — violates §Correct & Simple (no external storage).
