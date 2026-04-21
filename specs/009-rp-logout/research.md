# Phase 0 — Research: PR-RP-LOGOUT

All open questions that drive Phase 1 design decisions, with the decision taken, the rationale, and alternatives explicitly rejected. No `NEEDS CLARIFICATION` markers remain.

---

## R1. Back-channel retry schedule

**Decision**: 6 attempts over ≈24 h with exponential backoff.

| Attempt | Offset from enqueue |
|---|---|
| 0 | immediate |
| 1 | +1 min |
| 2 | +5 min |
| 3 | +30 min |
| 4 | +2 h |
| 5 | +8 h |

After the 5th retry fails, the `LogoutDelivery` entry is marked `Failed` and the worker stops touching it. Total budget ≈ 10.5 h ± jitter; suitable for intermittent-outage recovery without trying forever.

**Rationale**: Covers the common failure modes that operators care about (RP restart, brief network partition, deploy-window) without accumulating records indefinitely. Exponential backoff avoids hammering a permanently-broken endpoint.

**Alternatives rejected**:
- **3 attempts over 1 h** — too short; a deploy-window outage would exceed the window.
- **Continue until the logout token's `exp` passes** — logout tokens are short-lived per spec (≤ 2 min recommended); worker would give up in minutes.
- **Admin-tunable per-client retry budget** — premature configurability; bring back if operators request it.

**Per-request timeout**: 5 s. Matches the network-level timeouts used elsewhere in netidm's `reqwest` clients (e.g. the OAuth2 upstream connectors).

---

## R2. Logout-token claim set

**Decision**: Mint per OpenID Back-Channel Logout 1.0 §2.4. Required claims:

| Claim | Source | Notes |
|---|---|---|
| `iss` | netidm's OIDC issuer URL (existing) | same as id-token `iss` |
| `aud` | target RP's client identifier | one delivery = one audience |
| `iat` | `now()` | |
| `jti` | freshly generated UUID v4 | for RP-side replay protection |
| `sub` | user's UUID (stringified) | same shape as id-token `sub` |
| `sid` | session (UAT) UUID (stringified) | enables RP to tie to its local session |
| `events` | `{"http://schemas.openid.net/event/backchannel-logout": {}}` | literal per spec |

Omit `nonce` (forbidden by spec §2.4). Omit `nbf`, `exp` — not required by spec; `jti` + `iat` + RP-side dedup is sufficient. (Spec explicitly allows absence of `exp`.)

**Signing**: `compact_jwt` JWS with the existing netidm OIDC signing key. Header `alg` matches the RP's registered ID-token signing alg (default `RS256`). Header `typ` = `"logout+jwt"` per spec §2.4.

**Rationale**: One-to-one with the OpenID spec; no speculation. Reusing the existing signing key means zero new key management.

**Alternatives rejected**:
- **Including `exp`** — RPs aren't supposed to honour `exp` on logout tokens (spec forbids rejecting based on `exp` alone). Including it adds failure modes for nothing.
- **Per-client signing keys** — no operational reason; netidm's OIDC signing key is already the RP-trusted key.

---

## R3. Session identifier (`sid`) shape

**Decision**: `sid` = the UAT UUID (the existing netidm session identifier), stringified as a hyphenated UUID.

**Rationale**: Netidm already assigns every session a UUID; the `sid` in the ID token issued at auth time is already this value. Keeping them identical means RPs that store `sid` from the ID token can correlate the logout token against it without transformation.

**Alternatives rejected**:
- **Short opaque token derived from session UUID + hash** — no security gain; more moving parts.
- **Per-RP `sid` (different per audience)** — violates the spec's expectation that `sid` matches the ID-token `sid`.

---

## R4. `end_session_endpoint` route shape — per-client + global

**Decision (from spec Q4)**: Both routes, sharing one handler. Per-client at `/oauth2/openid/{client_id}/end_session_endpoint`; global fallback at `/oauth2/openid/end_session_endpoint`. Per-client route is the one advertised in each RP's discovery document.

**Handler dispatch**:
- Per-client route takes `client_id` from path → passes it as an optional override to the handler.
- Global route gets no `client_id` from path → handler must derive it from the ID token hint's `aud` claim.
- Both paths converge on the same internal function.

**Rationale**: Matches netidm's existing per-client OIDC URL convention (authorize, userinfo, webfinger, discovery, public key, RFC 8414 metadata are all per-client at `server/core/src/https/oauth2.rs:769–793`). Global form is a convenience for clients that don't consume discovery and hard-code a URL.

**Alternatives rejected**: See spec §Clarifications Q4.

---

## R5. SAML SessionIndex shape

**Decision**: UUID v4 string (hyphenated, no URN prefix). Emitted as `SessionIndex="<uuid>"` in the `<AuthnStatement>` element.

**Rationale**:
- Unique without coordination (no counter, no shared state).
- Opaque; an SP cannot infer any per-user or per-time ordering.
- Same shape as the `sid` claim on the OIDC side — maintains one session-identifier shape across netidm.

**Alternatives rejected**:
- **Incrementing integer** — requires a global counter; race conditions; leaks volume.
- **Hash of (user, SP, UAT, time)** — no advantage over UUID v4; more moving parts.
- **Reusing the UAT UUID as SessionIndex** — one UAT can back sessions at multiple SPs. If SessionIndex == UAT UUID and the user is logged in to SP-A and SP-B from the same browser, SP-A and SP-B could correlate the user across SPs by `SessionIndex` value. Rejected on privacy grounds. Each (UAT, SP) pair gets its own fresh UUID.

---

## R6. SAML backfill migration — detecting "which UATs are SAML-sourced"

**Decision**: Two-stage approach.

**Stage 1 (preferred)** — check whether DL25 UAT entries already carry a provenance tag indicating a SAML auth (e.g. a `Session` sub-entry with an SP reference). The tag exists if `IdmServerProxyWriteTransaction::grant_account_session` at the SAML path records the authenticating `SamlClient` UUID on the session metadata. A pre-implementation spike in `server/lib/src/idm/saml_client.rs` and the grant-session helper decides this empirically on the first task.

**Stage 2 (fallback, if Stage 1 shows no existing provenance)** — the backfill phase iterates every active UAT. For each UAT, it emits one `SamlSession` entry with `SamlSessionUser = uat.user_uuid`, `SamlSessionSp = nil`, `SamlSessionIndex = <fresh uuid>`, `SamlSessionUatUuid = uat.uuid`. At SLO correlation time, entries with `SamlSessionSp = nil` are treated as "legacy, SP unknown" — they match no inbound `<LogoutRequest>` (which always targets a specific SP) and are pruned as their UATs expire naturally. New post-migration SAML auths produce full-fidelity `SamlSession` entries with a non-nil SP reference.

**Rationale**: Stage 1 gives us clean backfill coverage if netidm was already tagging SAML sessions. Stage 2 is a safe degradation — it avoids the "pre-existing session is unaddressable" footgun for the rare cases where Stage 1's tag doesn't exist, by at least giving every active UAT a SessionIndex, even if we can't recover which SP the session was for.

**Alternatives rejected**:
- **Refuse to upgrade if we can't prove SAML provenance** — blocks the whole DL26 migration for a minor edge case.
- **Drop all active sessions during upgrade** — user-hostile, violates constitution §II.
- **Synthesise SP from the UAT's history** — not possible; UAT records don't carry an audit trail of which SP was authenticated to.

**Implementation note**: The migration phase uses the `IdmServerProxyWriteTransaction::backfill_saml_session_indices` helper (new in this PR) so both stages share one code path. The stage choice is logged at upgrade time.

---

## R7. `post_logout_redirect_uri` matching semantics

**Decision**: Exact-string match against entries in `Attribute::OAuth2RsPostLogoutRedirectUri` (multi-value URL). No normalisation other than what the `Url` type already does (lowercasing scheme + host). No wildcard matching. No prefix matching. Query strings and fragments are part of the match.

**Rationale**: Spec §Edge Cases — "Only exact matches are allowed — no partial or prefix matching, no query-string wildcards."

**Alternatives rejected**:
- **Prefix match on path** — opens open-redirect footguns via `https://evil/path` under a legitimate `https://evil/` allowed entry.
- **Host-only match** — same.
- **Exact match modulo query-string ordering** — complicates implementation for negligible user value.

Admins who need many variants register each URI explicitly.

---

## R8. Confirmation page template

**Decision**: New askama template at `server/core/templates/logged_out.html`. Minimal content: a heading ("You have been logged out"), a single paragraph of body copy, and a link back to the netidm UI home. No branding beyond existing netidm template inheritance; honour the project's light/dark palette.

**Rationale**: Dedicated template keeps the intent explicit ("this page is reached when a redirect isn't honoured"). Reusing the existing login page would be misleading; reusing `reset.rs`'s `end_session_response` shortcut would couple logout UX to password-reset machinery.

**Alternatives rejected**:
- **Reuse existing `end_session_response` in `server/core/src/https/views/reset.rs:250`** — that page is part of the credential-reset flow and communicates reset success, not logout; reusing it would confuse users.
- **Plain-text 200 response** — constitution §II ("humans first") prefers a visible landing page.

---

## R9. Worker lifecycle and shutdown

**Decision**: One back-channel delivery worker task per `netidmd` instance, spawned from `server/core/src/lib.rs` startup alongside the existing HTTP routers. Worker is a `tokio::task` driven by a `select!` over (a) a 30 s interval timer, (b) a `tokio::sync::Notify` that `terminate_session` signals after an enqueue, and (c) the existing shutdown broadcast.

On shutdown: worker finishes the in-flight HTTP request (bounded by the 5 s timeout) then exits. Pending records remain `Pending` in the DB; they are picked up on next boot. In-progress records that exit mid-flight are re-attempted on boot (idempotent from the RP side — the RP should dedup by `jti` per spec).

**Rationale**: Matches the existing netidm task-spawning pattern; single worker avoids double-delivery on multi-node (replication TBD for delivery ownership — not a concern for MVP, which runs single-node).

**Alternatives rejected**:
- **Spawn per-request tasks on enqueue** — makes shutdown hard to reason about; can't coordinate retries.
- **Cron-style fixed-interval polling only** — no `Notify` means up to 30 s latency before the first attempt, which user-facing logout feels slow.

---

## R10. CLI verb naming

**Decision**:

- OAuth2: `add-post-logout-redirect-uri`, `remove-post-logout-redirect-uri`, `list-post-logout-redirect-uris`, `set-backchannel-logout-uri`, `clear-backchannel-logout-uri`.
- SAML: `set-slo-url`, `clear-slo-url`.
- US5: `netidm person logout-all <id>`, `netidm self logout-all`.
- Delivery queue: `netidm logout-deliveries list [--pending|--succeeded|--failed]`, `netidm logout-deliveries show <uuid>`.

**Rationale**: Follows PR-GROUPS-PIPELINE's `add/remove/list` triplet convention (`add-group-mapping`, `remove-group-mapping`, `list-group-mappings`). `set`/`clear` used for single-value attributes (backchannel URI, SLO URL) to signal "one value, replaced wholesale".

**Alternatives rejected**:
- **`oauth2 post-logout {add,remove,list}`** — nested subcommands are inconsistent with existing verb-direct pattern.
- **`oauth2 logout set-backchannel`** — also a nested shape not used elsewhere.

---

## R11. Discovery document content-model change

**Decision**: Extend the JSON returned by `oauth2_openid_discovery_get` with three new fields:

```json
{
  "end_session_endpoint": "<origin>/oauth2/openid/<client_id>/end_session_endpoint",
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true
}
```

The per-client base URL mirrors how `authorization_endpoint` and `userinfo_endpoint` are emitted today. `backchannel_logout_session_supported: true` attests that logout tokens carry `sid`.

**Rationale**: One-to-one with OpenID Back-Channel Logout 1.0 discovery metadata and OpenID RP-Initiated Logout 1.0 discovery metadata.

**Alternatives rejected**:
- **Emit only `end_session_endpoint` (no back-channel claims)** — RPs that support back-channel logout wouldn't know netidm supports it; they'd skip registering their endpoint.
- **Emit a separate version of the discovery doc for RPs that want logout metadata** — spec doesn't allow this; metadata is one document.

---

## R12. ACP model for new configuration attributes

**Decision**: Three admin-CRUD ACPs (one per new OAuth2/SAML configuration attribute) mirroring the DL24 shape for `OAuth2RsLinkBy`. One admin-read ACP for `LogoutDelivery` entries. One self-read ACP for `SamlSession` entries limited to `SamlSessionUser == own uuid`.

**Rationale**: Per-attribute ACPs are how netidm already gates OAuth2 client configuration (see how `OAuth2RsLinkBy` was added in DL24 with its own ACP). Self-read on `SamlSession` supports a future UX where users see their own SAML sessions without any admin involvement.

**Alternatives rejected**:
- **Broad "logout-admin" role** — over-grants; admins should get these through the existing `idm_admins` group membership, not a new role.
- **No ACP for `LogoutDelivery`** — operators would need raw DB access to inspect delivery state; violates §Administrative Controls.
