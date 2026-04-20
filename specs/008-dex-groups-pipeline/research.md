# Research: Upstream Group Plumbing (PR-GROUPS-PIPELINE)

## Context

This feature is Phase 0 research for PR-GROUPS-PIPELINE. The Technical Context in `plan.md` has no NEEDS CLARIFICATION markers; research here documents the design decisions made up-front and the alternatives considered. These decisions shape the implementation and the testing strategy.

## Decisions

### D1 — Value format for `OAuth2GroupMapping` and `SamlGroupMapping`

**Decision**: Store each mapping as a single Utf8String value `<upstream-name>:<netidm-group-uuid>`. Split on the **last** `:` when parsing.

**Rationale**: Upstream group names can contain colons in practice — SAML often emits fully-qualified names like `team:infra:lead`, and Azure AD group claims can include hierarchical paths. UUIDs (hex with hyphens, fixed length, no `:`) cannot. Splitting on the last `:` unambiguously separates the name from the UUID regardless of how many colons the name contains.

**Alternatives considered**:
- **Split on first `:`** — rejected: breaks on any upstream name containing `:`, which is common in enterprise IdPs.
- **JSON value per entry** (`{"name":"...","uuid":"..."}`) — rejected: unnecessary serialisation overhead; harder to edit manually in the admin DB; inconsistent with other single-string multi-value attributes in the project.
- **Separate attributes for names and UUIDs** (parallel arrays) — rejected: no ordering guarantee in multi-value attributes; correlation between entries becomes stateful and error-prone.
- **Pair delimiter other than `:`** (e.g., `→` or `|`) — rejected: unicode in stored DB values has historically caused interop issues with LDAP export paths; ASCII printable is safer.

### D2 — Value format for `OAuth2UpstreamSyncedGroup`

**Decision**: Each value is `<provider-uuid>:<group-uuid>`. Single multi-value attribute on the `Person` entry (systemmay). Parse on last `:` just like D1.

**Rationale**: The marker needs to answer "is this netidm group membership the result of a prior reconciliation through *this specific* connector?" Encoding `provider_uuid` in the value allows a single attribute to span multiple connectors and a single query (read the Person) to yield the full picture. UUIDs are fixed-format, so the format stays parse-safe even though provider/group UUIDs both contain `-`.

**Alternatives considered**:
- **Tag on `MemberOf`** — rejected: `MemberOf` is plugin-computed (by `plugins/memberof.rs`). It is derived from `Member`/`DynMember` writes on the group side. Tags can't hang off a computed attribute.
- **Reverse attribute on the group** (e.g., `OAuth2UpstreamProviderOrigin` listing `<person>:<provider>` pairs) — rejected: explodes writes on group modification; reconciliation for one user would contend with many others' writes on the same group entry, serializing logins.
- **Separate log table / event entry** — rejected: more moving pieces for the same information; MVCC reads on a single Person attribute are the cheapest path to the diff baseline.
- **Per-provider attribute** (one attribute per connector) — rejected: attribute explosion; violates the one-schema-per-feature principle.

### D3 — Where does reconciliation run relative to `CredState::Success`?

**Decision**: Run reconciliation **synchronously**, inside the existing proxy_write transaction, **before** the handler emits `CredState::Success` for the already-linked path and **before** the cookie-driven link/provision commit completes for the link path. Errors MUST NOT cause auth to fail (FR-018), but they MUST be logged.

**Rationale**: The write transaction that links or provisions the account already holds the locks needed to mutate `Member` on target groups and the Person's marker. Re-entering those writes in a separate transaction (async) would require re-resolving the account, re-validating state, and either a cross-transaction reconciliation queue or a "re-try later" mechanism — none of which exist in netidm today. Synchronous is both simpler and more correct (downstream tokens issued immediately after auth will already reflect the new memberships).

The "errors don't fail auth" constraint (FR-018) is honoured by wrapping the reconcile call in the handler: on `Err`, log at `warn!` severity with context (person, provider, upstream group names if present) and continue to emit `CredState::Success`. The user logs in; the admin sees the warning; partial/stale memberships persist until the next successful reconciliation. This is preferable to blocking a user's login because a single mapping entry is malformed.

**Alternatives considered**:
- **Async via DelayedAction** — rejected: no precedent for calling into `qs_write` from the delayed action executor, and the membership write must be atomic with the auth-record commit for downstream tokens to be correct.
- **After `CredState::Success`, synchronously in the handler** — rejected: once `Success` is emitted, the caller's expectations shift (session cookie issuance). Interleaving more writes in that window complicates error handling.

### D4 — Distinguishing "connector-granted" from "locally-granted" memberships

**Decision**: The `OAuth2UpstreamSyncedGroup` marker is the **sole** source of truth. A membership is connector-managed for purposes of removal if and only if the marker contains an entry `<provider-uuid>:<group-uuid>` for that provider and group. Memberships without a marker entry are locally-granted and are never removed by reconciliation.

**Rationale**: Directly encodes FR-011. The algorithm reads the marker set, diffs against the desired set, and mutates only those groups whose UUIDs appear in the marker. Pure set logic; no heuristics.

**Alternatives considered**:
- **Timestamp-based heuristic** ("if the membership was added within the last 10 minutes by a reconcile txn, it's connector-managed") — rejected: fragile, ambiguous, insecure.
- **Audit-log replay** ("search the audit log for a reconcile event that added this membership") — rejected: O(log entries) lookup per membership; couples reconciliation to audit log retention.

### D5 — Multi-connector overlap semantics

**Decision**: A membership is retained while **any** connector's marker still contains it OR a local grant exists (i.e., at least one marker or no marker at all). Reconciliation for connector A only affects markers for A; it computes the diff against A's markers alone and does not consider B's markers. If A's reconciliation would remove the person from group X but B's marker still contains X, the reverse `Modify::Removed(Member, Refer(person))` call MAY still fire — BUT the membership will remain because B independently re-issues the membership at its own next reconciliation.

**Wait — that is incorrect.** Revision: to avoid removing a membership that connector B still asserts, slice D of the algorithm must check whether any **other** provider's marker still references the same `group_uuid` before emitting the `Modify::Removed` on `Member`. If another provider's marker references the group, skip the removal — but still remove A's marker entry for that group.

**Rationale**: FR-011 and FR-016 require that memberships persist while any connector asserts them. The marker entry for A is removed either way; the net effect is "A stops claiming this membership, but B still does, so the user keeps it."

**Alternatives considered**:
- **Per-connector Member edges** — infeasible: the entry system has one `Member` attribute; it does not natively model multi-connector provenance. The marker approach simulates it.
- **Reference counting in the marker itself** — overengineered; set semantics are sufficient.

### D6 — Scope of reconciliation: which attributes get modified

**Decision**: Only `Attribute::Member` on target netidm groups, and `Attribute::OAuth2UpstreamSyncedGroup` on the Person. No other attribute is written.

**Rationale**: The reconciler has one job — membership — and should not mutate unrelated state. Downstream consumers (MemberOf plugin, account.groups loader, OIDC groups claim projection) already transform `Member` writes into the correct derived state.

### D7 — Error policy on malformed or stale stored values

**Decision**: `warn!` log with context, then skip the offending entry. Never return an error to the caller for parse or resolve failures in stored mapping / marker values.

**Rationale**: FR-014 and FR-018 require auth to not fail on reconciliation errors. Mapping data is admin-curated and can drift out of sync with groups over time (admin deletes a netidm group without first removing its mapping entries). The reconciler must be tolerant of this; the admin sees warnings and corrects at their own pace.

**Alternatives considered**:
- **Fail-closed at the first malformed value** — rejected: turns one stale value into a site-wide outage.
- **Surface errors through a separate admin-visible "reconciliation health" attribute** — future enhancement; not needed for PR #1.

## Upstream references

- Spec: `specs/008-dex-groups-pipeline/spec.md`
- Reference technical plan (session scratch): `~/.claude/plans/here-is-the-approved-pure-oasis.md`
- Roadmap: `~/.claude/plans/in-this-session-we-mossy-reef.md` (17-PR dex-parity sequence; this is PR #1)
- Netidm downstream projection: `server/lib/src/idm/oauth2.rs:3291-3324`
- Netidm linking path: `server/core/src/actors/v1_write.rs:1825` (`handle_link_account_by_email`)
- Netidm JIT path: `server/core/src/actors/v1_write.rs:~1840` (`handle_jit_provision_oauth2_account`)
- Existing `claim_map` pattern to mirror: `server/lib/src/idm/oauth2_client.rs:246-283`
- `MemberOf` plugin: `server/lib/src/plugins/memberof.rs`

## Open questions carried to planning / implementation

None. All clarifications recorded in `spec.md` under `## Clarifications`.
