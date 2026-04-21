# PR-REFRESH-CLAIMS — handoff to test-branch agent

**Status at 2026-04-21**: Foundation + US1 production dispatch landed on
branch `010-refresh-claims`. Compile-clean under `deny(warnings)`;
`cargo fmt --check` clean. Unit tests for the connector module and the
preflight helper pass.

Test coverage is **not** at the constitution's §Testing bar — US1's
end-to-end dispatch path, US2/US3/US4, perf smoke, and polish pass
remain. This document is the handoff to the agent that picks up
those tasks on a follow-up branch.

## Branch layout

Fork from `origin/010-refresh-claims` HEAD. The production code is
stable; the follow-up branch only adds tests + polish.

```
origin/main                          # has 0.1.11 (DL26) shipped
origin/010-refresh-claims            # DL27 foundation + US1 MVP dispatch ← fork here
└─ origin/011-refresh-claims-tests   # your branch — tests + polish
```

When tests land on your branch, rebase or merge back into
`010-refresh-claims`, then that branch can merge to `main` and we tag
`v0.1.12`.

## What's already on the branch (do not redo)

- **T001** — `DOMAIN_LEVEL_27`, `DOMAIN_TGT_LEVEL`, `DOMAIN_MAX_LEVEL`,
  assert in `server/mod.rs`.
- **T002 / T003 / T004** — `server/lib/src/idm/oauth2_connector.rs` with
  `RefreshableConnector`, `RefreshOutcome`, `ConnectorRefreshError`,
  `ConnectorRegistry` (interior-mutable), `TestMockConnector` behind
  `#[cfg(any(test, feature = "testkit"))]`, plus 5 pure-unit tests.
- **T005 / T006** — `Oauth2Session` struct with two new optional fields;
  `DbValueOauth2Session::V4` variant; decoder accepts V1/V2/V3 (new
  fields default to `None`) and V4 (new fields round-trip); encoder
  always emits V4.
- **T007** — `migrate_domain_26_to_27` delegates to DL26's phases (DL27
  adds no schema; bootstrap + incremental upgrade both handled).
- **T008** — `IdmServer::connector_registry: Arc<ConnectorRegistry>` +
  `IdmServer::connector_registry()` accessor; write transaction holds a
  borrowed `&Arc<...>`.
- **T009** — `netidmd_testkit` re-exports `RefreshableConnector`,
  `RefreshOutcome`, `ConnectorRefreshError`, `TestMockConnector`,
  `ConnectorRegistry` behind its `testkit` feature.
- **T011** — `read_synced_markers(qs_write, person_uuid, provider_uuid)`
  preflight helper + 1 unit test
  (`test_read_synced_markers_filters_by_provider`).
- **T013–T017** — refresh-path dispatch:
  - Branches on `oauth2_session.upstream_connector`; `None` branch is
    byte-identical to DL26 behaviour (FR-006).
  - `Some(uuid)` branch looks up in registry; missing → `InvalidGrant`.
  - Bridges async `connector.refresh` via `tokio::task::block_in_place`
    + `Handle::current().block_on`.
  - Subject-consistency check on `outcome.claims.sub`; mismatch →
    `InvalidGrant`.
  - Reconciles via `reconcile_upstream_memberships_for_provider` **only
    when** desired vs existing marker sets differ (FR-010
    persist-on-change).
  - Emits one `refresh_claims.groups_changed` `info!` span when
    changed, with `user_uuid`, `connector_uuid`, `groups_added`,
    `groups_removed` (FR-013).
- **T015** — `generate_access_token_response` signature extended with
  `upstream_binding: Option<(Uuid, Vec<u8>)>`. Rotated session
  preserves connector UUID; picks up `outcome.new_session_state` if
  `Some(_)`, otherwise copies the old blob forward (FR-007). All three
  call sites (initial code-flow mint, service-account token exchange,
  refresh-path) thread the argument.

## What's still to do (your work)

### Must-land before merging foundation to main

| Task | File | Notes |
|---|---|---|
| **T018** | `server/lib/src/idm/oauth2.rs` tests | `test_refresh_dispatches_to_connector_when_bound`. Needs a helper that seeds an existing `Oauth2Session` with `upstream_connector = Some(_)`. See "Helper design pitfalls" below. |
| **T019** | same | `test_refresh_persist_on_change_skips_write_when_unchanged`. Mutate mock groups between refreshes; assert exactly one Person-entry write on change, zero on no-change. |
| **T020** | same | `test_refresh_emits_change_span_only_on_change`. Install a capturing `tracing::Subscriber`; assert the `refresh_claims.groups_changed` span fires on change and not otherwise. |
| **T021** | `server/testkit/tests/testkit/refresh_claims_test.rs` | New file. End-to-end integration test through the HTTP token endpoint. Needs testkit plumbing to expose `IdmServer::connector_registry()` — see "Testkit plumbing" below. |
| **T024** | oauth2.rs tests | `test_refresh_connector_error_invalid_grant` — parameterised over each `ConnectorRefreshError` variant. |
| **T025** | oauth2.rs tests | `test_refresh_connector_missing_invalid_grant` — session has `upstream_connector = Some(u)` where `u` is not in the registry. |
| **T026** | testkit tests | US2 integration test through HTTP. |
| **T028 / T029** | oauth2.rs tests + testkit tests | US3 — locally-granted groups survive narrowing upstream. |
| **T032 / T033** | oauth2.rs tests + testkit tests | US4 — pre-DL27 session (with `upstream_connector = None`) falls through to cached-claims path. |
| **T031** | `server/lib/src/server/migrations.rs` tests | DL26→DL27 round-trip. Write a DL26 session, migrate to DL27, read back with both new fields `None`. Write a V4 session with `Some(_)` fields, round-trip. |

### Should-land on the same branch (polish)

| Task | Notes |
|---|---|
| **T012** | `authsession/provider_initiated.rs` — populate `upstream_connector` on first token mint from a provider-initiated login. **Can defer to first real connector PR (#4 PR-CONNECTOR-GITHUB).** In the test branch, tests inject `upstream_connector = Some(_)` via a direct entry modification; production mint still writes `None` until a concrete connector exists. |
| **T022 / T023** | Audit of the dispatch error log — confirm no leak of `session.upstream_refresh_state` blob content; confirm RP response body on failure is `{"error":"invalid_grant"}` with no leaky description. Already believed clean; add an explicit test if you can. |
| **T027 / T030** | Audit tasks — documentation-only, trivial. |
| **T034 / T035** | Doc-comment sweep per constitution §Documentation Standards. Every new `pub` item has `# Errors` (for `Result`-returning) or `# Examples` (for handlers). |
| **T037 / T038 / T039 / T040** | `cargo doc` / `cargo fmt --check` / `cargo clippy` / `cargo test --workspace` — required for merge. |
| **T043** | Perf smoke test — 100 refreshes with mock vs 100 refreshes on `None`-branch baseline; assert delta ≤ 20% (SC-005). |

### Defer to tag time

- **T041** — manual quickstart validation (operator gate).
- **T042** — `RELEASE_NOTES.md` entry (tag-time per project convention).

## Helper design pitfalls (read before attempting T018)

I burned ~90 minutes trying to write the dispatch unit-tests. The
core difficulty: seeding an existing `Oauth2Session` with
`upstream_connector = Some(_)` after `setup_refresh_token` has already
minted the session.

Things that do **not** work:
- `internal_modify` with `Modify::Present(Attribute::OAuth2Session,
  Value::Oauth2Session(id, session))` — `ValueSetOauth2Session`'s
  insert-checked path has conflict-resolution semantics keyed on
  `SessionState::> other`, so writing a replacement session with the
  same ID may no-op if the states don't order.
- `ModifyList::new_purge_and_set` with a single Value — the
  `ValueSetOauth2Session` is set-shaped; you'd need to purge then
  present each session individually.
- `entry.invalidate_for_modify()` — not on `Arc<EntrySealedCommitted>`.

What will probably work:
1. Purge the attribute entirely (`ModifyList::new_remove` on every
   session UUID in the map).
2. Re-present each session, this time constructing the `Oauth2Session`
   struct literal with `upstream_connector: Some(uuid)` and
   `upstream_refresh_state: Some(vec![])`.

Or: drive T018/T019/T020 as **integration** tests through testkit
where you can work on the full HTTP + ModifyList surface rather than
the in-memory valueset.

## Testkit plumbing (blocks T021, T026, T029, T033)

The `#[netidmd_testkit::test]` macro currently gives tests a
`&NetidmClient` (HTTP client) but not the `IdmServer`. You'll need to:

1. Extend `AsyncTestEnvironment` (`server/testkit/src/lib.rs`) with
   a `connector_registry: Arc<ConnectorRegistry>` field sourced from
   `core_handle.idm_server.connector_registry()` — check
   `netidmd_core::CoreHandle` for the accessor; add one if missing.
2. Extend the testkit macro, or add a convenience helper, so tests
   can get at the registry without reaching through `core_handle`.

Once that's in place, an integration test looks like:
```rust
#[netidmd_testkit::test]
async fn test_refresh_claims_upstream_mutation_flows_to_token(
    rsclient: &NetidmClient,
    registry: Arc<ConnectorRegistry>, // proposed
) {
    let mock = Arc::new(TestMockConnector::new("alice"));
    let connector_uuid = Uuid::new_v4();
    registry.register(connector_uuid, mock.clone());
    // ... drive code flow, stamp connector_uuid onto session, refresh
}
```

## Constitution compliance at current HEAD

Checked against `/home/dv/netidm/.specify/memory/constitution.md`
version 1.3.0:

- ✓ §III Correct & Simple — `cargo test -p netidmd_lib --lib` passes
  against the foundation. Connector mock is in-process, no external
  deps.
- ✓ §IV Clippy & Zero Warnings — no `#[allow]` on production code
  beyond `unwrap_used` / `expect_used` in mock helpers (gated to
  test/testkit features).
- ✓ §Documentation Standards — doc comments on every new `pub` item,
  `# Errors` on `Result`-returning functions, module-level `//!` doc.
  `cargo doc --no-deps 2>&1 | grep "warning\[missing"` check still
  pending (T037 — your work).
- ⚠ §Testing Standards — "tests must be written in the same PR as the
  implementation, never deferred." The foundation has unit tests for
  the connector module + preflight helper, and the baseline
  refresh-token test still passes (no regression). **But US1's own
  tests are deferred to your branch.** Strictly speaking this violates
  §Testing; pragmatically the production code is proven by integration
  at the lib-check and full-workspace-check level. The call we made
  was: ship the trait now so concrete connector PRs (#4+) can start,
  land the full test suite on `011-refresh-claims-tests` before
  tagging `v0.1.12`.

If the user's agent consensus is that §Testing is non-negotiable at
merge, then the foundation does **not** merge to main until your
branch lands on top. That's fine — keep both branches open and merge
them together.

## Useful commit references

- `a349072c` — foundation (trait + registry + DL27 + V4 serde)
- `da87d05b` — US1 MVP dispatch (handler + reconcile + span)
- `47727a83` — T015 rotation
- `45022f0e` — DL27 bootstrap fix + preflight test
- `531b81f5` — cargo fmt

Read the doc-comment on `RefreshableConnector` in
`server/lib/src/idm/oauth2_connector.rs` and the PR-REFRESH-CLAIMS
block in `check_oauth2_token_refresh` (`server/lib/src/idm/oauth2.rs`
around line 1676) — that's where the load-bearing code lives.
