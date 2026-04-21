# Quickstart: OAuth2 Refresh-Token Claim Re-Fetch (PR-REFRESH-CLAIMS)

Operator-facing test scenarios. Each maps to one user story and the acceptance scenarios inside it. Each scenario is reproducible on a fresh DL27 database with nothing but netidmd and an in-process `TestMockConnector`.

## Prerequisites

- netidmd built from this branch, running at DL27.
- `netidm` CLI configured to talk to this instance.
- A test Person entry (`krab_test_user`) and a downstream RP (`test_integration` OAuth2 Resource Server) already set up — `server/testkit` provisions both automatically for integration tests.
- An upstream trust provider (`OAuth2Client` entry with an authorisation endpoint) whose UUID we'll call `PROVIDER_UUID`. In an integration test, this is a test fixture; in a manual walkthrough, this is whatever upstream connector is deployed in your environment.
- The `TestMockConnector` bound to `PROVIDER_UUID` in the registry.

## Scenario 1: Upstream group change reflects on next refresh (US1, SC-001)

**Given** `krab_test_user` has authenticated through `PROVIDER_UUID` and received an access + refresh token pair. The initial upstream group list includes `platform`, which is mapped to netidm group `platform-admin`. The access token's `groups` claim contains `platform-admin`.

**When** the upstream administrator removes `krab_test_user` from the `platform` group (simulated in the integration test by `mock.set_groups(vec![])`), and the RP then exchanges its refresh token against `POST /oauth2/token` with `grant_type=refresh_token`:

**Then** the token endpoint returns a new `AccessTokenResponse`. The new `access_token`, decoded, contains a `groups` claim that no longer includes `platform-admin`. The Person entry's `OAuth2UpstreamSyncedGroup` markers for `PROVIDER_UUID` have been updated to reflect the absence. Exactly one structured tracing span named `refresh_claims.groups_changed` has been emitted, carrying `user_uuid`, `connector_uuid = PROVIDER_UUID`, `groups_added = []`, `groups_removed = [platform-admin]`.

**Negative variant**: if the mock is NOT mutated (upstream still asserts `platform`), the refresh succeeds, the `groups` claim still contains `platform-admin`, and NO `refresh_claims.groups_changed` span is emitted. The Person entry is not written.

---

## Scenario 2: Connector failure rejects the refresh (US2, SC-002)

**Given** `krab_test_user`'s session from Scenario 1.

**When** the mock is put into error mode (`mock.set_error(Some(ConnectorRefreshError::Network("connection refused".into())))`), and the RP exchanges its refresh token:

**Then** the token endpoint returns HTTP 400 with `{"error": "invalid_grant"}`. No new access / refresh / ID tokens are issued. No `refresh_claims.groups_changed` span is emitted (the change-detection path doesn't run on failures). The Person entry is not written. An `error`-level log line is emitted server-side carrying `connector_uuid`, `user_uuid`, and the upstream error detail — but the detail does NOT appear in the HTTP response to the RP.

**Recovery variant**: the RP, having received `invalid_grant`, initiates a fresh authorization-code flow. If the upstream is now reachable, the fresh login succeeds and a new session is minted. If the upstream is still unreachable, the fresh login itself fails at the upstream-callback step (existing behaviour from PR-LINKBY / PR-OIDC-CONNECTOR).

---

## Scenario 3: Locally-granted memberships survive a narrowing upstream (US3, SC-003)

**Given** `krab_test_user` has two group memberships: `platform-admin` (upstream-synced from `PROVIDER_UUID`'s `platform` group) and `audit-readers` (granted directly by a netidm administrator, no upstream marker). Both appear in the initial access token's `groups` claim.

**When** the upstream mutates to assert an empty group set (`mock.set_groups(vec![])`), and the RP refreshes:

**Then** the new access token's `groups` claim contains `audit-readers` but NOT `platform-admin`. The Person entry's `OAuth2UpstreamSyncedGroup` markers for `PROVIDER_UUID` are empty. The Person entry's direct `MemberOf` for `audit-readers` is unchanged — the admin-granted membership survived. A `refresh_claims.groups_changed` span was emitted with `groups_removed = [platform-admin]` and `groups_added = []`.

**Re-addition variant**: if the upstream re-asserts `platform` on a subsequent refresh, `platform-admin` reappears in the token and on the Person entry's upstream markers. `audit-readers` remains throughout.

---

## Scenario 4: Pre-DL27 session passes through unchanged (US4, SC-004)

**Given** an `Oauth2Session` value on `krab_test_user`'s entry whose `upstream_connector` field is `None` (simulating a session minted under DL26 before the upgrade). The session's cached claims include `groups = [platform-admin]`.

**When** the RP exchanges this pre-DL27 refresh token against `POST /oauth2/token`:

**Then** the token endpoint returns a new `AccessTokenResponse` identical in shape to the DL26 behaviour — the `groups` claim contains `platform-admin` from the cached session state. No connector call is made. No `refresh_claims.groups_changed` span is emitted. The Person entry is not touched. The rotated session retains `upstream_connector = None` (forward compat — the grandfather state is preserved across rotation).

**Upgrade-path variant**: if `krab_test_user` then completes a fresh authorization-code flow through the connector, the new session is minted with `upstream_connector = Some(PROVIDER_UUID)` and the refresh path for THAT session invokes the connector on subsequent refreshes (Scenarios 1–3 apply to it). The old pre-DL27 session's refresh path remains unchanged.

---

## How to run these from integration tests

Each scenario maps to one `#[netidmd_testkit::test]` in `server/testkit/tests/testkit/refresh_claims_test.rs`:

| Scenario | Test name (proposed) |
|----------|----------------------|
| 1        | `test_refresh_claims_upstream_mutation_flows_to_token` |
| 2        | `test_refresh_claims_connector_error_rejects_with_invalid_grant` |
| 3        | `test_refresh_claims_local_groups_survive_narrowing_upstream` |
| 4        | `test_refresh_claims_predl27_session_falls_through` |

Each test uses `TestMockConnector` re-exported from `netidmd_testkit`, mutates it between code-flow-login and refresh-token-exchange, and asserts both the token endpoint response AND the Person entry's `OAuth2UpstreamSyncedGroup` markers. Assertions on the emitted tracing span use a custom test-only `tracing` subscriber (added as needed; if the existing testkit already captures spans, reuse that).

## How to run these manually on a live netidmd

Manual end-to-end validation without integration-test scaffolding requires an actual upstream provider (because `TestMockConnector` is test-gated). Rerun Scenarios 1–3 against a real GitHub / Google / OIDC upstream once PR #4 or #5 lands their concrete connector. Scenario 4 can be exercised right away on any DL27 deployment that still carries refresh tokens minted under DL26 — observe that they continue to work.
