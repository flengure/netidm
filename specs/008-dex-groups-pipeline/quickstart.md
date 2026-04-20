# Quickstart: Upstream Group Plumbing (PR-GROUPS-PIPELINE)

This document describes how to validate the feature end-to-end once it lands.

## Prerequisites

- `cargo build -p netidmd_lib` succeeds (DL25 schema compiles).
- `cargo test --workspace` is clean at the current tip of the branch.
- A running netidmd (development mode) with at least one administrator account.

## Scenario A — CLI round-trip (no login involved)

Exercises User Story 1 and FR-001 through FR-008.

1. Create a test OAuth2 upstream connector:
   ```bash
   netidm system oauth2 create-external \
     oauth2_test_github 'Test GitHub' https://localhost/auth/callback
   ```

2. Create two netidm groups to map into:
   ```bash
   netidm group create approovia_admins
   netidm group create approovia_devs
   ```

3. Add two mappings — once by group name, once by UUID — to validate FR-005:
   ```bash
   netidm system oauth2 add-group-mapping \
     oauth2_test_github approovia/admins approovia_admins

   DEVS_UUID=$(netidm group get approovia_devs --output-mode json | jq -r '.uuid')
   netidm system oauth2 add-group-mapping \
     oauth2_test_github approovia/devs "$DEVS_UUID"
   ```
   Both commands exit 0.

4. List mappings:
   ```bash
   netidm system oauth2 list-group-mappings oauth2_test_github
   ```
   Expected output (exact format, columns tab-separated):
   ```
   approovia/admins   approovia_admins   <admins-uuid>
   approovia/devs     approovia_devs     <devs-uuid>
   ```

5. Attempt to re-add an existing mapping (FR-007a):
   ```bash
   netidm system oauth2 add-group-mapping \
     oauth2_test_github approovia/admins approovia_devs
   ```
   Expected: exit 3; stderr `mapping already exists: approovia/admins → approovia_admins (<uuid>); remove it first to change it`. List output from step 4 is unchanged.

6. Attempt to add with a non-existent netidm group (FR-006):
   ```bash
   netidm system oauth2 add-group-mapping \
     oauth2_test_github approovia/nowhere definitely_not_a_group
   ```
   Expected: exit 2; stderr `no such netidm group: definitely_not_a_group`. No mapping added.

7. Remove one mapping:
   ```bash
   netidm system oauth2 remove-group-mapping oauth2_test_github approovia/devs
   ```
   List now shows only `approovia/admins`.

8. Idempotent no-op remove:
   ```bash
   netidm system oauth2 remove-group-mapping oauth2_test_github approovia/devs
   ```
   Expected: exit 0; stdout `no mapping for approovia/devs; nothing to remove`.

9. Restart netidmd; re-run step 4. List output matches pre-restart state (FR-007).

## Scenario B — Reconciliation round-trip (unit-test level)

Exercises User Stories 2 and 3 directly via the reconcile helper, bypassing any connector-level fetch logic (which ships in later PRs).

Runs in `cargo test -p netidmd_lib --lib idm::group_mapping`:

1. **`reconcile_adds_membership`**: Test fixture creates a Person and a Group. Invokes `reconcile_upstream_memberships(qs, person, provider_A, &[mapping{upstream=X, group=grp}], &["X".to_string()])`. Asserts:
   - Group's `Member` now contains `Refer(person)`.
   - Person's `OAuth2UpstreamSyncedGroup` contains exactly one value: `"<provider_A>:<grp_uuid>"`.
   - Person's `MemberOf` (plugin-computed on commit) contains the group.

2. **`reconcile_removes_membership`**: continuing from (1), invoke with `&[]`. Asserts:
   - Group's `Member` no longer contains `Refer(person)`.
   - Person's `OAuth2UpstreamSyncedGroup` is now empty.

3. **`reconcile_preserves_local_grant`**: Person is added to group via `internal_modify` (no marker). Invoke reconcile with `&[]`. Asserts:
   - Group's `Member` still contains `Refer(person)`.
   - Person's `OAuth2UpstreamSyncedGroup` remains empty.

4. **`reconcile_multi_provider_overlap`**: Two providers A and B both map to the same group. Invoke A's reconcile with `&["X"]`, then B's with `&["X"]`. Person is a member of group with two markers. Now reconcile A with `&[]`. Asserts:
   - Group's `Member` still contains `Refer(person)` (because B still asserts).
   - Person's `OAuth2UpstreamSyncedGroup` has exactly one value left: B's marker.
   Now reconcile B with `&[]`. Asserts:
   - Group's `Member` no longer contains `Refer(person)`.
   - Person's `OAuth2UpstreamSyncedGroup` is empty.

5. **`reconcile_unknown_group_uuid_warns_and_skips`**: Connector has a mapping whose UUID does not resolve to any group. Reconcile. Asserts:
   - Returns `Ok(())` (no error).
   - No changes applied anywhere.
   - (Optional) log capture asserts a `warn!` was emitted.

6. **`reconcile_unmapped_upstream_name_ignored`**: Connector has one mapping for `X`. Invoke with `&["Y"]`. Asserts:
   - No changes applied.
   - Returns `Ok(())`.

7. **`parse_roundtrip_basic`**: `GroupMapping::parse("admins:<uuid>")` → `GroupMapping { upstream_name: "admins", netidm_uuid: <uuid> }`.

8. **`parse_roundtrip_with_colons_in_name`**: `GroupMapping::parse("team:infra:lead:<uuid>")` → `upstream_name = "team:infra:lead"`, correctly split on last `:`.

9. **`parse_rejects_malformed`**: `GroupMapping::parse("no-colon-uuid")` → `Err(OperationError::InvalidValueState)`. Same for a non-UUID suffix.

10. **`reconcile_idempotent`** (FR-012): Invoke `reconcile_upstream_memberships` with the same inputs twice in succession. Second call produces no DB writes (verifiable via DB write-counter instrumentation or post-state comparison).

## Scenario C — End-to-end with testkit

Exercises User Story 4 via the existing testkit harness.

1. Set up (via testkit fixture): a Person, two netidm groups `admins` / `devs`, an OAuth2Client upstream connector with mappings `upstream_admins → admins`, `upstream_devs → devs`, and a downstream OAuth2 ResourceServer (RS) that has `groups` in its `scope_map`.

2. Directly call `reconcile_upstream_memberships` on a write transaction with `upstream=["upstream_admins"]` to simulate the connector having fetched that set. Commit.

3. Request an OIDC id_token for the person against the downstream RS (using the testkit auth harness or a direct oauth2 service call). Decode the token; assert `groups` claim contains `admins` and NOT `devs`.

4. Reconcile again with `upstream=[]`. Request another token. Assert `groups` claim is empty (modulo any locally-granted memberships).

## Scenario D — DL25 schema round-trip

Exercises the migration.

In `server/lib/src/server/migrations.rs` test block (pattern at existing line 1796):
- `migrate_domain_24_to_25` is invoked in a fresh test DB seeded at DL24.
- Post-migration assertions:
  - `Attribute::OAuth2GroupMapping` exists in the schema.
  - `Attribute::SamlGroupMapping` exists.
  - `Attribute::OAuth2UpstreamSyncedGroup` exists.
  - `EntryClass::OAuth2Client` lists `OAuth2GroupMapping` in its `systemmay`.
  - `EntryClass::SamlClient` lists `SamlGroupMapping` in its `systemmay`.
  - `EntryClass::Person` lists `OAuth2UpstreamSyncedGroup` in its `systemmay`.
  - `DomainInfo::target_domain_version == DOMAIN_LEVEL_25`.

## Regression checks

- `cargo test --workspace` — no existing OAuth2 or SAML test breaks. `claims.groups` defaults to empty, so no observable change to today's paths.
- `cargo clippy --lib --bins --examples --all-features` — zero warnings. No `#[allow]` additions.
- `cargo fmt --check` — clean.
- Grep sanity: `grep -rn reconcile_upstream_memberships server/` returns exactly three call sites (link, JIT, handler) plus the module definition and its unit tests.

## Operational observability checks

- Logs during a reconciliation with a malformed mapping value include a single `warn!` line naming the provider, the raw value, and the parse reason. Authentication still succeeds.
- Logs during a reconciliation with an unresolvable group UUID include a single `warn!` line naming the provider and the unresolved UUID. Authentication still succeeds.
- No log output includes any upstream group name at debug-or-below severity.
