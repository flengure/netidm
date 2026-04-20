# Feature Specification: Upstream Group Plumbing (PR-GROUPS-PIPELINE)

**Feature Branch**: `008-dex-groups-pipeline`
**Created**: 2026-04-20
**Status**: Draft
**Input**: User description: "PR-GROUPS-PIPELINE — upstream → downstream group plumbing for netidm. Introduces per-connector group mapping tables, adds a groups field to external upstream claims, and a reconciliation helper that applies upstream-asserted memberships to netidm groups while leaving locally-granted memberships alone. Pure plumbing — does not port any connector's fetch logic. This is PR #1 of a 17-PR dex-parity roadmap."

## Clarifications

### Session 2026-04-20

- Q: When an administrator runs add-group-mapping for an upstream group name that is already mapped on the same connector, should the system reject, overwrite, or prompt? → A: Reject with an error naming the existing mapping; to change it, the administrator runs remove-group-mapping first. No implicit upsert.
- Q: When an administrator removes a mapping that has already produced memberships for some users, what happens to those memberships? → A: Memberships track the mapping. The remove-group-mapping command only touches the mapping itself; affected users keep the membership until their next login, at which point reconciliation removes it like any other now-unmapped membership. No eager cross-user sweep.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Administrator configures mapping of upstream groups to netidm groups (Priority: P1)

A netidm administrator operates an OAuth2 or SAML upstream connector that will assert group memberships for users who sign in through it. The administrator needs to declare, for each upstream group name the connector may report, which netidm group a user in that upstream group should become a member of.

**Why this priority**: Without this mapping, upstream group assertions cannot be translated into netidm membership — the entire feature is inert. It is the entry point for every downstream consequence.

**Independent Test**: Admin can run the CLI commands to add, list, and remove mappings on a test connector; the changes persist across server restarts and appear in subsequent listings. No end-user login is required to verify this story.

**Acceptance Scenarios**:

1. **Given** an OAuth2 upstream connector exists with no mappings, **When** the administrator runs the add-mapping command naming an upstream group and a netidm group, **Then** the mapping is persisted and appears in a subsequent list command.
2. **Given** a connector has one or more mappings, **When** the administrator runs the list-mappings command, **Then** every mapping appears with both the upstream name and the netidm group it resolves to.
3. **Given** a connector has a mapping, **When** the administrator runs the remove-mapping command naming the upstream group, **Then** the mapping disappears from a subsequent listing.
4. **Given** a SAML upstream connector, **When** the administrator runs the equivalent SAML CLI commands, **Then** behaviour mirrors the OAuth2 case.
5. **Given** the administrator passes either a netidm group name or a netidm group UUID for the target, **When** the mapping is added, **Then** both forms resolve to the same persisted mapping.
6. **Given** an upstream group name is already mapped on a connector, **When** the administrator runs add-group-mapping for that same upstream name with any target, **Then** the command fails with an error naming the existing mapping, and storage is unchanged.

---

### User Story 2 - End user's memberships reconcile on login (Priority: P1)

When an end user authenticates through a connector that has mappings configured, their netidm group memberships for the groups named in those mappings reflect exactly what the upstream currently asserts — they gain membership in mapped groups the upstream now includes them in, and lose membership in mapped groups the upstream no longer includes them in.

**Why this priority**: This is the point of the feature. If US1 works but logins do not reconcile, nothing an administrator configures has effect. P1 alongside US1.

**Independent Test**: Using the reconciliation helper directly (no live upstream fetch), invoke it with a set of upstream group names against a test person and a test connector that has a mapping; assert the person's memberships on the mapped netidm groups reflect the supplied set. Invoke again with a different set; assert the diff applied correctly.

**Acceptance Scenarios**:

1. **Given** a connector maps `upstream-a` to netidm group `X`, and a person has no memberships, **When** reconciliation runs with upstream groups `[upstream-a]`, **Then** the person becomes a member of netidm group `X`.
2. **Given** the person is a member of netidm group `X` from a prior reconciliation through that connector, **When** reconciliation runs with upstream groups `[]` (empty), **Then** the person is no longer a member of netidm group `X`.
3. **Given** a connector maps `upstream-a` to `X` and `upstream-b` to `Y`, **When** reconciliation runs with `[upstream-a, upstream-b]`, **Then** the person gains both `X` and `Y`.
4. **Given** a connector has no mapping for an upstream name the reconciler receives, **When** reconciliation runs, **Then** that upstream name is ignored — no change occurs on any netidm group on its account.
5. **Given** a connector's stored mapping references an unknown netidm group, **When** reconciliation runs, **Then** that mapping entry is ignored with a warning and other entries proceed normally — reconciliation does not fail.

---

### User Story 3 - Locally-granted memberships survive reconciliation (Priority: P1)

Administrators sometimes add users to netidm groups directly — memberships that are not tied to any upstream assertion. When a reconciliation runs for a user who has such locally-granted memberships, those memberships must remain untouched, regardless of whether the upstream asserts them or not.

**Why this priority**: Without this guarantee, a login would silently undo admin actions, making the feature unsafe to enable for any group an administrator might also curate by hand. P1 — required for the feature to be shippable.

**Independent Test**: Add a person to a netidm group directly (no upstream involvement). Invoke reconciliation with an empty upstream-group set for that connector. Assert the person is still a member of the netidm group.

**Acceptance Scenarios**:

1. **Given** a person has a locally-granted membership in netidm group `X` (never applied by any upstream), **When** reconciliation runs for a connector mapping something to `X`, with upstream groups `[]`, **Then** the person remains a member of `X`.
2. **Given** a connector `A` granted the person membership in `X`, and an administrator also locally granted the same membership through a separate action, **When** reconciliation runs for `A` with upstream groups `[]`, **Then** the person remains a member of `X` (the connector-granted tag is removed; the local grant is preserved).
3. **Given** two connectors `A` and `B` each map to the same netidm group `X`, and a person gained `X` through both, **When** reconciliation runs for `A` with upstream groups `[]`, **Then** the person remains a member of `X` (because connector `B` still asserts it). Reconciling for `B` with `[]` afterwards removes the membership.

---

### User Story 4 - Downstream applications see the correct groups claim (Priority: P2)

When a user with upstream-sourced memberships requests a token from a downstream OAuth2 application through netidm, the `groups` claim in that token reflects the user's netidm group memberships — including those applied by upstream reconciliation.

**Why this priority**: This is the operational outcome that unblocks the `github → netidm → portainer` chain. It is P2 rather than P1 because it depends on US1 + US2 + US3 being correct, and because the mechanism that populates the claim (the existing downstream projection) is already implemented — this story confirms end-to-end success rather than introducing new behaviour.

**Independent Test**: Given a person who is a member of netidm group `X` (however they got there), request a token for a downstream OAuth2 application and inspect its `groups` claim. Assert `X` appears. This is already working for locally-granted memberships today; once US1–US3 ship, it works for upstream-sourced memberships too.

**Acceptance Scenarios**:

1. **Given** a person is a member of netidm group `X` via upstream reconciliation, **When** a downstream application requests a token for that person, **Then** the `groups` claim in the token contains `X`.
2. **Given** a person's upstream-sourced membership in `X` has been removed by reconciliation, **When** a downstream application requests a token for that person after reconciliation, **Then** the `groups` claim does not contain `X`.

---

### Edge Cases

- An upstream group name contains a colon (e.g., `team:infra:lead`). Mapping storage must preserve it exactly; the stored format must unambiguously split name from netidm group identifier.
- A mapping's stored netidm group identifier becomes unresolvable (the group is deleted). Reconciliation must not fail; the affected mapping entry is skipped with a warning, and other mappings proceed normally.
- The same upstream group is added twice for a connector. The system rejects the second add with an error that names the existing mapping; no data is mutated. To change a mapping, the administrator runs remove-group-mapping first, then add-group-mapping with the new target.
- The same netidm group is mapped from two different upstream names (legitimate: e.g., both `admins` and `superadmins` upstream roll up to `admins` in netidm). Reconciliation must correctly accumulate and never produce redundant writes.
- A person authenticates via a connector that has no mappings configured. Reconciliation runs as a no-op; no error, no audit noise.
- Two connectors map overlapping sets of upstream names to the same netidm group. Reconciling through connector A does not affect what connector B contributed (see Story 3 acceptance 3).
- An administrator attempts to add a mapping naming a netidm group that does not exist. The CLI must reject the command at invocation time with a clear error; no mapping is stored.
- An administrator attempts to remove a mapping that does not exist. The CLI reports the mapping was not present; no error; no side effects.
- A person has zero memberships before reconciliation and the upstream asserts zero mapped groups. Reconciliation is a no-op.
- An administrator removes a mapping that currently produces memberships for live users. The remove command itself does not change any user's memberships; each affected user loses the membership on their next authentication through the connector.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST allow an administrator to associate an upstream group name with a netidm group on an OAuth2 upstream connector.
- **FR-002**: System MUST allow an administrator to associate an upstream group name with a netidm group on a SAML upstream connector.
- **FR-003**: System MUST allow an administrator to list all upstream→netidm group mappings for a given connector.
- **FR-004**: System MUST allow an administrator to remove a single upstream→netidm group mapping from a connector.
- **FR-005**: System MUST accept a netidm group either by its name or by its unique identifier when adding a mapping; both forms MUST produce the same persisted mapping.
- **FR-006**: System MUST reject an add-mapping command whose named netidm group does not exist, with an error that identifies the missing group.
- **FR-007**: System MUST persist mappings such that a subsequent list command, potentially after a server restart, returns every mapping that was added and has not since been removed.
- **FR-007a**: System MUST reject an add-mapping command whose upstream group name is already mapped on the target connector, with an error that identifies the existing netidm group target; no change is made to storage. To change a mapping, the administrator removes the existing mapping first.
- **FR-007b**: The remove-mapping command MUST affect only the mapping record on the connector; it MUST NOT eagerly modify any user's group memberships. Users who had memberships granted through the removed mapping retain those memberships until their next authentication through the connector, at which point reconciliation removes them as now-unmapped.
- **FR-008**: System MUST preserve exact upstream group names, including any special characters legal in upstream group naming schemes, when storing and retrieving mappings.
- **FR-009**: Upon successful authentication of a user through an upstream connector, system MUST reconcile the user's memberships on each netidm group named in that connector's mappings so that the user's membership matches the upstream assertion — gaining memberships for mapped upstream groups the upstream now asserts and losing memberships for mapped upstream groups the upstream no longer asserts.
- **FR-010**: Reconciliation MUST NOT change a user's membership on any netidm group not named in the reconciling connector's mappings.
- **FR-011**: Reconciliation MUST NOT remove a user's membership on a netidm group unless that membership was itself applied by a prior reconciliation through the same connector (locally-granted memberships MUST persist).
- **FR-012**: Reconciliation MUST be idempotent — running it twice with the same inputs MUST produce the same outcome as running it once.
- **FR-013**: Reconciliation MUST operate correctly regardless of which authentication outcome triggered it: initial linking to a pre-existing account, just-in-time account creation, or subsequent login of an already-linked account.
- **FR-014**: Reconciliation MUST tolerate mapping entries that reference non-existent or malformed netidm groups — the affected entries MUST be ignored with a warning recorded and other entries MUST proceed.
- **FR-015**: Reconciliation MUST tolerate upstream group names that are not present in the connector's mappings — such names MUST be silently ignored.
- **FR-016**: When two or more connectors independently assert membership in the same netidm group for the same user, the user MUST remain a member of that group until no connector asserts it AND no local grant exists.
- **FR-017**: The outbound OAuth2/OIDC token groups claim produced by netidm for downstream applications MUST include netidm groups the user is a member of as a result of upstream reconciliation (through the existing downstream claim projection; no new emission logic is required for this feature).
- **FR-018**: System MUST NOT fail a user's authentication due to errors in mapping reconciliation — reconciliation errors MUST be recorded for operational review but MUST NOT block a successful authentication.

### Key Entities *(include if feature involves data)*

- **Upstream connector**: An OAuth2 or SAML connection from netidm to an external identity provider. Existing entity. Feature adds: a set of group mappings owned by the connector.
- **Group mapping**: A record on a connector associating one upstream group name with one netidm group identifier. Multiple mappings per connector. Order is not significant. Uniqueness: an upstream group name appears at most once in a given connector's mappings.
- **Upstream-sourced membership marker**: Per-user record that remembers which netidm-group memberships were most recently applied by reconciliation through a specific connector. Used as the diff baseline on subsequent reconciliations and as the safety mechanism that distinguishes upstream-managed memberships from locally-granted ones. Has no meaning to any consumer outside reconciliation.
- **External user claims**: The set of attributes carried from an upstream identity provider into netidm during authentication (e.g., email, display name, identifier). Feature extends this set with an optional list of upstream group names; in this feature the list is always empty (future per-connector work will populate it).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An administrator can add, list, and remove a mapping on a connector and observe the result in each of the three CLI commands within the same session, with no hand-editing of storage.
- **SC-002**: Reconciliation applied to a person and a connector with `N` upstream group names completes in time that scales linearly with the number of newly-added and newly-removed memberships — not with the total number of mappings or the total number of a user's existing memberships.
- **SC-003**: 100% of test cases covering mapping CRUD, reconciliation add/remove/no-op, locally-granted preservation, multi-connector overlap, and error-tolerance pass without modification to existing OAuth2 or SAML test suites.
- **SC-004**: When the feature ships, zero regressions are observed in downstream OIDC token issuance for users whose memberships derive solely from local grants (the behaviour is unchanged for them).
- **SC-005**: An administrator who reconfigures which upstream group maps to which netidm group can do so without touching any downstream application — no downstream sees upstream group names at any point.
- **SC-006**: Malformed or stale stored mapping entries never produce an authentication failure; 100% of such entries are logged with enough information for the administrator to locate and correct them.

## Assumptions

- This feature is pure plumbing. No connector in this release populates the upstream-groups list on external user claims; each later per-connector PR in the dex-parity roadmap populates it for its own provider.
- The downstream `groups` claim in OAuth2/OIDC tokens is already emitted from the user's netidm group memberships through the existing downstream projection — no change to the outbound side is in scope.
- Netidm's existing `MemberOf` computation is authoritative and is derived from group-side `Member` writes; direct writes to `MemberOf` are not attempted or expected.
- Administrators of upstream connectors are netidm administrators — no new role or permission boundary is introduced by this feature.
- Both OAuth2 and SAML connector entries already exist as first-class netidm objects with administrator-manageable attributes; this feature extends the attribute set, not the object model.
- A schema migration step is acceptable and expected on upgrade; downstream tooling (CLI, client library) can require matching server versions.
- Mapping is a netidm administrative concern, not an end-user concern; end users have no visibility into or control over mappings.
- Upstream group names are case-sensitive in this feature; if an upstream provider treats them case-insensitively, that normalisation is the connector's responsibility.
