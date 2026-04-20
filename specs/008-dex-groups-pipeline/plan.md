# Implementation Plan: Upstream Group Plumbing (PR-GROUPS-PIPELINE)

**Branch**: `008-dex-groups-pipeline` | **Date**: 2026-04-20 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/008-dex-groups-pipeline/spec.md`

## Summary

Add upstream → downstream group plumbing to netidm. Three new multi-value Utf8String attributes on `OAuth2Client` / `SamlClient` / `Person` (DL25 migration), a `groups: Vec<String>` field on `ExternalUserClaims`, and a new `server/lib/src/idm/group_mapping.rs` module with `reconcile_upstream_memberships()`. The helper diffs upstream-asserted group names against the connector's mapping and mutates `Member` on each target netidm group while a per-user, per-provider marker (`OAuth2UpstreamSyncedGroup`) tracks which memberships the connector is responsible for — so admin-granted memberships are never touched. Three hook points call the helper (link path, JIT provision path, already-linked auth path). No connector populates `claims.groups` in this PR; that is the job of each subsequent per-connector PR. CLI adds three verbs per connector type for mapping CRUD.

## Technical Context

**Language/Version**: Rust stable (see `rust-toolchain.toml`)
**Primary Dependencies**: Existing — `netidmd_lib` (MVCC entry DB, schema/migration framework), `netidm_proto` (Attribute / EntryClass / constants), `async-trait`, `hashbrown` (std HashSet banned by clippy). No new workspace deps.
**New Dependencies**: None.
**Storage**: Netidm MVCC entry database. DL25 migration adds three new `Utf8String` multi-value attributes. Class UUIDs reuse existing `UUID_SCHEMA_CLASS_OAUTH2_CLIENT`, `UUID_SCHEMA_CLASS_SAML_CLIENT`, `UUID_SCHEMA_CLASS_PERSON`. No new classes.
**Testing**: `cargo test` via `server/testkit` integration infrastructure (real in-process netidmd); unit tests co-located in `server/lib/src/idm/group_mapping.rs`.
**Target Platform**: Linux server (same as rest of netidm).
**Project Type**: Library + HTTP service + CLI tool (tri-crate: `server/lib`, `server/core`, `tools/cli`).
**Performance Goals**: Reconciliation complexity scales linearly with the size of the diff (added + removed memberships), not with total mappings or total user memberships. For typical login volumes this is below millisecond-level overhead in the existing proxy_write transaction.
**Constraints**: Reconciliation runs inside the existing write transaction that completed JIT/link; MUST NOT fail a user's authentication on reconciliation error (FR-018). MUST NOT eagerly sweep on mapping removal (FR-007b). Mapping value delimiter is the **last** `:` — upstream group names may contain colons (Azure/SAML); UUIDs cannot.

## Constitution Check

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Ethics & Human Rights | PASS | No new PII fields. The new `OAuth2UpstreamSyncedGroup` marker is a derivation artifact, not personal data. User retains self-control over memberships because admins can remove the mapping and the marker, and locally-granted memberships are preserved by design (FR-011). |
| II. Humans First | PASS | Admin CLI accepts netidm group by name or UUID (FR-005). Errors identify existing mappings by name. No burden placed on end users. |
| III. Correct & Simple | PASS | `cargo test` remains self-contained — unit tests in `group_mapping.rs` plus testkit integration tests. No external services required. |
| IV. Clippy & Zero Warnings | PASS | No `#[allow(...)]` introduced. `hashbrown::HashSet` used; std `HashSet` banned by project clippy config. |
| V. Security by Hierarchy | PASS | Engineering Control: marker is the authoritative source for "connector-granted vs local-granted"; no heuristic-based inference. Administrative Control: warnings on malformed mapping entries logged for operator review. No failure of reconciliation can escalate membership (FR-014, FR-018). |
| Security Standards | PASS | Reconciliation errors do not block auth (FR-018); logs must not leak upstream group names containing sensitive personal identifiers — constraint: log at info/warn severity, never include group names at debug level below. |
| Documentation Standards | REQUIRED | Doc comments on all new `pub` items (`GroupMapping`, `reconcile_upstream_memberships`, CLI verbs, client SDK methods). `# Errors` on every `Result`-returning `pub fn`. |
| Testing Standards | REQUIRED | Unit tests for parse round-trip, add/remove/no-op reconcile, locally-granted preservation, multi-connector overlap, unknown-UUID tolerance, duplicate-add rejection, mapping-removal-does-not-eagerly-sweep. |
| DL Migration | REQUIRED | DL25 migration introduced; round-trip test in `migrations.rs` asserts new attributes exist after DL24→DL25 upgrade. |

No constitution violations. No Complexity Tracking entries required.

## Project Structure

### Documentation (this feature)

```text
specs/008-dex-groups-pipeline/
├── plan.md              # This file
├── research.md          # Design decisions + alternatives (Phase 0)
├── data-model.md        # Entity model (Phase 1)
├── quickstart.md        # Test scenarios (Phase 1)
├── contracts/
│   └── cli-commands.md  # CLI command contract
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Generated by /speckit.tasks
```

### Source Code Changes

```text
proto/src/
├── attribute.rs                            # + OAuth2GroupMapping, SamlGroupMapping,
│                                             OAuth2UpstreamSyncedGroup variants
│                                             (Attribute enum + as_str + FromStr)
└── constants.rs                            # + ATTR_OAUTH2_GROUP_MAPPING,
                                              ATTR_SAML_GROUP_MAPPING,
                                              ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP

server/lib/src/
├── constants/
│   ├── mod.rs                              # DOMAIN_LEVEL_25; bump TGT/MAX; PREVIOUS follows
│   └── uuids.rs                            # UUID_SCHEMA_ATTR_OAUTH2_GROUP_MAPPING (...0256)
│                                             UUID_SCHEMA_ATTR_SAML_GROUP_MAPPING  (...0257)
│                                             UUID_SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP (...0258)
├── idm/
│   ├── group_mapping.rs                    # NEW: GroupMapping, reconcile_upstream_memberships,
│   │                                              unit tests
│   ├── mod.rs                              # + pub mod group_mapping;
│   ├── oauth2_client.rs                    # + group_mapping: Vec<GroupMapping> on
│   │                                              OAuth2ClientProvider; loader additions at
│   │                                              lines 246-283
│   ├── saml_client.rs                      # + group_mapping: Vec<GroupMapping> on
│   │                                              SamlClientProvider; mirror loader
│   ├── server.rs                           # + reconcile_upstream_memberships_for_cred helper
│   │                                              on IdmServerProxyWriteTransaction
│   └── authsession/
│       ├── handler_oauth2_client.rs        # + groups: Vec<String> on ExternalUserClaims (line 20);
│       │                                     initialise Vec::new() at lines 287, 379, 467;
│       │                                     call reconcile_upstream_memberships_for_cred before
│       │                                     CredState::Success at line 215
│       ├── handler_saml_client.rs          # Wire groups extraction into reconcile helper
│       └── provider_initiated.rs           # Initialise groups: Vec::new() at line 228
├── migration_data/
│   ├── mod.rs                              # + dl25 module; flip latest alias
│   └── dl25/
│       ├── mod.rs                          # DL25 phase functions (delegate to dl24 except
│       │                                     phases 1 and 2)
│       └── schema.rs                       # SCHEMA_ATTR_OAUTH2_GROUP_MAPPING_DL25,
│                                             SCHEMA_ATTR_SAML_GROUP_MAPPING_DL25,
│                                             SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP_DL25;
│                                             SCHEMA_CLASS_OAUTH2_CLIENT_DL25 (adds systemmay),
│                                             SCHEMA_CLASS_SAML_CLIENT_DL25 (adds systemmay),
│                                             SCHEMA_CLASS_PERSON_DL25 (adds systemmay)
└── server/
    ├── migrations.rs                       # migrate_domain_24_to_25() method
    │                                         (line ~1471, mirrors migrate_domain_23_to_24);
    │                                         DOMAIN_LEVEL_25 => migrate_domain_24_to_25() arm
    │                                         (~line 78)
    └── mod.rs                              # DL24→25 upgrade block;
                                              const assert!(DOMAIN_MAX_LEVEL == DOMAIN_LEVEL_25)
                                              at line 2694

server/core/src/
├── actors/v1_write.rs                      # handle_link_account_by_email (line 1825):
│                                            after link, invoke reconcile helper.
│                                            handle_jit_provision_oauth2_account (line ~1840+):
│                                            after create, invoke reconcile helper.
└── https/views/login.rs                    # ExternalUserClaims construction — initialise
                                              groups: Vec::new() at lines 1778, 1882
                                              (cookie rebuild across provision round-trip;
                                              explicitly no groups persisted in ProvisionCookieData).

libs/client/src/
├── oauth.rs                                # + idm_oauth2_client_add_group_mapping,
│                                             idm_oauth2_client_remove_group_mapping,
│                                             idm_oauth2_client_list_group_mappings
└── saml.rs                                 # Mirror for SAML

tools/cli/src/
├── opt/netidm.rs                           # + AddGroupMapping, RemoveGroupMapping,
│                                             ListGroupMappings on OAuth2Opt and SamlClientOpt
└── cli/
    ├── oauth2.rs                           # Command handlers
    └── saml.rs                             # Mirror for SAML
```

## Implementation Notes by Layer

### Layer 1: Protocol (`proto/`)

**`proto/src/constants.rs`** — three new const strings:
```rust
pub const ATTR_OAUTH2_GROUP_MAPPING: &str = "oauth2_group_mapping";
pub const ATTR_SAML_GROUP_MAPPING: &str = "saml_group_mapping";
pub const ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP: &str = "oauth2_upstream_synced_group";
```

**`proto/src/attribute.rs`** — `Attribute` enum gains three variants; both `as_str` and `FromStr` match arms updated.

### Layer 2: Schema Constants (`server/lib/src/constants/`)

```rust
// uuids.rs — block continues from UUID_SCHEMA_ATTR_OAUTH2_LINK_BY (…0255)
pub const UUID_SCHEMA_ATTR_OAUTH2_GROUP_MAPPING: Uuid =
    uuid!("00000000-0000-0000-0000-ffff00000256");
pub const UUID_SCHEMA_ATTR_SAML_GROUP_MAPPING: Uuid =
    uuid!("00000000-0000-0000-0000-ffff00000257");
pub const UUID_SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP: Uuid =
    uuid!("00000000-0000-0000-0000-ffff00000258");

// mod.rs
pub const DOMAIN_LEVEL_25: DomainVersion = 25;
// Bump: DOMAIN_TGT_LEVEL = DOMAIN_LEVEL_25, DOMAIN_MAX_LEVEL = DOMAIN_LEVEL_25
```

### Layer 3: `GroupMapping` + reconciliation module (`server/lib/src/idm/group_mapping.rs`)

```rust
//! Upstream-to-netidm group mapping and login-time membership reconciliation.
//!
//! Each OAuth2 or SAML connector carries a set of `<upstream-name>:<group-uuid>`
//! values. At login the connector reports upstream group names; this module
//! resolves them through the connector's mapping and adjusts the user's `Member`
//! attribute on each target netidm group. A per-user, per-provider marker
//! (`OAuth2UpstreamSyncedGroup`) records which memberships the connector has
//! applied — so only those are subject to removal on subsequent reconciliations.

use uuid::Uuid;
use hashbrown::HashSet;
use crate::prelude::*;

pub struct GroupMapping {
    pub upstream_name: String,
    pub netidm_uuid: Uuid,
}

impl GroupMapping {
    /// Parse `<upstream-name>:<netidm-uuid>` — split on the LAST `:`.
    ///
    /// # Errors
    /// Returns `OperationError::InvalidValueState` if the value has no `:` or
    /// the UUID portion is unparseable.
    pub fn parse(raw: &str) -> Result<Self, OperationError> { ... }
}

/// Reconcile a person's memberships on mapped netidm groups to match upstream.
///
/// Adds missing memberships, removes now-absent ones, and updates the
/// per-provider marker. Locally-granted memberships (no marker for this
/// provider) are never touched.
///
/// # Errors
/// Returns any `OperationError` from the underlying `internal_modify` calls.
/// Unresolvable mapping entries are logged and skipped, not surfaced.
pub fn reconcile_upstream_memberships(
    qs_write: &mut QueryServerWriteTransaction,
    person_uuid: Uuid,
    provider_uuid: Uuid,
    mapping: &[GroupMapping],
    upstream_group_names: &[String],
) -> Result<(), OperationError> { ... }
```

Algorithm:
1. `desired: HashSet<Uuid>` = for each upstream name in `upstream_group_names`, look up in `mapping` and collect its `netidm_uuid`. Upstream names with no matching mapping entry are ignored (FR-015).
2. Read the person's current `OAuth2UpstreamSyncedGroup` values; parse each as `<provider-uuid>:<group-uuid>` on last `:`; filter by `provider_uuid` prefix → `previous: HashSet<Uuid>`.
3. Compute `to_add = desired - previous` and `to_remove = previous - desired`.
4. For each `group_uuid` in `to_add`: `qs_write.internal_modify(Filter::Pres(Attribute::Uuid) + Filter::Eq(Attribute::Uuid, PartialValue::Uuid(group_uuid)), ModifyList::Present(Attribute::Member, Value::Refer(person_uuid)))`. Unresolvable UUIDs emit `warn!` and skip (FR-014).
5. For each `group_uuid` in `to_remove`: analogous `Modify::Removed(Attribute::Member, PartialValue::Refer(person_uuid))`.
6. On the person entry: first remove all prior markers for `provider_uuid` (`Modify::Removed` of each `"{provider_uuid}:{old_group_uuid}"`), then add one marker per `group_uuid` in `desired`.
7. All modifications use `qs_write.internal_modify` in the calling txn — consistent with `idm/server.rs:2622` (`find_and_link_account`).

### Layer 4: `ExternalUserClaims` extension (`server/lib/src/idm/authsession/handler_oauth2_client.rs`)

```rust
pub struct ExternalUserClaims {
    pub external_id: String,
    pub username_hint: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub groups: Vec<String>,  // NEW — default empty
}
```

Construction sites — all initialise `groups: Vec::new()`:
- `handler_oauth2_client.rs:287` (access-token path)
- `handler_oauth2_client.rs:379` (userinfo path)
- `handler_oauth2_client.rs:467` (jwks / id_token path)
- `authsession/provider_initiated.rs:228`
- `server/core/src/https/views/login.rs:1778, 1882` (cookie rebuild on provision round-trip)

`ProvisionCookieData` does NOT carry groups. Reconciliation runs inside the write transaction that completes JIT/link, where the connector-side claims are still in scope via the credential handler — not the cookie.

### Layer 5: Loader additions (`oauth2_client.rs`, `saml_client.rs`)

```rust
// OAuth2ClientProvider — alongside existing claim_map at lines 246-283
pub(crate) struct OAuth2ClientProvider {
    // ... existing fields ...
    pub(crate) group_mapping: Vec<GroupMapping>,
}
```

Loader reads `Attribute::OAuth2GroupMapping` values; calls `GroupMapping::parse` for each; log-and-skip on parse failure (FR-014).

Mirror in `SamlClientProvider` reading `Attribute::SamlGroupMapping`.

### Layer 6: `reconcile_upstream_memberships_for_cred` helper (`server/lib/src/idm/server.rs`)

```rust
impl IdmServerProxyWriteTransaction<'_> {
    /// Reconcile memberships for a user identified by their upstream
    /// credential UUID.
    ///
    /// Resolves `user_cred_id` (an `OAuth2AccountCredentialUuid`) to the owning
    /// Person's UUID, then dispatches to `group_mapping::reconcile_upstream_memberships`.
    ///
    /// # Errors
    /// Returns `OperationError::NoMatchingEntries` if the cred UUID is not
    /// found (this is a logic error, not an expected path). All other errors
    /// pass through from the underlying reconcile helper.
    pub(crate) fn reconcile_upstream_memberships_for_cred(
        &mut self,
        user_cred_id: OAuth2AccountCredentialUuid,
        provider_uuid: Uuid,
        upstream_group_names: &[String],
    ) -> Result<(), OperationError> { ... }
}
```

### Layer 7: Hook wiring

**Call site 1 — link path (`server/core/src/actors/v1_write.rs:1825`):**
```rust
// After find_and_link_account_by_email returns Some(target_uuid)
let mapping = idms_prox_write
    .oauth2_client_providers
    .get(&provider_uuid)
    .map(|p| p.group_mapping.clone())
    .unwrap_or_default();
group_mapping::reconcile_upstream_memberships(
    &mut idms_prox_write.qs_write,
    target_uuid,
    provider_uuid,
    &mapping,
    &claims.groups,
)?;
```

**Call site 2 — JIT provision path (`handle_jit_provision_oauth2_account`, same file, ~line 1840):** identical shape, after account creation.

**Call site 3 — already-linked auth path (`handler_oauth2_client.rs`):** before emitting `CredState::Success` at line 215, invoke `idms.reconcile_upstream_memberships_for_cred(user_cred_id, provider_uuid, &claims.groups)` in all three of `validate_access_token_response`, `validate_userinfo_response`, `validate_jwks_token_response`.

A project-wide `grep` for `reconcile_upstream_memberships` MUST return exactly three call sites after the PR lands.

### Layer 8: DL25 Migration

`server/lib/src/migration_data/dl25/schema.rs`:
```rust
pub static SCHEMA_ATTR_OAUTH2_GROUP_MAPPING_DL25: LazyLock<SchemaAttribute> = LazyLock::new(|| {
    SchemaAttribute {
        name: Attribute::OAuth2GroupMapping,
        uuid: UUID_SCHEMA_ATTR_OAUTH2_GROUP_MAPPING,
        description: "Mapping from an upstream group name to a netidm group UUID, \
                      stored as '<upstream-name>:<group-uuid>' (split on last ':')".to_string(),
        multivalue: true,
        syntax: SyntaxType::Utf8String,
        ..Default::default()
    }
});

// Analogously: SCHEMA_ATTR_SAML_GROUP_MAPPING_DL25,
// SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP_DL25.

// Class updates: OAuth2Client gains OAuth2GroupMapping in systemmay;
// SamlClient gains SamlGroupMapping in systemmay;
// Person gains OAuth2UpstreamSyncedGroup in systemmay.
```

`dl25/mod.rs`: all phase functions delegate to `super::dl24` except phases 1 (schema attrs) and 2 (schema classes).

`server/lib/src/server/migrations.rs`: new `migrate_domain_24_to_25()` mirrors `migrate_domain_23_to_24()` structurally.

### Layer 9: Client SDK (`libs/client/src/oauth.rs`, `saml.rs`)

```rust
// oauth.rs — mirror idm_oauth2_client_set_link_by at line 775
pub async fn idm_oauth2_client_add_group_mapping(
    &self,
    id: &str,
    upstream: &str,
    netidm_uuid: Uuid,
) -> Result<(), ClientError>;

pub async fn idm_oauth2_client_remove_group_mapping(
    &self,
    id: &str,
    upstream: &str,
) -> Result<(), ClientError>;

pub async fn idm_oauth2_client_list_group_mappings(
    &self,
    id: &str,
) -> Result<Vec<(String, Uuid)>, ClientError>;
```

Mirror in `saml.rs`.

### Layer 10: CLI (`tools/cli/src/`)

`opt/netidm.rs` — add variants on the relevant `OAuth2Opt` and `SamlClientOpt` enums:
```rust
AddGroupMapping { name: String, upstream: String, netidm_group: String },
RemoveGroupMapping { name: String, upstream: String },
ListGroupMappings { name: String },
```

`cli/oauth2.rs` (and `cli/saml.rs`): handlers resolve `netidm_group` via `idm_group_get(name_or_uuid)`. If the input parses as a UUID, use directly; otherwise look up the group by name and read `Attribute::Uuid`. Error surface: group not found → CLI error per FR-006; duplicate upstream name → server error surfaces as-is per FR-007a.

## Complexity Tracking

No constitution violations. No entries required.

Note: the `OAuth2UpstreamSyncedGroup` marker is intentionally on `Person` rather than on the group side or a separate log entry. Alternatives considered in `research.md`:
- Tag on `MemberOf`: infeasible — `MemberOf` is plugin-computed, not directly writable.
- Separate log/event entries: more data, more complexity, same information. Rejected.
- Reverse attribute on the group: would require a write to every target group on every reconcile even for unchanged memberships. Rejected.
