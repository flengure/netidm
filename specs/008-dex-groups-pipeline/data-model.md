# Data Model: Upstream Group Plumbing (PR-GROUPS-PIPELINE)

## Summary

Three new attributes. No new entry classes. Changes apply via DL25 migration.

## New attributes

### `OAuth2GroupMapping`

| Property | Value |
|---|---|
| Protocol name | `oauth2_group_mapping` |
| Rust enum | `Attribute::OAuth2GroupMapping` |
| Schema UUID | `00000000-0000-0000-0000-ffff00000256` |
| Syntax | `Utf8String` |
| Multi-value | Yes |
| Applied via | `systemmay` on `EntryClass::OAuth2Client` |
| Value format | `<upstream-name>:<netidm-group-uuid>` — split on **last** `:` |
| DL | 25 |

**Validation**:
- Each value MUST contain at least one `:`; the substring after the last `:` MUST parse as a UUID.
- Upstream name (substring before the last `:`) MAY contain any UTF-8 characters including `:`.
- Duplicate upstream names within a single entry's values MUST be rejected by the CLI (FR-007a).
- Admin CLI SHOULD verify that the referenced UUID identifies an existing `EntryClass::Group`; the server MUST tolerate mappings whose referenced UUID later becomes unresolvable (FR-014) and MUST log without error.

**Lifecycle**: written by `AddGroupMapping` / `RemoveGroupMapping` CLI verbs. Read at connector-load time and at reconciliation time. Not modified by reconciliation.

---

### `SamlGroupMapping`

| Property | Value |
|---|---|
| Protocol name | `saml_group_mapping` |
| Rust enum | `Attribute::SamlGroupMapping` |
| Schema UUID | `00000000-0000-0000-0000-ffff00000257` |
| Syntax | `Utf8String` |
| Multi-value | Yes |
| Applied via | `systemmay` on `EntryClass::SamlClient` |
| Value format | Identical to `OAuth2GroupMapping` |
| DL | 25 |

Same validation, lifecycle, and semantics as `OAuth2GroupMapping`, scoped to the SAML connector class.

---

### `OAuth2UpstreamSyncedGroup`

| Property | Value |
|---|---|
| Protocol name | `oauth2_upstream_synced_group` |
| Rust enum | `Attribute::OAuth2UpstreamSyncedGroup` |
| Schema UUID | `00000000-0000-0000-0000-ffff00000258` |
| Syntax | `Utf8String` |
| Multi-value | Yes |
| Applied via | `systemmay` on `EntryClass::Person` |
| Value format | `<provider-uuid>:<netidm-group-uuid>` — split on **last** `:` |
| DL | 25 |

**Validation**:
- Both substrings MUST parse as UUIDs.
- The presence of a value implies: "the named provider applied the named group membership to this person during a prior reconciliation and has not since retracted it." Memberships with no corresponding marker entry are locally-granted and MUST NOT be removed by reconciliation (FR-011).
- `(person_uuid, provider_uuid, group_uuid)` is the conceptual primary key; the multi-value attribute enforces uniqueness across all three components.

**Lifecycle**: written only by the reconciliation helper
(`server/lib/src/idm/group_mapping.rs::reconcile_upstream_memberships`). Added
as a mapping resolves to the person during a login; removed when a
reconciliation for the same provider observes the upstream no longer asserts
that group for the person.

**Privacy note** (Constitution I): the marker is a derivation artifact, not personal data, but it reveals a user's group memberships by provider. Per-user deletion paths MUST also delete this attribute.

## Entities

### Upstream connector (existing, extended)

| Aspect | Description |
|---|---|
| Classes | `EntryClass::OAuth2Client` OR `EntryClass::SamlClient` |
| Feature-added attributes | `OAuth2GroupMapping` or `SamlGroupMapping` (multi-value) |
| Relationships | References zero or more netidm groups by UUID through mapping values |
| Identity | Existing (connector name) |

### Group mapping (conceptual, serialised as attribute value)

| Aspect | Description |
|---|---|
| Representation | One value in the connector's `{OAuth2,Saml}GroupMapping` multi-value attribute |
| Fields | `upstream_name: String`, `netidm_uuid: Uuid` |
| Uniqueness | `upstream_name` is unique per connector (FR-007a) |
| Lifecycle | Created by admin add-mapping; removed by admin remove-mapping. Never modified in place; to change, admin removes then adds. |

### Upstream-sourced membership marker (conceptual, serialised as attribute value)

| Aspect | Description |
|---|---|
| Representation | One value in the person's `OAuth2UpstreamSyncedGroup` multi-value attribute |
| Fields | `provider_uuid: Uuid`, `netidm_group_uuid: Uuid` |
| Uniqueness | `(provider_uuid, netidm_group_uuid)` unique per person |
| Lifecycle | Added by reconciliation when mapping resolves a then-absent membership; removed by a subsequent reconciliation for the same provider whose upstream set no longer includes it, OR when the mapping entry that produced it is removed and next reconciliation runs for the affected user. |

### External user claims (existing Rust type, extended)

`server/lib/src/idm/authsession/handler_oauth2_client.rs`:

| Field | Type | Status | Notes |
|---|---|---|---|
| `external_id` | `String` | Existing | |
| `username_hint` | `Option<String>` | Existing | |
| `email` | `Option<String>` | Existing | |
| `email_verified` | `bool` | Existing | |
| `display_name` | `Option<String>` | Existing | |
| `groups` | `Vec<String>` | **NEW** | Default empty; populated by connector implementations in later PRs. |

## Relationships diagram

```
                ┌─────────────────────┐
                │  OAuth2Client /     │
                │  SamlClient entry   │
                │                     │
                │  {Oauth2,Saml}      │
                │  GroupMapping       │───(value: upstream-name:group-uuid)───┐
                │   (multi-value)     │                                       │
                └──────────┬──────────┘                                       │
                           │                                                  │
                           │ connector_uuid                                   │
                           │                                                  ▼
                           │                                        ┌─────────────────┐
                           │                                        │  netidm Group   │
                           │                                        │  (by UUID)      │
                           │                                        │                 │
                           │                                        │  Member───┐     │
                           │                                        └───────────┼─────┘
                           │                                                    │
                           │                                                    │ Refer
                           │                                                    ▼
                           │                                        ┌─────────────────┐
                           │                                        │     Person      │
                           │                                        │                 │
                           └────(marker)───────────────────────────▶│ OAuth2Upstream  │
                                value: provider-uuid:group-uuid     │ SyncedGroup     │
                                                                    │  (multi-value)  │
                                                                    └─────────────────┘
```

## State transitions

### Group mapping

```
(none)  ─── admin add-group-mapping ───▶  Present
Present ─── admin remove-group-mapping ───▶  (none)
Present ─── admin add-group-mapping(same upstream name) ───▶  Error (FR-007a);
                                                              stays Present
```

### Upstream-sourced membership marker (per person, per provider, per group)

```
(none) ─── reconcile: provider asserts upstream name mapping to this group ───▶  Present
Present ─── reconcile: provider no longer asserts it ───▶  (none)
Present ─── reconcile: mapping removed (no resolution for group) ───▶  (none)
Present ─── provider is deleted ───▶  (none), eventually — but only if a later
                                       reconcile somehow observes the state.
                                       In practice, the marker becomes inert.
```

### Membership on the target netidm group

```
Local add (admin adds Person to group)          ──▶  Present, no marker
                                                     (locally-granted)
Connector reconcile adds                         ──▶  Present, marker for provider
Connector reconcile removes (no other markers)   ──▶  (removed from group)
Connector reconcile removes (other provider still
  has marker)                                    ──▶  stays Present; only the
                                                       reconciling provider's marker
                                                       is removed
Connector reconcile removes (local grant exists) ──▶  stays Present; no marker
                                                       for any provider remains
```

## Indices

No new secondary indices required; all access patterns use existing primary indices (`Attribute::Uuid` and the inverted index on `Attribute::Member`). The marker attribute is only ever read by UUID of the person, which is already indexed.

## Schema-migration impact

- `OAuth2Client` class gains `OAuth2GroupMapping` in `systemmay`.
- `SamlClient` class gains `SamlGroupMapping` in `systemmay`.
- `Person` class gains `OAuth2UpstreamSyncedGroup` in `systemmay`.
- No class removals or renames.
- Existing entries require no data migration; existing rows simply have the new attribute absent (= empty).

## Constants

```rust
pub const DOMAIN_LEVEL_25: DomainVersion = 25;

pub const UUID_SCHEMA_ATTR_OAUTH2_GROUP_MAPPING: Uuid =
    uuid!("00000000-0000-0000-0000-ffff00000256");
pub const UUID_SCHEMA_ATTR_SAML_GROUP_MAPPING: Uuid =
    uuid!("00000000-0000-0000-0000-ffff00000257");
pub const UUID_SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP: Uuid =
    uuid!("00000000-0000-0000-0000-ffff00000258");
```

## Out of scope

- No new class UUIDs. Class schema updates reuse the existing
  `UUID_SCHEMA_CLASS_OAUTH2_CLIENT`, `UUID_SCHEMA_CLASS_SAML_CLIENT`,
  `UUID_SCHEMA_CLASS_PERSON`.
- No new ACP. The existing OAuth2 / SAML client admin ACPs already grant
  write access to `systemmay` attributes on their respective classes.
