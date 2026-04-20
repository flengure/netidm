# Contract: CLI Commands (PR-GROUPS-PIPELINE)

Three new verbs on the OAuth2 client management surface and three mirror verbs on the SAML client surface. All are administrative; end users have no commands.

## OAuth2 upstream client

### `netidm system oauth2 add-group-mapping <id> <upstream> <netidm-group>`

Associate an upstream group name with a netidm group on an OAuth2 upstream connector.

**Arguments**:
- `<id>` — the OAuth2Client entry's `name` attribute (not UUID).
- `<upstream>` — the exact upstream group name as the IdP will emit it. Case-sensitive. May contain colons.
- `<netidm-group>` — either a netidm group name (resolved via `idm_group_get`) or a UUID. Both forms MUST produce the same persisted mapping (FR-005).

**Success** (exit 0):
- Server persists one value in `OAuth2GroupMapping` of the form `<upstream>:<netidm-group-uuid>`.
- Output: `added mapping: <upstream> → <netidm-group-display-name> (<uuid>)`.

**Failures** (exit non-zero):
- `<id>` does not resolve to an `OAuth2Client` entry → exit 1; stderr: `no such OAuth2 client: <id>`.
- `<netidm-group>` (if a name was supplied) does not resolve to a `Group` entry → exit 2; stderr: `no such netidm group: <name>` (FR-006).
- `<upstream>` is already mapped on this connector → exit 3; stderr: `mapping already exists: <upstream> → <existing-target> (<uuid>); remove it first to change it` (FR-007a).
- Server error (e.g., permission denied) → exit 4; stderr: the server's error string.

**Side effects**: none beyond the single persisted mapping value on success. No reconciliation runs.

---

### `netidm system oauth2 remove-group-mapping <id> <upstream>`

Remove an upstream→netidm group mapping from an OAuth2 upstream connector.

**Arguments**:
- `<id>` — OAuth2Client entry name.
- `<upstream>` — exact upstream name matching a current mapping value's upstream-name prefix.

**Success** (exit 0):
- Server removes the matching `OAuth2GroupMapping` value.
- Output: `removed mapping: <upstream>`.
- If the mapping did not exist: still exit 0; output: `no mapping for <upstream>; nothing to remove` (explicit edge case — no error). No side effects.

**Failures** (exit non-zero):
- `<id>` does not resolve → exit 1.
- Server error → exit 4.

**Side effects**: none on any Person's memberships. Users who had the corresponding membership keep it until their next authentication through this connector, at which point reconciliation observes the absent mapping and removes the membership (per FR-007b and the Q2 clarification).

---

### `netidm system oauth2 list-group-mappings <id>`

List all upstream→netidm group mappings on an OAuth2 upstream connector.

**Arguments**:
- `<id>` — OAuth2Client entry name.

**Success** (exit 0):
- Output, one line per mapping, sorted by upstream name (case-sensitive, byte-lex):
  ```
  <upstream>\t<netidm-group-display-name>\t<uuid>
  ```
- If a mapping's UUID doesn't resolve to a current group: `<upstream>\t(no such group)\t<uuid>` — display-name column holds the literal `(no such group)` sentinel (FR-014 admin discoverability).
- Empty result: no output, exit 0 (no "none" message).

**Failures** (exit non-zero):
- `<id>` does not resolve → exit 1.
- Server error → exit 4.

---

## SAML upstream client

Equivalent commands under `netidm system saml`:

| Verb | Syntax |
|---|---|
| add | `netidm system saml add-group-mapping <id> <upstream> <netidm-group>` |
| remove | `netidm system saml remove-group-mapping <id> <upstream>` |
| list | `netidm system saml list-group-mappings <id>` |

Semantics and exit codes identical to the OAuth2 equivalents, operating on `SamlClient` entries and the `SamlGroupMapping` attribute.

## Client SDK methods

Corresponding additions to `libs/client/src/oauth.rs`:

```rust
impl KanidmClient {
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
}
```

Mirror methods in `libs/client/src/saml.rs`:
- `idm_saml_client_add_group_mapping`
- `idm_saml_client_remove_group_mapping`
- `idm_saml_client_list_group_mappings`

Resolving the `<netidm-group>` argument from the CLI (name vs. UUID) is a CLI-side concern; the client SDK receives `Uuid` directly.

## Error surface summary

| CLI exit | Meaning |
|---|---|
| 0 | Success, including idempotent no-op on remove |
| 1 | Connector not found |
| 2 | Netidm group not found (add only) |
| 3 | Mapping already exists (add only) |
| 4 | Server error (permission, transport, transaction conflict) |
| other | Reserved for future |

## Invariants

- No CLI verb triggers reconciliation of any user's memberships. Reconciliation is exclusively a login-time action.
- No CLI verb modifies `OAuth2UpstreamSyncedGroup` on any Person. The marker is managed solely by the reconciliation helper.
- Any output format or exit code change in a later PR is a breaking change to this contract; callers may depend on the exit-code table above.
