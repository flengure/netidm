# Tasks: WireGuard Management Crate

**Input**: Design documents from `specs/002-wg-mgmt-crate/`
**Branch**: `002-wg-mgmt-crate`

---

## Phase 1: Setup

**Purpose**: Create the `server/wg/` crate, register workspace dependencies, add DL17 migration skeleton.

- [X] T001 Create `server/wg/` crate with `Cargo.toml` declaring deps: `wireguard-control`, `boringtun`, `tun2`, `rtnetlink`, `ipnet`, `tokio`, `anyhow`, `tracing`; add crate to workspace `Cargo.toml` members
- [X] T002 Create `server/wg/src/lib.rs` with module declarations: `backend`, `manager`, `alloc`, `hooks`, `types`; re-export `WgManager` and `detect_backend`
- [X] T003 [P] Create `server/lib/src/migration_data/dl17/mod.rs` and `schema.rs` as empty skeletons (phase functions delegating to dl16); wire into `migration_data/mod.rs` and `server/migrations.rs`
- [X] T004 [P] Add WireGuard attribute and class constants to `proto/src/attribute.rs` and `proto/src/constants.rs`: `WgLastSeen`, `WgTokenSecret`, `WgTokenUsesLeft`, `WgTokenExpiry`, `WgTokenPrincipalRef`, `WgToken` class

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared types, trait definitions, and DL17 schema that every user story depends on.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T005 Add `WgTunnelConfig` and `WgPeerConfig` structs to `server/wg/src/types.rs`; derive `Clone`, `Debug`; fields match DL16 schema attributes (name, interface, private_key, listen_port, address, dns, mtu, peers, hooks)
- [X] T006 Define `WgBackend` trait in `server/wg/src/backend/mod.rs`: async methods `create_link`, `delete_link`, `configure`, `add_peer`, `remove_peer`, `peer_handshakes`; add `detect_backend() -> Box<dyn WgBackend>` probing `/sys/module/wireguard`
- [X] T007 [P] Add DL17 schema attrs to `server/lib/src/migration_data/dl17/schema.rs`: `SCHEMA_ATTR_WG_LAST_SEEN_DL17`, `SCHEMA_ATTR_WG_TOKEN_SECRET_DL17`, `SCHEMA_ATTR_WG_TOKEN_USES_LEFT_DL17`, `SCHEMA_ATTR_WG_TOKEN_EXPIRY_DL17`, `SCHEMA_ATTR_WG_TOKEN_PRINCIPAL_REF_DL17`; add `SCHEMA_CLASS_WG_TOKEN_DL17` (systemmust: Name, WgTunnelRef, WgTokenSecret; systemmay: WgTokenUsesLeft, WgTokenExpiry, WgTokenPrincipalRef)
- [X] T008 [P] Add `SCHEMA_ATTR_WG_LAST_SEEN_DL17` to `WgPeer.systemmay` in `server/lib/src/migration_data/dl17/schema.rs`; register all DL17 attrs and classes in `dl17/mod.rs` phase functions
- [X] T009 [P] Add new UUIDs for DL17 attrs/classes to `server/lib/src/constants/uuids.rs`; add `EntryClass::WgToken` to `server/lib/src/constants/entries.rs`; add `Attribute::WgLastSeen`, `Attribute::WgTokenSecret`, `Attribute::WgTokenUsesLeft`, `Attribute::WgTokenExpiry`, `Attribute::WgTokenPrincipalRef` to `proto/src/attribute.rs`
- [X] T010 Create `proto/src/wg.rs` with all API types deriving `Serialize`, `Deserialize`, `ToSchema`: `WgTunnelCreate`, `WgTunnelPatch`, `WgTunnelResponse`, `WgPeerResponse`, `WgTokenCreate`, `WgTokenCreatedResponse`, `WgTokenInfo`, `WgConnectRequest`, `WgConnectResponse`; add module to `proto/src/lib.rs`
- [X] T011 Increment DL migration version: update `server/lib/src/server/migrations.rs` to include DL17 phase calls; update `server/lib/src/constants/mod.rs` DOMAIN_LEVEL constant to 17

**Checkpoint**: Foundation complete — WgBackend trait, DL17 schema, and proto types are in place.

---

## Phase 3: User Story 1 — Tunnel Bring-Up with Runtime Backend Detection (Priority: P1) 🎯 MVP

**Goal**: netidmd reads all enabled WgTunnel entries at startup, detects kernel vs userspace, creates live interfaces.

**Independent Test**: Create a WgTunnel entry, start netidmd on a Linux host. Verify `ip link show wg0` shows the interface with correct address and WireGuard config (`wg show wg0`).

- [X] T012 [US1] Implement `KernelBackend` in `server/wg/src/backend/kernel.rs`: `create_link` via rtnetlink `LinkMessage` add type wireguard; `delete_link` via rtnetlink; `configure`/`add_peer`/`remove_peer`/`peer_handshakes` via `wireguard_control::DeviceUpdate` with `Backend::Kernel`; `add_address`/`add_route` helpers via rtnetlink
- [X] T013 [US1] Implement `BoringtunBackend` in `server/wg/src/backend/boringtun.rs`: `create_link` spawns boringtun `device::Device` in background thread with `tun2` TUN device; stores device handles in `Arc<Mutex<HashMap>>`; `configure`/`add_peer`/`remove_peer`/`peer_handshakes` via `wireguard_control::DeviceUpdate` with `Backend::Userspace` (UAPI socket at `/var/run/wireguard/<name>.sock`); `add_address`/`add_route` via rtnetlink
- [X] T014 [US1] Implement hook execution in `server/wg/src/hooks.rs`: `run_hooks(commands: &[String], iface_name: &str)` splits each command string, substitutes `%i` placeholder, runs via `std::process::Command`, returns error on non-zero exit
- [X] T015 [US1] Implement `WgManager` in `server/wg/src/manager.rs`: holds `Box<dyn WgBackend>` and `HashMap<String, WgTunnelConfig>` of live tunnels; `bring_up(tunnel, peers)` runs pre_up → create_link → configure → add_address (rtnetlink) → link_up → add_routes → post_up; `tear_down(name)` runs pre_down → delete_link → post_down; `reconcile(name)` handles already-existing interface on startup
- [X] T016 [US1] Create `server/lib/src/idm/wg.rs`: add `IdmServerProxyReadTransaction::wg_list_tunnels()` reading all `EntryClass::WgTunnel` entries and returning `Vec<WgTunnelConfig>`; add `wg_list_peers_for_tunnel(tunnel_uuid)` returning `Vec<WgPeerConfig>`
- [X] T017 [US1] Add `QueryServerWriteV1::handle_wg_tunnel_create`, `handle_wg_tunnel_patch`, `handle_wg_tunnel_delete`, `handle_wg_tunnel_get` to `server/core/src/actors/v1_write.rs`; wire through `server/lib/src/idm/wg.rs` for entry CRUD via `idms.proxy_write`
- [X] T018 [US1] Integrate `WgManager` into netidmd startup in `server/core/src/lib.rs` (or equivalent startup path): call `detect_backend()`, construct `WgManager`, read all WgTunnel entries via `IdmServer`, call `bring_up` for each enabled tunnel; store `Arc<WgManager>` in `ServerState`
- [X] T019 [US1] Add `WgManager::derive_and_write_public_key(tunnel_name)` to `server/wg/src/manager.rs` that derives the public key from the stored private key and writes `WgPublicKey` back to the WgTunnel entry via the actor write path; call this in `bring_up` if `WgPublicKey` is absent or stale
- [X] T020 [P] [US1] Implement HTTP handlers in `server/core/src/https/v1_wg.rs`: `wg_tunnel_get`, `wg_tunnel_post`, `wg_tunnel_id_get`, `wg_tunnel_id_patch`, `wg_tunnel_id_delete`; each annotated with `#[utoipa::path(...)]`; request/response types from `proto::wg`
- [X] T021 [US1] Register `/v1/wg/tunnel` routes in `server/core/src/https/v1.rs`; add all `v1_wg` tunnel handler paths and `WgTunnelCreate`/`WgTunnelResponse`/`WgTunnelPatch` schemas to `ApiDoc` in `server/core/src/https/apidocs/mod.rs`
- [X] T022 [P] [US1] Add `WgOpt` enum to `tools/cli/src/opt/netidm.rs` with subcommands: `TunnelCreate`, `TunnelGet`, `TunnelList`, `TunnelPatch`, `TunnelDelete`; add `wg` subcommand to root opt
- [X] T023 [US1] Implement CLI dispatch in `tools/cli/src/cli/wg.rs` for all tunnel subcommands; wire into main CLI dispatch

**Checkpoint**: US1 complete — `netidmd` brings up WireGuard tunnels from Netidm entries on both kernel and userspace hosts.

---

## Phase 4: User Story 2 — Token-Gated Peer Registration (Priority: P2)

**Goal**: An authenticated user presents a WgToken secret + their WireGuard public key and receives a ready-to-use client config.

**Independent Test**: Create a WgTunnel + WgToken (1 use). POST `/v1/wg/connect` with valid Netidm bearer token, WG token secret, and generated pubkey. Verify WgPeer entry created in Netidm, peer appears in `wg show wg0 peers`, returned config is valid wg-quick format.

- [X] T024 [US2] Implement `IpAllocator` in `server/wg/src/alloc.rs`: `allocate(tunnel_cidrs: &[IpNet], existing_peers: &[IpNet]) -> Result<Vec<IpNet>>` — parses tunnel address CIDRs, reserves slot 1 (server), finds lowest unused slot ≥ 2, returns `/32` (IPv4) and `/128` (IPv6) per address family; `release` is implicit (peer entry deletion)
- [X] T025 [US2] Add token operations to `server/lib/src/idm/wg.rs`: `wg_token_create(tunnel_uuid, req: WgTokenCreate) -> WgTokenCreatedResponse` (generate opaque secret, store hash); `wg_token_validate(secret: &str) -> Result<WgTokenEntry>` (lookup by hash, check expiry, check uses_left, check principal_ref vs caller); `wg_token_consume(token_uuid)` (decrement uses_left or delete entry)
- [X] T026 [US2] Add peer provisioning to `server/lib/src/idm/wg.rs`: `wg_connect(caller_uuid, req: WgConnectRequest) -> Result<WgConnectResponse>` — validate token, check pubkey uniqueness on tunnel, allocate IPs via `IpAllocator`, create WgPeer entry (Name=`peer-<username>-<tunnel>`, WgPubkey, WgAllowedIps, WgTunnelRef, WgUserRef=caller), consume token, return serialised wg-quick config string
- [X] T027 [US2] Add `QueryServerWriteV1::handle_wg_connect`, `handle_wg_token_create`, `handle_wg_token_list`, `handle_wg_token_delete` to `server/core/src/actors/v1_write.rs`; after peer entry created, call `state.wg_manager.add_peer(tunnel_iface, &peer_config).await` to hot-add to live interface
- [X] T028 [P] [US2] Implement HTTP handlers in `server/core/src/https/v1_wg.rs`: `wg_connect` (POST `/v1/wg/connect`, requires bearer auth + token secret in body), `wg_token_post`, `wg_token_get`, `wg_token_id_delete`; annotate all with `#[utoipa::path(...)]`
- [X] T029 [US2] Register `/v1/wg/connect` and `/v1/wg/tunnel/{name}/token` routes in `server/core/src/https/v1.rs`; add `WgConnectRequest`, `WgConnectResponse`, `WgTokenCreate`, `WgTokenCreatedResponse`, `WgTokenInfo` schemas to `ApiDoc` in `server/core/src/https/apidocs/mod.rs`
- [X] T030 [P] [US2] Add `WgOpt` token subcommands to `tools/cli/src/opt/netidm.rs`: `TokenCreate { tunnel, uses, expiry, principal }`, `TokenList { tunnel }`, `TokenDelete { tunnel, token_name }`
- [X] T031 [US2] Implement CLI dispatch for token subcommands in `tools/cli/src/cli/wg.rs`

**Checkpoint**: US2 complete — users can self-register peers via token; IPs allocated and hot-added to live interface.

---

## Phase 5: User Story 3 — Peer Handshake Monitoring (Priority: P3)

**Goal**: Background poller writes `WgLastSeen` timestamps back to WgPeer entries every 30 seconds.

**Independent Test**: Register a peer, initiate a WireGuard handshake, wait ≤60 seconds, query the WgPeer entry. Verify `WgLastSeen` attribute is present and matches the handshake time from `wg show wg0`.

- [X] T032 [US3] Add `IdmServerProxyWriteTransaction::wg_update_last_seen(peer_uuid: Uuid, ts: DateTime<Utc>)` to `server/lib/src/idm/wg.rs` — modifies `WgLastSeen` attribute on the WgPeer entry
- [X] T033 [US3] Add `QueryServerWriteV1::handle_wg_update_last_seen` to `server/core/src/actors/v1_write.rs`
- [X] T034 [US3] Implement handshake poller as background task in `server/core/src/lib.rs`: tokio task, 60s interval, calls `wg_manager.peer_handshakes()` for each live tunnel, maps pubkeys to WgPeer UUIDs via `wg_list_peer_pubkeys_for_tunnel`, calls `handle_wg_update_last_seen` for each changed timestamp; registered in task handles vec
- [X] T035 [P] [US3] `WgLastSeen` field already in `WgPeerResponse` in `proto/src/wg.rs`; `wg_peer_list` handler reads and populates it; `WgPeerResponse` schema registered in `ApiDoc`

**Checkpoint**: US3 complete — `WgLastSeen` updated in Netidm within 60s of a peer handshake.

---

## Phase 6: User Story 4 — Peer Revocation (Priority: P4)

**Goal**: Deleting a WgPeer entry in Netidm causes the daemon to hot-remove the peer from the live interface within 30 seconds.

**Independent Test**: Register a peer, confirm handshake, DELETE the WgPeer entry via API or CLI, wait ≤30 seconds, run `wg show wg0 peers` and confirm the pubkey is absent.

- [X] T036 [US4] Add `IdmServerProxyReadTransaction::wg_list_peer_pubkeys_for_tunnel(tunnel_uuid) -> Vec<(Uuid, String)>` to `server/lib/src/idm/wg.rs` (returns all current WgPeer pubkeys for a tunnel); add `wg_peer_delete(peer_uuid)` to the write transaction
- [X] T037 [US4] Add `QueryServerWriteV1::handle_wg_peer_delete` to `server/core/src/actors/v1_write.rs`; deletes WgPeer entry in Netidm
- [X] T038 [US4] Implement peer revocation watch in `server/core/src/lib.rs`: 30s background task diffs live WG peers vs Netidm DB, calls `wg_manager.remove_peer()` for orphaned pubkeys
- [X] T039 [P] [US4] Implement `wg_peer_delete` HTTP handler in `server/core/src/https/v1_wg.rs` (DELETE `/v1/wg/tunnel/{id}/peer/{peer_id}`); registered in route_setup
- [X] T040 [P] [US4] Add `WgOpt` peer subcommands to `tools/cli/src/opt/netidm.rs`: `PeerList { tunnel }`, `PeerDelete { tunnel, peer_uuid }`; implement dispatch in `tools/cli/src/cli/wg.rs`

**Checkpoint**: US4 complete — peer revocation is hot-applied within 30 seconds with no tunnel restart.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [X] T041 [P] `cargo clippy -- -D warnings` passes clean across netidmd_lib, netidmd_core, netidmd_wg, netidm_tools, netidm_client — no `#[allow(...)]` bypasses
- [X] T042 [P] Add unit tests for `IpAllocator` in `server/wg/src/alloc.rs`: test slot 2 allocation, dual-stack allocation, exhaustion error, no-duplicate guarantee
- [X] T043 [P] Add unit tests in `server/lib/src/idm/wg.rs`: sha256_of determinism/length, base64url_encode no-padding, total 4 tests pass
- [X] T044 Update `book/src/SUMMARY.md` and create `book/src/integrations/wireguard.md` documenting tunnel create, token issue, peer connect, and peer revoke CLI flows
- [X] T045 Update `CLAUDE.md` via agent context script: `wg` crate added; new deps wireguard-control, boringtun, tun2, rtnetlink, ipnet

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No dependencies — start immediately
- **Phase 2 (Foundational)**: Depends on Phase 1 — **blocks all user stories**
- **Phase 3 (US1)**: Depends on Phase 2 — no other story dependencies
- **Phase 4 (US2)**: Depends on Phase 2 + US1 (needs live interface for `add_peer`)
- **Phase 5 (US3)**: Depends on Phase 2 + US1 (needs live interface for handshake polling)
- **Phase 6 (US4)**: Depends on Phase 2 + US1 + US2 (needs peers to revoke)
- **Phase 7 (Polish)**: Depends on all desired stories complete

### Parallel Opportunities Per Phase

**Phase 2**: T007, T008, T009 can run in parallel (different files)

**Phase 3 (US1)**:
- T012 (KernelBackend) and T013 (BoringtunBackend) and T014 (hooks) run in parallel
- T015 (WgManager) requires T012 + T013 + T014
- T016 (idm/wg.rs reads) and T022 (CLI opt) and T020 (HTTP handlers) run in parallel after T015
- T017 (actors) requires T016

**Phase 4 (US2)**:
- T024 (IpAllocator), T030 (CLI opt), T028 (HTTP handlers) can run in parallel after T025

---

## Implementation Strategy

### MVP (User Story 1 Only)

1. Phase 1: Setup
2. Phase 2: Foundational
3. Phase 3: US1 — tunnel bring-up
4. **Validate**: start netidmd, check `ip link show wg0` and `wg show wg0`
5. Stop here for earliest deployable value

### Full Feature Delivery (Sequential)

US1 → US2 → US3 → US4 → Polish

Each story is independently testable before proceeding to the next.
