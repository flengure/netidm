# Feature Specification: WireGuard Management Crate

**Feature Branch**: `002-wg-mgmt-crate`
**Created**: 2026-04-17
**Status**: Draft

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Server Administrator Brings Up a WireGuard Tunnel (Priority: P1)

An administrator has defined a WireGuard tunnel in Netidm (via DL16 schema entries) and wants the system to activate it automatically on daemon startup — creating the network interface, applying the WireGuard configuration, assigning addresses, and making it ready for peers to connect, regardless of whether the host has a kernel WireGuard module or must use a software fallback.

**Why this priority**: This is the foundational capability. Without a tunnel that comes up reliably, no other story is possible. It must work on both kernel-capable hosts and restricted environments (containers, VMs without the kernel module).

**Independent Test**: Create a WgTunnel entry in Netidm and start the daemon. Verify the interface appears on the host, has the correct address, and the WireGuard configuration is active.

**Acceptance Scenarios**:

1. **Given** a WgTunnel entry exists in Netidm with a private key, listen port, address, and endpoint, **When** netidmd starts, **Then** the corresponding network interface is created, configured, and brought up within 5 seconds.
2. **Given** the host has the WireGuard kernel module available, **When** the daemon starts, **Then** the kernel backend is selected without any administrator configuration.
3. **Given** the host does not have the WireGuard kernel module (e.g. a container), **When** the daemon starts, **Then** the userspace backend is selected and the interface is managed via an in-process software implementation.
4. **Given** a tunnel's pre_up or post_up hooks are defined, **When** the tunnel is brought up, **Then** those commands are executed in order at the appropriate stage.
5. **Given** a required hook command fails, **When** the tunnel is brought up, **Then** the bring-up is aborted, the error is surfaced, and no partial interface configuration is left.
6. **Given** a WgTunnel entry is disabled or deleted, **When** the daemon detects this, **Then** the interface is torn down, post_down hooks run, and the interface is removed.

---

### User Story 2 — User Registers a Peer via Token (Priority: P2)

A user who has been issued a registration token wants to join a WireGuard tunnel by presenting their token and WireGuard public key. They receive back a complete, ready-to-use WireGuard client configuration — with their allocated IP addresses and all necessary server details — without any manual admin intervention.

**Why this priority**: This is the client-facing value of the system. Admins create tunnels; users self-enroll. The token flow decouples key exchange from manual config delivery.

**Independent Test**: Issue a registration token scoped to a tunnel. Present the token and a generated public key to the registration endpoint. Verify a WgPeer entry is created in Netidm, an IP is allocated, the peer is hot-added to the live interface, and the returned config contains correct server details and the peer's assigned address.

**Acceptance Scenarios**:

1. **Given** a valid single-use token scoped to a tunnel, **When** a client submits the token and their public key, **Then** a WgPeer entry is created, an IP is allocated, the peer is hot-added to the live interface, and a valid WireGuard client config is returned within 3 seconds.
2. **Given** a token has already been consumed, **When** a second client attempts to use it, **Then** the request is rejected and no peer is created.
3. **Given** a token has an expiry time in the past, **When** a client submits it, **Then** registration is rejected.
4. **Given** a peer is hot-added to a live interface, **When** existing peers attempt handshakes, **Then** their sessions are unaffected.
5. **Given** the tunnel's address space is exhausted, **When** a new registration is attempted, **Then** the request is rejected with a clear error.

---

### User Story 3 — Administrator Monitors Peer Connectivity (Priority: P3)

An administrator wants to know which peers are actively connected to a tunnel and when each peer last completed a WireGuard handshake, so they can identify stale or inactive clients.

**Why this priority**: Operational visibility. Tunnels and registration must work first; this story adds the monitoring layer on top.

**Independent Test**: Bring up a tunnel with at least one registered peer. Wait for the background polling cycle. Verify that the WgPeer entry in Netidm has a `last_seen` timestamp updated within 60 seconds of a completed handshake.

**Acceptance Scenarios**:

1. **Given** a registered peer has completed a WireGuard handshake, **When** the background poller runs (at most every 30 seconds), **Then** the corresponding WgPeer entry in Netidm is updated with the correct last-handshake timestamp.
2. **Given** a peer has not completed any handshake since registration, **When** the poller runs, **Then** the peer's `last_seen` field remains absent — it is not fabricated.

---

### User Story 4 — Administrator Revokes a Peer (Priority: P4)

An administrator wants to immediately remove a peer from an active WireGuard tunnel by deleting the corresponding entry in Netidm, without restarting the tunnel or interrupting other peers.

**Why this priority**: Security hygiene. Peer removal must be hot-applied so that access revocation takes effect immediately.

**Independent Test**: Register a peer, confirm the handshake succeeds, then delete the WgPeer entry in Netidm. Verify the peer is removed from the live WireGuard interface within the next watch/poll cycle.

**Acceptance Scenarios**:

1. **Given** a WgPeer entry is deleted in Netidm, **When** the daemon detects the deletion, **Then** the peer is removed from the live interface within 30 seconds.
2. **Given** a peer is removed from a live interface, **When** other peers attempt handshakes, **Then** their sessions are unaffected.

---

### Edge Cases

- What happens when the daemon starts and the interface already exists (e.g. after a crash)? The daemon must reconcile and reuse the existing interface rather than failing.
- What happens if address allocation produces a CIDR that is already in use? The daemon must detect and report the conflict without allocating a duplicate.
- What happens if both backends fail to initialise? The daemon must log the error and refuse to start rather than operating with no WireGuard support.
- What happens when multiple tunnels are defined? Each must be managed independently — failure of one must not prevent others from coming up.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST detect at startup whether the host supports native kernel WireGuard and select the appropriate backend automatically, without requiring administrator configuration.
- **FR-002**: The system MUST bring up all enabled WgTunnel entries found in Netidm on daemon startup, creating network interfaces and applying configurations derived from those entries.
- **FR-003**: The system MUST execute pre_up hooks before interface creation and post_up hooks after the interface is fully configured and addressed.
- **FR-004**: The system MUST execute pre_down hooks before interface removal and post_down hooks after the interface is removed.
- **FR-005**: The system MUST tear down WireGuard interfaces when the corresponding WgTunnel entry is disabled or deleted.
- **FR-006**: The system MUST support a token-gated peer registration flow: a user presents a valid token and their public key and receives back a complete WireGuard client configuration.
- **FR-007**: The system MUST allocate IP addresses from the tunnel's configured address space on peer registration, ensuring no two peers share the same address within the same tunnel.
- **FR-008**: The system MUST hot-add a newly registered peer to the live WireGuard interface without disrupting existing peer sessions.
- **FR-009**: The system MUST enforce single-use semantics on registration tokens: once consumed, a token cannot be reused.
- **FR-010**: The system MUST enforce token expiry: expired tokens must be rejected at registration time.
- **FR-011**: The system MUST poll all active WireGuard interfaces at most every 30 seconds and write the latest handshake timestamp for each peer back to its WgPeer entry in Netidm.
- **FR-012**: The system MUST hot-remove a peer from the live WireGuard interface within 30 seconds of its WgPeer entry being deleted or suspended in Netidm.
- **FR-013**: The system MUST reconcile interface state on startup if the interface already exists rather than treating it as a fatal error.
- **FR-014**: The system MUST abort tunnel bring-up and surface a clear error if a required hook command fails, leaving no partial interface configuration in place.

### Key Entities

- **WgTunnel**: A server-side WireGuard interface configuration. Attributes: name, interface name, private key, public key (derived by daemon), endpoint, listen port, address(es), DNS, MTU, routing table, pre/post hooks, save_config flag.
- **WgPeer**: A single client peer on a tunnel. Attributes: name, public key, allowed IPs (server-assigned), tunnel reference, user reference, preshared key (optional), persistent keepalive (optional), last_seen timestamp (written by daemon poller).
- **RegistrationToken**: A single-use or limited-use credential scoped to a tunnel and optionally to a user, with an optional expiry time. Consumed on successful peer registration.
- **Backend**: The runtime-selected WireGuard implementation (kernel or userspace). Not persisted — determined at daemon startup by probing the host environment.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All enabled tunnels are brought up within 5 seconds of daemon startup.
- **SC-002**: Peer registration — from token submission to live interface update and config response — completes in under 3 seconds under normal load.
- **SC-003**: Peer handshake timestamps in Netidm are never more than 60 seconds stale relative to the last completed handshake.
- **SC-004**: A peer revoked in Netidm is removed from the live interface within 30 seconds, with zero disruption to other active peers.
- **SC-005**: The system starts and operates correctly on hosts without a kernel WireGuard module, with no administrator intervention required to switch modes.
- **SC-006**: 100% of consumed or expired tokens are rejected at registration time — no peer entry is created for an invalid token.
- **SC-007**: IP address allocation produces no duplicates across peers of the same tunnel, including under concurrent registration requests.

## Assumptions

- The DL16 schema migration (WgTunnel and WgPeer entry classes) is already present in the Netidm database before this feature is activated.
- The daemon process has sufficient OS privileges to create and configure network interfaces (CAP_NET_ADMIN or root equivalent).
- Hook commands (pre_up, post_up, etc.) are trusted administrator-provided strings; sanitisation is enforced at schema write time.
- Peer IP allocation reserves the first address slot for the server interface; client peers receive sequential slots from slot 2 onward, matching the wgdb reference behavior.
- The userspace backend is Linux-only for this iteration; macOS and Windows are out of scope.
- Registration token issuance is a separate admin operation (existing Netidm CLI/API); this feature only consumes tokens.
- The public key on a WgTunnel entry is always derived from the private key by the daemon; administrators never set it directly.
