# Research: WireGuard Management Crate

**Feature**: 002-wg-mgmt-crate  
**Date**: 2026-04-17

---

## Decision 1: WireGuard Control Library

**Decision**: Use `wireguard-control` crate for both the kernel and userspace backends.

**Rationale**: `wireguard-control` provides a unified `DeviceUpdate` API that applies configuration via either the Linux kernel netlink interface (`Backend::Kernel`) or a UAPI socket (`Backend::Userspace`). This means peer add/remove/configure calls are identical regardless of backend — only link creation/deletion differs.

**Alternatives considered**:
- `defguard_wireguard_rs` — higher-level, handles both modes, but adds a heavier dependency and is less established.
- Raw `neli`/netlink — too low-level; wireguard-control already wraps this correctly.

---

## Decision 2: Userspace Backend — boringtun Device Module

**Decision**: Use `boringtun` crate's `device::Device` (spawned in-process) as the userspace WireGuard implementation, paired with the `tun2` crate for TUN interface creation.

**Rationale**: `wireguard-control`'s `Backend::Userspace` speaks the standard UAPI protocol over a Unix socket at `/var/run/wireguard/<name>.sock`. `boringtun`'s `device::Device` implements this UAPI listener — it creates the socket and accepts configuration commands. This means `wireguard-control` can configure a boringtun device exactly the same way it configures a kernel device, keeping the `WgBackend` trait implementation symmetric.

The `tun2` crate handles TUN device creation on Linux (and macOS if needed later). boringtun's device reads/writes raw IP packets from/to the TUN fd.

**Integration sketch**:
```rust
// Userspace: create TUN + start boringtun device in background thread
let tun = tun2::create(&tun2::Configuration::default().name(iface_name))?;
let config = boringtun::device::DeviceConfig { tun, uapi_fd: None, ..Default::default() };
std::thread::spawn(|| boringtun::device::Device::new(config).run());
// wireguard-control then connects to /var/run/wireguard/<name>.sock
```

**Alternatives considered**:
- `wireguard-go` subprocess (Go binary) — requires shipping a Go binary alongside the Rust daemon; rejected.
- boringtun `noise::Tunn` low-level API — requires building a full packet I/O loop; the `device` module already does this correctly.

---

## Decision 3: Link and Address Management — rtnetlink

**Decision**: Use the `rtnetlink` crate (async, tokio-based) for interface creation/deletion, address assignment, link-up, and route management on Linux.

**Rationale**: Netidm's server/core already initialises an rtnetlink handle on Linux (seen in the existing main startup code). The `rtnetlink` crate provides async APIs for all required netlink operations. This avoids shelling out to `ip link` / `ip addr` / `ip route`.

For the `BoringtunBackend`, TUN device creation is handled by `tun2`; rtnetlink still manages address/route assignment after the device exists.

**Alternatives considered**:
- `ip` subprocess — works but fragile and adds subprocess dependency.
- `neli` raw netlink — too low-level; rtnetlink wraps it correctly.

---

## Decision 4: Backend Detection

**Decision**: At daemon startup, probe `/sys/module/wireguard` existence. If present → `KernelBackend`. Otherwise → `BoringtunBackend`.

**Rationale**: `/sys/module/wireguard` is the canonical indicator that the kernel WireGuard module is loaded. This is a filesystem probe (no syscall, no privilege required, instantaneous). Consistent with the pattern in the original design brief.

**Alternatives considered**:
- Opening a netlink socket and attempting a wg device query — more robust but requires CAP_NET_ADMIN at detection time.
- Config flag in netidm.toml — administrator should not need to configure this.

---

## Decision 5: Registration Token Scheme — New WgToken Entry Class

**Decision**: Add a `WgToken` entry class (in a new DL17 migration) rather than extending the existing `IntentToken` machinery.

**Rationale**: WireGuard registration tokens have a different lifecycle and scope from credential update intent tokens. They are scoped to a tunnel (not a credential session), have a `uses_left` counter (not just a consumed flag), and do not need the InProgress/session-tracking state. A new entry class gives clean ACL control (admins manage them via standard Netidm CRUD), proper audit trail, and no coupling to credential update internals.

**Token schema**: `WgToken` entry has `Name`, `WgTunnelRef`, `WgTokenUsesLeft` (Uint32, optional — absent means unlimited), `WgTokenExpiry` (optional datetime), `WgTokenPrincipalRef` (optional — locks token to a specific user).

**Alternatives considered**:
- Extending `IntentTokenState` with a WG variant — tightly couples WG tokens to credential update machinery; the token consumption path (idm/credupdatesession.rs) is not appropriate for WG.
- Storing tokens as attributes on WgTunnel entries — poor ACL granularity (no per-token expiry/revocation without touching the tunnel entry).

---

## Decision 6: IP Allocation

**Decision**: Slot-based allocation matching wgdb reference behavior. Slot 1 is reserved for the server interface address. Client peers receive sequential slot numbers (2, 3, 4, …) within the tunnel's CIDR(s). Allocation is computed at registration time by scanning existing WgPeer `WgAllowedIps` values.

**Rationale**: Simple, deterministic, consistent with wgdb Go reference. No external IPAM required.

**Constraints**: The tunnel's `WgAddress` must be a proper CIDR (not a host route). IPv4 and IPv6 are both supported; if a tunnel has both, the peer receives one slot in each space.

---

## Decision 7: New Crate Location and Integration

**Decision**: `server/wg/` Rust crate, added to the workspace. Consumed by `server/core` (not exposed as a public library). HTTP handlers in `server/core/src/https/v1_wg.rs`, registered in the existing Axum router and `apidocs/mod.rs`.

**Rationale**: Matches the existing pattern (`server/lib/`, `server/core/`). The WG management code is tightly coupled to netidmd's lifecycle (startup, shutdown, actor system) and should not be a standalone binary.

**New dependencies (workspace-level)**:
- `wireguard-control` — WireGuard device configuration (kernel + UAPI)
- `boringtun` — userspace WireGuard protocol implementation
- `tun2` — TUN device creation
- `rtnetlink` — async netlink for link/address/route management
- `ipnet` — CIDR parsing and arithmetic (IP slot allocation)

---

## Decision 8: Background Poller and Peer Watch

**Decision**: Two background tasks spawned at netidmd startup:
1. **Handshake poller** — every 30 seconds, reads peer handshake timestamps from all live WireGuard interfaces via wireguard-control and writes `last_seen` back to WgPeer entries via the actor write path.
2. **Peer watch** — polls Netidm for deleted/suspended WgPeer entries on the same 30s cycle and hot-removes them from live interfaces.

**Rationale**: Netidm does not yet have a push-based internal event system for entry modifications (it has async tasks but not live watches). A 30s polling cycle matches the wgdb Go reference and satisfies the spec's 30-second revocation SLA.

**Alternatives considered**:
- Change-log based watch — Netidm has an internal changelog but it is not currently exposed for this use case.
- Longer poll interval — would violate the 30-second revocation SLA from the spec.
