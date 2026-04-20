# Data Model: WireGuard Management Crate

**Feature**: 002-wg-mgmt-crate  
**Date**: 2026-04-17

---

## Existing Entities (DL16 — already in codebase)

### WgTunnel (EntryClass::WgTunnel)

Represents a server-side WireGuard interface. One entry per tunnel.

| Attribute | Syntax | Required | Multi | Notes |
|-----------|--------|----------|-------|-------|
| Name | Utf8StringIname | yes | no | Netidm entry name (also used as logical tunnel name) |
| WgInterface | Utf8StringIname | yes | no | OS interface name (e.g. `wg0`) |
| WgPrivateKey | Utf8String | yes | no | Base64 private key; public key derived by daemon |
| WgPublicKey | Utf8String | no | no | Derived and written back by daemon on startup |
| WgEndpoint | Utf8String | yes | no | `host:port` sent to clients as `[Peer] Endpoint` |
| WgListenPort | Uint32 | yes | no | UDP listen port |
| WgAddress | Utf8String | yes | yes | Server CIDR(s); slot 1 = server IP |
| WgDns | Utf8String | no | yes | DNS pushed to clients |
| WgMtu | Uint32 | no | no | MTU override |
| WgTable | Utf8String | no | no | Routing table: `auto`, `off`, or table id |
| WgPreUp | Utf8String | no | yes | Commands run before link creation |
| WgPostUp | Utf8String | no | yes | Commands run after link is up and addressed |
| WgPreDown | Utf8String | no | yes | Commands run before link deletion |
| WgPostDown | Utf8String | no | yes | Commands run after link is deleted |
| WgSaveConfig | Boolean | no | no | Whether to persist runtime state |

**State transitions**:
- Created → daemon reads it and calls `bring_up()` → interface exists on host
- Deleted/disabled → daemon detects and calls `tear_down()` → interface removed

---

### WgPeer (EntryClass::WgPeer)

Represents a single client peer. Created by the daemon during registration.

| Attribute | Syntax | Required | Multi | Notes |
|-----------|--------|----------|-------|-------|
| Name | Utf8StringIname | yes | no | Netidm entry name (e.g. `peer-<username>-<tunnel>`) |
| WgPubkey | Utf8String | yes | no | Client WireGuard public key (unique) |
| WgAllowedIps | Utf8String | yes | yes | Server-assigned CIDR(s) for this peer |
| WgTunnelRef | ReferenceUuid | yes | no | → WgTunnel entry |
| WgUserRef | ReferenceUuid | yes | no | → Person/Account entry |
| WgPresharedKey | Utf8String | no | no | Per-peer PSK (optional) |
| WgPersistentKeepalive | Uint32 | no | no | Keepalive interval in seconds |
| WgLastSeen | Utf8String | no | no | ISO-8601 timestamp; written by poller *(new attr — DL17)* |

**State transitions**:
- Created by daemon during registration → hot-added to live interface
- Deleted in Netidm → daemon detects within 30s → hot-removed from interface

---

## New Entities (DL17 — to be added)

### WgToken (EntryClass::WgToken)

A single-use or limited-use registration token scoped to a tunnel.

| Attribute | Syntax | Required | Multi | Notes |
|-----------|--------|----------|-------|-------|
| Name | Utf8StringIname | yes | no | Human-readable token name |
| WgTunnelRef | ReferenceUuid | yes | no | → WgTunnel this token authorises access to |
| WgTokenSecret | Utf8String | yes | no | Opaque secret string presented by client |
| WgTokenUsesLeft | Uint32 | no | no | Absent = unlimited. Decremented on each use; deleted at 0 |
| WgTokenExpiry | Utf8String | no | no | ISO-8601 expiry datetime; rejected if past |
| WgTokenPrincipalRef | ReferenceUuid | no | no | If set, only this account may redeem the token. Absent = any authenticated user may redeem it. The peer's WgUserRef is always set from the authenticated session, not from this field. |

**State transitions**:
- Created by admin → available for use
- Consumed (`WgTokenUsesLeft` decremented to 0, or single-use) → entry deleted
- Expired (current time ≥ WgTokenExpiry) → rejected at consumption, entry may be garbage-collected

### WgLastSeen attribute (new schema attr — DL17)

Single new attribute added to the WgPeer class's `systemmay` list:

| Attribute | Syntax | Notes |
|-----------|--------|-------|
| WgLastSeen | Utf8String | Last WireGuard handshake timestamp (RFC3339). Written by daemon poller. |

---

## Relationships

```
WgToken ──WgTunnelRef──► WgTunnel ◄──WgTunnelRef── WgPeer
                                                     │
WgToken ──WgTokenPrincipalRef──► Person/Account ◄──WgUserRef
```

- One `WgTunnel` has many `WgPeer` (one-to-many via WgTunnelRef)
- One `WgTunnel` has many `WgToken` (one-to-many via WgTunnelRef)
- Each `WgPeer` belongs to exactly one `Person/Account` (WgUserRef)
- A `WgToken` may optionally be locked to one `Person/Account` (WgTokenPrincipalRef)

---

## Runtime State (not persisted in Netidm)

| Struct | Location | Purpose |
|--------|----------|---------|
| `WgManager` | server/wg/src/manager.rs | Owns live interfaces; holds backend handle |
| `WgBackend` (trait) | server/wg/src/backend/mod.rs | Abstracts kernel vs userspace |
| `KernelBackend` | server/wg/src/backend/kernel.rs | wireguard-control Backend::Kernel + rtnetlink |
| `BoringtunBackend` | server/wg/src/backend/boringtun.rs | boringtun device + tun2 + wireguard-control Backend::Userspace |
| `IpAllocator` | server/wg/src/alloc.rs | Slot-based CIDR allocation per tunnel |
