# API Contract: WireGuard Management

**Feature**: 002-wg-mgmt-crate  
**Date**: 2026-04-17  
**Base path**: `/v1/wg`  
**Auth**: Kanidm bearer token (JWT) on all endpoints including `/v1/wg/connect` — the WG token secret is a second factor, not a replacement for authentication. The authenticated session determines `WgPeer.WgUserRef`.

All endpoints follow Kanidm conventions: JSON request/response bodies, `WebError` on failure, annotated with `#[utoipa::path(...)]`, registered in `apidocs/mod.rs`.

---

## Admin Endpoints

### Tunnel Management

#### `GET /v1/wg/tunnel`
List all WgTunnel entries the caller has read access to.

**Response**: `200 Ok` → `Vec<WgTunnelResponse>`

---

#### `POST /v1/wg/tunnel`
Create a new WgTunnel entry.

**Request body**: `WgTunnelCreate`
```json
{
  "name": "vpn0",
  "interface": "wg0",
  "private_key": "<base64>",
  "endpoint": "vpn.example.com:51820",
  "listen_port": 51820,
  "address": ["10.100.0.1/24"],
  "dns": ["1.1.1.1"],
  "mtu": 1420
}
```

**Response**: `201 Created` → `WgTunnelResponse`

---

#### `GET /v1/wg/tunnel/{name}`
Get a single WgTunnel by name.

**Response**: `200 Ok` → `WgTunnelResponse` | `404 Not Found`

---

#### `PATCH /v1/wg/tunnel/{name}`
Update mutable tunnel fields (DNS, MTU, hooks, listen port). Private key and interface name are immutable after creation.

**Request body**: `WgTunnelPatch` (all fields optional)

**Response**: `200 Ok` → `WgTunnelResponse`

---

#### `DELETE /v1/wg/tunnel/{name}`
Delete a WgTunnel entry. The daemon tears down the live interface within one poll cycle.

**Response**: `204 No Content`

---

### Token Management

#### `POST /v1/wg/tunnel/{name}/token`
Create a registration token for the named tunnel.

**Request body**: `WgTokenCreate`
```json
{
  "uses": 1,
  "expiry": "2026-05-01T00:00:00Z",
  "principal": "alice"
}
```
All fields optional. Absent `uses` = unlimited. Absent `expiry` = no expiry. Absent `principal` = any authenticated user.

**Response**: `201 Created` → `WgTokenCreatedResponse`
```json
{
  "token_name": "tok-abc123",
  "secret": "<opaque-string>",
  "expires": "2026-05-01T00:00:00Z"
}
```
**Note**: `secret` is returned only at creation time and not stored in readable form.

---

#### `GET /v1/wg/tunnel/{name}/token`
List tokens for the named tunnel (name, expiry, uses_left — no secrets).

**Response**: `200 Ok` → `Vec<WgTokenInfo>`

---

#### `DELETE /v1/wg/tunnel/{name}/token/{token_name}`
Revoke a registration token.

**Response**: `204 No Content`

---

### Peer Management

#### `GET /v1/wg/tunnel/{name}/peer`
List all WgPeer entries for a tunnel.

**Response**: `200 Ok` → `Vec<WgPeerResponse>`
```json
[
  {
    "name": "peer-alice-vpn0",
    "pubkey": "<base64>",
    "allowed_ips": ["10.100.0.2/32"],
    "user": "alice",
    "last_seen": "2026-04-17T12:34:56Z",
    "keepalive": 25
  }
]
```

---

#### `DELETE /v1/wg/tunnel/{name}/peer/{peer_name}`
Revoke a peer. Hot-removes from live interface within 30 seconds.

**Response**: `204 No Content`

---

## Client Endpoints

These endpoints are used by end-user WireGuard clients. They authenticate with a token secret rather than a Kanidm bearer token.

### `POST /v1/wg/connect`
Register a new peer and receive a WireGuard client config.

**Request body**: `WgConnectRequest`
```json
{
  "token": "<opaque-secret>",
  "pubkey": "<base64-client-public-key>"
}
```

**Response**: `200 Ok` → `WgConnectResponse`
```json
{
  "config": "[Interface]\nAddress = 10.100.0.2/32\nPrivateKey = <REDACTED - filled in by client>\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = <server-pubkey>\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
  "address": ["10.100.0.2/32"],
  "server_pubkey": "<base64>",
  "endpoint": "vpn.example.com:51820"
}
```

**Error cases**:
- `401 Unauthorized` — token not found, expired, or already consumed
- `403 Forbidden` — token is locked to a different principal
- `409 Conflict` — public key already registered on this tunnel
- `507 Insufficient Storage` — tunnel address space exhausted

---

## Shared Response Types

### `WgTunnelResponse`
```json
{
  "name": "vpn0",
  "interface": "wg0",
  "public_key": "<base64>",
  "endpoint": "vpn.example.com:51820",
  "listen_port": 51820,
  "address": ["10.100.0.1/24"],
  "dns": ["1.1.1.1"],
  "mtu": 1420,
  "peer_count": 12,
  "backend": "kernel"
}
```

### `WgPeerResponse`
```json
{
  "name": "peer-alice-vpn0",
  "pubkey": "<base64>",
  "allowed_ips": ["10.100.0.2/32"],
  "user": "alice",
  "last_seen": "2026-04-17T12:34:56Z",
  "keepalive": null
}
```

### `WgTokenInfo`
```json
{
  "name": "tok-abc123",
  "uses_left": 1,
  "expiry": "2026-05-01T00:00:00Z",
  "principal": "alice"
}
```
