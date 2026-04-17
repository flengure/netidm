# WireGuard

Netidm can manage WireGuard VPN tunnels and peer registrations, storing tunnel configuration and peer
credentials in the Netidm database. This allows you to:

- Define WireGuard tunnels as Netidm entries with full access-control support.
- Issue one-time (or limited-use) registration tokens to users.
- Let users self-register their devices by presenting a token and their WireGuard public key.
- Track when each peer last completed a handshake.
- Revoke peers by deleting their entry from Netidm.

Netidm automatically detects at startup whether the kernel WireGuard module is available and uses it
if so, otherwise it falls back to embedded userspace (`boringtun`).

## Prerequisites

- A Linux host running `netidmd`.
- The kernel WireGuard module loaded (`modprobe wireguard`), **or** no extra steps needed for
  userspace fallback.
- The `netidm` CLI configured to point at your server.

## Creating a Tunnel

Use the CLI to create a WireGuard tunnel entry. You need a WireGuard private key; generate one with
`wg genkey`.

```bash
PRIVATE_KEY=$(wg genkey)

netidm wg tunnel-create \
    my-vpn \
    wg0 \
    "$PRIVATE_KEY" \
    vpn.example.com:51820 \
    51820 \
    --address 10.100.0.0/24 \
    --address fd00::/64 \
    --dns 10.100.0.1
```

Arguments in order: `name`, `interface`, `private-key`, `endpoint`, `listen-port`, then optional
`--address` (repeatable), `--dns` (repeatable), `--mtu`.

Netidm derives the public key from the private key and stores it. The `netidmd` daemon reads all
tunnel entries at startup and brings up the interface automatically.

Verify the interface came up:

```bash
ip link show wg0
wg show wg0
```

## Listing and Inspecting Tunnels

```bash
# List all tunnels
netidm wg tunnel-list

# Get details of a specific tunnel (includes public key and address ranges)
netidm wg tunnel-get my-vpn
```

## Deleting a Tunnel

```bash
netidm wg tunnel-delete my-vpn
```

This removes the entry from Netidm. The daemon tears down the live interface on the next reload.

## Peer Registration via Tokens

Rather than manually creating peer entries, Netidm uses a **token-gated self-registration** flow:

1. An administrator creates a registration token for a tunnel.
2. The token (a short secret) is sent to the user out-of-band.
3. The user generates a WireGuard key pair and calls `netidm wg connect`.
4. Netidm validates the token, allocates IP addresses from the tunnel's address range, creates a
   peer entry, and returns a ready-to-use `wg-quick` configuration.

### Creating a Registration Token

```bash
# Single-use token (default), no expiry
netidm wg token-create my-vpn

# Token valid for 5 uses, expires at a specific time
netidm wg token-create my-vpn --uses 5 --expiry 2026-12-31T00:00:00Z
```

Output:

```
Token: wgtoken-my-vpn-<uuid>
Secret: <base64url-encoded-secret>
```

Send the **Secret** to the user. The token name is for your reference.

### Listing Tokens

```bash
netidm wg token-list my-vpn
```

### Revoking a Token

```bash
netidm wg token-delete my-vpn wgtoken-my-vpn-<uuid>
```

## Connecting a Device (User-Side)

The user generates a key pair and registers with the tunnel:

```bash
# Generate a key pair
wg genkey | tee privatekey | wg pubkey > publickey

# Register with the tunnel using the token secret
netidm wg connect <token-secret> $(cat publickey)
```

Output is a ready-to-use `wg-quick` config:

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.100.0.2/32, fd00::2/128
DNS = 10.100.0.1

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
```

Replace `<client-private-key>` with `$(cat privatekey)` and save as `/etc/wireguard/wg0.conf`, then
bring the tunnel up:

```bash
wg-quick up wg0
```

## Listing and Removing Peers

```bash
# List peers on a tunnel (shows public key, allocated IPs, last handshake)
netidm wg peer-list my-vpn

# Remove a peer by UUID (shown in peer-list output)
netidm wg peer-delete my-vpn <peer-uuid>
```

Deleting a peer entry in Netidm causes the daemon to hot-remove the peer from the live interface
within 30 seconds — no tunnel restart required.

## Address Allocation

Netidm allocates peer addresses automatically from the tunnel's CIDR ranges:

- The **first host address** in each CIDR (`.1` / `::1`) is reserved for the server.
- Peers receive the **lowest available host address** starting from `.2` / `::2`.
- For dual-stack tunnels (IPv4 + IPv6 address ranges), one address per address family is allocated.

## Last-Seen Monitoring

Netidm polls WireGuard handshake timestamps every 60 seconds and writes them back to each peer's
`WgLastSeen` attribute. This is visible in `netidm wg peer-list` as the `last_seen` field.

## Security Notes

- **Token secrets** are stored as SHA-256 hashes in Netidm; the plaintext is only shown once at
  creation time.
- Tokens can be **limited by use count** (`--uses`) or **expiry time** (`--expiry`), or both.
- **Peer public keys** are unique per tunnel — attempting to register the same public key twice is
  rejected.
- The WireGuard private key stored in Netidm is used only at daemon startup to configure the
  interface. It is not exposed via the API.
