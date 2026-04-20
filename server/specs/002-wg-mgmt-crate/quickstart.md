# Quickstart: WireGuard Management Crate

**Feature**: 002-wg-mgmt-crate  
**Date**: 2026-04-17

---

## Scenario 1: Admin Creates a Tunnel and Issues a Token

```bash
# Create a WireGuard tunnel
netidm system wg tunnel create \
  --name vpn0 \
  --interface wg0 \
  --private-key "$(wg genkey)" \
  --endpoint vpn.example.com:51820 \
  --listen-port 51820 \
  --address 10.100.0.1/24

# Issue a single-use registration token for a specific user
netidm system wg token create vpn0 \
  --uses 1 \
  --principal alice \
  --expiry 2026-05-01 \
  --output token-for-alice.txt
```

---

## Scenario 2: User Registers a Peer

```bash
# Generate a WireGuard keypair (on the client)
wg genkey | tee client.key | wg pubkey > client.pub

# Register with the server token (POST /v1/wg/connect)
curl -s -X POST https://netidm.example.com/v1/wg/connect \
  -H 'Content-Type: application/json' \
  -d "{\"token\": \"$(cat token-for-alice.txt)\", \"pubkey\": \"$(cat client.pub)\"}" \
  | jq -r '.config' \
  | sed "s|<REDACTED>|$(cat client.key)|" \
  > /etc/wireguard/wg0.conf

# Bring up the interface
wg-quick up wg0
```

---

## Scenario 3: Admin Monitors Peers

```bash
# List all peers on a tunnel with last-seen timestamps
netidm system wg peer list vpn0

# Example output:
# NAME                 PUBKEY     ALLOWED_IPS        LAST_SEEN
# peer-alice-vpn0      abc123...  10.100.0.2/32      2026-04-17T12:34:56Z
# peer-bob-vpn0        def456...  10.100.0.3/32      2026-04-17T11:00:00Z
```

---

## Scenario 4: Admin Revokes a Peer

```bash
# Delete the peer entry — daemon hot-removes within 30 seconds
netidm system wg peer delete vpn0 peer-alice-vpn0
```

---

## Scenario 5: Server with No Kernel Module (Container)

The daemon detects the absence of `/sys/module/wireguard` at startup and automatically selects the boringtun userspace backend. No configuration change required.

```
[2026-04-17T00:00:00Z INFO  netidmd::wg] kernel WireGuard module not available — using boringtun userspace backend
[2026-04-17T00:00:00Z INFO  netidmd::wg] bringing up tunnel vpn0 (wg0) via userspace backend
[2026-04-17T00:00:00Z INFO  netidmd::wg] tunnel vpn0 up — listening on :51820
```
