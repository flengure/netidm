# Entry Management

Netidm reads TOML preload files on startup and on SIGHUP reload. These files let you seed and
maintain users, groups, WireGuard tunnels, OAuth2 clients, and social login connectors without
touching the database directly.

## Preload Path

The default path is `/etc/netidm/preload.d` (or `/data/preload.d` for containers). Override it
in `server.toml`:

```toml
preload_path = "/etc/netidm/preload.d"
```

## File Naming

Files must match `xx-name.toml` where `xx` are two digits. They are applied in lexicographic
order, so numbering controls dependencies:

```
00-tunnel.toml
10-users.toml
20-groups.toml
30-oauth2-portainer.toml
40-github.toml
```

## Resource Types

Each file may contain any mix of `[[tunnel]]`, `[[user]]`, `[[group]]`, `[[oauth2_client]]`,
and `[[connector]]` tables.

### Tunnel

```toml
[[tunnel]]
name        = "access"
interface   = "access"
private_key = "..."
endpoint    = "wg.example.com:51820"
listen_port = 51820
address     = ["10.64.68.0/24", "fd64:0:0:68::/64"]
```

### User

```toml
[[user]]
name        = "alice"
displayname = "Alice Smith"
email       = "alice@example.com"
shell       = "/bin/bash"          # omit if not a POSIX account
ssh_keys = [
  {label = "laptop", value = "ssh-ed25519 AAAA..."},
]
wg_peers = [
  {tunnel = "access", name = "alice-laptop", pubkey = "...", address = ["10.64.68.2/32"], psk = "..."},
]
```

### Group

```toml
[[group]]
name    = "platform-admins"
members = ["alice", "bob"]

[[group]]
name    = "linux-sudo"
posix   = true
members = ["alice", "bob"]
```

### OAuth2 Client

```toml
[[oauth2_client]]
name        = "portainer"
displayname = "Portainer"
origin      = "https://portainer.example.com"
disable_pkce = true   # only for clients that do not support PKCE
```

The default scope map grants `idm_all_accounts` the scopes `openid profile email groups
offline_access`. Add `scope_maps` to override.

### Social Login Connector

```toml
[[connector]]
name                = "github"
displayname         = "GitHub"
provider            = "github"
client_id           = "..."
client_secret       = "..."
jit_provisioning    = true
email_link_accounts = true
org_filter          = ["MyOrg"]
allowed_teams       = ["MyOrg:platform-users", "MyOrg:platform-admins"]
group_mappings      = [
  {upstream = "MyOrg:platform-admins", group = "platform-admins"},
]
```

## Idempotency

Each file's content is SHA-256 hashed. If the hash has not changed since the last apply, the
file is skipped entirely. Modify any field in the file to force a re-apply.

Removing a file from `preload.d/` stops future assertion but does **not** delete the resource
from the database.

## Timing

Preload runs on startup and whenever the server receives SIGHUP (`systemctl reload netidmd`).
