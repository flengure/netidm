# Client Tools

To interact with Netidm as an administrator, you'll need to use our command line tools. If you haven't installed them
yet, [install them now](installing_client_tools.md).

## Netidm configuration

You can configure `netidm` to help make commands simpler by modifying `~/.config/netidm` or `/etc/netidm/config`.

```toml
uri = "https://idm.example.com"
ca_path = "/path/to/ca.pem"
```

The full configuration reference is in the
[definition of `NetidmClientConfig`](https://netidm.github.io/netidm/master/rustdoc/netidm_client/struct.NetidmClientConfig.html).

Once configured, you can test this with:

```bash
netidm self whoami --name anonymous
```

## Session Management

To authenticate as a user (for use with the command line), you need to use the `login` command to establish a session
token.

```bash
netidm login --name USERNAME
netidm login --name admin
netidm login -D USERNAME
netidm login -D admin
```

Once complete, you can use `netidm` without re-authenticating for a period of time for administration.

You can list active sessions with:

```bash
netidm session list
```

Sessions will expire after a period of time. To remove these expired sessions locally you can use:

```bash
netidm session cleanup
```

To log out of a session:

```bash
netidm logout --name USERNAME
netidm logout --name admin
```

## Multiple Instances

In some cases you may have multiple Netidm instances. For example you may have a production instance and a development
instance. This can introduce friction for admins when they need to change between those instances.

The Netidm cli tool allows you to configure multiple instances and swap between them with an environment variable, or
the `--instance` flag. Instances maintain separate session stores.

```toml
uri = "https://idm.example.com"
ca_path = "/path/to/ca.pem"

["development"]
uri = "https://idm.dev.example.com"
ca_path = "/path/to/dev-ca.pem"
```

The instance can then be selected with:

```
export NETIDM_INSTANCE=development
netidm login -D username@idm.dev.example.com
```

To return to the default instance you `unset` the `NETIDM_INSTANCE` variable.
