# Server Configuration

In this section we will configure your server and create its container instance.

## Configuring server.toml

There are two methods for configuration:

1. Providing a configuration file in the volume named `server.toml`. (Within the container it should be
   `/data/server.toml`)
2. Using environment variables to specify configuration options (uppercased, prefixed with `NETIDM_`).

You can use one or both methods, but environment variables take precedence over options specified in files.The full
options and explanations are in the
[netidmd_core::config::ServerConfig](https://netidm.github.io/netidm/master/rustdoc/netidmd_core/config/struct.ServerConfig.html)
docs page for your particular build.

> [!WARNING]
>
> You MUST set the `domain`, `origin`, `tls_chain` and `tls_key` options via one method or the other, or the server
> cannot start!

The following is a commented example configuration.

```toml
{{#rustdoc_include ../../examples/server_container.toml}}
```

This example is located in
[examples/server_container.toml](https://github.com/netidm/netidm/blob/master/examples/server_container.toml).

> [!WARNING]
>
> You MUST set the "domain" name correctly, aligned with your "origin", else the server may refuse to start or some
> features (e.g. WebAuthn, OAuth2) may not work correctly!

### Check the configuration is valid

You should test your configuration is valid before you proceed. This defaults to using `-c /data/server.toml`. The
`netidmd` volume was created in the [evaluation quickstart](evaluation_quickstart.md)

```bash
docker run --rm -i -t -v netidmd:/data \
    netidm/server:latest /sbin/netidmd configtest
```

## Run the Server

Now we can run the server so that it can accept connections. The container defaults to using a configuration file in
`/data/server.toml`.

```bash
docker run -p 443:8443 -v netidmd:/data netidm/server:latest
```

### Using the `NET_BIND_SERVICE` capability

If you plan to run without using docker port mapping or some other reverse proxy, and your `bindaddress` or
`ldapbindaddress` port is less than `1024` you will need the `NET_BIND_SERVICE` in docker to allow these port binds. You
can add this with `--cap-add` in your docker run command.

```bash
docker run --cap-add NET_BIND_SERVICE \
  --network [host OR macvlan OR ipvlan] \
  -v netidmd:/data \
  netidm/server:latest
```

> [!TIP]
>
> However you choose to run your server, you should document and keep note of the docker run / create command you chose
> to start the instance. This will be used in the upgrade procedure.

### Default Admin Accounts

Now that the server is running, you can initialise the default admin accounts. There are two parallel admin accounts
that have separate functions. `admin` which manages Netidm's configuration, and `idm_admin` which manages accounts and
groups in Netidm.

You should consider these as "break-glass" accounts. They exist to allow the server to be bootstrapped and accessed in
emergencies. They are not intended for day-to-day use.

These commands will generate a new random password for the admin accounts. You must run the commands as the same user as
the netidmd process or as root. This defaults to using `-c /data/server.toml`.

```bash
docker exec -i -t <container name> \
  netidmd recover-account admin
#  new_password: "xjgG4..."
```

```bash
docker exec -i -t <container name> \
  netidmd recover-account idm_admin
#  new_password: "9Eux1..."
```
