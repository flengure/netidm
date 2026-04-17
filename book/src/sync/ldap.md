# LDAP

If you have an LDAP server that supports sync repl (RFC4533 content synchronisation) then you are able to synchronise
from it to Netidm for the purposes of coexistence or migration.

If there is a specific Netidm sync tool for your LDAP server, you should use that instead of the generic LDAP server
sync.

## Installing the LDAP Sync Tool

See [installing the client tools](../installing_client_tools.md).

## Configure the LDAP Sync Tool

The sync tool is a bridge between LDAP and Netidm, meaning that the tool must be configured to communicate to both
sides.

Like other components of Netidm, the LDAP sync tool will read your /etc/netidm/config if present to understand how to
connect to Netidm.

The sync tool specific components are configured in its own configuration file.

```toml
{{#rustdoc_include ../../../examples/netidm-ldap-sync}}
```

This example is located in
[examples/netidm-ldap-sync](https://github.com/flengure/netidm/blob/master/examples/netidm-ldap-sync).

In addition to this, you may be required to make some configuration changes to your LDAP server to enable
synchronisation.

### OpenLDAP

You must enable the syncprov overlay in slapd.conf

```text
moduleload syncprov.la
overlay syncprov
```

In addition you must grant an account full read access and raise its search limits.

```text
access to *
    by dn.base="cn=sync,dc=example,dc=com" read
    by * break

limits dn.exact="cn=sync,dc=example,dc=com" time.soft=unlimited time.hard=unlimited size.soft=unlimited size.hard=unlimited
```

For more details see the
[openldap administration guide](https://openldap.org/doc/admin24/replication.html#Configuring%20the%20different%20replication%20types).

### 389 Directory Server

You can find the name of your 389 Directory Server instance with:

```bash
dsctl --list
```

Using this you can show the current status of the retro changelog plugin to see if you need to change its configuration.

```bash
dsconf <instance name> plugin retro-changelog show
dsconf slapd-DEV-NETIDM-COM plugin retro-changelog show
```

To enable the both the content sync and retro-changelog plugins:

```bash
dsconf <instance name> plugin retro-changelog enable
dsconf <instance name> plugin contentsync enable
```

You must configure the `targetUniqueId` to be the `nsUniqueId` attribute. It is also recommend to limit the size of the
changelog to only retain events for a number of days.

```bash
dsconf <instance name> plugin retro-changelog add --attribute nsuniqueid:targetUniqueId
dsconf <instance name> plugin retro-changelog set --max-age 14d
```

You must modify the retro changelog plugin to include the full scope of the database suffix so that the sync tool can
view the changes to the database. Currently dsconf can not modify the include-suffix so you must do this manually.

You need to change the `nsslapd-include-suffix` to match your LDAP baseDN here. You can access the basedn with:

```bash
ldapsearch -H ldaps://<SERVER HOSTNAME/IP> -x -b '' -s base namingContexts
# namingContexts: dc=ldap,dc=dev,dc=netidm,dc=com
```

You should ignore `cn=changelog` as this is a system internal namingContext. You can then create an ldapmodify like the
following.

```rust
{{#rustdoc_include ../../../tools/iam_migrations/freeipa/00config-mod.ldif}}
```

And apply it with:

```bash
ldapmodify -f change.ldif -H ldaps://<SERVER HOSTNAME/IP> -x -D 'cn=Directory Manager' -W
# Enter LDAP Password:
```

Create a service account that will be used for content synchronisation.

```bash
dsidm -b dc=ldap,dc=dev,dc=netidm,dc=com localhost service create --cn netidm-sync --description sync
```

Generate a password for the account and reset it with.

```bash
dsidm -b dc=ldap,dc=dev,dc=netidm,dc=com localhost account reset_password cn=netidm-sync,ou=Services,dc=ldap,dc=dev,dc=netidm,dc=com
```

Allow the account to access the content sync control:

```text
dn: oid=1.3.6.1.4.1.4203.1.9.1.1,cn=features,cn=config
changetype: modify
add: aci
aci: (targetattr != "aci")(version 3.0; acl "Sync Request Control"; allow( read, search ) userdn = "ldap:///cn=netidm-sync,ou=Services,dc=ldap,dc=dev,dc=netidm,dc=com";)
```

Additionally, you must update ACI's in your directory to allow this user to read the relevant attributes of directory
entries you want to sync. For example.

```text
dn: ou=people,dc=example,dc=com
changetype: modify
add: aci
aci: (targetattr = "objectClass || description || nsUniqueId || uid || displayName || loginShell || uidNumber || gidNumber || gecos || homeDirectory || cn || memberOf || mail || nsSshPublicKey || nsAccountLock || userCertificate || userPassword" )(version 3.0; acl "Sync Request Read"; allow( read, search ) userdn = "ldap:///cn=netidm-sync,ou=Services,dc=ldap,dc=dev,dc=netidm,dc=com";)

dn: ou=groups,dc=example,dc=com
changetype: modify
add: aci
aci: (targetattr = "cn || member || memberUid || gidNumber || nsUniqueId || description || objectClass")(version 3.0; acl "Sync Request Read"; allow( read, search ) userdn = "ldap:///cn=netidm-sync,ou=Services,dc=ldap,dc=dev,dc=netidm,dc=com";)
```

You must then restart your 389 Directory Server for these changes to take effect.

The control can be tested with:

```bash
ldapsearch -H ldaps://<SERVER HOSTNAME/IP> -x -E \!sync=ro -D cn=netidm-sync,ou=Services,dc=ldap,dc=dev,dc=netidm,dc=com -w password -b dc=ldap,dc=dev,dc=netidm,dc=com
```

## Running the Sync Tool Manually

You can perform a dry run with the sync tool manually to check your configurations are correct and that the tool can
synchronise from LDAP.

```bash
netidm-ldap-sync [-c /path/to/netidm/config] -l /path/to/netidm-ldap-sync -n
netidm-ldap-sync -l /etc/netidm/ldap-sync -n
```

## Running the Sync Tool Automatically

The sync tool can be run on a schedule if you configure the `schedule` parameter, and provide the option "--schedule" on
the cli

```bash
netidm-ldap-sync [-c /path/to/netidm/config] -l /path/to/netidm-ldap-sync --schedule
netidm-ldap-sync -l /etc/netidm/ldap-sync --schedule
```

As the sync tool is part of the tools container, you can run this with:

```bash
docker create --name netidm-ldap-sync \
  --user uid:gid \
  -p 12345:12345 \
  -v /etc/netidm/config:/etc/netidm/config:ro \
  -v /path/to/ldap-sync:/etc/netidm/ldap-sync:ro \
  netidm-ldap-sync -l /etc/netidm/ldap-sync --schedule
```

## Monitoring the Sync Tool

When running in schedule mode, you may wish to monitor the sync tool for failures. Since failures block the sync
process, this is important for a smooth and reliable synchronisation process.

You can configure a status listener that can be monitored via tcp with the parameter `status_bind`.

An example of monitoring this with netcat is:

```bash
# status_bind = "[::1]:12345"
# nc ::1 12345
Ok
```

It's important to note no details are revealed via the status socket, and is purely for Ok or Err status of the last
sync. This status socket is suitable for monitoring from tools such as Nagios.
