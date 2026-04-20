# CLI Contracts: OAuth2 Email-Based Account Linking

## New Admin Commands

### Set global email-linking default

```
netidm system oauth2 set-email-link-accounts [true|false]
```

Sets `oauth2_domain_email_link_accounts` on the domain object. Applies to all providers that do not have a per-provider override.

### Set per-provider email-linking

```
netidm system oauth2 update <provider-name> --email-link-accounts [true|false]
```

Sets `oauth2_email_link_accounts` on the named `OAuth2Client` entry. Overrides the global setting for that provider only.

### Clear per-provider override (inherit global)

```
netidm system oauth2 update <provider-name> --email-link-accounts inherit
```

Removes the per-provider attribute, reverting to global default.

---

## Existing Commands Unaffected

- `netidm system oauth2 create` — no change; new attribute is optional and defaults to absent
- All other `oauth2` subcommands — no change

---

## No REST API Changes

Email linking is internal to the authentication flow. No new endpoints are required. The existing OAuth2 authorization endpoint (`/oauth2/authorise`, `/oauth2/token`) handles linking transparently.
