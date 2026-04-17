# Data Model: OAuth2 Email-Based Account Linking

## New Schema Attributes (DL18)

### `oauth2_email_link_accounts` (per-provider)

| Field       | Value |
|-------------|-------|
| Name        | `Attribute::OAuth2EmailLinkAccounts` |
| Syntax      | `SyntaxType::Boolean` |
| Indexed     | false |
| Multivalue  | false |
| Class       | Added to `systemmay` of `OAuth2Client` |
| Default     | absent = inherit global domain setting |
| Description | When set, overrides the global domain email-linking setting for this provider. |

### `oauth2_domain_email_link_accounts` (global)

| Field       | Value |
|-------------|-------|
| Name        | `Attribute::OAuth2DomainEmailLinkAccounts` |
| Syntax      | `SyntaxType::Boolean` |
| Indexed     | false |
| Multivalue  | false |
| Class       | Added to `systemmay` of `DomainInfo` |
| Default     | absent = false (off) |
| Description | Global default for email-based account linking across all OAuth2 providers. Per-provider setting takes precedence when set. |

---

## Modified Structs

### `OAuth2ClientProvider` (server/lib/src/idm/oauth2_client.rs)

Add field:
```
email_link_accounts: bool   // effective value: per_provider.unwrap_or(global_domain)
```

Resolved at load time from the OAuth2Client entry + domain entry.

### `CredHandlerOAuth2Client` (server/lib/src/idm/authsession/handler_oauth2_client.rs)

Add field:
```
email_link_accounts: bool   // copied from OAuth2ClientProvider
```

### `CredState::ProvisioningRequired` (server/lib/src/idm/authsession/mod.rs)

Add field:
```
email_link_accounts: bool   // propagated from handler into state
```

---

## New Function

### `find_and_link_account_by_email` (server/lib/src/idm/server.rs)

```
Input:
  provider_uuid: Uuid
  claims: &ExternalUserClaims   // must have email, email_verified != Some(false)

Guard conditions (return Ok(None) to fall through to JIT):
  - claims.email is None
  - claims.email_verified == Some(false)
  - DB search returns 0 accounts
  - DB search returns 2+ accounts  
  - Found account already has OAuth2AccountProvider set

On success:
  1. internal_modify: add Class::OAuth2Account + three OAuth2 attributes
  2. Reload entry → Account::try_from_entry_rw()
  3. Return Ok(Some(account))

Output:
  Result<Option<Account>, OperationError>
```

---

## Effective Setting Resolution

```
fn effective_email_link(provider_entry, domain_entry) -> bool:
  per_provider = provider_entry.get_ava_single_bool(OAuth2EmailLinkAccounts)
  global       = domain_entry.get_ava_single_bool(OAuth2DomainEmailLinkAccounts).unwrap_or(false)
  per_provider.unwrap_or(global)
```

---

## State Transition: Updated JIT Flow

```
ProvisioningRequired { provider_uuid, claims, email_link_accounts }
  │
  ├─ email_link_accounts = false  ─────────────────────────► jit_provision_oauth2_account()
  │
  ├─ claims.email = None  ──────────────────────────────────► jit_provision_oauth2_account()
  │
  ├─ claims.email_verified = Some(false) ──────────────────► jit_provision_oauth2_account()
  │
  └─ find_and_link_account_by_email(provider_uuid, claims)
       │
       ├─ Ok(Some(account)) ───────────────────────────────► login existing account ✓
       │
       └─ Ok(None) ─────────────────────────────────────────► jit_provision_oauth2_account()
```

---

## No New Migrations for Existing Entries

Existing `Person` entries without OAuth2 attributes are unaffected. The new attributes are written onto an existing entry only at link time. The `OAuth2Account` class is added as a supplement to `Person` — this is already supported by the schema (class supplement relationship exists from DL13).
