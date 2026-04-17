# Research: OAuth2 Email-Based Account Linking

## Decision: Schema — Two New Attributes (DL18)

**Decision**: Add `oauth2_email_link_accounts` (Boolean) to `OAuth2Client` class (per-provider) and `oauth2_domain_email_link_accounts` (Boolean) to `DomainInfo` class (global default).

**Rationale**: Mirrors the existing `oauth2_jit_provisioning` per-provider pattern exactly. No new patterns needed. Global on domain follows the `domain_development_taint` / `domain_allow_easter_eggs` boolean pattern.

**Alternatives considered**: Single global-only flag — rejected because admins need provider-level granularity (trust one provider's emails but not another's).

---

## Decision: Effective Value Resolution

**Decision**: Resolve `effective_email_link = per_provider.unwrap_or(global_domain_default)` when loading `OAuth2ClientProvider` from the DB entry. Store as `email_link_accounts: bool` on `OAuth2ClientProvider` and copy into `CredHandlerOAuth2Client`.

**Rationale**: Same pattern as `jit_provisioning`. The handler is a pure state machine with no DB access — all DB-derived config must be embedded at load time. The domain setting is read once when the provider is loaded.

**Alternatives considered**: Re-reading the domain setting at auth time — rejected; adds DB round-trip per login.

---

## Decision: Insertion Point

**Decision**: The email-match check runs in `server/lib/src/idm/server.rs` where `CredState::ProvisioningRequired` is handled, NOT inside the handler state machine.

**Rationale**: `CredHandlerOAuth2Client` has no DB access. The handler emits `ProvisioningRequired { provider_uuid, claims }`. The query server layer processes this state and calls `jit_provision_oauth2_account()`. We insert `find_and_link_account_by_email()` before that call. The `email_link_accounts` flag must be passed through `ProvisioningRequired` so the outer layer knows whether to attempt email matching.

**Alternatives considered**: Inserting in the handler — impossible, no DB access there.

---

## Decision: Pass Flag Through ProvisioningRequired

**Decision**: Extend `CredState::ProvisioningRequired` to include `email_link_accounts: bool` alongside existing `provider_uuid` and `claims`.

**Rationale**: The outer layer (server.rs) needs to know the effective setting when deciding whether to call `find_and_link_account_by_email()`. The cleanest transport is the existing state struct.

---

## Decision: Email-Match Filter

**Decision**: Use `filter_all!(f_eq(Attribute::Mail, PartialValue::EmailAddress(email, true)))` for the equality search.

**Rationale**: `Attribute::Mail` is already indexed for equality (`IndexType::Equality`) and unique. The search is O(1). `PartialValue::EmailAddress` takes the email string and `true` for primary-only matching — confirmed from existing value.rs patterns.

**Alternatives considered**: Full-text substring search — unnecessary overhead given equality index.

---

## Decision: Guard Conditions Before Linking

**Decision**: Linking is skipped (falls through to JIT) when any of:
1. `email_link_accounts` is false for this provider
2. `claims.email` is None
3. `claims.email_verified` is Some(false) — i.e., explicitly unverified; None is treated as verified for GitHub (primary email is always verified)
4. Zero or 2+ accounts found with that email
5. Found account already has `OAuth2AccountProvider` set

**Rationale**: Matches FR-005 through FR-011. Guard #5 prevents overwriting an existing provider link. Guard #4 prevents ambiguous linking.

---

## Decision: Linking Write Operation

**Decision**: On successful email match, call `internal_modify()` with a `ModifyList` that adds:
- `Modify::Present(Attribute::Class, EntryClass::OAuth2Account.into())`
- `Modify::Present(Attribute::OAuth2AccountProvider, Value::Refer(provider_uuid))`
- `Modify::Present(Attribute::OAuth2AccountUniqueUserId, Value::new_utf8(sub))`
- `Modify::Present(Attribute::OAuth2AccountCredentialUuid, Value::Uuid(Uuid::new_v4()))`

Then load the account normally via `Account::try_from_entry_rw()`.

**Rationale**: `internal_modify` is transactional. The `OAuth2Account` class must be added alongside the attributes (class defines the allowed attributes). `Uuid::new_v4()` for cred_id matches the JIT provisioning pattern.

---

## Key File Locations

| File | Purpose |
|------|---------|
| `server/lib/src/migration_data/dl17/` | Latest DL — DL18 follows same pattern |
| `server/lib/src/migration_data/dl15/schema.rs` | Template for `oauth2_jit_provisioning` attribute |
| `server/lib/src/idm/authsession/handler_oauth2_client.rs` | Handler state machine, `CredState::ProvisioningRequired` |
| `server/lib/src/idm/server.rs:2294` | `find_account_by_oauth2_provider_and_user_id` — template for new search |
| `server/lib/src/idm/server.rs:2338` | `jit_provision_oauth2_account` — where email check inserts |
| `server/lib/src/idm/oauth2_client.rs:132` | `OAuth2ClientProvider` loading — add `email_link_accounts` field |
| `proto/src/` | `Attribute` enum — add two new variants |
