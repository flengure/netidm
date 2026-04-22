# Contract: provider-initiated callback dispatch by `OAuth2ClientProviderKind`

This document defines how the existing OAuth2 provider-initiated-login callback handler routes an incoming `?code=...&state=...` to the correct connector implementation based on the `OAuth2ClientProviderKind` discriminator attribute added in DL28.

## Entry points

- The external callback URL established by PR-OIDC-CONNECTOR (DL21) stays unchanged. No new HTTP path.
- The existing handler in `server/core/src/https/views/login.rs` (or wherever PR-OIDC-CONNECTOR put it — Phase 1 implementation locates the exact file) gains a dispatch branch at the top.

## Dispatch logic

Pseudocode:

```rust
async fn handle_provider_initiated_callback(
    code: String,
    state: String,
    // ... other existing parameters
) -> Response {
    let entry = resolve_client_entry_from_state(&state).await?;

    let kind = entry
        .get_ava_single_iutf8(Attribute::OAuth2ClientProviderKind)
        .unwrap_or("generic-oidc");

    match kind {
        "github" => github_connector::handle_callback(&entry, &code, &state).await,
        "generic-oidc" => existing_oidc_handler(&entry, &code, &state).await,
        other => render_error_page(format!("Unknown connector kind: {}", other)),
    }
}
```

**Invariants**:
1. The callback URL stays at the DL21+ path — the external contract is stable (FR-016).
2. Absence of `OAuth2ClientProviderKind` resolves to `"generic-oidc"` (default), so pre-DL28 entries are byte-identical to their previous behaviour.
3. Unknown `kind` values render an error page — they are NOT silently promoted to any default. Admins misconfiguring the discriminator see an immediate visible error.
4. The match arm for `"github"` is the only new code this PR adds to the dispatch handler. Each future connector PR (#5 Generic-OIDC-beyond-OIDC, #6 Google, #7 Microsoft, …) adds its own arm without touching this one.

## Rejection-path diagram for the GitHub connector specifically

Once dispatched into `github_connector::handle_callback`, the call flow follows this decision tree. Any "reject" leaf renders the configured error page and does NOT touch Person state:

```
                     handle_callback(entry, code, state)
                                   │
                                   ▼
                     code exchange (contracts/github-api.md §2)
                                   │
                     ┌─────────────┴─────────────┐
                   failure                    success
                     │                            │
                     ▼                            ▼
              reject → error page          fetch profile + emails + orgs + teams
                                                  │
                                     ┌────────────┴────────────┐
                                   any fetch error          all succeed
                                     │                            │
                                     ▼                            ▼
                              reject → error page        apply AllowedTeams (FR-005a)
                                                                  │
                                                    ┌─────────────┴─────────────┐
                                              list non-empty AND             list empty OR
                                              zero intersection              non-empty intersection
                                                    │                            │
                                                    ▼                            ▼
                                           reject → error page        apply OrgFilter (FR-005)
                                           (NO Person written)                   │
                                                                                 ▼
                                                                   4-step linking chain (FR-013a)
                                                                                 │
                                                         ┌───────────────┼───────────────┐
                                                       step 1         step 2/3         step 4
                                                    (email match)   (id/login match)  (no match)
                                                         │              │                │
                                                         │              │      ┌─────────┴─────────┐
                                                         │              │   allow_jit=true   allow_jit=false
                                                         │              │      │                │
                                                         ▼              ▼      ▼                ▼
                                                  link to Person  link to    provision    reject → error page
                                                                  Person     new Person
                                                                                 │
                                                                                 ▼
                                                     update linking records on Person (ID + login)
                                                                                 │
                                                                                 ▼
                                                     persist GitHubSessionState as opaque blob
                                                     on the new OAuth2Session
                                                                                 │
                                                                                 ▼
                                                     call reconcile_upstream_memberships
                                                     with the filtered team names
                                                                                 │
                                                                                 ▼
                                                     redirect user to RP with netidm session cookie
```

**Key invariants on this diagram**:
- Every "reject → error page" leaf writes zero state to the database. No Person entries, no upstream-synced markers, no Oauth2Session rows.
- The error page rendered is operator-actionable — it tells the end-user WHAT went wrong, not a generic "login failed". Example page content for each leaf is defined in Phase 1 implementation.
- The AllowedTeams access gate runs STRICTLY FIRST after the GitHub fetches succeed. This is the FR-005a contract: no provisioning, no linking, no reconciliation happens for a user the access gate rejects.

## Testing this contract

Integration tests (one per leaf in the tree above) live in `server/testkit/tests/testkit/github_connector_test.rs`. The mock GitHub server (see testkit `spawn_mock_github_server()`) is driven to produce:
- Happy path (passes every check).
- Code-exchange failure (§2 error → reject).
- Fetch failure at each of §3 / §4 / §5 / §6 → reject.
- AllowedTeams rejection — user in wrong teams.
- JIT rejection — `allow_jit_provisioning=false` and no prior match.
- Each of the three non-rejection linking-chain steps (1/2/3) hit on a deterministic setup.
- JIT provisioning (step 4 with `allow_jit_provisioning=true`).

Each leaf is independently testable because the rejection happens before any observable state is written.
