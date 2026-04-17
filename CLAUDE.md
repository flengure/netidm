# netidm Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-04-17

## Active Technologies
- Rust stable (see `rust-toolchain.toml`) (002-wg-mgmt-crate)
- Netidm entry database (netidmd_lib QueryServer) (002-wg-mgmt-crate)
- `wireguard-control` 1.7.1 — WireGuard device/peer management (kernel + userspace UAPI) (002-wg-mgmt-crate)
- `rtnetlink` 0.20.0 — netlink for link/address management; use `LinkUnspec::new_with_index(idx).up().mtu(m).build()` builder API (002-wg-mgmt-crate)
- `ipnet` — CIDR parsing and arithmetic for WireGuard address allocation (002-wg-mgmt-crate)
- `hashbrown` — required by clippy rules (std::collections::HashSet disallowed) (002-wg-mgmt-crate)
- `async-trait` — required for `WgBackend` async trait (002-wg-mgmt-crate)
- `netidmd_wg` crate — `server/wg/` — live WireGuard interface management embedded in netidmd (002-wg-mgmt-crate)
- Rust stable (see `rust-toolchain.toml`) + Internal netidm crates (`netidmd_lib`, `netidm_proto`), `kanidm-hsm-crypto` (external, unchanged) (003-oauth2-email-linking)
- Netidm MVCC database (concread) — schema changes via numbered DL migration; current target is DL18 (`DOMAIN_TGT_LEVEL = DOMAIN_LEVEL_18`) (003-oauth2-email-linking)
- Email-based OAuth2 account linking: `find_and_link_account_by_email()` in `IdmServerProxyWriteTransaction`; per-provider `OAuth2EmailLinkAccounts` overrides global `OAuth2DomainEmailLinkAccounts`; linking intercept in `server/core/src/https/views/login.rs` `AuthState::ProvisioningRequired` arm (003-oauth2-email-linking)

- Rust (stable, current toolchain — check `rust-toolchain.toml`) + Internal Netidm crates; `reqwest` for userinfo HTTP calls; `jsonwebtoken`/existing JWT handling for Google `id_token` verification; `serde_json` for claim parsing (001-social-login-jit)

## Project Structure

```text
src/
tests/
```

## Commands

cargo test && cargo clippy

## Code Style

Rust (stable, current toolchain — check `rust-toolchain.toml`): Follow standard conventions

## Recent Changes
- 003-oauth2-email-linking: Added Rust stable (see `rust-toolchain.toml`) + Internal netidm crates (`netidmd_lib`, `netidm_proto`), `kanidm-hsm-crypto` (external, unchanged)
- 002-wg-mgmt-crate: Added Rust stable (see `rust-toolchain.toml`)

- 001-social-login-jit: Added Rust (stable, current toolchain — check `rust-toolchain.toml`) + Internal Netidm crates; `reqwest` for userinfo HTTP calls; `jsonwebtoken`/existing JWT handling for Google `id_token` verification; `serde_json` for claim parsing

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
