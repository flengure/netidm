# netidm Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-04-19

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
- Rust stable (see `rust-toolchain.toml`) + `axum`, `axum-extra` (cookies), `compact_jwt`, `netidmd_lib`, `netidm_proto`, `regex` — all already present; zero new deps (004-forward-auth-endpoint)
- No new storage. Group resolution via existing MVCC read path (`qe_r_ref.handle_whoami`) (004-forward-auth-endpoint)
- Rust stable (see `rust-toolchain.toml`) + `axum`, `axum-extra` (cookies), `askama` (templates), `compact_jwt`, `netidmd_lib`, `netidm_proto` — all already present; zero new external dependencies for P1/P2. P3 (logo) may require no new deps either (URL is rendered as `<img src>`). (005-sso-login-choice)
- No new database storage for P1/P2. P3 adds `Attribute::OAuth2ClientLogoUri` via DL20 schema migration (URL type, optional, single-value on `EntryClass::OAuth2Client`). (005-sso-login-choice)
- Rust stable (see `rust-toolchain.toml`) + `compact_jwt` 0.5.6 (workspace, already present — provides `OidcUnverified`, `JwkKeySet`, `JwsEs256Verifier`, `JwsRs256Verifier`); `reqwest` (workspace, already in `server/core` and `libs/client`); `serde_json` (already present) (006-oidc-connector)
- Netidm MVCC entry database — DL21 migration adds two URL-type `systemmay` attributes to `EntryClass::OAuth2Client` (006-oidc-connector)
- Rust stable (see `rust-toolchain.toml`) + `samael` 0.0.20 with `xmlsec` feature (SAML 2.0 parsing + XML signature verification); all other deps already present (`axum`, `askama`, `compact_jwt`, `netidmd_lib`, `netidm_proto`) (007-saml2-connector)
- Netidm MVCC entry database — DL22 migration adds new `EntryClass::SamlClient` with 9 attributes; DB nonce via existing `AssertionNonce` infrastructure (007-saml2-connector)

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
- 007-saml2-connector: Added Rust stable (see `rust-toolchain.toml`) + `samael` 0.0.20 with `xmlsec` feature (SAML 2.0 parsing + XML signature verification); all other deps already present (`axum`, `askama`, `compact_jwt`, `netidmd_lib`, `netidm_proto`)
- 006-oidc-connector: Added Rust stable (see `rust-toolchain.toml`) + `compact_jwt` 0.5.6 (workspace, already present — provides `OidcUnverified`, `JwkKeySet`, `JwsEs256Verifier`, `JwsRs256Verifier`); `reqwest` (workspace, already in `server/core` and `libs/client`); `serde_json` (already present)
- 005-sso-login-choice: Added Rust stable (see `rust-toolchain.toml`) + `axum`, `axum-extra` (cookies), `askama` (templates), `compact_jwt`, `netidmd_lib`, `netidm_proto` — all already present; zero new external dependencies for P1/P2. P3 (logo) may require no new deps either (URL is rendered as `<img src>`).


<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
