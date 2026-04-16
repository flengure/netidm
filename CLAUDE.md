# kanidm Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-04-16

## Active Technologies

- Rust (stable, current toolchain — check `rust-toolchain.toml`) + Internal Kanidm crates; `reqwest` for userinfo HTTP calls; `jsonwebtoken`/existing JWT handling for Google `id_token` verification; `serde_json` for claim parsing (001-social-login-jit)

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

- 001-social-login-jit: Added Rust (stable, current toolchain — check `rust-toolchain.toml`) + Internal Kanidm crates; `reqwest` for userinfo HTTP calls; `jsonwebtoken`/existing JWT handling for Google `id_token` verification; `serde_json` for claim parsing

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
