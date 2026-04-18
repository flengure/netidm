# Implementation Plan: SSO Login Choice UX

**Branch**: `005-sso-login-choice` | **Date**: 2026-04-18 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/005-sso-login-choice/spec.md`

## Summary

Replace the username-first login page with a landing that shows configured OAuth2 provider buttons above a collapsible "Use internal authentication" section. When no providers are configured the page falls back to the current layout unchanged. A new `GET /ui/sso/:provider_name` endpoint initiates the provider-first OAuth2 flow using a new `AuthStep::InitOAuth2Provider` variant. A session cookie persists the user's last-used auth method preference so internal-auth users see the form pre-expanded on return visits.

## Technical Context

**Language/Version**: Rust stable (see `rust-toolchain.toml`)
**Primary Dependencies**: `axum`, `axum-extra` (cookies), `askama` (templates), `compact_jwt`, `netidmd_lib`, `netidm_proto` — all already present; zero new external dependencies for P1/P2. P3 (logo) may require no new deps either (URL is rendered as `<img src>`).
**Storage**: No new database storage for P1/P2. P3 adds `Attribute::OAuth2ClientLogoUri` via DL20 schema migration (URL type, optional, single-value on `EntryClass::OAuth2Client`).
**Testing**: `cargo test` / `server/testkit` integration tests against real in-process netidmd
**Target Platform**: Linux server (same as existing netidmd)
**Project Type**: Web service (HTMX + server-rendered HTML)
**Performance Goals**: SC-002: ≤50ms additional latency. Provider list is read from in-memory cache (`oauth2_client_providers: HashMap`) — no additional database queries at render time.
**Constraints**: No JavaScript framework. Toggle must work with 3 lines of inline JS (FR-006). Mobile: Bootstrap `w-100` buttons, 44px touch targets.
**Scale/Scope**: Up to all configured OAuth2 client providers rendered (no pagination in v1).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I (Ethics) | ✅ | Provider names are admin-configured; no user personal data exposed on login page |
| II (Humans First) | ✅ | SSO-first reduces friction for majority; internal auth pref avoids repeated clicks for power users |
| III (Correct & Simple) | ✅ | Tests required for all user stories; `cargo test` must pass; testkit used (no mocks) |
| IV (Clippy) | ✅ | No `#[allow]` suppression; `AuthStep::InitOAuth2Provider` must be matched exhaustively |
| V (Security) | ✅ | Provider name validated before auth session creation (prevents unknown-provider sessions); `?next=` path-only validation preserved |

**Post-Phase-1 re-check**:
- `AuthStep::InitOAuth2Provider` adds a new variant — all existing `match auth_step` arms must be updated; clippy exhaustiveness check catches any missed arms ✅
- Cookie `COOKIE_AUTH_METHOD_PREF` is unsigned (UI preference only, no security implication) — appropriate ✅

## Project Structure

### Documentation (this feature)

```text
specs/005-sso-login-choice/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   ├── http_routes.md   # Phase 1 output
│   └── template_contracts.md  # Phase 1 output
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
proto/src/
└── v1/auth.rs                          # Add AuthStep::InitOAuth2Provider variant

server/lib/src/idm/
├── oauth2_client.rs                    # Add display_name, logo_uri fields to OAuth2ClientProvider
├── server.rs                           # Add list_sso_providers() to read transaction
└── authsession/
    ├── mod.rs                          # Provider-initiated session creation
    └── handler_oauth2_client.rs       # Resolve user from identity claims on callback

server/core/src/https/views/
├── login.rs                            # SsoProviderInfo, view_sso_initiate_get, LoginDisplayCtx change
├── mod.rs                              # Register GET /ui/sso/:provider_name
└── cookies.rs                          # Add COOKIE_AUTH_METHOD_PREF constant

server/core/templates/
└── login.html                          # Restructured: SSO section + toggle + existing form

# P3 only (DL20):
server/lib/src/migration_data/dl20/
├── mod.rs                              # New DL module
└── schema.rs                           # SCHEMA_ATTR_OAUTH2_CLIENT_LOGO_URI_DL20
server/lib/src/constants/uuids.rs       # UUID_SCHEMA_ATTR_OAUTH2_CLIENT_LOGO_URI
proto/src/attribute.rs                  # Attribute::OAuth2ClientLogoUri

tests/
└── server/testkit/tests/               # Integration tests per user story
```

**Structure Decision**: Single project, server-rendered web service. No new crates, no new files except the DL20 migration module (P3). All changes are in existing files.

## Complexity Tracking

No constitution violations. Feature adds one new auth step variant and one new HTTP route — both are minimal extensions to existing patterns.
