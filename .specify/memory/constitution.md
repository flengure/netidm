<!--
SYNC IMPACT REPORT
Version change: (template) → 1.0.0
Added sections: Core Principles (I–V), Code Quality Standards, Development Workflow, Governance
Modified principles: N/A (initial ratification)
Removed sections: All placeholder tokens replaced
Templates requiring updates:
  ✅ .specify/templates/plan-template.md — Constitution Check section references principles by name
  ✅ .specify/templates/spec-template.md — no constitution-specific changes required
  ✅ .specify/templates/tasks-template.md — no constitution-specific changes required
Follow-up TODOs: None — all fields populated from project sources
-->

# Netidm Constitution

## Core Principles

### I. Ethics & Human Rights (NON-NEGOTIABLE)

Netidm stores and processes people's personal identity data. Every design and implementation decision
MUST respect the rights of all people who interact with the system — including those who have no
choice in its use (e.g. employees, end-users of services that delegate to Netidm).

People using this software MUST always have:
- Self-control over their data, including the ability to alter or delete it at any time.
- Freedom from harmful discrimination of any kind.
- Informed consent over the privacy and sharing of data held on their behalf.
- The ability to use and access this software regardless of ability, culture, or language.

Name fields MUST be case-sensitive UTF-8 with no maximum or minimum length. Users MUST be able to
change their name, display name, and legal name at any time without system obstruction.

### II. Humans First

All decisions MUST put humans first. We MUST respect all cultures, languages, and identities and
how they are represented. We MUST NEVER place a burden on the user to correct for poor design on
our part — even when that means making technically harder or unconventional choices.

### III. Correct & Simple

As security-sensitive software, correctness comes before convenience.

- All code MUST have tests.
- `git clone && cargo test` MUST always work on a clean checkout with no external services or
  preconfiguration required.
- If a change requires an external database, network service, or preconfiguration to test, it MUST
  NOT be merged until that requirement is removed or the test is made conditional/optional.
- The project MUST remain simple enough that any contributor can understand how it works and why
  those decisions were made.

### IV. Code Quality: Clippy & Zero Warnings

All Rust code MUST compile without warnings, and MUST pass `cargo clippy` without warnings.

- Warnings MUST be resolved by fixing the underlying code issue — NEVER by adding
  `#[allow(...)]` attributes, `#![allow(...)]` crate-level suppression, or `--allow` flags.
- The only permitted exception is a suppression that exists in upstream code we do not own, or
  a lint that is demonstrably a false positive with a documented justification in a code comment
  explaining *why* the suppression is correct in that specific case.
- CI MUST run `cargo clippy -- -D warnings` and fail the build on any warning.
- Newly introduced code that produces clippy warnings MUST NOT be merged.

### V. Security by Hierarchy of Controls

When a risk arises, apply the hierarchy of controls in descending order of preference:

1. **Elimination** — remove the risk entirely
2. **Substitution** — replace it with something less dangerous
3. **Engineering Controls** — isolate the risk from causing harm
4. **Administrative Controls** — educate, add warnings
5. **Personal Protection** — document the risk as a last resort

This hierarchy MUST guide security decisions in authentication flows, data handling, and
privilege escalation paths.

## Security Standards

- Authentication flows MUST deny on any validation failure — partial auth states are forbidden.
- Sensitive fields (secrets, tokens, personal data) MUST NOT appear in logs.
- Account deletion MUST be a true deletion, not a soft-delete flag, unless an explicit recycle bin
  with a defined purge path is in place.
- `legalName` MUST only be collected and accessible on a need-to-know basis.

## Development Workflow

- `cargo test` MUST pass on every commit.
- `cargo clippy -- -D warnings` MUST pass on every commit. Fix the code; never suppress.
- New features MUST include tests covering the primary success path and primary failure paths.
- All new schema attributes MUST be introduced via a numbered data-level (DL) migration.
- PRs MUST be reviewed for compliance with Principles I–V before merge.

## Documentation Standards

All new and modified public Rust items MUST have doc comments following standard Rust conventions:

- `//!` at the top of every new module file (one-line summary, blank line, extended description).
- `///` on every `pub fn`, `pub struct`, `pub enum`, `pub trait`, and `pub type`.
- `# Errors` section on every `Result`-returning public function, listing each `OperationError` variant that can be returned.
- `# Examples` section with a working ` ```rust ` code block on every public handler function and any non-trivial public API.
- `# Panics` section on any function that can panic.
- Intra-doc links (`[TypeName]`) used to cross-reference related types within the same crate.
- `cargo doc --no-deps 2>&1 | grep "warning\[missing"` MUST produce no output for all new items.

These requirements apply to every feature. Tasks for doc comments MUST be included in every feature's tasks.md.

## Testing Standards

Every feature MUST include unit tests and/or integration tests as part of its definition of done:

- Each user story MUST have tests covering:
  - The primary success path (happy path).
  - The primary failure path (authentication failure, validation failure, etc.).
  - Any edge cases identified in the spec (e.g., missing optional fields, boundary conditions).
- Tests MUST be written in the same PR as the implementation — never deferred.
- Tests that exercise HTTP handlers MUST assert both the response status code and the relevant response headers or body.
- Tests MUST NOT use mocks for the database layer — use the existing `server/testkit` integration test infrastructure that runs against a real in-process netidmd instance.
- `cargo test` MUST pass before any PR is considered ready for review.

These requirements apply to every feature. Test tasks MUST be included in every feature's tasks.md.

## Governance

This constitution supersedes all other development practices and guidelines for this project.
Amendments require:
1. A documented rationale for the change.
2. Agreement from at least one other active contributor.
3. An update to this file with an incremented version and amended date.

The versioning policy follows semantic versioning:
- **MAJOR**: Backward-incompatible removal or redefinition of a principle.
- **MINOR**: New principle or section added, or materially expanded guidance.
- **PATCH**: Clarifications, wording, or typo fixes.

All PRs and code reviews MUST verify compliance with this constitution. Complexity that violates
a principle MUST be justified in the implementation plan's Complexity Tracking table.

## Release Etiquette

1. **Verify tag position before any release action.** Run `git log --oneline <tag>..main`. If
   non-empty, move the tag to `main` HEAD before proceeding.
2. **Never create GitHub releases manually.** Push the tag; `release.yml` builds binaries and
   creates the release automatically.
3. **Determine next version by inspecting tags**, not releases. Run
   `git tag --sort=-version:refname | head -1`. A tag without a GitHub release is still a tag.
4. **Before every commit**, run `cargo fmt --check` and `cargo clippy --all-features` locally.
   Do not rely on CI to catch formatting or lint errors.

**Version**: 1.2.0 | **Ratified**: 2026-04-16 | **Last Amended**: 2026-04-19
