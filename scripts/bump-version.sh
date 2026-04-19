#!/usr/bin/env bash
# bump-version.sh — atomically update every version pin in the workspace.
# Usage: ./scripts/bump-version.sh <new-version>
# Example: ./scripts/bump-version.sh 0.1.7-dev
#          ./scripts/bump-version.sh 0.1.7

set -euo pipefail

NEW="$1"
if [[ -z "$NEW" ]]; then
    echo "Usage: $0 <new-version>" >&2
    exit 1
fi

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

OLD=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
echo "Bumping $OLD → $NEW"

# 1. Workspace package version
sed -i "s/^version = \"${OLD}\"/version = \"${NEW}\"/" Cargo.toml

# 2. Internal exact-pin deps in [workspace.dependencies]
sed -i "s/version = \"=${OLD}\"/version = \"=${NEW}\"/g" Cargo.toml

# 3. netidmd_wg pins in per-crate Cargo.toml files (not using workspace = true)
grep -rl "version = \"${OLD}\"" server/ --include="Cargo.toml" | while read -r f; do
    sed -i "s/version = \"${OLD}\"/version = \"${NEW}\"/g" "$f"
    echo "  updated $f"
done

# 4. Regenerate Cargo.lock
cargo generate-lockfile

echo "Done. Files to commit:"
git diff --name-only
