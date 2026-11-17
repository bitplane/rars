#!/usr/bin/env bash
# Open the pull request for a release.
#
#   scripts/release-pr.sh [patch|minor|major|X.Y.Z]
#
# Cuts release/vX.Y.Z from an up-to-date master, bumps every version with
# cargo-release (whose hook syncs pyproject.toml and the lockfiles and
# re-blesses the golden fixtures that carry the version), pushes the branch and
# opens a PR. Nothing is tagged or published here: merging the PR is what does
# that, in .github/workflows/release.yml, after its test gate and the release
# environment's approval.
set -euo pipefail

level="${1:-patch}"
die() {
    echo "release: $*" >&2
    exit 1
}

cd "$(git rev-parse --show-toplevel)"
command -v cargo-release >/dev/null || die "needs cargo-release: cargo install cargo-release"
command -v gh >/dev/null || die "needs the GitHub CLI (gh)"
[ -z "$(git status --porcelain)" ] || die "the working tree has changes; commit or stash them first"

git fetch -q origin master --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/master)" ] \
    || die "start from an up-to-date master: git checkout master && git pull"

current="$(sed -n 's/^version = "\(.*\)"$/\1/p' crates/rars/Cargo.toml | head -1)"
next="$(python3 - "$current" "$level" <<'PY'
import re
import sys

current, level = sys.argv[1], sys.argv[2]
if re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?", level):
    print(level)
    raise SystemExit
major, minor, patch = (int(part) for part in current.split("-")[0].split("."))
if level == "major":
    print(f"{major + 1}.0.0")
elif level == "minor":
    print(f"{major}.{minor + 1}.0")
elif level == "patch":
    print(f"{major}.{minor}.{patch + 1}")
else:
    raise SystemExit(f"release: unknown level {level!r}; use patch, minor, major or X.Y.Z")
PY
)"

branch="release/v$next"
! git rev-parse -q --verify "refs/tags/v$next" >/dev/null || die "v$next is already tagged"
! git ls-remote --exit-code origin "refs/heads/$branch" >/dev/null \
    || die "$branch already exists on origin"

echo "release: $current -> $next on $branch"
git checkout -b "$branch"
cargo release "$next" --execute --no-confirm
git commit -q --amend -m "Release v$next"
git push -u origin "$branch"
gh pr create --base master --head "$branch" --title "Release v$next" --body "$(cat <<EOF
Bumps every package from $current to $next and re-blesses the golden fixtures that carry the version.

Merging this tags \`v$next\` and starts the release workflow: its test gate runs on the merge commit, the tag is pushed once that passes, and publishing to crates.io, PyPI and npm waits for approval in the \`release\` environment.
EOF
)"
