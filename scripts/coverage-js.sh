#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${1:-$ROOT/target/coverage-js}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
if [[ -d "$OUT/raw" ]]; then
    echo "Coverage profiles already exist in $OUT/raw; choose a fresh output directory." >&2
    exit 1
fi
./scripts/build-npm.sh > "$OUT/build.log" 2>&1
git rev-parse HEAD > "$OUT/revision.txt"
git status --porcelain > "$OUT/working-tree.txt"
node --version > "$OUT/node-version.txt"
mkdir -p "$OUT/raw"
NODE_V8_COVERAGE="$OUT/raw" node --test --test-concurrency=1 \
    --experimental-test-coverage \
    --test-coverage-include='**/npm/node/*.js' \
    --test-coverage-include='**/npm/node/*.cjs' \
    --test-coverage-exclude='**/npm/node/worker-engine.js' \
    --test-reporter=spec \
    scripts/test-npm-package.js 2>&1 | tee "$OUT/summary.txt"
