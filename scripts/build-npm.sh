#!/usr/bin/env bash
set -euo pipefail

# Build the npm package from crates/rars-wasm.
#
# Three wasm-bindgen targets go into one package because the three ways a
# JavaScript project loads WebAssembly are genuinely different, and picking one
# would lock out the other two:
#
#   bundler  ESM with a bare `import` of the .wasm, which webpack, Vite and
#            Rollup resolve themselves. The default.
#   node     CommonJS that reads the .wasm off disk. Node's `require`.
#   web      ESM that fetches the .wasm, for a browser with no build step.
#            The only one where `init()` must be awaited first.
#
# The `exports` map in package.json routes each importer to its own build.
# Output goes to npm/ at the repo root, which is generated and gitignored.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/npm"
CRATE="rars-wasm"
WASM="$ROOT/target/wasm32-unknown-unknown/release-wasm/rars_wasm.wasm"

VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/crates/rars-wasm/Cargo.toml" | head -1)"
echo "building rars@$VERSION for npm"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
    echo "wasm-bindgen not found. Install it with:" >&2
    echo "  cargo install wasm-bindgen-cli --version 0.2.126 --locked" >&2
    exit 1
fi

rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
cargo build --profile release-wasm --locked -p "$CRATE" --target wasm32-unknown-unknown

rm -rf "$OUT"
mkdir -p "$OUT"

for pair in "bundler:bundler" "node:nodejs" "web:web"; do
    dir="${pair%%:*}"
    target="${pair##*:}"
    # No --omit-default-module-path: it is what makes `init()` resolve the
    # .wasm beside the JS, so the browser build works from a CDN with no
    # arguments.
    wasm-bindgen "$WASM" --out-dir "$OUT/$dir" --target "$target"
done

# wasm-opt is optional: it costs about a third of the module size, and a build
# without it is correct, just larger. Say which happened rather than failing.
if command -v wasm-opt >/dev/null 2>&1; then
    for dir in bundler node web; do
        # Exactly the features Rust's wasm32-unknown-unknown target emits.
        # Without them binaryen refuses to validate the module; with `-all`
        # instead it enables the string proposal, and the result imports
        # something no released engine has.
        wasm-opt -Oz \
            --enable-bulk-memory \
            --enable-mutable-globals \
            --enable-nontrapping-float-to-int \
            --enable-sign-ext \
            --enable-multivalue \
            --enable-reference-types \
            --enable-extended-const \
            "$OUT/$dir/rars_wasm_bg.wasm" -o "$OUT/$dir/rars_wasm_bg.wasm"
    done
    echo "optimised with wasm-opt"
else
    echo "wasm-opt not found; shipping unoptimised modules (about a third larger)"
fi

cp "$ROOT/COPYING" "$OUT/COPYING"
cp "$ROOT/crates/rars-wasm/README.md" "$OUT/README.md"

python3 - "$OUT" "$VERSION" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
version = sys.argv[2]

(out / "package.json").write_text(
    json.dumps(
        {
            "name": "rars",
            "version": version,
            "description": "Read, write and repair RAR archives in the browser and in Node, with no native dependency.",
            "license": "MIT OR Apache-2.0",
            "homepage": "https://github.com/bitplane/rars",
            "repository": {"type": "git", "url": "git+https://github.com/bitplane/rars.git"},
            "keywords": ["rar", "archive", "compression", "unrar", "wasm", "webassembly"],
            "type": "module",
            "types": "./bundler/rars_wasm.d.ts",
            "main": "./node/rars_wasm.js",
            "module": "./bundler/rars_wasm.js",
            "browser": "./web/rars_wasm.js",
            "exports": {
                ".": {
                    "types": "./bundler/rars_wasm.d.ts",
                    "node": "./node/rars_wasm.js",
                    "browser": "./bundler/rars_wasm.js",
                    "default": "./bundler/rars_wasm.js",
                },
                "./web": {
                    "types": "./web/rars_wasm.d.ts",
                    "default": "./web/rars_wasm.js",
                },
                "./node": {
                    "types": "./node/rars_wasm.d.ts",
                    "default": "./node/rars_wasm.js",
                },
                "./package.json": "./package.json",
            },
            "files": ["bundler/", "node/", "web/", "README.md", "COPYING"],
            "sideEffects": ["./bundler/rars_wasm.js", "./web/rars_wasm.js"],
            "engines": {"node": ">=18"},
        },
        indent=2,
    )
    + "\n"
)

# wasm-bindgen writes a package.json into each target directory. They name the
# same package and would confuse a publish, so drop them.
for stale in out.glob("*/package.json"):
    stale.unlink()

# The node target is CommonJS, and a top-level "type": "module" would make Node
# refuse to require it. Its own directory says otherwise.
(out / "node" / "package.json").write_text('{ "type": "commonjs" }\n')
PY

echo
du -sh "$OUT"/*/ | sed 's/^/  /'
echo
echo "package built in $OUT"
