#!/usr/bin/env bash
set -euo pipefail

# Build the npm package from crates/rars-wasm.
#
# The public API is handwritten JavaScript plus declarations. wasm-bindgen's
# generated API lives under each platform's worker and is not exported.
# Output goes to npm/ at the repo root, which is generated and gitignored.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/npm"
CRATE="rars-wasm"
WASM="$ROOT/target/wasm32-unknown-unknown/release-wasm/rars_wasm.wasm"

VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/crates/rars-wasm/Cargo.toml" | head -1)"
echo "building @bitplane/rars@$VERSION for npm"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
    echo "wasm-bindgen not found. Install it with:" >&2
    echo "  cargo install wasm-bindgen-cli --version 0.2.126 --locked" >&2
    exit 1
fi

rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
cargo build --profile release-wasm --locked -p "$CRATE" --target wasm32-unknown-unknown

rm -rf "$OUT"
mkdir -p "$OUT/browser/wasm" "$OUT/node/wasm"

wasm-bindgen "$WASM" --out-dir "$OUT/browser/wasm" --target web
wasm-bindgen "$WASM" --out-dir "$OUT/node/wasm" --target nodejs
rm -f "$OUT/browser/wasm/"*.d.ts "$OUT/node/wasm/"*.d.ts

# wasm-opt is optional: it costs about a third of the module size, and a build
# without it is correct, just larger. Say which happened rather than failing.
if command -v wasm-opt >/dev/null 2>&1; then
    for dir in browser/wasm node/wasm; do
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

for file in api.js client.js worker-engine.js; do
    sed "s/__RARS_VERSION__/$VERSION/g" "$ROOT/npm-src/$file" > "$OUT/browser/$file"
    sed "s/__RARS_VERSION__/$VERSION/g" "$ROOT/npm-src/$file" > "$OUT/node/$file"
done
sed "s/__RARS_VERSION__/$VERSION/g" "$ROOT/npm-src/browser-index.js" > "$OUT/browser/index.js"
cp "$ROOT/npm-src/browser-worker.js" "$OUT/browser/worker.js"
sed "s/__RARS_VERSION__/$VERSION/g" "$ROOT/npm-src/node-index.js" > "$OUT/node/index.js"
sed "s/__RARS_VERSION__/$VERSION/g" "$ROOT/npm-src/node-index.cjs" > "$OUT/node/index.cjs"
cp "$ROOT/npm-src/node-worker.cjs" "$OUT/node/worker.cjs"
cp "$ROOT/npm-src/index.d.ts" "$OUT/browser/index.d.ts"
cp "$ROOT/npm-src/index.d.ts" "$OUT/node/base.d.ts"
cp "$ROOT/npm-src/node.d.ts" "$OUT/node/index.d.ts"

# These three sources use one named ESM export each. Produce their CommonJS
# twins without introducing a bundler into the release toolchain.
sed 's/^export function createApi/function createApi/' "$ROOT/npm-src/api.js" > "$OUT/node/api.cjs"
echo 'module.exports = { createApi };' >> "$OUT/node/api.cjs"
sed 's/^export function createClient/function createClient/' "$ROOT/npm-src/client.js" > "$OUT/node/client.cjs"
echo 'module.exports = { createClient };' >> "$OUT/node/client.cjs"
sed 's/^export function startWorker/function startWorker/' "$ROOT/npm-src/worker-engine.js" > "$OUT/node/worker-engine.cjs"
echo 'module.exports = { startWorker };' >> "$OUT/node/worker-engine.cjs"

python3 - "$OUT" "$VERSION" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
version = sys.argv[2]

(out / "package.json").write_text(
    json.dumps(
        {
            # Scoped, because npm's typo-squat filter refuses the bare name:
            # "rars" is within an edit of raf, rax, tar and arg. A scoped name
            # skips that check. `publishConfig` is what stops a scoped package
            # defaulting to private on publish.
            "name": "@bitplane/rars",
            "version": version,
            "description": "Read, write and repair RAR archives in the browser and in Node, with no native dependency.",
            "license": "MIT OR Apache-2.0",
            "homepage": "https://github.com/bitplane/rars",
            "repository": {"type": "git", "url": "git+https://github.com/bitplane/rars.git"},
            "keywords": ["rar", "archive", "compression", "unrar", "wasm", "webassembly"],
            "type": "module",
            "types": "./browser/index.d.ts",
            "main": "./node/index.cjs",
            "module": "./browser/index.js",
            "browser": "./browser/index.js",
            "exports": {
                ".": {
                    "node": {
                        "types": "./node/index.d.ts",
                        "import": "./node/index.js",
                        "require": "./node/index.cjs",
                    },
                    "browser": {
                        "types": "./browser/index.d.ts",
                        "default": "./browser/index.js",
                    },
                    "types": "./browser/index.d.ts",
                    "default": "./browser/index.js",
                },
                "./package.json": "./package.json",
            },
            "files": ["browser/", "node/", "README.md", "COPYING"],
            "sideEffects": False,
            "engines": {"node": ">=18"},
            "publishConfig": {"access": "public"},
        },
        indent=2,
    )
    + "\n"
)

# wasm-bindgen writes a package.json into each target directory. They name the
# same package and would confuse a publish, so drop them.
for stale in out.glob("*/*/package.json"):
    stale.unlink()
(out / "node" / "wasm" / "package.json").write_text('{ "type": "commonjs" }\n')
PY

echo
du -sh "$OUT"/*/ | sed 's/^/  /'
echo
echo "package built in $OUT"
