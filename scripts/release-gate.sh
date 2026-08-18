#!/usr/bin/env bash
set -euo pipefail

# The write matrix in crates/rars-cli/tests/external_decoders.rs skips when it
# cannot find a decoder that reads RAR. A release gate that skips it is the
# blind spot every corruption bug has shipped through, so make absence fatal.
# Install unrar, and the official 7zz from github.com/ip7z/7zip; distribution
# 7zip packages usually ship without the RAR decompressor and are ignored.
export RARS_REQUIRE_EXTERNAL_DECODERS=1

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace --all-targets --locked

# The Python package ships from the same tag as the crates, so the gate covers
# it too. This builds the extension into a throwaway virtualenv and runs
# python/tests against it, which nothing else does: until this line existed the
# suite had never run anywhere, in CI or out of it.
python3 scripts/test-python-bindings.py

# The npm package ships from the same tag as the crates, so the gate builds it
# and runs its checks under Node. This is the only place the JavaScript API is
# executed rather than compiled: the Rust suite proves the codec, and these
# prove the boundary the codec is reached through.
#
# Needs the wasm32-unknown-unknown target, wasm-bindgen and Node. Missing tools
# fail here rather than skipping, for the same reason the decoder matrix does.
./scripts/build-npm.sh
node scripts/test-npm-package.js
