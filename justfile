# Rars build and release recipes. Cargo remains the build system; these are
# short, memorable entry points for the local workflow.

# Everyday checks. The external decoder matrix skips whatever it cannot find,
# so this passes without unrar or 7zz installed; `just gate` is the strict one.
check:
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test --workspace --all-targets --locked

# A minute of timings over three kinds of data, before and after anything that
# touches the encoder. A ratio sweep takes an hour and says nothing about speed;
# this says how long a megabyte costs at each level.
speed *ARGS:
    cargo build --release
    python3 scripts/speed.py {{ ARGS }}

# Build the Python extension into a throwaway virtualenv and run python/tests
# against it. Separate from `check` because it compiles the extension and needs
# to fetch maturin and pytest; `gate` runs it.
python:
    python3 scripts/test-python-bindings.py

# Build the npm package from crates/rars-wasm into npm/ and run its checks
# under Node. Separate from `check` because it needs the wasm32 target,
# wasm-bindgen and Node; `gate` runs it.
npm:
    ./scripts/build-npm.sh
    node scripts/test-npm-package.js

# What CI runs before a release, including the external decoders and the Python
# bindings. Fails rather than skips when the decoders are missing.
gate:
    ./scripts/release-gate.sh

# Bump the version (patch/minor/major or X.Y.Z), commit, tag vX.Y.Z and push.
# The pushed tag triggers the release workflow, which publishes the Rust crates,
# Python package, binaries, and GitHub release after its checks pass.
# Cut and push a versioned release; defaults to a patch bump.
release level="patch":
    cargo release {{ level }} --execute --no-confirm
