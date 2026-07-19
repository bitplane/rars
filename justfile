# Rars build and release recipes. Cargo remains the build system; these are
# short, memorable entry points for the local workflow.

# Run the same checks as CI before cutting a release.
check:
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test --workspace --all-targets --locked

# Bump the version (patch/minor/major or X.Y.Z), commit, tag vX.Y.Z and push.
# The pushed tag triggers the release workflow, which publishes the Rust crates,
# Python package, binaries, and GitHub release after its checks pass.
# Cut and push a versioned release; defaults to a patch bump.
release level="patch":
    cargo release {{ level }} --execute --no-confirm
