//! Checked-in archives under `tests/fixtures`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// `path` under `tests/fixtures`.
pub fn fixture(path: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}
