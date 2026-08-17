//! Where the tests put the files they write.
//!
//! Not `std::env::temp_dir()`. On a stock Linux install that is `/tmp`, and on
//! a stock systemd install `/tmp` is a tmpfs, so it spends RAM. This suite
//! writes hundreds of megabytes of archives, and a few of the streaming tests
//! write a single member larger than the memory budget they are proving,
//! which is the whole point of them. Sending that to RAM is the opposite of
//! what those tests measure, and on a loaded machine it wakes the OOM killer.
//!
//! Nor does it leave anything behind. Tests used to remove their directory on
//! the last line, so every failure and every interrupted run leaked one; a few
//! thousand of them had piled up by the time anyone looked. [`case`] hands out
//! a directory that removes itself when the test drops it, which happens on
//! the way out of a panic too.
//!
//! Included with `#[path]` by each test target rather than shared through a
//! crate boundary, so it stays a test detail and does not become API.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A directory of a test's own, removed when the test drops it.
///
/// Derefs to [`Path`], so it goes wherever a `&Path` goes.
///
/// A test that panics keeps its directory and prints the path, since that is
/// the one run whose files are worth reading.
pub struct Scratch {
    path: PathBuf,
}

impl Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

// `Command::arg` is generic, so it takes no deref coercion.
impl AsRef<std::ffi::OsStr> for Scratch {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("scratch kept for inspection: {}", self.path.display());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// An empty directory named after the test asking for it.
///
/// The name only has to be readable; the process id and a counter make it
/// unique, so two tests running at once cannot collide.
pub fn case(name: &str) -> Scratch {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = root().join(format!("{name}-{}-{serial}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path)
        .unwrap_or_else(|err| panic!("cannot create {}: {err}", path.display()));
    Scratch { path }
}

/// The directory the scratch directories live in, created if it is missing.
///
/// Integration tests and benchmarks get `CARGO_TARGET_TMPDIR` from cargo,
/// which already follows `CARGO_TARGET_DIR`. Unit tests inside `src/` get no
/// such variable, so they work the target directory out from the manifest.
fn root() -> PathBuf {
    let path = match option_env!("CARGO_TARGET_TMPDIR") {
        Some(path) => PathBuf::from(path),
        None => target_dir().join("tmp"),
    };
    std::fs::create_dir_all(&path)
        .unwrap_or_else(|err| panic!("cannot create {}: {err}", path.display()));
    path
}

fn target_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    // Every crate here lives at <workspace>/crates/<crate>, and cargo puts the
    // target directory at the workspace root.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .unwrap_or(manifest)
        .join("target")
}
