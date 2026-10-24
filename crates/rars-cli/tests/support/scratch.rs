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
use std::sync::atomic::{AtomicUsize, Ordering};

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
    // This is a directory serial, not a byte count, so pointer width suffices.
    static NEXT: AtomicUsize = AtomicUsize::new(0);
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
/// such variable, so they use the location of the running test executable.
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
        let dir = PathBuf::from(dir);
        if dir.is_absolute() {
            return dir.canonicalize().unwrap_or(dir);
        }
    }
    // Cargo resolves relative target directories before changing to each
    // crate's directory to run its tests. Resolve from the executable rather
    // than interpreting that relative path a second time in the new cwd.
    // This also follows target-dir settings in Cargo configuration files.
    if let Ok(executable) = std::env::current_exe() {
        if let Some(dir) = executable_target_dir(&executable) {
            return dir;
        }
    }
    // Fallback for runners that relocate test executables outside Cargo's
    // profile/deps layout. Every crate lives at <workspace>/crates/<crate>.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .unwrap_or(manifest)
        .join("target")
}

/// Probe the test filesystem rather than assuming every Unix volume accepts
/// non-Unicode filenames. APFS/HFS+ can reject them even on a Unix host.
#[cfg(unix)]
#[allow(dead_code)] // This support module is also included by targets without filename tests.
pub fn supports_raw_byte_names(root: &Path) -> bool {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let path = root.join(OsStr::from_bytes(b"raw-name-probe-\xff"));
    match std::fs::write(&path, []) {
        Ok(()) => {
            let exact_name = std::fs::read_dir(root)
                .unwrap()
                .any(|entry| entry.unwrap().file_name().as_bytes() == b"raw-name-probe-\xff");
            std::fs::remove_file(path).unwrap();
            exact_name
        }
        Err(error)
            if error.kind() == std::io::ErrorKind::InvalidInput
                || error.raw_os_error() == Some(libc::EILSEQ) =>
        {
            false
        }
        Err(error) => panic!("raw filename probe failed unexpectedly: {error}"),
    }
}

fn executable_target_dir(executable: &Path) -> Option<PathBuf> {
    if !executable.is_absolute() {
        return None;
    }
    let deps = executable.parent()?;
    if deps.file_name()? != "deps" {
        return None;
    }
    Some(deps.parent()?.parent()?.to_path_buf())
}

#[cfg(test)]
mod target_directory_tests {
    use super::*;

    #[test]
    fn test_executable_layouts_produce_absolute_scratch_roots() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("rars-scratch-layout-probe");
        for profile in ["debug", "release", "custom-profile"] {
            let executable = base.join(profile).join("deps").join("rars-tests");
            assert_eq!(executable_target_dir(&executable), Some(base.clone()));
        }
        let cross_target = base.join("aarch64-apple-darwin");
        assert_eq!(
            executable_target_dir(&cross_target.join("debug/deps/rars-tests")),
            Some(cross_target),
        );
        assert_eq!(
            executable_target_dir(Path::new("target/debug/deps/test")),
            None
        );
        assert_eq!(executable_target_dir(&base.join("relocated-tests")), None);
    }
}
