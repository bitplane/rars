//! Where the tests put the files they write.
//!
//! Not `std::env::temp_dir()`. On a stock Linux install that is `/tmp`, and on
//! a stock systemd install `/tmp` is a tmpfs, so it spends RAM. This suite
//! writes hundreds of megabytes of archives, and a few of the streaming tests
//! write a single member larger than the memory budget they are proving,
//! which is the whole point of them. Sending that to RAM is the opposite of
//! what those tests measure, and on a loaded machine it wakes the OOM killer.
//!
//! Nor does it leave anything behind. [`case`] hands out a directory that
//! removes itself when the test drops it, which happens on the way out of a
//! panic too.
//!
//! Included with `#[path]` by each test target rather than shared through a
//! crate boundary, so it stays a test detail and does not become API.

include!("scratch_impl.rs");

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
