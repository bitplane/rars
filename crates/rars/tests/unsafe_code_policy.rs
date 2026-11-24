// The workspace denies `unsafe_code`, but any module can lift that with one
// attribute. This keeps the one exception, `crates/rars/src/simd.rs`, the only
// one: a new exception should be argued for in review and added to
// `ALLOWED` here, not slipped in as a one-line opt-out.

use std::path::{Path, PathBuf};

/// Files allowed to lift the `unsafe_code` lint, relative to the repository.
const ALLOWED: &[&str] = &["crates/rars/src/simd.rs"];

const CHECKER: &str = "crates/rars/tests/unsafe_code_policy.rs";

#[test]
fn only_simd_lifts_the_unsafe_code_lint() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // The published crate carries this test but not the workspace around it.
    if !repo.join("crates/rars/src/simd.rs").is_file() {
        eprintln!("not in the rars repository; nothing to check");
        return;
    }
    let mut files = Vec::new();
    for dir in ["crates", "fuzz"] {
        rust_files(&repo.join(dir), &mut files);
    }
    assert!(
        files
            .iter()
            .any(|file| file.ends_with("crates/rars/src/simd.rs")),
        "the walk found no sources under {}",
        repo.display()
    );

    let mut offenders = Vec::new();
    for file in &files {
        let relative = file.strip_prefix(&repo).unwrap_or(file);
        let relative = relative.to_string_lossy().replace('\\', "/");
        // This file names the attributes it looks for.
        if ALLOWED.contains(&relative.as_str()) || relative == CHECKER {
            continue;
        }
        let text = std::fs::read_to_string(file).unwrap_or_default();
        for line in lifting_lines(&text) {
            let shown = text.lines().nth(line - 1).unwrap_or_default().trim();
            offenders.push(format!("{relative}:{line}: {shown}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "`unsafe` is confined to crates/rars/src/simd.rs. The workspace denies \
         the `unsafe_code` lint, and only that module may lift it. Find a safe \
         alternative (a vetted crate's safe API, as the PPMd pool uses \
         memmap2), or make the case for a new exception in review and add the \
         file to ALLOWED in {CHECKER}. Found:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn every_way_of_lifting_the_lint_is_caught() {
    for lifting in [
        "#![allow(unsafe_code)]",
        "#[allow(dead_code, unsafe_code)]",
        "#[cfg_attr(unix, expect(\n    unsafe_code,\n))]",
        "#![warn(clippy::all, unsafe_code)]",
    ] {
        assert_eq!(lifting_lines(lifting).len(), 1, "{lifting}");
    }
    for keeping in [
        "#![deny(unsafe_code)]",
        "#![forbid(unsafe_code)]",
        "// The workspace denies `unsafe_code`.",
    ] {
        assert!(lifting_lines(keeping).is_empty(), "{keeping}");
    }
}

/// One-based lines where an `allow`, `expect` or `warn` attribute names the
/// `unsafe_code` lint, including inside `cfg_attr` and across lines.
fn lifting_lines(text: &str) -> Vec<usize> {
    let lint = "unsafe_code";
    let mut lines = Vec::new();
    for (at, _) in text.match_indices(lint) {
        // Back over the rest of the lint list to its opening parenthesis.
        let before = &text[..at];
        let Some(open) = before.rfind(|c: char| {
            !(c.is_alphanumeric() || c.is_whitespace() || matches!(c, '_' | ':' | ','))
        }) else {
            continue;
        };
        if !before[open..].starts_with('(') {
            continue;
        }
        let level = before[..open].trim_end();
        if ["allow", "expect", "warn"]
            .iter()
            .any(|word| level.ends_with(word))
        {
            lines.push(before.matches('\n').count() + 1);
        }
    }
    lines
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != ".git" {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}
