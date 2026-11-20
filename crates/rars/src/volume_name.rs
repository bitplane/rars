//! The names RAR gives the volumes of a set, derived from the first volume's path.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// How a set names its volume files.
pub enum VolumeNaming {
    /// `name.part01.rar`, `name.part02.rar`, ...
    Part,
    /// `name.rar`, `name.r00`, `name.r01`, ...
    Old,
}

/// Volume `index` as `.r00` on, rolling `.r99` to `.s00` up to `.z99` as rar 4.2's `-vn` does; upper case follows the first extension's.
pub fn old_style(first: &Path, index: usize) -> Option<PathBuf> {
    let Some(number) = index.checked_sub(1) else {
        return Some(first.to_path_buf());
    };
    let step = u8::try_from(number / 100)
        .ok()
        .filter(|&step| step <= b'z' - b'r')?;
    let upper = first
        .extension()
        .and_then(|extension| extension.as_encoded_bytes().first())
        .is_some_and(u8::is_ascii_uppercase);
    let letter = if upper { b'R' } else { b'r' } + step;
    Some(first.with_extension(format!("{}{:02}", letter as char, number % 100)))
}

/// Volume `index` as `name.partN.rar`, keeping the first volume's `.RAR` case as RAR does.
/// A self-extracting first volume (`name.part1.exe`, `.sfx`) is followed by `.rar` volumes.
pub fn part_style(first: &Path, index: usize, width: usize) -> Option<PathBuf> {
    let file_name = crate::filename::native_bytes(first.file_name()?).ok()?;
    let (stem, suffix) = match split_rar_suffix(file_name) {
        (stem, "") => split_sfx_suffix(stem).unwrap_or((stem, "")),
        split => split,
    };
    let stem = part_number(stem).map_or(stem, |(base, _)| base);
    // Removing ASCII suffixes from a native name keeps it native.
    let mut name = crate::filename::native_string(stem).ok()?;
    let suffix = if suffix.is_empty() { ".rar" } else { suffix };
    name.push(format!(".part{:0width$}{suffix}", index + 1));
    Some(first.with_file_name(name))
}

/// The digit count of the first volume's `.partN.rar` (or `.partN.exe`) number, if it has one.
pub fn part_width(first: &Path) -> Option<usize> {
    let file_name = crate::filename::native_bytes(first.file_name()?).ok()?;
    match split_rar_suffix(file_name) {
        (stem, suffix) if !suffix.is_empty() => part_number(stem).map(|(_, digits)| digits.len()),
        (stem, _) => {
            split_sfx_suffix(stem).map(|(stem, _)| part_number(stem).expect("part").1.len())
        }
    }
}

/// `name.partN` and the `.rar` its later volumes take, when the name is `name.partN.exe` or `.sfx`.
fn split_sfx_suffix(file_name: &[u8]) -> Option<(&[u8], &'static str)> {
    let start = file_name.len().checked_sub(4)?;
    let (stem, extension) = file_name.split_at(start);
    if !is_sfx_extension(extension) {
        return None;
    }
    part_number(stem)?;
    let upper = extension.iter().all(|byte| !byte.is_ascii_lowercase());
    Some((stem, if upper { ".RAR" } else { ".rar" }))
}

/// `.exe` or `.sfx` in any case: the names RAR gives a self-extracting first volume.
pub fn is_sfx_extension(extension: &[u8]) -> bool {
    extension.eq_ignore_ascii_case(b".exe") || extension.eq_ignore_ascii_case(b".sfx")
}

/// The name without a trailing `.rar`, and that `.rar` as written (empty when absent).
fn split_rar_suffix(file_name: &[u8]) -> (&[u8], &str) {
    match file_name.len().checked_sub(4) {
        Some(start) if file_name[start..].eq_ignore_ascii_case(b".rar") => (
            &file_name[..start],
            std::str::from_utf8(&file_name[start..]).expect("ASCII suffix"),
        ),
        _ => (file_name, ""),
    }
}

fn part_number(stem: &[u8]) -> Option<(&[u8], &[u8])> {
    let pos = stem
        .windows(5)
        .rposition(|s| s.eq_ignore_ascii_case(b".part"))?;
    let digits = &stem[pos + 5..];
    (!digits.is_empty() && digits.iter().all(u8::is_ascii_digit)).then(|| (&stem[..pos], digits))
}
