//! The names RAR gives the volumes of a set, derived from the first volume's path.

use std::path::{Path, PathBuf};

/// Volume `index` as `.rar`, `.r00`, ..., `.r99`, with `.R00` after `.RAR`; RAR documents no name past `.r99`.
pub fn old_style(first: &Path, index: usize) -> Option<PathBuf> {
    let Some(number) = index.checked_sub(1) else {
        return Some(first.to_path_buf());
    };
    if number > 99 {
        return None;
    }
    let letter = match first
        .extension()
        .and_then(|extension| extension.as_encoded_bytes().first())
    {
        Some(b'R') => 'R',
        _ => 'r',
    };
    Some(first.with_extension(format!("{letter}{number:02}")))
}

/// Volume `index` as `name.partN.rar`, keeping the first volume's `.RAR` case as RAR does.
pub fn part_style(first: &Path, index: usize, width: usize) -> Option<PathBuf> {
    let file_name = crate::filename::native_bytes(first.file_name()?).ok()?;
    let (stem, suffix) = split_rar_suffix(file_name);
    let stem = part_number(stem).map_or(stem, |(base, _)| base);
    // Removing ASCII suffixes from a native name keeps it native.
    let mut name = crate::filename::native_string(stem).ok()?;
    let suffix = if suffix.is_empty() { ".rar" } else { suffix };
    name.push(format!(".part{:0width$}{suffix}", index + 1));
    Some(first.with_file_name(name))
}

/// The digit count of the first volume's `.partN.rar` number, if it has one.
pub fn part_width(first: &Path) -> Option<usize> {
    let file_name = crate::filename::native_bytes(first.file_name()?).ok()?;
    match split_rar_suffix(file_name) {
        (stem, suffix) if !suffix.is_empty() => part_number(stem).map(|(_, digits)| digits.len()),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_style_names_stop_at_r99() {
        let first = Path::new("dir/set.rar");
        for (index, expected) in [(0, "dir/set.rar"), (1, "dir/set.r00"), (100, "dir/set.r99")] {
            assert_eq!(
                old_style(first, index).as_deref(),
                Some(Path::new(expected))
            );
        }
        assert_eq!(old_style(first, 101), None);
        for (input, expected) in [
            ("set.RAR", "set.R00"),
            ("set.Rar", "set.R00"),
            ("set.rAR", "set.r00"),
            ("set", "set.r00"),
        ] {
            assert_eq!(
                old_style(Path::new(input), 1).as_deref(),
                Some(Path::new(expected))
            );
        }
    }

    #[test]
    fn part_style_names_replace_the_first_part_number() {
        for (input, index, width, expected) in [
            ("set.part01.rar", 1, 2, "set.part02.rar"),
            ("set.part01.rar", 99, 2, "set.part100.rar"),
            ("set.part001.rar", 1, 3, "set.part002.rar"),
            ("set.RAR", 0, 2, "set.part01.RAR"),
            ("set.PART009.RAR", 0, 2, "set.part01.RAR"),
            ("set.part.rar", 0, 2, "set.part.part01.rar"),
            ("set", 0, 2, "set.part01.rar"),
            ("set.bin", 0, 2, "set.bin.part01.rar"),
            ("set.part2.part3.rar", 0, 2, "set.part2.part01.rar"),
            ("dir/set.rar", 9, 3, "dir/set.part010.rar"),
        ] {
            assert_eq!(
                part_style(Path::new(input), index, width).as_deref(),
                Some(Path::new(expected)),
                "{input}"
            );
        }
        assert_eq!(part_style(Path::new("/"), 0, 2), None);
    }

    #[test]
    fn part_width_counts_the_first_part_digits() {
        for (input, expected) in [
            ("set.part1.rar", Some(1)),
            ("set.part01.RAR", Some(2)),
            ("set.part001.rar", Some(3)),
            ("set.rar", None),
            ("set.part.rar", None),
            ("set.partx.rar", None),
            ("set.part01", None),
        ] {
            assert_eq!(part_width(Path::new(input)), expected, "{input}");
        }
    }
}
