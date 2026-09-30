use crate::CliResult;
use rars::crc32::crc32;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn volume_part_path(first_path: &Path, index: usize) -> CliResult<PathBuf> {
    if index == 0 {
        return Ok(first_path.to_path_buf());
    }
    // Extension-based RAR volume names are finite: first .rar, then .r00
    // through .r99. Later RAR families use part-number names instead.
    if index > 100 {
        return Err("RAR 1.4 old-style volume names only support .r00 through .r99 here".into());
    }
    Ok(first_path.with_extension(format!("r{:02}", index - 1)))
}

pub(crate) fn rar50_volume_part_path(
    first_path: &Path,
    index: usize,
    total_parts: usize,
) -> CliResult<PathBuf> {
    let parent = first_path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = rars::filename::native_bytes(
        first_path
            .file_name()
            .ok_or("RAR 5 volume path needs a file name")?,
    )?;
    let stem = rar50_volume_stem(file_name);
    let width = total_parts.to_string().len().max(2);
    let mut name = rars::filename::native_string(stem)?;
    name.push(format!(".part{:0width$}.rar", index + 1));
    Ok(parent.join(name))
}

fn rar50_volume_stem(file_name: &[u8]) -> &[u8] {
    let without_rar =
        if file_name.len() >= 4 && file_name[file_name.len() - 4..].eq_ignore_ascii_case(b".rar") {
            &file_name[..file_name.len() - 4]
        } else {
            file_name
        };
    if let Some(pos) = without_rar
        .windows(5)
        .rposition(|s| s.eq_ignore_ascii_case(b".part"))
    {
        let digits = &without_rar[pos + 5..];
        if !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) {
            return &without_rar[..pos];
        }
    }
    without_rar
}

pub(crate) fn sort_volume_paths(paths: &mut [PathBuf]) {
    paths.sort_by(|a, b| {
        volume_sort_key(Path::new(a))
            .cmp(&volume_sort_key(Path::new(b)))
            .then_with(|| a.cmp(b))
    });
}

pub(crate) fn discover_sibling_volumes(first_path: &Path) -> Vec<PathBuf> {
    let first = Path::new(first_path);
    let parent = first
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let Some(first_key) = volume_name_key(first) else {
        return vec![first_path.to_path_buf()];
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return vec![first_path.to_path_buf()];
    };
    let mut paths = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if volume_name_key(&path).as_ref() == Some(&first_key) && volume_sort_key(&path).is_some() {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        paths.push(first_path.to_path_buf());
    }
    sort_volume_paths(&mut paths);
    paths
}

fn volume_name_key(path: &Path) -> Option<Vec<u8>> {
    let name = rars::filename::native_bytes(path.file_name()?).ok()?;
    let lower = name.to_ascii_lowercase();
    if let Some(pos) = lower.windows(5).rposition(|s| s == b".part") {
        let suffix = &lower[pos + 5..];
        if let Some(digits) = suffix.strip_suffix(b".rar") {
            if !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) {
                return Some([b"part:".as_slice(), &name[..pos]].concat());
            }
        }
    }
    if lower.ends_with(b".rar")
        || (lower.len() >= 4
            && lower[lower.len() - 4..lower.len() - 2] == *b".r"
            && lower[lower.len() - 2..].iter().all(u8::is_ascii_digit))
    {
        return Some([b"old:".as_slice(), &name[..name.len() - 4]].concat());
    }
    None
}

fn volume_sort_key(path: &Path) -> Option<usize> {
    let name = rars::filename::native_bytes(path.file_name()?).ok()?;
    let lower = name.to_ascii_lowercase();
    if let Some(pos) = lower.windows(5).rposition(|s| s == b".part") {
        if let Some(digits) = lower[pos + 5..].strip_suffix(b".rar") {
            return std::str::from_utf8(digits)
                .ok()?
                .parse::<usize>()
                .ok()?
                .checked_sub(1);
        }
    }
    if lower.ends_with(b".rar") {
        return Some(0);
    }
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    if ext.len() == 3 && ext.starts_with('r') {
        return ext[1..].parse::<usize>().ok().map(|index| index + 1);
    }
    None
}

pub(crate) fn path_has_extension(path: &Path, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
}

pub(crate) fn parse_rar3_rev_volume(
    path: &Path,
    bytes: &[u8],
) -> Option<(usize, usize, usize, Vec<u8>)> {
    if let Some((recovery_index, recovery_count, data_count)) = parse_rar3_new_style_rev(bytes) {
        let mut payload = bytes[..bytes.len() - 7].to_vec();
        payload.extend_from_slice(&[0; 7]);
        return Some((recovery_index, recovery_count, data_count, payload));
    }
    let (recovery_index, recovery_count, data_count) = parse_rar3_old_style_rev_name(path)?;
    Some((recovery_index, recovery_count, data_count, bytes.to_vec()))
}

fn parse_rar3_new_style_rev(bytes: &[u8]) -> Option<(usize, usize, usize)> {
    if bytes.len() < 7 {
        return None;
    }
    let trailer = &bytes[bytes.len() - 7..];
    let stored_crc = u32::from_le_bytes(trailer[3..7].try_into().ok()?);
    if crc32(&bytes[..bytes.len() - 4]) != stored_crc {
        return None;
    }
    let recovery_index = usize::from(trailer[2]);
    let recovery_count = usize::from(trailer[1]) + 1;
    let data_count = usize::from(trailer[0]) + 1;
    Some((recovery_index, recovery_count, data_count))
}

fn parse_rar3_old_style_rev_name(path: &Path) -> Option<(usize, usize, usize)> {
    let bytes = rars::filename::native_bytes(path.file_stem()?).ok()?;
    let mut cursor = bytes.len();
    let mut numbers = Vec::new();
    while cursor > 0 && numbers.len() < 3 {
        while cursor > 0 && !bytes[cursor - 1].is_ascii_digit() {
            cursor -= 1;
        }
        if cursor == 0 {
            break;
        }
        let end = cursor;
        while cursor > 0 && bytes[cursor - 1].is_ascii_digit() {
            cursor -= 1;
        }
        let number = std::str::from_utf8(&bytes[cursor..end])
            .ok()?
            .parse::<usize>()
            .ok()?;
        numbers.push(number);
    }
    if numbers.len() != 3 || numbers.iter().any(|&number| number == 0 || number > 255) {
        return None;
    }
    Some((numbers[0] - 1, numbers[1], numbers[2]))
}

pub(crate) fn infer_part_index(path: &Path, data_count: u16) -> Option<usize> {
    let index = volume_sort_key(path)?;
    (index < usize::from(data_count)).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_volume_names_observe_format_boundaries() {
        let first = Path::new("dir/set.rar");
        assert_eq!(volume_part_path(first, 0).unwrap(), first);
        assert_eq!(
            volume_part_path(first, 1).unwrap(),
            Path::new("dir/set.r00")
        );
        assert_eq!(
            volume_part_path(first, 100).unwrap(),
            Path::new("dir/set.r99")
        );
        assert!(volume_part_path(first, 101).is_err());
        for (input, expected) in [
            ("set.RAR", "set.part01.rar"),
            ("set.PART009.RAR", "set.part01.rar"),
            ("set.part.rar", "set.part.part01.rar"),
            ("set.partx.rar", "set.partx.part01.rar"),
            ("set", "set.part01.rar"),
            ("set.part2.part3.rar", "set.part2.part01.rar"),
        ] {
            assert_eq!(
                rar50_volume_part_path(Path::new(input), 0, 2).unwrap(),
                Path::new(expected)
            );
        }
        assert_eq!(
            rar50_volume_part_path(first, 9, 100).unwrap(),
            Path::new("dir/set.part010.rar")
        );
        assert!(rar50_volume_part_path(Path::new("/"), 0, 1).is_err());
    }

    #[test]
    fn volume_indices_reject_invalid_and_out_of_range_names() {
        for (name, expected) in [
            ("set.rar", Some(0)),
            ("set.R99", Some(100)),
            ("set.part2.rar", Some(1)),
            ("set.part0.rar", None),
            ("set.part.rar", None),
            ("set.partx.rar", None),
            ("set.part999999999999999999999999999999.rar", None),
            ("set.rx0", None),
            ("set.r100", None),
            ("set.txt", None),
            ("set", None),
            ("/", None),
        ] {
            assert_eq!(volume_sort_key(Path::new(name)), expected, "{name}");
        }
        assert_eq!(infer_part_index(Path::new("set.part2.rar"), 2), Some(1));
        assert_eq!(infer_part_index(Path::new("set.part2.rar"), 1), None);
        assert_eq!(infer_part_index(Path::new("set.rar"), 0), None);
        assert!(path_has_extension(Path::new("set.REV"), "rev"));
        assert!(!path_has_extension(Path::new("set"), "rev"));
        let mut paths = vec![
            PathBuf::from("set.part10.rar"),
            PathBuf::from("set.part2.rar"),
            PathBuf::from("set.part1.rar"),
        ];
        sort_volume_paths(&mut paths);
        assert_eq!(
            paths,
            ["set.part1.rar", "set.part2.rar", "set.part10.rar"].map(PathBuf::from)
        );
    }

    #[test]
    fn discovery_falls_back_and_excludes_invalid_part_numbers() {
        let dir = crate::scratch::case("volume-discovery-fallbacks");
        for name in [
            "set.part1.rar",
            "set.part02.rar",
            "set.part0.rar",
            "set.partx.rar",
            "set.part999999999999999999999999999999.rar",
            "other.part1.rar",
        ] {
            fs::write(dir.join(name), []).unwrap();
        }
        assert_eq!(
            discover_sibling_volumes(&dir.join("set.part1.rar")),
            vec![dir.join("set.part1.rar"), dir.join("set.part02.rar")]
        );
        for path in [
            dir.join("not-a-volume.bin"),
            dir.join("absent.rar"),
            dir.join("missing-parent/set.rar"),
            PathBuf::from("/"),
        ] {
            assert_eq!(discover_sibling_volumes(&path), vec![path]);
        }
        assert_eq!(
            discover_sibling_volumes(Path::new("not-a-volume.bin")),
            vec![PathBuf::from("not-a-volume.bin")]
        );
    }

    #[test]
    fn malformed_suffixes_and_equal_indices_have_deterministic_order() {
        for name in [
            "x",
            "set.part",
            "set.partx",
            "set.part.rar",
            "set.partx.rar",
            "set.rx0",
        ] {
            assert_eq!(
                volume_name_key(Path::new(name)),
                if name.ends_with(".rar") {
                    Some([b"old:".as_slice(), &name.as_bytes()[..name.len() - 4]].concat())
                } else {
                    None
                },
                "{name}"
            );
        }
        assert_eq!(volume_sort_key(Path::new("set.part")), None);
        assert_eq!(volume_sort_key(Path::new("set.partx")), None);
        let mut paths = [
            PathBuf::from("set.part01.rar"),
            PathBuf::from("set.part1.rar"),
        ];
        let expected = paths.clone();
        paths.reverse();
        sort_volume_paths(&mut paths);
        assert_eq!(paths, expected);
        assert_eq!(
            parse_rar3_old_style_rev_name(Path::new("4_2_1.rev")),
            Some((0, 2, 4))
        );
        assert_eq!(parse_rar3_old_style_rev_name(Path::new("123.rev")), None);
        assert_eq!(parse_rar3_old_style_rev_name(Path::new(".rev")), None);
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let name = Path::new(OsStr::from_bytes(b"set.part\xff.rar"));
            assert_eq!(volume_sort_key(name), None);
            assert!(!path_has_extension(
                Path::new(OsStr::from_bytes(b"set.\xff")),
                "rev"
            ));
            assert_eq!(
                volume_sort_key(Path::new(OsStr::from_bytes(b"set.\xff"))),
                None
            );
        }
    }

    #[test]
    fn rev_trailer_crc_and_old_style_metadata_boundaries() {
        let mut bytes = b"recovery payload".to_vec();
        bytes.extend_from_slice(&[3, 1, 1]);
        let crc = crc32(&bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        let (index, recovery, data, payload) =
            parse_rar3_rev_volume(Path::new("unnamed.rev"), &bytes).unwrap();
        assert_eq!((index, recovery, data), (1, 2, 4));
        assert_eq!(&payload[..payload.len() - 7], b"recovery payload");
        assert_eq!(&payload[payload.len() - 7..], &[0; 7]);
        bytes[0] ^= 1;
        assert!(parse_rar3_rev_volume(Path::new("unnamed.rev"), &bytes).is_none());
        assert_eq!(
            parse_rar3_rev_volume(Path::new("set_4_2_1.rev"), &bytes).unwrap(),
            (0, 2, 4, bytes)
        );
        assert!(parse_rar3_rev_volume(Path::new("unnamed.rev"), b"short").is_none());
        for (name, expected) in [
            ("set_4_2_1.rev", Some((0, 2, 4))),
            ("set_255_255_255.rev", Some((254, 255, 255))),
            ("set_0_2_1.rev", None),
            ("set_256_2_1.rev", None),
            ("set_4_2.rev", None),
            ("set.rev", None),
            ("set_999999999999999999999999999999_2_1.rev", None),
            ("/", None),
        ] {
            assert_eq!(
                parse_rar3_old_style_rev_name(Path::new(name)),
                expected,
                "{name}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_volume_names_remain_distinct() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let dir = crate::scratch::case("native-volume-names");
        let first = dir.join(OsStr::from_bytes(b"set-\xff.part01.rar"));
        let second = dir.join(OsStr::from_bytes(b"set-\xff.part02.rar"));
        let other = dir.join(OsStr::from_bytes(b"set-\xfe.part01.rar"));
        for path in [&first, &second, &other] {
            fs::write(path, []).unwrap();
        }
        assert_eq!(
            discover_sibling_volumes(&first),
            vec![first.clone(), second.clone()]
        );
        assert_eq!(rar50_volume_part_path(&first, 1, 2).unwrap(), second);
        assert_eq!(discover_sibling_volumes(&other), vec![other]);
    }

    #[test]
    fn volume_name_key_preserves_base_case() {
        assert_eq!(
            volume_name_key(Path::new("setup.rar")).as_deref(),
            Some(b"old:setup".as_slice())
        );
        assert_eq!(
            volume_name_key(Path::new("Setup.rar")).as_deref(),
            Some(b"old:Setup".as_slice())
        );
        assert_eq!(
            volume_name_key(Path::new("setup.R00")).as_deref(),
            Some(b"old:setup".as_slice())
        );
        assert_eq!(
            volume_name_key(Path::new("setup.part1.rar")).as_deref(),
            Some(b"part:setup".as_slice())
        );
    }

    #[test]
    fn discover_sibling_volumes_does_not_merge_case_distinct_bases() {
        let dir = crate::scratch::case("rars-volume-case");
        let lower = dir.join("setup.rar");
        let upper = dir.join("Setup.rar");
        fs::write(&lower, []).unwrap();
        fs::write(&upper, []).unwrap();

        let discovered = discover_sibling_volumes(&lower);

        assert_eq!(discovered, vec![lower]);
    }

    #[test]
    fn discover_sibling_volumes_does_not_merge_part_and_plain_rar_names() {
        let dir = crate::scratch::case("rars-volume-style");
        let plain = dir.join("setup.rar");
        let part = dir.join("setup.part1.rar");
        fs::write(&plain, []).unwrap();
        fs::write(&part, []).unwrap();

        let discovered = discover_sibling_volumes(&plain);

        assert_eq!(discovered, vec![plain]);
    }
}
