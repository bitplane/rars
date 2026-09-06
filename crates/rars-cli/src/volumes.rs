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
