use crate::CliResult;
use rars_crc32::crc32;
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
    let file_name = first_path
        .file_name()
        .ok_or("RAR 5 volume path needs a file name")?
        .to_string_lossy();
    let stem = rar50_volume_stem(&file_name);
    let width = total_parts.to_string().len().max(2);
    Ok(parent.join(format!(
        "{stem}.part{:0width$}.rar",
        index + 1,
        width = width
    )))
}

fn rar50_volume_stem(file_name: &str) -> &str {
    let without_rar = file_name
        .strip_suffix(".rar")
        .or_else(|| file_name.strip_suffix(".RAR"))
        .unwrap_or(file_name);
    if let Some((base, digits)) = without_rar.rsplit_once(".part") {
        if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return base;
        }
    }
    without_rar
}

pub(crate) fn sort_volume_paths(paths: &mut [String]) {
    paths.sort_by(|a, b| {
        volume_sort_key(Path::new(a))
            .cmp(&volume_sort_key(Path::new(b)))
            .then_with(|| a.cmp(b))
    });
}

pub(crate) fn discover_sibling_volumes(first_path: &str) -> Vec<String> {
    let first = Path::new(first_path);
    let parent = first.parent().unwrap_or_else(|| Path::new("."));
    let Some(first_key) = volume_name_key(first) else {
        return vec![first_path.to_string()];
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return vec![first_path.to_string()];
    };
    let mut paths = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if volume_name_key(&path).as_ref() == Some(&first_key) && volume_sort_key(&path).is_some() {
            paths.push(path.to_string_lossy().into_owned());
        }
    }
    if paths.is_empty() {
        paths.push(first_path.to_string());
    }
    sort_volume_paths(&mut paths);
    paths
}

fn volume_name_key(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let lower = name.to_ascii_lowercase();
    if let Some((base, suffix)) = lower.rsplit_once(".part") {
        if suffix.ends_with(".rar")
            && suffix[..suffix.len() - 4]
                .bytes()
                .all(|b| b.is_ascii_digit())
        {
            return Some(format!("part:{}", &name[..base.len()]));
        }
    }
    if lower.ends_with(".rar") {
        return Some(format!("old:{}", &name[..name.len() - 4]));
    }
    if let Some((base, ext)) = lower.rsplit_once('.') {
        if ext.len() == 3 && ext.starts_with('r') && ext[1..].bytes().all(|b| b.is_ascii_digit()) {
            return Some(format!("old:{}", &name[..base.len()]));
        }
    }
    None
}

fn volume_sort_key(path: &Path) -> Option<usize> {
    let name = path.file_name()?.to_string_lossy();
    let lower = name.to_ascii_lowercase();
    if let Some(part_pos) = lower.rfind(".part") {
        let suffix = &lower[part_pos + ".part".len()..];
        if let Some(digits) = suffix.strip_suffix(".rar") {
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                return digits.parse::<usize>().ok()?.checked_sub(1);
            }
        }
    }
    if lower.ends_with(".rar") {
        return Some(0);
    }
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    if ext.len() == 3 && ext.starts_with('r') {
        return ext[1..].parse::<usize>().ok().map(|index| index + 1);
    }
    None
}

pub(crate) fn path_has_extension(path: &str, extension: &str) -> bool {
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
    let stem = path.file_stem()?.to_string_lossy();
    let bytes = stem.as_bytes();
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
        let number = stem[cursor..end].parse::<usize>().ok()?;
        numbers.push(number);
    }
    if numbers.len() != 3 || numbers.iter().any(|&number| number == 0 || number > 255) {
        return None;
    }
    Some((numbers[0] - 1, numbers[1], numbers[2]))
}

pub(crate) fn infer_part_index(path: &Path, data_count: u16) -> Option<usize> {
    let name = path.file_name()?.to_string_lossy();
    let index = if let Some(part_pos) = name.find(".part") {
        let suffix = &name[part_pos + ".part".len()..];
        if suffix.len() <= 4 || !suffix[suffix.len() - 4..].eq_ignore_ascii_case(".rar") {
            return None;
        }
        let digits = &suffix[..suffix.len() - 4];
        if digits.is_empty() || !digits.chars().all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        digits.parse::<usize>().ok()?.checked_sub(1)?
    } else {
        let ext = path.extension()?.to_str()?;
        if ext.eq_ignore_ascii_case("rar") {
            0
        } else if ext.len() == 3 && ext.starts_with(['r', 'R']) {
            let number = ext[1..].parse::<usize>().ok()?;
            number + 1
        } else {
            return None;
        }
    };
    (index < usize::from(data_count)).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_name_key_preserves_base_case() {
        assert_eq!(
            volume_name_key(Path::new("setup.rar")).as_deref(),
            Some("old:setup")
        );
        assert_eq!(
            volume_name_key(Path::new("Setup.rar")).as_deref(),
            Some("old:Setup")
        );
        assert_eq!(
            volume_name_key(Path::new("setup.R00")).as_deref(),
            Some("old:setup")
        );
        assert_eq!(
            volume_name_key(Path::new("setup.part1.rar")).as_deref(),
            Some("part:setup")
        );
    }

    #[test]
    fn discover_sibling_volumes_does_not_merge_case_distinct_bases() {
        let dir = std::env::temp_dir().join(format!("rars-volume-case-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let lower = dir.join("setup.rar");
        let upper = dir.join("Setup.rar");
        fs::write(&lower, []).unwrap();
        fs::write(&upper, []).unwrap();

        let discovered = discover_sibling_volumes(&lower.to_string_lossy());

        let _ = fs::remove_dir_all(&dir);
        assert_eq!(discovered, vec![lower.to_string_lossy().into_owned()]);
    }

    #[test]
    fn discover_sibling_volumes_does_not_merge_part_and_plain_rar_names() {
        let dir = std::env::temp_dir().join(format!("rars-volume-style-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let plain = dir.join("setup.rar");
        let part = dir.join("setup.part1.rar");
        fs::write(&plain, []).unwrap();
        fs::write(&part, []).unwrap();

        let discovered = discover_sibling_volumes(&plain.to_string_lossy());

        let _ = fs::remove_dir_all(&dir);
        assert_eq!(discovered, vec![plain.to_string_lossy().into_owned()]);
    }
}
