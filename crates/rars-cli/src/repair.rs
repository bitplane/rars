use crate::cli::RepairArgs;
use crate::password::read_archive_path_prompting;
use crate::volumes::{infer_part_index, parse_rar3_rev_volume, path_has_extension};
use crate::{resolve_password_args, CliError, CliResult};
use rars::crc32::crc32;
use rars::Error;
use std::fs;
use std::path::{Path, PathBuf};

const RAR50_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";

pub(crate) fn cmd_repair(args: RepairArgs) -> CliResult<()> {
    let mut password = resolve_password_args(&args.password)?;
    let paths = args.paths;
    if paths.len() > 2 {
        if password.is_some() {
            return Err("REV repair does not use archive passwords".into());
        }
        return cmd_repair_volumes(&paths);
    }
    let archive = read_archive_path_prompting(&paths[0], &mut password);
    match archive {
        Ok(archive) => {
            let report = crate::write_archive_file(&paths[1], |output| {
                archive
                    .repair_recovery_to_with_report(
                        output,
                        crate::password::password_bytes(&password),
                    )
                    .map_err(|err| {
                        CliError::general(format!(
                            "failed to repair archive '{}': {err}",
                            paths[0].display()
                        ))
                    })
            })?;
            print_repair_report(&paths[1], report);
        }
        Err(parse_error) => {
            if !path_starts_with(&paths[0], RAR50_SIGNATURE)? {
                return Err(parse_error);
            }
            let bytes = fs::read(&paths[0])?;
            let options = match crate::password::password_bytes(&password) {
                Some(password) => rars::ArchiveReadOptions::with_password(password),
                None => rars::ArchiveReadOptions::new(),
            };
            let repaired = rars::rar50::repair_inline_recovery_bytes_with_options(&bytes, options)
                .map_err(|repair_error| {
                    format!(
                        "failed to parse archive '{}': {}; raw inline recovery repair also failed: {}",
                        paths[0].display(), parse_error, repair_error
                    )
                })?;
            let report = crate::write_archive_file(&paths[1], |output| {
                output.write_all(&repaired.data)?;
                Ok(repaired.report)
            })?;
            print_repair_report(&paths[1], report);
        }
    }
    Ok(())
}

fn print_repair_report(path: &Path, report: rars::RecoveryRepairReport) {
    let path = path.display();
    let mut actions = Vec::new();
    if report.data_repaired {
        actions.push("repaired protected data");
    }
    if report.recovery_record_rebuilt {
        actions.push("rebuilt recovery record");
    }
    if report.end_record_rebuilt {
        actions.push("rebuilt archive end");
    }
    if actions.is_empty() {
        println!("no repair needed; wrote {path}");
    } else {
        println!("{}; wrote {path}", actions.join(", "));
    }
}

fn path_starts_with(path: &Path, prefix: &[u8]) -> CliResult<bool> {
    let mut file = fs::File::open(path)?;
    let mut buf = vec![0; prefix.len()];
    let read = std::io::Read::read(&mut file, &mut buf)?;
    Ok(read == prefix.len() && buf == prefix)
}

fn cmd_repair_volumes(paths: &[PathBuf]) -> CliResult<()> {
    let input_paths = &paths[..paths.len() - 1];
    for path in input_paths {
        if path_has_extension(path, "rev") {
            let bytes = fs::read(path)?;
            if rars::rar50::Rev5Volume::parse(&bytes).is_ok() {
                return cmd_repair_rev5(paths);
            }
        }
    }
    cmd_repair_rev3(paths)
}

fn cmd_repair_rev5(paths: &[PathBuf]) -> CliResult<()> {
    // Invariant: cmd_repair dispatches here only after checking at least two paths.
    let out_dir = PathBuf::from(paths.last().expect("outdir"));
    fs::create_dir_all(&out_dir)?;
    let input_paths = &paths[..paths.len() - 1];
    let mut data_inputs = Vec::new();
    let mut recovery = Vec::new();
    for path in input_paths {
        let bytes = fs::read(path)?;
        match rars::rar50::Rev5Volume::parse(&bytes) {
            Ok(rev) => recovery.push(rev),
            Err(Error::UnsupportedSignature) => data_inputs.push((PathBuf::from(path), bytes)),
            Err(error) => {
                return Err(CliError::general(format!(
                    "failed to parse REV volume '{}': {error}",
                    path.display()
                )))
            }
        }
    }
    let first = recovery
        .first()
        .ok_or("RAR 5 REV repair requires at least one .rev file")?;
    let mut slots: Vec<Option<&[u8]>> = vec![None; usize::from(first.data_count)];
    for (path, bytes) in &data_inputs {
        if let Some(index) = infer_part_index(path, first.data_count) {
            slots[index] = Some(bytes.as_slice());
            continue;
        }
        if let Some((index, _)) =
            first.data_volumes.iter().enumerate().find(|(_, meta)| {
                bytes.len() as u64 == meta.file_size && crc32(bytes) == meta.crc32
            })
        {
            slots[index] = Some(bytes.as_slice());
        }
    }

    rars::rar50::repair_rev5_volumes_to(&slots, &recovery, |index, bytes| {
        let path =
            repaired_volume_path(&out_dir, &data_inputs, index, usize::from(first.data_count));
        fs::write(&path, bytes)?;
        println!("repaired {}", path.display());
        Ok(())
    })
    .map_err(|err| CliError::general(format!("failed to repair RAR 5 REV volume set: {err}")))?;
    Ok(())
}

fn cmd_repair_rev3(paths: &[PathBuf]) -> CliResult<()> {
    // Invariant: cmd_repair dispatches here only after checking at least two paths.
    let out_dir = PathBuf::from(paths.last().expect("outdir"));
    fs::create_dir_all(&out_dir)?;
    let input_paths = &paths[..paths.len() - 1];
    let mut data_inputs = Vec::new();
    let mut recovery_inputs = Vec::new();
    let mut data_count = None;
    let mut recovery_count = None;

    for path in input_paths {
        let bytes = fs::read(path)?;
        if path_has_extension(path, "rev") {
            let (recovery_index, rec_count, dat_count, payload) =
                parse_rar3_rev_volume(Path::new(path), &bytes).ok_or_else(|| {
                    CliError::general(format!(
                        "failed to parse RAR 3 REV volume name '{}'",
                        path.display()
                    ))
                })?;
            if recovery_count
                .replace(rec_count)
                .is_some_and(|count| count != rec_count)
                || data_count
                    .replace(dat_count)
                    .is_some_and(|count| count != dat_count)
            {
                return Err("RAR 3 REV volume metadata differs across files".into());
            }
            recovery_inputs.push((recovery_index, payload));
        } else {
            data_inputs.push((PathBuf::from(path), bytes));
        }
    }

    let data_count = data_count.ok_or("RAR 3 REV repair requires at least one .rev file")?;
    let recovery_count =
        recovery_count.ok_or("RAR 3 REV repair requires at least one .rev file")?;
    let mut slots: Vec<Option<&[u8]>> = vec![None; data_count];
    for (path, bytes) in &data_inputs {
        if let Some(index) = infer_part_index(path, data_count as u16) {
            slots[index] = Some(bytes.as_slice());
        }
    }
    let recovery: Vec<(usize, &[u8])> = recovery_inputs
        .iter()
        .map(|(index, bytes)| (*index, bytes.as_slice()))
        .collect();
    rars::rar15_40::repair_rev3_volumes_to(&slots, recovery_count, &recovery, |index, bytes| {
        let path = repaired_volume_path(&out_dir, &data_inputs, index, data_count);
        fs::write(&path, bytes)?;
        println!("repaired {}", path.display());
        Ok(())
    })
    .map_err(|err| CliError::general(format!("failed to repair RAR 3 REV volume set: {err}")))?;
    Ok(())
}

fn repaired_volume_path(
    out_dir: &Path,
    data_inputs: &[(PathBuf, Vec<u8>)],
    index: usize,
    data_count: usize,
) -> PathBuf {
    let Some(first_path) = data_inputs.first().map(|(path, _)| path) else {
        return out_dir.join(format!("repaired.part{}.rar", index + 1));
    };
    let Some(file_name) = first_path.file_name().and_then(|name| name.to_str()) else {
        return out_dir.join(format!("repaired.part{}.rar", index + 1));
    };
    let lower = file_name.to_ascii_lowercase();
    if let Some(part_pos) = lower.rfind(".part") {
        if lower.ends_with(".rar") {
            let digits = &file_name[part_pos + ".part".len()..file_name.len() - 4];
            if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
                let width = digits.len().max(data_count.to_string().len());
                return out_dir.join(format!(
                    "{}.part{:0width$}.rar",
                    &file_name[..part_pos],
                    index + 1,
                    width = width
                ));
            }
        }
    }
    if lower.ends_with(".rar")
        || lower.rsplit_once('.').is_some_and(|(_, ext)| {
            ext.len() == 3
                && ext.starts_with('r')
                && ext[1..].bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        let first_out = out_dir.join(file_name);
        return crate::volumes::volume_part_path(&first_out, index)
            .unwrap_or_else(|_| out_dir.join(format!("repaired.part{}.rar", index + 1)));
    }
    out_dir.join(format!("repaired.part{}.rar", index + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repair(input: &Path, output: &Path) -> CliResult<()> {
        cmd_repair(RepairArgs {
            password: crate::cli::PasswordArgs {
                password: None,
                password_file: None,
            },
            paths: vec![input.to_path_buf(), output.to_path_buf()],
        })
    }

    fn destinations(root: &Path, input: &Path) -> Vec<PathBuf> {
        let output = root.join("existing.rar");
        fs::write(&output, b"existing destination").unwrap();
        let paths = vec![output, input.to_path_buf()];
        #[cfg(unix)]
        let paths = {
            let mut paths = paths;
            let hard = root.join("hard.rar");
            fs::hard_link(input, &hard).unwrap();
            let symbolic = root.join("symbolic.rar");
            std::os::unix::fs::symlink(input, &symbolic).unwrap();
            paths.extend([hard, symbolic]);
            paths
        };
        paths
    }

    #[test]
    fn repair_failure_preserves_existing_files() {
        let root = crate::scratch::case("repair-preserves-failure");
        let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar50).store(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let original = builder.to_bytes().unwrap();
        let input = root.join("input.rar");
        fs::write(&input, &original).unwrap();
        for output in destinations(&root, &input) {
            let previous = fs::read(&output).unwrap();
            let error = repair(&input, &output).unwrap_err();
            assert!(error.to_string().contains("failed to repair archive"));
            assert_eq!(fs::read(&output).unwrap(), previous);
            assert_eq!(fs::read(&input).unwrap(), original);
        }
        assert!(fs::read_dir(&*root).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".rars-writing-")));
    }

    #[test]
    fn repair_success_replaces_destination_without_truncating_aliases() {
        let root = crate::scratch::case("repair-safe-aliases");
        let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar50)
            .store(true)
            .recovery_percent(Some(20));
        builder
            .add_bytes(b"file".to_vec(), vec![b'p'; 4096], None, None)
            .unwrap();
        let original = builder.to_bytes().unwrap();
        let archive = rars::ArchiveReader::read_owned(original.clone()).unwrap();
        let range = archive
            .as_rar50()
            .unwrap()
            .files()
            .next()
            .unwrap()
            .block
            .data_range
            .clone();
        let mut damaged = original.clone();
        damaged[range.start + 16..range.start + 32].fill(0xa5);
        let input = root.join("input.rar");
        fs::write(&input, &damaged).unwrap();
        let paths = destinations(&root, &input);
        for output in paths
            .iter()
            .filter(|path| **path != input)
            .chain(std::iter::once(&input))
        {
            repair(&input, output).unwrap();
            assert_eq!(fs::read(output).unwrap(), original);
            if output != &input {
                assert_eq!(fs::read(&input).unwrap(), damaged);
            }
            assert!(!fs::symlink_metadata(output)
                .unwrap()
                .file_type()
                .is_symlink());
        }
        assert!(fs::read_dir(&*root).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".rars-writing-")));
    }
}
