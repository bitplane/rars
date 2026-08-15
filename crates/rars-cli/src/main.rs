//! Command-line frontend for the `rars` RAR archive toolkit.

mod add_plan;
mod cli;
mod error;
mod input;
mod output;
mod password;
mod progress;
mod repair;
mod time;
mod volumes;

use cli::{AddArgs, Command, ExtractArgs, InfoArgs, PasswordArgs, TestArgs};
use error::{CliError, CliResult};
use input::{collect_inputs, rar15_file_attr, read_inputs_with_progress};
use output::{
    create_rar50_redirection as create_rar50_redirection_output, open_output_writer,
    output_path_for_entry, output_path_for_rar50_entry, output_relative_path, print_ok_entry,
    restore_output_metadata, warn_rar50_redirections, ExtractedOutput, OverwritePolicy,
};
use password::{
    classify_rars_error, ensure_password_for_archives_extract, ensure_password_for_extract,
    error_is_password_class, parse_archives_prompting, password_bytes, read_archive_path_prompting,
    resolve_password, Password,
};
use progress::CliProgress;
use rars::rar13::{
    self, FileEntry, StoredEntry as Rar13StoredEntry, WriterOptions as Rar13WriterOptions,
};
use rars::rar15_40::{
    FileEntry as Rar15FileEntry, StoredEntry as Rar15StoredEntry,
    WriterOptions as Rar15WriterOptions,
};
use rars::{
    extract_volumes_to_with_options, Archive as DetectedArchive, ArchiveReadOptions, ArchiveReader,
    ArchiveVersion, FeatureSet, MemberCoding,
};
use repair::cmd_repair;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use time::{current_filetime, format_filetime_utc};
use volumes::{
    discover_sibling_volumes, rar50_volume_part_path, sort_volume_paths, volume_part_path,
};

const DOS_ARCHIVE_ATTR: u8 = 0x20;
#[cfg(windows)]
const RAR50_HOST_NATIVE: u64 = 0;
#[cfg(not(windows))]
const RAR50_HOST_NATIVE: u64 = 1;
const RAR50_STRUCTURAL_RR_WARNING: &str =
    "warning: RAR 5 recovery writer emits validation-ready RR metadata; WinRAR recovery layout matching is not expected";

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(err.exit_code());
    }
}

impl From<rars::Error> for CliError {
    fn from(error: rars::Error) -> Self {
        let message = format!("{error}{}", rar50_buffered_decode_limit_hint(&error));
        if error_is_password_class(&error) {
            Self::password(message)
        } else {
            Self::general(message)
        }
    }
}

fn run() -> CliResult<()> {
    let cli = cli::parse();
    configure_threads(cli.threads)?;
    match cli.command {
        Command::Info(args) => cmd_info(args),
        Command::Test(args) => cmd_test(args),
        Command::Extract(args) => cmd_extract(args),
        Command::Repair(args) => cmd_repair(args),
        Command::Add(args) => cmd_add(args, CliProgress::new(cli.progress)),
    }
}

fn configure_threads(threads: Option<usize>) -> CliResult<()> {
    let default_threads = std::thread::available_parallelism()
        .ok()
        .map(std::num::NonZeroUsize::get);
    let mut builder = rayon::ThreadPoolBuilder::new();
    if let Some(threads) = threads.or(default_threads) {
        builder = builder.num_threads(threads);
    }
    builder
        .build_global()
        .map_err(|err| CliError::general(format!("failed to configure parallel workers: {err}")))
}

fn extract_archive_to_with_options<F>(
    archive: &DetectedArchive,
    options: ArchiveReadOptions<'_>,
    open: F,
) -> rars::Result<()>
where
    F: FnMut(&rars::ExtractedEntryMeta) -> rars::Result<Box<dyn Write>>,
{
    archive.extract_to_parallel_buffered_with_options(options, open)
}

fn extract_options(
    password: Option<&[u8]>,
    rar50_buffered_decode_limit: Option<usize>,
) -> ArchiveReadOptions<'_> {
    let options = match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    };
    match rar50_buffered_decode_limit {
        Some(limit) => options.with_rar50_buffered_decode_limit(limit as u64),
        None => options,
    }
}

fn rar50_buffered_decode_limit_hint(error: &rars::Error) -> String {
    let Some((_, required)) = find_rar50_buffered_decode_limit_error(error) else {
        return String::new();
    };
    format!(
        "\nhint: retry with --rar50-buffered-decode-limit {required} if you trust this archive and have enough memory"
    )
}

fn find_rar50_buffered_decode_limit_error(error: &rars::Error) -> Option<(u64, u64)> {
    match error {
        rars::Error::Rar50BufferedDecodeLimitExceeded { limit, required } => {
            Some((*limit, *required))
        }
        rars::Error::AtEntry { source, .. } | rars::Error::AtArchiveOffset { source, .. } => {
            find_rar50_buffered_decode_limit_error(source)
        }
        _ => None,
    }
}

fn display_text(text: impl AsRef<str>) -> String {
    let mut out = String::new();
    for ch in text.as_ref().chars() {
        // Escape control characters (e.g. terminal escape sequences) so a
        // hostile archive name can't manipulate the terminal, but pass
        // printable Unicode such as Cyrillic or CJK through unchanged.
        if ch.is_control() {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}

fn display_bytes_lossy(bytes: &[u8]) -> String {
    display_text(String::from_utf8_lossy(bytes))
}

fn cmd_info(args: InfoArgs) -> CliResult<()> {
    let mut password = resolve_password_args(&args.password)?;
    for path in &args.paths {
        let archive = read_archive_path_prompting(path, &mut password)?;
        let family = archive.family();
        if args.verbose {
            println!("{path}: {family:?} at offset {}", archive.sfx_offset());
        } else {
            print_terse_header(path, &archive);
        }
        match archive {
            DetectedArchive::Rar13(archive) => {
                if args.verbose {
                    info_rar13_verbose(path, &archive)?;
                } else {
                    info_rar13_terse(path, &archive)?;
                }
            }
            DetectedArchive::Rar15To40(archive) => {
                if args.verbose {
                    info_rar15_40_verbose(path, &archive)?;
                } else {
                    info_rar15_40_terse(path, &archive)?;
                }
            }
            DetectedArchive::Rar50Plus(archive) => {
                if args.verbose {
                    info_rar50_verbose(path, &archive, password_bytes(&password))?;
                } else {
                    info_rar50_terse(path, &archive, password_bytes(&password))?;
                }
            }
            _ => {
                return Err(CliError::general(format!(
                    "archive family {family:?} is not handled by info output"
                )));
            }
        }
    }

    Ok(())
}

fn print_terse_header(path: &str, archive: &DetectedArchive) {
    let label = match archive {
        DetectedArchive::Rar13(_) => "RAR 1.3",
        DetectedArchive::Rar15To40(_) => "RAR 1.5-4.x",
        DetectedArchive::Rar50Plus(_) => "RAR 5.0+",
        _ => "unknown",
    };
    let sfx_offset = archive.sfx_offset();
    if sfx_offset > 0 {
        println!("{path}: {label} (SFX, payload at offset {sfx_offset})");
    } else {
        println!("{path}: {label}");
    }
}

fn render_comment_safe(bytes: &[u8]) -> String {
    // Strip trailing NUL terminators, decode lossily, then escape ANSI-dangerous
    // control characters so a hostile comment can't smuggle terminal escapes
    // through us. Tabs and newlines pass through verbatim.
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let text = String::from_utf8_lossy(&bytes[..end]);
    let trimmed = text.trim_end_matches(['\0', '\r', '\n']);
    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch == '\t' || ch == '\n' || !ch.is_control() {
            out.push(ch);
        } else {
            out.push_str(&format!("\\x{:02x}", ch as u32));
        }
    }
    out
}

fn print_comment(indent: &str, bytes: &[u8]) {
    let rendered = render_comment_safe(bytes);
    if rendered.is_empty() {
        return;
    }
    if rendered.contains('\n') {
        println!("{indent}Comment:");
        for line in rendered.lines() {
            println!("{indent}  {line}");
        }
    } else {
        println!("{indent}Comment: {rendered}");
    }
}

fn print_entry_table<I>(rows: I)
where
    I: IntoIterator<Item = (u64, u64, String)>,
{
    let rows: Vec<(u64, u64, String)> = rows.into_iter().collect();
    if rows.is_empty() {
        return;
    }
    let size_w = rows
        .iter()
        .map(|(unp, _, _)| unp.to_string().len())
        .max()
        .unwrap_or(0)
        .max(4);
    let pack_w = rows
        .iter()
        .map(|(_, pack, _)| pack.to_string().len())
        .max()
        .unwrap_or(0)
        .max(6);
    println!("  {:>size_w$}  {:>pack_w$}  Name", "Size", "Packed");
    for (unp, pack, name) in &rows {
        println!("  {unp:>size_w$}  {pack:>pack_w$}  {name}");
    }
}

fn info_rar13_terse(path: &str, archive: &rars::rar13::Archive) -> CliResult<()> {
    if let Some(comment) = archive
        .archive_comment()
        .map_err(|err| format!("failed to decode archive comment '{path}': {err}"))?
    {
        print_comment("  ", &comment);
    }
    print_entry_table(archive.entries.iter().map(|entry| {
        (
            u64::from(entry.header.unp_size),
            u64::from(entry.header.pack_size),
            display_text(entry.name_lossy()),
        )
    }));
    Ok(())
}

fn info_rar13_verbose(path: &str, archive: &rars::rar13::Archive) -> CliResult<()> {
    println!(
        "  rar13 main: flags={:#04x} head_size={} sfx_offset={}",
        archive.main.flags, archive.main.head_size, archive.sfx_offset
    );
    if archive.main.has_archive_comment() {
        println!(
            "  archive comment extension: {} bytes{}",
            archive.main.extra.len(),
            if archive.main.has_packed_comment() {
                " (packed)"
            } else {
                ""
            }
        );
        if let Some(comment) = archive
            .archive_comment()
            .map_err(|err| format!("failed to decode archive comment '{path}': {err}"))?
        {
            println!("  comment: {}", display_bytes_lossy(&comment));
        }
    }
    if let Some(av) = archive
        .authenticity_verification()
        .map_err(|err| format!("failed to parse authenticity verification in '{path}': {err}"))?
    {
        println!(
            "  authenticity verification: structural size={} cipher_body={} status=not-cryptographically-verified",
            av.size,
            av.cipher_body.len()
        );
    }
    for (index, entry) in archive.entries.iter().enumerate() {
        println!(
            "  #{index}: {} pack={} unp={} method={} flags={:#04x} attr={:#04x} checksum={:#06x}",
            display_text(entry.name_lossy()),
            entry.header.pack_size,
            entry.header.unp_size,
            entry.header.method,
            entry.header.flags,
            entry.header.file_attr,
            entry.header.file_crc
        );
        if let Some(comment) = entry.file_comment().map_err(|err| {
            format!(
                "failed to decode file comment '{}' in '{path}': {err}",
                display_text(entry.name_lossy())
            )
        })? {
            println!("    comment: {}", display_bytes_lossy(&comment));
        }
    }
    Ok(())
}

fn info_rar15_40_terse(path: &str, archive: &rars::rar15_40::Archive) -> CliResult<()> {
    if let Some(comment) = archive
        .archive_comment()
        .map_err(|err| format!("failed to decode archive comment '{path}': {err}"))?
    {
        print_comment("  ", &comment);
    }
    print_entry_table(archive.files().map(|file| {
        (
            file.unp_size,
            file.pack_size,
            display_text(file.name_lossy()),
        )
    }));
    let sub_count = archive.new_subs().count();
    if sub_count > 0 {
        let kinds: Vec<String> = archive
            .new_subs()
            .map(|sub| format!("{:?}", sub.kind))
            .collect();
        println!("  Subblocks: {}", kinds.join(", "));
    }
    Ok(())
}

fn info_rar15_40_verbose(path: &str, archive: &rars::rar15_40::Archive) -> CliResult<()> {
    println!(
        "  rar15-40 main: flags={:#06x} head_size={} sfx_offset={}",
        archive.main.flags, archive.main.head_size, archive.sfx_offset
    );
    if let Some(comment) = archive
        .archive_comment()
        .map_err(|err| format!("failed to decode archive comment '{path}': {err}"))?
    {
        println!("  comment: {}", display_bytes_lossy(&comment));
    }
    for (index, file) in archive.files().enumerate() {
        println!(
            "  #{index}: {} pack={} unp={} method={:#04x} flags={:#06x} attr={:#010x} crc={:#010x} ver={}",
            display_text(file.name_lossy()),
            file.pack_size,
            file.unp_size,
            file.method,
            file.block.flags,
            file.attr,
            file.file_crc,
            file.unp_ver
        );
        if let Some(comment) = file.file_comment().map_err(|err| {
            format!(
                "failed to decode file comment '{}' in '{path}': {err}",
                display_text(file.name_lossy())
            )
        })? {
            println!("    comment: {}", display_bytes_lossy(&comment));
        }
    }
    for sub in archive.new_subs() {
        println!(
            "  subblock: {:?} {} pack={} unp={} method={:#04x} flags={:#06x}",
            sub.kind,
            display_text(sub.name_lossy()),
            sub.file.pack_size,
            sub.file.unp_size,
            sub.file.method,
            sub.file.block.flags
        );
    }
    Ok(())
}

fn info_rar50_terse(
    path: &str,
    archive: &rars::rar50::Archive,
    password: Option<&[u8]>,
) -> CliResult<()> {
    if let Some(metadata) = archive.main.archive_metadata() {
        if let Some(name) = &metadata.name {
            println!("  Archive name: {}", display_bytes_lossy(name));
        }
        if let Some(creation_time) = metadata.creation_time {
            println!("  Created: {}", format_filetime_utc(creation_time));
        }
    }
    let archive_comment = archive
        .archive_comment_with_password(password)
        .map_err(|err| format!("failed to decode archive comment '{path}': {err}"))?;
    if let Some(comment) = &archive_comment {
        print_comment("  ", comment);
    }
    print_entry_table(archive.files().map(|file| {
        let mut name = display_text(file.name_lossy());
        if let Some(redirection) = &file.redirection {
            name.push_str(" → ");
            name.push_str(&display_bytes_lossy(&redirection.target_name));
        }
        (file.unpacked_size, file.packed_size(), name)
    }));
    let suppressed_cmt = archive_comment.is_some();
    let services: Vec<&[u8]> = archive
        .services()
        .filter_map(|service| {
            if suppressed_cmt && service.name == b"CMT" {
                None
            } else {
                Some(service.name.as_slice())
            }
        })
        .collect();
    if !services.is_empty() {
        let names: Vec<String> = services.iter().map(|s| service_label(s)).collect();
        println!("  Services: {}", names.join(", "));
    }
    Ok(())
}

fn service_label(name: &[u8]) -> String {
    match name {
        b"QO" => "quick-open".to_string(),
        b"RR" => "recovery".to_string(),
        b"CMT" => "comment".to_string(),
        b"ACL" => "acl".to_string(),
        b"STM" => "stream".to_string(),
        other => display_bytes_lossy(other),
    }
}

fn info_rar50_verbose(
    path: &str,
    archive: &rars::rar50::Archive,
    password: Option<&[u8]>,
) -> CliResult<()> {
    println!(
        "  rar50 main: flags={:#06x} header_size={} sfx_offset={}",
        archive.main.archive_flags, archive.main.block.header_size, archive.sfx_offset
    );
    if let Some(metadata) = archive.main.archive_metadata() {
        if let Some(name) = &metadata.name {
            println!("  archive name: {}", display_bytes_lossy(name));
        }
        if let Some(creation_time) = metadata.creation_time {
            println!(
                "  archive creation time: {} ({creation_time:#018x})",
                format_filetime_utc(creation_time)
            );
        }
    }
    let archive_comment = archive
        .archive_comment_with_password(password)
        .map_err(|err| format!("failed to decode archive comment '{path}': {err}"))?;
    if let Some(ref comment) = archive_comment {
        println!("  comment: {}", display_bytes_lossy(comment));
    }
    for (index, file) in archive.files().enumerate() {
        let compression_info = file.decoded_compression_info().map_err(|err| {
            format!(
                "failed to decode RAR 5 compression info for '{}': {err}",
                display_text(file.name_lossy())
            )
        })?;
        println!(
            "  #{index}: {} pack={} unp={} algo={} method={} solid={} dict={} flags={:#06x} attr={:#010x} crc={}",
            display_text(file.name_lossy()),
            file.packed_size(),
            file.unpacked_size,
            compression_info.algorithm_version,
            compression_info.method,
            compression_info.solid,
            compression_info.dictionary_size,
            file.block.flags,
            file.attributes,
            file.data_crc32
                .map(|crc| format!("{crc:#010x}"))
                .unwrap_or_else(|| "none".to_string())
        );
        if let Some(redirection) = &file.redirection {
            println!(
                "       redirection: type={} flags={:#x} target={}",
                redirection.redirection_type,
                redirection.flags,
                display_bytes_lossy(&redirection.target_name)
            );
        }
    }
    let mut suppressed_archive_cmt = archive_comment.is_some();
    for service in archive.services() {
        if suppressed_archive_cmt && service.name == b"CMT" {
            suppressed_archive_cmt = false;
            continue;
        }
        println!(
            "  service: {} pack={} unp={} flags={:#06x}",
            display_text(service.name_lossy()),
            service.packed_size(),
            service.unpacked_size,
            service.block.flags
        );
    }
    Ok(())
}

fn cmd_test(args: TestArgs) -> CliResult<()> {
    let mut password = resolve_password_args(&args.password)?;
    let mut paths = args.paths;
    if paths.len() == 1 {
        let discovered = discover_sibling_volumes(&paths[0]);
        if discovered.len() > 1 {
            paths = discovered;
        }
    } else {
        sort_volume_paths(&mut paths);
    }

    if paths.len() == 1 {
        let archive = read_archive_path_prompting(&paths[0], &mut password)?;
        ensure_password_for_extract(&archive, &mut password)?;
        warn_rar50_redirections(&archive);
        let mut entries = Vec::new();
        let options = extract_options(
            password_bytes(&password),
            args.read_options.rar50_buffered_decode_limit,
        );
        extract_archive_to_with_options(&archive, options, |meta| {
            entries.push(meta.clone());
            Ok(Box::new(std::io::sink()))
        })
        .map_err(|err| {
            classify_rars_error(err, |err| {
                format!(
                    "failed to test archive '{}': {err}{}",
                    paths[0],
                    rar50_buffered_decode_limit_hint(err)
                )
            })
        })?;
        for entry in &entries {
            print_ok_entry(entry);
        }
    } else {
        let archives = parse_archives_prompting(&paths, &mut password)?;
        ensure_password_for_archives_extract(&archives, &mut password)?;
        for archive in &archives {
            warn_rar50_redirections(archive);
        }
        let mut entries = Vec::new();
        let options = extract_options(
            password_bytes(&password),
            args.read_options.rar50_buffered_decode_limit,
        );
        extract_volumes_to_with_options(&archives, options, |meta| {
            entries.push(meta.clone());
            Ok(Box::new(std::io::sink()))
        })
        .map_err(|err| {
            classify_rars_error(err, |err| {
                format!(
                    "failed to test volume set '{}': {err}{}",
                    paths.join(", "),
                    rar50_buffered_decode_limit_hint(err)
                )
            })
        })?;
        for entry in &entries {
            print_ok_entry(entry);
        }
    }
    Ok(())
}

fn cmd_extract(args: ExtractArgs) -> CliResult<()> {
    let mut password = resolve_password_args(&args.password)?;
    let overwrite: OverwritePolicy = args.overwrite.into();
    let mut paths = args.paths;
    reject_ambiguous_extract_target(&paths)?;
    // Invariant: clap enforces at least two positional paths (archive + outdir).
    let out_dir = PathBuf::from(paths.pop().expect("outdir"));
    validate_extract_destination(&out_dir)?;
    if paths.len() == 1 {
        let discovered = discover_sibling_volumes(&paths[0]);
        if discovered.len() > 1 {
            paths = discovered;
        }
    } else {
        sort_volume_paths(&mut paths);
    }

    if paths.len() == 1 {
        let archive = read_archive_path_prompting(&paths[0], &mut password)?;
        ensure_password_for_extract(&archive, &mut password)?;
        let family = archive.family();
        let state = RefCell::new(ExtractOutputState::new(&out_dir, overwrite, family));
        let options = extract_options(
            password_bytes(&password),
            args.read_options.rar50_buffered_decode_limit,
        );
        extract_single_archive(&archive, options, &state).map_err(|err| {
            classify_rars_error(err, |err| {
                format!(
                    "failed to write extracted entry to '{}': {err}{}",
                    out_dir.display(),
                    rar50_buffered_decode_limit_hint(err)
                )
            })
        })?;
        let outputs = state.into_inner().outputs;
        restore_output_metadata(&outputs).map_err(|err| {
            CliError::general(format!(
                "failed to restore extracted metadata under '{}': {err}",
                out_dir.display()
            ))
        })?;
        for output in &outputs {
            println!("x {}", display_bytes_lossy(&output.name));
        }
    } else {
        let archives = parse_archives_prompting(&paths, &mut password)?;
        ensure_password_for_archives_extract(&archives, &mut password)?;
        let family = archives
            .first()
            .map(DetectedArchive::family)
            .ok_or("no archive parts provided")?;
        let state = RefCell::new(ExtractOutputState::new(&out_dir, overwrite, family));
        let options = extract_options(
            password_bytes(&password),
            args.read_options.rar50_buffered_decode_limit,
        );
        extract_volume_archives(&archives, options, &state).map_err(|err| {
            classify_rars_error(err, |err| {
                format!(
                    "failed to extract volume set '{}': {err}{}",
                    paths.join(", "),
                    rar50_buffered_decode_limit_hint(err)
                )
            })
        })?;
        let outputs = state.into_inner().outputs;
        restore_output_metadata(&outputs).map_err(|err| {
            CliError::general(format!(
                "failed to restore extracted metadata under '{}': {err}",
                out_dir.display()
            ))
        })?;
        for output in &outputs {
            println!("x {}", display_bytes_lossy(&output.name));
        }
    }
    Ok(())
}

struct ExtractOutputState<'a> {
    out_dir: &'a Path,
    overwrite: OverwritePolicy,
    family: rars::ArchiveFamily,
    outputs: Vec<ExtractedOutput>,
    planned_paths: HashSet<PathBuf>,
    created_paths: HashMap<PathBuf, PathBuf>,
}

impl<'a> ExtractOutputState<'a> {
    fn new(out_dir: &'a Path, overwrite: OverwritePolicy, family: rars::ArchiveFamily) -> Self {
        Self {
            out_dir,
            overwrite,
            family,
            outputs: Vec::new(),
            planned_paths: HashSet::new(),
            created_paths: HashMap::new(),
        }
    }

    fn open_entry(&mut self, meta: &rars::ExtractedEntryMeta) -> rars::Result<Box<dyn Write>> {
        let planned = output_path_for_entry(self.out_dir, meta)?;
        self.reserve_output_path(planned)?;
        let (path, writer) = open_output_writer(self.out_dir, meta, self.overwrite)?;
        self.record_created_path(&meta.name, path.clone())?;
        self.outputs.push(ExtractedOutput {
            name: meta.name.clone(),
            path,
            meta: meta.clone(),
            family: self.family,
            restore_metadata: true,
        });
        Ok(writer)
    }

    fn open_rar50_entry(
        &mut self,
        meta: &rars::rar50::ExtractedEntryMeta,
    ) -> rars::Result<Box<dyn Write>> {
        let common = rar50_extracted_meta(meta);
        let planned = output_path_for_rar50_entry(self.out_dir, meta)?;
        self.reserve_output_path(planned)?;
        let (path, writer) = open_output_writer(self.out_dir, &common, self.overwrite)?;
        self.record_created_path(&meta.name, path.clone())?;
        self.outputs.push(ExtractedOutput {
            name: meta.name.clone(),
            path,
            meta: common,
            family: self.family,
            restore_metadata: true,
        });
        Ok(writer)
    }

    fn create_rar50_redirection(
        &mut self,
        meta: &rars::rar50::ExtractedEntryMeta,
        redirection: &rars::rar50::FileRedirection,
    ) -> rars::Result<()> {
        let planned = output_path_for_rar50_entry(self.out_dir, meta)?;
        self.reserve_output_path(planned)?;
        let (path, restore_metadata) = create_rar50_redirection_output(
            self.out_dir,
            meta,
            redirection,
            self.overwrite,
            &self.created_paths,
        )?;
        self.record_created_path(&meta.name, path.clone())?;
        self.outputs.push(ExtractedOutput {
            name: meta.name.clone(),
            path,
            meta: rar50_extracted_meta(meta),
            family: self.family,
            restore_metadata,
        });
        Ok(())
    }

    fn reserve_output_path(&mut self, path: PathBuf) -> rars::Result<()> {
        if !self.planned_paths.insert(path) {
            return Err(rars::Error::InvalidHeader(
                "multiple archive entries map to the same output path",
            ));
        }
        Ok(())
    }

    fn record_created_path(&mut self, name: &[u8], path: PathBuf) -> rars::Result<()> {
        let key = output_relative_path(name)
            .map_err(|_| rars::Error::InvalidHeader("unsafe archive path"))?;
        self.created_paths.insert(key, path);
        Ok(())
    }
}

fn rar50_extracted_meta(meta: &rars::rar50::ExtractedEntryMeta) -> rars::ExtractedEntryMeta {
    rars::ExtractedEntryMeta::new(
        meta.name.clone(),
        meta.file_time,
        meta.attr,
        meta.is_directory,
    )
}

fn extract_single_archive(
    archive: &DetectedArchive,
    options: ArchiveReadOptions<'_>,
    state: &RefCell<ExtractOutputState<'_>>,
) -> rars::Result<()> {
    match archive {
        DetectedArchive::Rar50Plus(archive) => archive.extract_to_with_redirections(
            options,
            |meta| state.borrow_mut().open_rar50_entry(meta),
            |meta, redirection| {
                state
                    .borrow_mut()
                    .create_rar50_redirection(meta, redirection)
            },
        ),
        _ => extract_archive_to_with_options(archive, options, |meta| {
            state.borrow_mut().open_entry(meta)
        }),
    }
}

fn extract_volume_archives(
    archives: &[DetectedArchive],
    options: ArchiveReadOptions<'_>,
    state: &RefCell<ExtractOutputState<'_>>,
) -> rars::Result<()> {
    if archives
        .iter()
        .all(|archive| matches!(archive, DetectedArchive::Rar50Plus(_)))
    {
        let rar50_archives: Vec<_> = archives
            .iter()
            .map(|archive| match archive {
                DetectedArchive::Rar50Plus(archive) => archive.clone(),
                _ => unreachable!("all archives are RAR5"),
            })
            .collect();
        return rars::rar50::extract_volumes_to_with_redirections(
            &rar50_archives,
            options,
            |meta| state.borrow_mut().open_rar50_entry(meta),
            |meta, redirection| {
                state
                    .borrow_mut()
                    .create_rar50_redirection(meta, redirection)
            },
        );
    }

    extract_volumes_to_with_options(archives, options, |meta| {
        state.borrow_mut().open_entry(meta)
    })
}

fn validate_extract_destination(out_dir: &Path) -> CliResult<()> {
    if out_dir.exists() && !out_dir.is_dir() {
        return Err(CliError::general(format!(
            "extract destination '{}' is not a directory",
            out_dir.display()
        )));
    }
    Ok(())
}

fn reject_ambiguous_extract_target(paths: &[String]) -> CliResult<()> {
    let Some(out_path) = paths.last() else {
        return Ok(());
    };
    if looks_like_archive_path(out_path)? {
        return Err(CliError::usage("ambiguous extract arguments: final argument looks like an archive; pass an explicit output directory"));
    }
    Ok(())
}

fn looks_like_archive_path(path: &str) -> CliResult<bool> {
    const ARCHIVE_SNIFF_LIMIT: u64 = 128 * 1024;

    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(CliError::general(format!(
                "failed to inspect extract output path '{path}': {error}"
            )))
        }
    };
    if metadata.is_dir() {
        return Ok(false);
    }
    if !metadata.is_file() {
        return Err(CliError::general(format!(
            "extract destination '{path}' is not a regular file or directory"
        )));
    }

    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            return Err(CliError::general(format!(
                "failed to inspect extract output path '{path}': {error}"
            )))
        }
    };
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(ARCHIVE_SNIFF_LIMIT)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CliError::general(format!(
                "failed to inspect extract output path '{path}': {error}"
            ))
        })?;
    Ok(ArchiveReader::detect(&bytes).is_ok())
}

/// Which of the two in-memory legacy writers a target uses. RAR 5 and RAR 7
/// return through the streaming engine before this is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddWritePlan {
    Rar13,
    Rar15To40,
}

impl AddWritePlan {
    fn for_target(target: ArchiveVersion) -> CliResult<Self> {
        match target {
            ArchiveVersion::Rar14 => Ok(Self::Rar13),
            ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40 => Ok(Self::Rar15To40),
            _ => Err(format!("unsupported writer target: {target:?}").into()),
        }
    }
}

struct AddCommand {
    password: Option<Password>,
    target: ArchiveVersion,
    store: bool,
    compression_level: Option<u8>,
    dictionary_size: Option<usize>,
    memory_limit: Option<usize>,
    temp_dir: Option<PathBuf>,
    solid: bool,
    header_encryption: bool,
    quick_open: bool,
    archive_comment: Option<Vec<u8>>,
    archive_name: Option<Vec<u8>>,
    file_comment: Option<Vec<u8>>,
    recovery_percent: Option<u64>,
    volume_size: Option<usize>,
    delta_filter: Option<usize>,
    e8_filter: Option<bool>,
    itanium_filter: bool,
    rgb_filter: Option<usize>,
    audio_filter: Option<usize>,
    arm_filter: bool,
    auto_filter: bool,
    no_filter: bool,
    ppmd: bool,
    archive_path: PathBuf,
    input_paths: Vec<String>,
}

fn build_add_command(args: AddArgs) -> CliResult<AddCommand> {
    let password = resolve_password_args(&args.password)?;
    let target = args.format.archive_version();
    let mut store = args.store;
    let compression_level = args.level;
    if let Some(level) = compression_level {
        if level > 5 {
            return Err(CliError::usage(
                "compression level must be in the range 0..5",
            ));
        }
        if store && level != 0 {
            return Err(CliError::usage(
                "--store cannot be combined with --level > 0",
            ));
        }
        if level == 0 {
            store = true;
        }
    }
    if args.solid && store {
        return Err(CliError::usage("solid output requires compression"));
    }
    let e8_filter = if args.e8e9_filter {
        Some(true)
    } else if args.e8_filter {
        Some(false)
    } else {
        None
    };
    Ok(AddCommand {
        password,
        target,
        store,
        compression_level,
        dictionary_size: args.dict_size,
        memory_limit: args.memory_limit,
        temp_dir: args.temp_dir.map(PathBuf::from),
        solid: args.solid,
        header_encryption: args.encrypt_headers,
        quick_open: args.quick_open,
        archive_comment: args.comment.map(String::into_bytes),
        archive_name: args.archive_name.map(String::into_bytes),
        file_comment: args.file_comment.map(String::into_bytes),
        recovery_percent: args.recovery_percent,
        volume_size: args.volume_size,
        delta_filter: args.delta_filter,
        e8_filter,
        itanium_filter: args.itanium_filter,
        rgb_filter: args.rgb_filter,
        audio_filter: args.audio_filter,
        arm_filter: args.arm_filter,
        auto_filter: args.auto_filter,
        no_filter: args.no_filter,
        ppmd: args.ppmd,
        archive_path: PathBuf::from(args.archive),
        input_paths: args.files,
    })
}

fn cmd_add(args: AddArgs, progress: CliProgress) -> CliResult<()> {
    let AddCommand {
        password,
        target,
        store,
        compression_level,
        dictionary_size,
        memory_limit,
        temp_dir,
        solid,
        header_encryption,
        quick_open,
        archive_comment,
        archive_name,
        file_comment,
        recovery_percent,
        volume_size,
        delta_filter,
        e8_filter,
        itanium_filter,
        rgb_filter,
        audio_filter,
        arm_filter,
        auto_filter,
        no_filter,
        ppmd,
        archive_path,
        input_paths,
    } = build_add_command(args)?;
    let input_paths = input_paths.as_slice();
    let compress = !store;

    validate_archive_output_path(&archive_path)?;

    // Everything the chosen format cannot do is refused here, before a single
    // input is read, and named by the flag that asked for it.
    let asked_filters = add_plan::AskedFilters {
        delta: delta_filter.is_some(),
        e8: e8_filter == Some(false),
        e8e9: e8_filter == Some(true),
        itanium: itanium_filter,
        rgb: rgb_filter.is_some(),
        audio: audio_filter.is_some(),
        arm: arm_filter,
    };
    let shape = rars::PlanShape::new()
        .compressed(compress)
        .volumes(volume_size.is_some())
        .filtered(asked_filters.count() > 0 || auto_filter);
    add_plan::reject_unsupported(
        target,
        shape,
        &asked_filters,
        &[
            (rars::WriterOption::Feature(rars::Feature::Solid), solid),
            (
                rars::WriterOption::Feature(rars::Feature::HeaderEncryption),
                header_encryption,
            ),
            (
                rars::WriterOption::Feature(rars::Feature::QuickOpen),
                quick_open,
            ),
            (
                rars::WriterOption::DictionarySize,
                dictionary_size.is_some(),
            ),
            (
                rars::WriterOption::Filter,
                asked_filters.count() > 0 || auto_filter,
            ),
            (rars::WriterOption::CompressionMethod, ppmd),
            (
                rars::WriterOption::RecoveryRecord,
                recovery_percent.is_some(),
            ),
            (rars::WriterOption::VolumeSize, volume_size.is_some()),
            (
                rars::WriterOption::ArchiveComment,
                archive_comment.is_some(),
            ),
            (rars::WriterOption::FileComment, file_comment.is_some()),
            (rars::WriterOption::ArchiveMetadata, archive_name.is_some()),
            (rars::WriterOption::Password, password.is_some()),
            (rars::WriterOption::MemoryLimit, memory_limit.is_some()),
            (rars::WriterOption::TempDir, temp_dir.is_some()),
        ],
    )?;
    // Before anything that asks which filter was requested: with two of them
    // asked for, "which one" has no answer, and the two helpers rank them
    // differently, so the format check would name a flag it had not looked at.
    add_plan::reject_multiple_filters(&asked_filters)?;
    add_plan::reject_unsupported_filter(target, &asked_filters)?;
    add_plan::reject_filter_with_solid(target, &asked_filters, auto_filter, solid)?;
    if store {
        add_plan::reject_coding_without_compression(&asked_filters, auto_filter, ppmd)?;
    }
    // A cross-flag rule rather than a capability: every format that encrypts
    // headers needs the key to do it with.
    if header_encryption && password.is_none() {
        return Err(CliError::usage(
            "--encrypt-headers needs a --password to encrypt them with",
        ));
    }
    // Every writer below RAR 5 splits a single packed payload, so a set can
    // only hold one member. This was a hand-written list of six versions with
    // rar13 already missing from it, harmless only because `--format rar13`
    // has no spelling yet: adding one would have let a set through to
    // `owned.first()`, which archives the first input and drops the rest
    // without a word.
    if target.family() != rars::ArchiveFamily::Rar50Plus
        && volume_size.is_some()
        && input_paths.len() != 1
    {
        return Err("multivolume writer supports one input file".into());
    }
    if matches!(target, ArchiveVersion::Rar50 | ArchiveVersion::Rar70) {
        // Quick-open indexes plaintext headers, so the two cannot combine.
        if quick_open && header_encryption {
            return Err("RAR 5 quick-open cannot be combined with header encryption".into());
        }
        return write_plain_rar50_streaming(
            input_paths,
            &archive_path,
            target,
            if store { Some(0) } else { compression_level },
            dictionary_size,
            memory_limit,
            temp_dir.as_deref(),
            password_bytes(&password),
            solid,
            header_encryption,
            recovery_percent,
            rar50_filter_policy(
                auto_filter,
                no_filter,
                solid,
                store,
                delta_filter,
                e8_filter,
                arm_filter,
            ),
            quick_open,
            archive_comment.as_deref(),
            file_comment.as_deref(),
            archive_name.as_deref(),
            volume_size.map(|size| size as u64),
            &progress,
        );
    }
    let write_plan = AddWritePlan::for_target(target)?;

    // A volume set is still built in memory: the split has to see the whole
    // packed payload before it can decide where the parts break.
    if let Some(volume_size) = volume_size {
        return write_legacy_volumes(
            LegacyVolumeWrite {
                write_plan,
                input_paths,
                archive_path: &archive_path,
                target,
                compression_level,
                dictionary_size,
                password: password_bytes(&password),
                solid,
                header_encryption,
                file_comment: file_comment.as_deref(),
                volume_size,
                compress,
            },
            &progress,
        );
    }

    progress.spinner("Scanning inputs");
    let inputs = collect_inputs(input_paths)?;
    let total: u64 = inputs.iter().map(|entry| entry.size).sum();
    progress.finish(format!(
        "Found {} files ({})",
        inputs.len(),
        indicatif::HumanBytes(total)
    ));
    progress.spinner(if compress {
        "Preparing compression"
    } else {
        "Preparing archive"
    });

    let coding = if store {
        MemberCoding::Stored
    } else if let Some(policy) = legacy_filter_policy(
        target,
        auto_filter,
        no_filter,
        delta_filter,
        e8_filter,
        itanium_filter,
        rgb_filter,
        audio_filter,
    ) {
        MemberCoding::Filtered(policy)
    } else {
        MemberCoding::Compressed
    };
    let mut features = FeatureSet::store_only();
    features.solid = solid;
    features.header_encryption = header_encryption;
    let password = password_bytes(&password);
    let resources = rars::WriterResources::new(
        memory_limit.map_or(rars::DEFAULT_WRITER_MEMORY_LIMIT, |limit| limit as u64),
    );
    progress.bar("Compressing archive", total);

    write_archive_streaming(&archive_path, |output| {
        let written = match write_plan {
            AddWritePlan::Rar15To40 => {
                let entries: Vec<_> = inputs
                    .iter()
                    .map(|input| {
                        let entry = rars::rar15_40::StreamingEntry::new(
                            input.name.clone(),
                            rars::EntrySource::from_path(input.path.clone()),
                        )
                        .with_file_time(input.dos_mtime)
                        .with_file_attr(rar15_file_attr(input.unix_mode, input.file_attr))
                        .with_host_os(3);
                        let entry = match file_comment.as_deref() {
                            Some(comment) => entry.with_file_comment(comment.to_vec()),
                            None => entry,
                        };
                        match password {
                            Some(password) => entry.with_password(password.to_vec()),
                            None => entry,
                        }
                    })
                    .collect();
                let mut options = Rar15WriterOptions::new(target, features);
                if let Some(level) = compression_level {
                    options = options.with_compression_level(level);
                }
                if let Some(size) = dictionary_size {
                    options = options.with_dictionary_size(size);
                }
                options = options.with_method(if ppmd {
                    rars::rar15_40::Rar29Method::Ppmd
                } else if coding.is_filtered() && !auto_filter && !no_filter {
                    // A named filter is a request for that filter, not an
                    // invitation to weigh it against another engine.
                    rars::rar15_40::Rar29Method::Lz
                } else {
                    rars::rar15_40::Rar29Method::Auto
                });
                rars::rar15_40::write_streaming_archive_to(
                    &entries,
                    options,
                    coding.clone(),
                    archive_comment.as_deref(),
                    &resources,
                    Some(&progress),
                    output,
                )
            }
            AddWritePlan::Rar13 => {
                let entries: Vec<_> = inputs
                    .iter()
                    .map(|input| {
                        let entry = rars::rar13::StreamingEntry::new(
                            input.name.clone(),
                            rars::EntrySource::from_path(input.path.clone()),
                        )
                        .with_file_time(input.dos_mtime)
                        .with_file_attr(input.file_attr);
                        let entry = match file_comment.as_deref() {
                            Some(comment) => entry.with_file_comment(comment.to_vec()),
                            None => entry,
                        };
                        match password {
                            Some(password) => entry.with_password(password.to_vec()),
                            None => entry,
                        }
                    })
                    .collect();
                let mut options = Rar13WriterOptions::new(target, features);
                if let Some(level) = compression_level {
                    options = options.with_compression_level(level);
                }
                rars::rar13::write_streaming_archive_to(
                    &entries,
                    options,
                    coding.clone(),
                    archive_comment.as_deref(),
                    &resources,
                    Some(&progress),
                    output,
                )
            }
        };
        written.map_err(|error| add_plan::map_write_error(error, shape, &asked_filters))
    })?;
    progress.finish("100%");
    eprintln!("created {}", archive_path.display());
    Ok(())
}

/// The filter policy the flags ask for, or `None` when nothing filter-related
/// was asked and the writer should choose for itself.
///
/// `--no-filter` only becomes a policy where there is a search to turn off. On
/// RAR 1.3 to 2.0 there is none, so the flag asks for what already happens and
/// passes without comment.
#[allow(clippy::too_many_arguments)]
fn legacy_filter_policy(
    target: ArchiveVersion,
    auto_filter: bool,
    no_filter: bool,
    delta_filter: Option<usize>,
    e8_filter: Option<bool>,
    itanium_filter: bool,
    rgb_filter: Option<usize>,
    audio_filter: Option<usize>,
) -> Option<rars::FilterPolicy> {
    use rars::{FilterKind, FilterSpec};

    let kind = if let Some(channels) = delta_filter {
        FilterKind::Delta { channels }
    } else if e8_filter == Some(true) {
        FilterKind::E8E9
    } else if e8_filter == Some(false) {
        FilterKind::E8
    } else if itanium_filter {
        FilterKind::Itanium
    } else if let Some(width) = rgb_filter {
        FilterKind::Rgb { width, pos_r: 0 }
    } else if let Some(channels) = audio_filter {
        FilterKind::Audio { channels }
    } else if auto_filter {
        return Some(rars::FilterPolicy::Auto);
    } else if no_filter
        && rars::supports(
            target,
            rars::WriterOption::Filter,
            rars::PlanShape::new().compressed(true),
        )
    {
        return Some(rars::FilterPolicy::None);
    } else {
        return None;
    };
    Some(rars::FilterPolicy::Explicit(FilterSpec::whole(kind)))
}

/// What a legacy volume set needs, which is still every input in memory.
struct LegacyVolumeWrite<'a> {
    write_plan: AddWritePlan,
    input_paths: &'a [String],
    archive_path: &'a Path,
    target: ArchiveVersion,
    compression_level: Option<u8>,
    dictionary_size: Option<usize>,
    password: Option<&'a [u8]>,
    solid: bool,
    header_encryption: bool,
    file_comment: Option<&'a [u8]>,
    volume_size: usize,
    compress: bool,
}

fn write_legacy_volumes(plan: LegacyVolumeWrite<'_>, progress: &CliProgress) -> CliResult<()> {
    warn_if_buffered_write_is_large(plan.input_paths, plan.target);
    progress.spinner("Scanning inputs");
    let owned = read_inputs_with_progress(
        plan.input_paths,
        plan.password,
        |files, bytes| progress.bar(format!("Reading {files} files"), bytes),
        |bytes, name| {
            progress.set_message(format!("Reading {}", display_bytes_lossy(name)));
            progress.advance(bytes);
        },
    )?;
    // Invariant: one input, checked before anything was read.
    let entry = owned.first().expect("one input checked above");
    progress.finish(format!(
        "Read 1 file ({})",
        indicatif::HumanBytes(entry.data.len() as u64)
    ));
    progress.spinner(if plan.compress {
        "Preparing compression"
    } else {
        "Preparing archive"
    });

    let mut features = FeatureSet::store_only();
    features.solid = plan.solid;
    features.header_encryption = plan.header_encryption;
    let password = entry.password.as_deref().map(Vec::as_slice);
    let parts = match plan.write_plan {
        AddWritePlan::Rar15To40 => {
            let mut options = Rar15WriterOptions::new(plan.target, features);
            if let Some(level) = plan.compression_level {
                options = options.with_compression_level(level);
            }
            if let Some(size) = plan.dictionary_size {
                options = options.with_dictionary_size(size);
            }
            if plan.compress {
                rars::rar15_40::write_compressed_volumes_with_progress(
                    Rar15FileEntry {
                        name: &entry.name,
                        data: &entry.data,
                        file_time: entry.dos_mtime,
                        file_attr: rar15_file_attr(entry.unix_mode, entry.file_attr),
                        host_os: 3,
                        password,
                        file_comment: plan.file_comment,
                    },
                    options,
                    plan.volume_size,
                    Some(progress),
                )?
            } else {
                rars::rar15_40::write_stored_volumes(
                    Rar15StoredEntry {
                        name: &entry.name,
                        data: &entry.data,
                        file_time: entry.dos_mtime,
                        file_attr: rar15_file_attr(entry.unix_mode, entry.file_attr),
                        host_os: 3,
                        password,
                        file_comment: plan.file_comment,
                    },
                    options,
                    plan.volume_size,
                )?
            }
        }
        AddWritePlan::Rar13 => {
            let mut options = Rar13WriterOptions::new(plan.target, features);
            if let Some(level) = plan.compression_level {
                options = options.with_compression_level(level);
            }
            if plan.compress {
                rar13::write_compressed_volumes_with_progress(
                    FileEntry {
                        name: &entry.name,
                        data: &entry.data,
                        file_time: entry.dos_mtime,
                        file_attr: entry.file_attr,
                        password,
                        file_comment: plan.file_comment,
                    },
                    options,
                    plan.volume_size,
                    Some(progress),
                )?
            } else {
                rar13::write_stored_volumes(
                    Rar13StoredEntry {
                        name: &entry.name,
                        data: &entry.data,
                        file_time: entry.dos_mtime,
                        file_attr: entry.file_attr,
                        password,
                        file_comment: plan.file_comment,
                    },
                    options,
                    plan.volume_size,
                )?
            }
        }
    };
    write_volume_parts(plan.archive_path, &parts, progress).map_err(|err| {
        format!(
            "failed to write volume set starting at '{}': {err}",
            plan.archive_path.display()
        )
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_plain_rar50_streaming(
    input_paths: &[String],
    archive_path: &Path,
    target: ArchiveVersion,
    compression_level: Option<u8>,
    dictionary_size: Option<usize>,
    memory_limit: Option<usize>,
    temp_dir: Option<&Path>,
    password: Option<&[u8]>,
    solid: bool,
    header_encryption: bool,
    recovery_percent: Option<u64>,
    filter_policy: rars::rar50::FilterPolicy,
    quick_open: bool,
    archive_comment: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    archive_name: Option<&[u8]>,
    volume_size: Option<u64>,
    progress: &CliProgress,
) -> CliResult<()> {
    progress.spinner("Scanning inputs");
    let inputs = collect_inputs(input_paths)?;
    let total: u64 = inputs.iter().map(|entry| entry.size).sum();
    progress.finish(format!(
        "Found {} files ({})",
        inputs.len(),
        indicatif::HumanBytes(total)
    ));
    let entries: Vec<_> = inputs
        .into_iter()
        .map(|entry| {
            let entry = rars::rar50::ArchiveEntry::new(
                entry.name,
                rars::EntrySource::from_path(entry.path),
            )
            .with_mtime(entry.unix_mtime)
            .with_attributes(u64::from(
                entry
                    .unix_mode
                    .unwrap_or_else(|| u32::from(entry.file_attr)),
            ))
            .with_host_os(RAR50_HOST_NATIVE);
            let entry = match file_comment {
                Some(comment) => entry.with_service(rars::rar50::ServiceEntry::new(
                    b"CMT".to_vec(),
                    comment.to_vec(),
                )),
                None => entry,
            };
            match password {
                Some(password) => entry.with_password(password.to_vec()),
                None => entry,
            }
        })
        .collect();
    let mut features = FeatureSet::store_only();
    features.header_encryption = header_encryption;
    features.solid = solid;
    features.quick_open = quick_open;
    let mut options = rars::rar50::WriterOptions::new(target, features);
    if let Some(level) = compression_level {
        options = options.with_compression_level(level);
    }
    if let Some(size) = dictionary_size {
        options = options.with_dictionary_size(size as u64);
    }
    let default_temp = archive_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let mut resources = rars::WriterResources::new(
        memory_limit.map_or(rars::DEFAULT_WRITER_MEMORY_LIMIT, |limit| limit as u64),
    );
    if let Some(directory) = temp_dir.or(default_temp) {
        resources = resources.with_temp_dir(directory);
    }
    if recovery_percent.is_some() {
        eprintln!("{RAR50_STRUCTURAL_RR_WARNING}");
    }
    let metadata = archive_name.map(|name| rars::rar50::ArchiveMetadataEntry {
        name: Some(name),
        creation_time: Some(current_filetime()),
    });
    let extras = streaming_extras(recovery_percent, filter_policy, archive_comment, metadata);
    progress.spinner("Preparing compression");
    progress.bar("Compressing archive", total);
    if let Some(volume_size) = volume_size {
        if archive_path == Path::new("-") || archive_path == Path::new("/dev/stdout") {
            return Err("volume sets cannot be written to stdout".into());
        }
        let mut sink = CliVolumeSink {
            first_path: archive_path,
            temporaries: Vec::new(),
        };
        let result = rars::rar50::write_streaming_volumes_with_progress(
            &entries,
            options,
            extras,
            volume_size,
            &mut sink,
            &resources,
            Some(progress),
        );
        let paths = sink.finish(result)?;
        progress.finish("Volumes written");
        print_created_volumes(&paths);
        return Ok(());
    }
    write_archive_streaming(archive_path, |output| {
        rars::rar50::write_streaming_archive_with_progress(
            &entries,
            options,
            extras.clone(),
            &resources,
            Some(progress),
            output,
        )?;
        Ok(())
    })?;
    progress.finish("100%");
    progress.spinner("Writing archive");
    progress.finish("Archive written");
    eprintln!("created {}", archive_path.display());
    Ok(())
}

/// Warns before a volume set that will not fit comfortably in memory.
///
/// Every writer streams a plain archive now, but a legacy volume set is still
/// built whole: the split has to see the entire packed payload before it can
/// decide where the parts break, so the input, the packed member and every part
/// are all resident at once. RAR 5 and RAR 7 split as they go, so this never
/// applies to them. Saying so up front beats an allocation failure an hour in.
fn warn_if_buffered_write_is_large(input_paths: &[String], target: ArchiveVersion) {
    const WARN_THRESHOLD: u64 = 256 * 1024 * 1024;

    if target.family() == rars::version::ArchiveFamily::Rar50Plus {
        return;
    }
    let Ok(inputs) = collect_inputs(input_paths) else {
        return;
    };
    let total: u64 = inputs.iter().map(|entry| entry.size).sum();
    if total < WARN_THRESHOLD {
        return;
    }

    eprintln!(
        "warning: --format {target} builds a volume set in memory, so this write needs \
         several times the {} of input and may run out; --format rar50 splits as it goes",
        indicatif::HumanBytes(total)
    );
}

/// Writes each volume to a temporary file, then renames the set once the
/// number of volumes is known, since that decides how the parts are numbered.
struct CliVolumeSink<'a> {
    first_path: &'a Path,
    temporaries: Vec<PathBuf>,
}

impl CliVolumeSink<'_> {
    /// Renames the finished set, or clears it up if the write failed.
    fn finish(self, result: rars::Result<()>) -> CliResult<Vec<PathBuf>> {
        if result.is_err() {
            for temporary in &self.temporaries {
                let _ = fs::remove_file(temporary);
            }
        }
        result?;

        let total = self.temporaries.len();
        let mut paths = Vec::with_capacity(total);
        for (index, temporary) in self.temporaries.iter().enumerate() {
            let path = rar50_volume_part_path(self.first_path, index, total)?;
            fs::rename(temporary, &path)?;
            paths.push(path);
        }
        Ok(paths)
    }
}

impl rars::rar50::VolumeSink for CliVolumeSink<'_> {
    fn start_volume(&mut self, index: u64) -> rars::Result<Box<dyn std::io::Write + Send>> {
        let parent = self.first_path.parent().unwrap_or_else(|| Path::new(""));
        let temporary = parent.join(format!(".rars-volume-{}-{index:06}", std::process::id()));
        let file = fs::File::create(&temporary)?;
        self.temporaries.push(temporary);
        Ok(Box::new(file))
    }
}

/// Archive-level options for a streaming write.
/// RAR 5 looks for a data filter by default, because it usually pays and the
/// cost is compression time rather than memory. Solid archives share one
/// dictionary across members and so cannot carry per-member filters, and
/// stored members are not compressed at all, so neither takes one.
fn rar50_filter_policy(
    auto_filter: bool,
    no_filter: bool,
    solid: bool,
    store: bool,
    delta_filter: Option<usize>,
    e8_filter: Option<bool>,
    arm_filter: bool,
) -> rars::rar50::FilterPolicy {
    use rars::rar50::{FilterKind, FilterPolicy};
    if let Some(channels) = delta_filter {
        return FilterPolicy::explicit(FilterKind::Delta { channels });
    }
    if let Some(include_e9) = e8_filter {
        return FilterPolicy::explicit(if include_e9 {
            FilterKind::E8E9
        } else {
            FilterKind::E8
        });
    }
    if arm_filter {
        return FilterPolicy::explicit(FilterKind::Arm);
    }
    if no_filter || store || (solid && !auto_filter) {
        return FilterPolicy::None;
    }
    FilterPolicy::Auto
}

/// Quick open is deliberately absent: it rides on the feature set, which is
/// what `validate_plan` reads, and saying it twice is how the streaming writer
/// came to accept it in one place and drop it in the other.
fn streaming_extras<'a>(
    recovery_percent: Option<u64>,
    filter_policy: rars::rar50::FilterPolicy,
    comment: Option<&'a [u8]>,
    metadata: Option<rars::rar50::ArchiveMetadataEntry<'a>>,
) -> rars::rar50::ArchiveExtras<'a> {
    let mut extras = rars::rar50::ArchiveExtras::default()
        .with_recovery_percent(recovery_percent)
        .with_filter_policy(filter_policy);
    if let Some(comment) = comment {
        extras = extras.with_comment(comment);
    }
    if let Some(metadata) = metadata {
        extras = extras.with_metadata(metadata);
    }
    extras
}

/// Writes an archive to its final path through a temporary file, so a write
/// that fails part way leaves no half-finished archive behind. `-` and
/// `/dev/stdout` go straight out, where there is nothing to rename.
fn write_archive_streaming(
    archive_path: &Path,
    write: impl FnOnce(&mut dyn Write) -> CliResult<()>,
) -> CliResult<()> {
    if archive_path == Path::new("-") || archive_path == Path::new("/dev/stdout") {
        return write(&mut std::io::stdout());
    }
    let (temporary, mut output) = create_streaming_archive_temp(archive_path)?;
    let result = (|| -> CliResult<()> {
        write(&mut output)?;
        output.sync_all()?;
        fs::rename(&temporary, archive_path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn create_streaming_archive_temp(archive_path: &Path) -> CliResult<(PathBuf, fs::File)> {
    let file_name = archive_path
        .file_name()
        .ok_or("archive output path has no file name")?
        .to_string_lossy();
    for sequence in 0..128u8 {
        let temporary = archive_path.with_file_name(format!(
            ".{file_name}.rars-writing-{}-{sequence:02x}",
            std::process::id()
        ));
        match fs::File::options()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "failed to create temporary archive '{}': {error}",
                    temporary.display()
                )
                .into())
            }
        }
    }
    Err("could not allocate a unique temporary archive file".into())
}

fn validate_archive_output_path(path: &Path) -> CliResult<()> {
    if path == Path::new("-") || path == Path::new("/dev/stdout") {
        return Ok(());
    }
    if path.is_dir() || has_trailing_path_separator(path) {
        return Err(format!(
            "archive output path '{}' is a directory; provide an archive filename",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(unix)]
fn has_trailing_path_separator(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().last() == Some(&b'/')
}

#[cfg(windows)]
fn has_trailing_path_separator(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .last()
        .is_some_and(|ch| ch == b'/' as u16 || ch == b'\\' as u16)
}

fn write_bytes_with_progress(
    writer: &mut impl Write,
    bytes: &[u8],
    progress: &CliProgress,
) -> std::io::Result<()> {
    for chunk in bytes.chunks(1024 * 1024) {
        writer.write_all(chunk)?;
        progress.advance(chunk.len() as u64);
    }
    Ok(())
}

fn write_volume_parts(
    first_path: &Path,
    parts: &[Vec<u8>],
    progress: &CliProgress,
) -> CliResult<()> {
    let total = parts.iter().map(|part| part.len() as u64).sum();
    progress.bar(format!("Writing {} volumes", parts.len()), total);
    let mut paths = Vec::with_capacity(parts.len());
    for (index, bytes) in parts.iter().enumerate() {
        let path = volume_part_path(first_path, index)?;
        let mut file = fs::File::create(&path)?;
        write_bytes_with_progress(&mut file, bytes, progress)?;
        paths.push(path);
    }
    progress.finish("Volumes written");
    print_created_volumes(&paths);
    Ok(())
}

fn print_created_volumes(paths: &[PathBuf]) {
    println!("created {} volumes:", paths.len());
    for path in paths {
        println!("  {}", path.display());
    }
}

fn parse_size(input: &str) -> CliResult<usize> {
    let input = input.trim();
    if input.is_empty() {
        return Err(CliError::usage("size is empty"));
    }
    let (digits, multiplier) = match input.as_bytes().last().copied() {
        Some(b'k' | b'K') => (&input[..input.len() - 1], 1024usize),
        Some(b'm' | b'M') => (&input[..input.len() - 1], 1024usize * 1024),
        Some(b'g' | b'G') => (&input[..input.len() - 1], 1024usize * 1024 * 1024),
        _ => (input, 1usize),
    };
    if digits.is_empty() {
        return Err(CliError::usage(format!("invalid size: {input}")));
    }
    let value = digits
        .parse::<usize>()
        .map_err(|_| CliError::usage(format!("invalid size value: {input}")))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| CliError::usage(format!("size overflows usize: {input}")))
}

pub(crate) fn parse_size_string(input: &str) -> Result<usize, String> {
    parse_size(input).map_err(|err| err.to_string())
}

pub(crate) fn parse_thread_count(input: &str) -> Result<usize, String> {
    let threads = input
        .parse::<usize>()
        .map_err(|_| format!("invalid thread count: {input}"))?;
    if threads == 0 {
        return Err("thread count must be at least 1".to_string());
    }
    Ok(threads)
}

pub(crate) fn resolve_password_args(args: &PasswordArgs) -> CliResult<Option<Password>> {
    resolve_password(args.password.as_deref(), args.password_file.as_deref())
}

#[cfg(test)]
mod tests {
    use super::{display_text, parse_size, rar50_buffered_decode_limit_hint};
    use crate::output::{checked_output_path, output_relative_path, redirection_warning};
    use crate::password::{error_needs_password, should_prompt_password};
    use crate::volumes::{infer_part_index, rar50_volume_part_path, volume_part_path};
    use rars::Error;
    use std::path::{Path, PathBuf};

    #[test]
    fn display_text_preserves_printable_unicode_but_escapes_control_chars() {
        // Cyrillic and CJK filenames must render as themselves, not \u{...}.
        assert_eq!(display_text("ваапап"), "ваапап");
        assert_eq!(display_text("日本語.txt"), "日本語.txt");
        // Control characters (terminal escape injection) are still escaped.
        assert_eq!(display_text("a\u{1b}[31mb"), "a\\u{1b}[31mb");
        assert_eq!(display_text("line\nfeed"), "line\\nfeed");
    }

    #[test]
    fn infer_part_index_accepts_new_and_old_numbered_volume_names() {
        assert_eq!(infer_part_index(Path::new("archive.part1.rar"), 4), Some(0));
        assert_eq!(infer_part_index(Path::new("archive.part4.rar"), 4), Some(3));
        assert_eq!(infer_part_index(Path::new("archive.part1foo.rar"), 4), None);
        assert_eq!(infer_part_index(Path::new("archive.part1"), 4), None);
        assert_eq!(infer_part_index(Path::new("archive.rar"), 4), Some(0));
        assert_eq!(infer_part_index(Path::new("archive.r00"), 4), Some(1));
        assert_eq!(infer_part_index(Path::new("archive.r02"), 4), Some(3));
        assert_eq!(infer_part_index(Path::new("archive.r03"), 4), None);
    }

    #[test]
    fn old_style_volume_writer_stops_at_r99() {
        assert_eq!(
            volume_part_path(Path::new("archive.rar"), 0).unwrap(),
            PathBuf::from("archive.rar")
        );
        assert_eq!(
            volume_part_path(Path::new("archive.rar"), 1).unwrap(),
            PathBuf::from("archive.r00")
        );
        assert_eq!(
            volume_part_path(Path::new("archive.rar"), 100).unwrap(),
            PathBuf::from("archive.r99")
        );
        assert!(volume_part_path(Path::new("archive.rar"), 101).is_err());
    }

    #[test]
    fn parse_size_accepts_binary_suffixes() {
        assert_eq!(parse_size("10").unwrap(), 10);
        assert_eq!(parse_size("10k").unwrap(), 10 * 1024);
        assert_eq!(parse_size("10M").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size("2g").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_size("m").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn rar50_buffered_decode_limit_hint_names_cli_option() {
        let error = Error::AtEntry {
            name: b"large.bin".to_vec(),
            operation: "decoding",
            source: Box::new(Error::Rar50BufferedDecodeLimitExceeded {
                limit: 512 * 1024 * 1024,
                required: 900 * 1024 * 1024,
            }),
        };

        assert_eq!(
            rar50_buffered_decode_limit_hint(&error),
            "\nhint: retry with --rar50-buffered-decode-limit 943718400 if you trust this archive and have enough memory"
        );
    }

    #[test]
    fn password_prompt_is_gated_on_terminal_stdin() {
        assert!(!should_prompt_password(false));
        assert!(should_prompt_password(true));
    }

    #[test]
    fn output_relative_path_accepts_plain_nested_names() {
        assert_eq!(
            output_relative_path(b"dir\\subdir/file.txt").unwrap(),
            Path::new("dir").join("subdir").join("file.txt")
        );
    }

    #[test]
    fn output_relative_path_rejects_traversal_and_absolute_names() {
        for name in [
            b"../evil.txt".as_slice(),
            b"safe/../../evil.txt",
            b"/tmp/evil.txt",
            b"//server/share/evil.txt",
            b"\\server\\share\\evil.txt",
            b"C:/evil.txt",
            b"C:evil.txt",
            b"",
            b".",
            b"./.",
            b"bad\0name.txt",
        ] {
            assert!(output_relative_path(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn output_relative_path_reports_non_utf8_archive_names() {
        let err = output_relative_path(b"legacy-\xff-name.txt").unwrap_err();

        assert_eq!(err.to_string(), "archive entry name is not UTF-8");
    }

    #[cfg(unix)]
    #[test]
    fn open_output_writer_rejects_existing_symlink_components() {
        let root = std::env::temp_dir().join(format!("rars-symlink-output-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let outside = root.with_extension("outside");
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        assert!(matches!(
            checked_output_path(&root, Path::new("link").join("escape.txt").as_path()),
            Err(Error::InvalidHeader("unsafe archive path crosses symlink"))
        ));
        assert!(!outside.join("escape.txt").exists());

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn rar50_volume_part_path_does_not_duplicate_existing_part_suffix() {
        assert_eq!(
            rar50_volume_part_path(Path::new("archive.part01.rar"), 0, 20).unwrap(),
            PathBuf::from("archive.part01.rar")
        );
        assert_eq!(
            rar50_volume_part_path(Path::new("archive.part01.rar"), 1, 20).unwrap(),
            PathBuf::from("archive.part02.rar")
        );
        assert_eq!(
            rar50_volume_part_path(Path::new("archive.rar"), 0, 20).unwrap(),
            PathBuf::from("archive.part01.rar")
        );
    }

    #[test]
    fn redirection_warning_names_unsupported_rar5_entry() {
        let warning = redirection_warning("link");

        assert!(warning.contains("RAR 5 redirection entry 'link'"));
        assert!(warning.contains("not recreated"));
    }

    #[test]
    fn detects_nested_need_password_errors_for_prompt_retry() {
        let nested = Error::AtEntry {
            name: b"secret.txt".to_vec(),
            operation: "decoding",
            source: Box::new(Error::NeedPassword),
        };

        assert!(error_needs_password(&nested));
        assert!(!error_needs_password(&Error::InvalidHeader(
            "not a password error"
        )));
    }
}
