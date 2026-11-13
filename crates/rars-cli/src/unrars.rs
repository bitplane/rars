//! `unrars`: the part of unrar's command line that other programs call.
//!
//! The commands, switches, output lines and exit codes follow what callers
//! such as python-rarfile and SABnzbd send and parse, as observed from unrar
//! run as a black box. Like unrar, it accepts switches it does not know.

use crate::output::{restore_output_metadata, ExtractedOutput, OverwritePolicy};
use crate::password::Password;
use crate::{display_bytes_lossy, ExtractOutputState};
use rars::{Archive, ArchiveReadOptions, ArchiveReader, ErrorKind};
use std::cell::{Cell, RefCell};
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// Exit codes, as unrar returns them.
const OK: i32 = 0;
const WARNING: i32 = 1;
const FATAL: i32 = 2;
const CHECKSUM: i32 = 3;
const MISSING_VOLUME: i32 = 6;
const USAGE: i32 = 7;
const NO_FILES: i32 = 10;
const BAD_PASSWORD: i32 = 11;

#[doc(hidden)]
pub fn unrars_main() {
    let code = match parse(std::env::args_os().skip(1)) {
        Ok(Some(invocation)) => run(&invocation),
        Ok(None) => {
            print!("{}", usage());
            OK
        }
        Err(()) => {
            print!("{}", usage());
            USAGE
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    /// `x` keeps stored paths; `e` writes every file straight into the destination.
    Extract {
        flat: bool,
    },
    Test,
    Print,
    List {
        bare: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Overwrite {
    /// unrar asks; without a terminal to ask on, existing files are kept.
    Ask,
    Always,
    Never,
    /// `-or`: write beside an existing file as `name(1).ext`.
    Rename,
}

#[derive(Debug, PartialEq)]
enum PasswordSwitch {
    /// Ask on a terminal if the archive needs one.
    Unset,
    Never,
    Prompt,
    Given(Password),
}

#[derive(Debug)]
struct Invocation {
    command: Command,
    overwrite: Overwrite,
    password: PasswordSwitch,
    /// `-inul`: no messages at all.
    silent: bool,
    /// `-idq`: errors only.
    quiet: bool,
    /// Off with `-idc`.
    banner: bool,
    /// Off with `-idd`.
    done: bool,
    /// `-kb`: keep a file whose checksum fails, written where it lands.
    keep_broken: bool,
    archive: PathBuf,
    masks: Vec<Vec<u8>>,
    destination: PathBuf,
}

/// `Ok(None)` asks for the usage text; `Err` is a command line unrar would refuse.
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Invocation>, ()> {
    let mut words = Vec::new();
    let mut switches = Vec::new();
    let mut switches_ended = false;
    for arg in args {
        let bytes = arg.as_encoded_bytes();
        if !switches_ended && bytes == b"--" {
            switches_ended = true;
        } else if !switches_ended && bytes.len() > 1 && bytes[0] == b'-' {
            switches.push(arg);
        } else {
            words.push(arg);
        }
    }
    let mut words = words.into_iter();
    let Some(command) = words.next() else {
        return Ok(None);
    };
    let command = match command.to_string_lossy().to_ascii_lowercase().as_str() {
        "x" => Command::Extract { flat: false },
        "e" => Command::Extract { flat: true },
        "t" => Command::Test,
        "p" => Command::Print,
        "l" | "v" | "lt" | "vt" | "lta" | "vta" => Command::List { bare: false },
        "lb" | "vb" => Command::List { bare: true },
        _ => return Err(()),
    };
    let mut invocation = Invocation {
        command,
        overwrite: Overwrite::Ask,
        password: PasswordSwitch::Unset,
        silent: false,
        quiet: false,
        banner: true,
        done: true,
        keep_broken: false,
        archive: PathBuf::from(words.next().ok_or(())?),
        masks: Vec::new(),
        destination: PathBuf::new(),
    };
    let mut rest: Vec<OsString> = words.collect();
    if matches!(command, Command::Extract { .. }) && rest.last().is_some_and(ends_with_separator) {
        invocation.destination = PathBuf::from(rest.pop().expect("checked above"));
    }
    for word in rest {
        match word.as_encoded_bytes().strip_prefix(b"@") {
            Some(list) => {
                let list = std::fs::read(OsString::from(String::from_utf8_lossy(list).as_ref()))
                    .map_err(|_| ())?;
                invocation.masks.extend(
                    list.split(|&byte| byte == b'\n')
                        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
                        .filter(|line| !line.is_empty())
                        .map(<[u8]>::to_vec),
                );
            }
            None => invocation.masks.push(word.as_encoded_bytes().to_vec()),
        }
    }
    let mut help = false;
    for switch in switches {
        let raw = &switch.as_encoded_bytes()[1..];
        let lower = raw.to_ascii_lowercase();
        match lower.as_slice() {
            b"?" => help = true,
            b"y" if invocation.overwrite == Overwrite::Ask => {
                invocation.overwrite = Overwrite::Always
            }
            b"o+" => invocation.overwrite = Overwrite::Always,
            b"o-" => invocation.overwrite = Overwrite::Never,
            b"or" => invocation.overwrite = Overwrite::Rename,
            b"p-" => invocation.password = PasswordSwitch::Never,
            b"p" => invocation.password = PasswordSwitch::Prompt,
            b"inul" => invocation.silent = true,
            b"kb" => invocation.keep_broken = true,
            _ if lower.starts_with(b"id") => {
                for flag in &lower[2..] {
                    match flag {
                        b'c' => invocation.banner = false,
                        b'd' => invocation.done = false,
                        b'q' => invocation.quiet = true,
                        _ => {}
                    }
                }
            }
            // The password keeps its case.
            _ if lower.starts_with(b"p") => {
                invocation.password = PasswordSwitch::Given(Zeroizing::new(raw[1..].to_vec()));
            }
            _ => {}
        }
    }
    if help {
        return Ok(None);
    }
    Ok(Some(invocation))
}

fn ends_with_separator(word: &OsString) -> bool {
    let bytes = word.as_encoded_bytes();
    bytes.ends_with(b"/") || (cfg!(windows) && bytes.ends_with(b"\\"))
}

fn usage() -> String {
    format!(
        "{}\
Usage: unrars <command> [-<switch>...] <archive> [<files>...] [@<listfile>...] [<path_to_extract/>]

Commands
  x       Extract with full paths
  e       Extract into the destination, without paths
  t       Test archive files
  p       Print files to stdout
  l, v    List archive contents (lb, vb: bare names)

Switches
  -o+     Overwrite existing files
  -o-     Keep existing files
  -or     Rename extracted files that would overwrite
  -y      Overwrite existing files unless -o- was given
  -p<pwd> Use this password; -p- for none; -p alone to be asked
  -kb     Keep files that fail their checksum
  -inul   No messages
  -idq    Errors only; -idc no banner; -idd no closing \"All OK\"
  --      End of switches

Other unrar switches are accepted and ignored.
",
        banner()
    )
}

fn banner() -> String {
    format!(
        "\nUNRARS {} (rars, Apache-2.0) https://github.com/bitplane/rars\n",
        env!("CARGO_PKG_VERSION")
    )
}

/// Where messages go: unrar puts progress on stdout and errors on stderr.
#[derive(Clone, Copy)]
struct Out {
    silent: bool,
    quiet: bool,
}

impl Out {
    fn info(self, line: &str) {
        if !self.silent && !self.quiet {
            println!("{line}");
        }
    }

    fn error(self, line: &str) {
        if !self.silent {
            eprintln!("{line}");
        }
    }
}

fn run(invocation: &Invocation) -> i32 {
    let out = Out {
        silent: invocation.silent,
        quiet: invocation.quiet,
    };
    let bare = invocation.command == Command::List { bare: true };
    if invocation.banner && !bare && !out.silent && !out.quiet {
        print!("{}", banner());
    }
    let path = archive_path(&invocation.archive);
    let mut password = match &invocation.password {
        PasswordSwitch::Given(password) => Some(password.clone()),
        PasswordSwitch::Prompt => match prompt_password() {
            Some(password) => Some(password),
            None => return USAGE,
        },
        PasswordSwitch::Unset | PasswordSwitch::Never => None,
    };
    let may_ask = invocation.password == PasswordSwitch::Unset;
    let archive = match open_archive(&path, &mut password, may_ask) {
        Ok(archive) => archive,
        Err(error) => return report_open_failure(out, &path, &error),
    };
    let listing = matches!(invocation.command, Command::List { .. });
    if may_ask
        && !listing
        && password.is_none()
        && archive.members().any(|member| member.meta.is_encrypted)
    {
        password = prompt_password();
    }
    match invocation.command {
        Command::List { bare } => list(&path, &archive, bare),
        _ => run_members(
            invocation,
            out,
            &path,
            &archive,
            password.as_deref().map(Vec::as_slice),
        ),
    }
}

/// unrar adds `.rar` to an archive named without an extension.
fn archive_path(archive: &Path) -> PathBuf {
    if !archive.exists() && archive.extension().is_none() {
        let mut with_extension = archive.as_os_str().to_os_string();
        with_extension.push(".rar");
        return PathBuf::from(with_extension);
    }
    archive.to_path_buf()
}

fn prompt_password() -> Option<Password> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let line = rpassword::prompt_password("Enter password: ").ok()?;
    Some(Zeroizing::new(line.into_bytes()))
}

fn open_archive(
    path: &Path,
    password: &mut Option<Password>,
    may_ask: bool,
) -> rars::Result<Archive> {
    let read = |password: &Option<Password>| {
        ArchiveReader::read_path_with_options(
            path,
            ArchiveReadOptions::with_optional_password(password.as_deref().map(Vec::as_slice)),
        )
    };
    match read(password) {
        Err(error) if may_ask && password.is_none() && needs_password(&error) => {
            *password = prompt_password();
            if password.is_none() {
                return Err(error);
            }
            read(password)
        }
        result => result,
    }
}

fn needs_password(error: &rars::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::PasswordRequired | ErrorKind::BadPassword
    )
}

fn report_open_failure(out: Out, path: &Path, error: &rars::Error) -> i32 {
    let code = match error.kind() {
        ErrorKind::Io => {
            out.error(&format!("Cannot open {}", path.display()));
            out.error(&io_reason(error));
            NO_FILES
        }
        ErrorKind::UnsupportedFormat | ErrorKind::InvalidArchive => {
            out.error(&format!("{} is not RAR archive", path.display()));
            NO_FILES
        }
        ErrorKind::PasswordRequired | ErrorKind::BadPassword => {
            out.error(&format!("Incorrect password for {}", path.display()));
            return BAD_PASSWORD;
        }
        _ => {
            out.error(&format!("ERROR: {error}"));
            return FATAL;
        }
    };
    out.info("No files to extract");
    code
}

/// An I/O error's message without Rust's "(os error N)" suffix, as unrar prints it.
fn io_reason(error: &rars::Error) -> String {
    let text = match error.root_cause() {
        rars::Error::Io(io) => io.source().to_string(),
        other => other.to_string(),
    };
    match text.find(" (os error") {
        Some(end) => text[..end].to_string(),
        None => text,
    }
}

fn list(path: &Path, archive: &Archive, bare: bool) -> i32 {
    let members: Vec<_> = archive
        .members()
        .map(|member| member.meta.clone())
        .collect();
    if bare {
        for meta in &members {
            println!("{}", display_name(&meta.name));
        }
        return OK;
    }
    let details = match archive.family() {
        rars::ArchiveFamily::Rar13 => "RAR 1.4",
        rars::ArchiveFamily::Rar15To40 => "RAR 4",
        rars::ArchiveFamily::Rar50Plus => "RAR 5",
        _ => "RAR",
    };
    println!("\nArchive: {}\nDetails: {details}\n", path.display());
    println!(" Attributes      Size     Date    Time   Name");
    println!("----------- ---------  ---------- -----  ----");
    let mut total = 0u64;
    for meta in &members {
        total += meta.unpacked_size;
        let (date, time) = match meta
            .stored_modification_time()
            .and_then(|time| time.calendar_fields())
        {
            Some((year, month, day, hour, minute, _)) => (
                format!("{year:04}-{month:02}-{day:02}"),
                format!("{hour:02}:{minute:02}"),
            ),
            None => ("????-??-??".to_string(), "??:??".to_string()),
        };
        println!(
            " {:<10} {:>9}  {date} {time}  {}",
            attributes(meta),
            meta.unpacked_size,
            display_name(&meta.name)
        );
    }
    println!("----------- ---------  ---------- -----  ----");
    println!(
        " {:<10} {total:>9}                    {}\n",
        "",
        members.len()
    );
    OK
}

fn display_name(name: &[u8]) -> String {
    display_bytes_lossy(name).replace('\\', "/")
}

/// `drwxr-xr-x` for archives made on Unix, DOS attribute letters otherwise.
fn attributes(meta: &rars::ArchiveMemberMeta) -> String {
    let unix = match meta.family {
        rars::ArchiveFamily::Rar50Plus => meta.host_os == Some(1),
        rars::ArchiveFamily::Rar15To40 => meta.host_os == Some(3),
        rars::ArchiveFamily::Rar13 => false,
        _ => false,
    };
    if unix {
        let mode = meta.file_attr as u32;
        let kind = match mode & 0o170000 {
            0o040000 => 'd',
            0o120000 => 'l',
            _ => '-',
        };
        let mut text = String::from(kind);
        for shift in [6, 3, 0] {
            let bits = (mode >> shift) & 7;
            text.push(if bits & 4 != 0 { 'r' } else { '-' });
            text.push(if bits & 2 != 0 { 'w' } else { '-' });
            text.push(if bits & 1 != 0 { 'x' } else { '-' });
        }
        return text;
    }
    [
        (0x10, 'D'),
        (0x01, 'R'),
        (0x02, 'H'),
        (0x04, 'S'),
        (0x20, 'A'),
    ]
    .iter()
    .map(|&(bit, letter)| {
        if meta.file_attr & bit != 0 {
            letter
        } else {
            '.'
        }
    })
    .collect()
}

/// A mask selects a member by its whole path, or by its name alone when the mask has no path.
fn selected(masks: &[Vec<u8>], name: &[u8]) -> bool {
    if masks.is_empty() {
        return true;
    }
    let name: Vec<u8> = name
        .iter()
        .map(|&byte| if byte == b'\\' { b'/' } else { byte })
        .collect();
    let base = name.rsplit(|&byte| byte == b'/').next().unwrap_or(&name);
    masks.iter().any(|mask| {
        let mask: Vec<u8> = mask
            .iter()
            .map(|&byte| if byte == b'\\' { b'/' } else { byte })
            .collect();
        wildcard(&mask, &name) || (!mask.contains(&b'/') && wildcard(&mask, base))
    })
}

/// `*` matches any run of bytes and `?` any one byte.
fn wildcard(mask: &[u8], name: &[u8]) -> bool {
    let (mut m, mut n) = (0, 0);
    let mut star = None;
    while n < name.len() {
        if m < mask.len() && (mask[m] == b'?' || mask[m] == name[n]) {
            m += 1;
            n += 1;
        } else if m < mask.len() && mask[m] == b'*' {
            star = Some((m, n));
            m += 1;
        } else if let Some((star_m, star_n)) = star {
            m = star_m + 1;
            n = star_n + 1;
            star = Some((star_m, star_n + 1));
        } else {
            return false;
        }
    }
    mask[m..].iter().all(|&byte| byte == b'*')
}

/// Extracts, tests or prints, reading later volumes as the members reach them.
fn run_members(
    invocation: &Invocation,
    out: Out,
    path: &Path,
    archive: &Archive,
    password: Option<&[u8]>,
) -> i32 {
    let options = ArchiveReadOptions::with_optional_password(password);
    let command = invocation.command;
    let announce = move |volume: &Path| match command {
        Command::Extract { .. } => out.info(&format!("\nExtracting from {}\n", volume.display())),
        Command::Test => out.info(&format!("\nTesting archive {}\n", volume.display())),
        _ => {}
    };
    announce(path);
    let mut index = 1;
    let volumes = std::iter::from_fn(move || {
        let next = archive.volume_path(path, index)?;
        if !next.exists() {
            return None;
        }
        index += 1;
        announce(&next);
        Some(ArchiveReader::read_path_with_options(
            &next,
            ArchiveReadOptions::with_optional_password(password),
        ))
    });
    let matched = Cell::new(0usize);
    let select = |meta: &rars::ExtractedEntryMeta| {
        let chosen = selected(&invocation.masks, &meta.name);
        matched.set(matched.get() + usize::from(chosen));
        chosen
    };
    let result = match command {
        Command::Extract { .. } => extract(invocation, out, archive, volumes, options, &select),
        _ => test_or_print(command, out, archive, volumes, options, &select).map(|warnings| {
            Extracted {
                warnings,
                all_kept: false,
            }
        }),
    };
    let code = match result {
        Ok(Extracted { warnings, all_kept }) => {
            if matched.get() == 0 || all_kept {
                out.info("No files to extract");
                return NO_FILES;
            }
            if warnings {
                WARNING
            } else {
                OK
            }
        }
        Err(error) => report_failure(out, archive, path, &error),
    };
    if code == OK && invocation.done && command != Command::Print {
        out.info("All OK");
    }
    code
}

struct Extracted {
    /// Finished with a warning, such as a link it left out.
    warnings: bool,
    /// `-o-` kept every selected file that was already there, so nothing was written.
    all_kept: bool,
}

fn extract<V>(
    invocation: &Invocation,
    out: Out,
    archive: &Archive,
    volumes: V,
    options: ArchiveReadOptions<'_>,
    select: &dyn Fn(&rars::ExtractedEntryMeta) -> bool,
) -> rars::Result<Extracted>
where
    V: Iterator<Item = rars::Result<Archive>> + Send,
{
    let policy = match invocation.overwrite {
        Overwrite::Always => OverwritePolicy::Always,
        Overwrite::Never | Overwrite::Ask => OverwritePolicy::Never,
        Overwrite::Rename => OverwritePolicy::Rename,
    };
    let mut state = ExtractOutputState::new(
        &invocation.destination,
        policy,
        invocation.keep_broken,
        invocation.command == (Command::Extract { flat: true }),
        archive.family(),
    );
    state.skip_existing = policy == OverwritePolicy::Never;
    state.selected = Some(Box::new(select));
    state.on_published = Some(Box::new(move |output: &ExtractedOutput| {
        let verb = if output.meta.is_directory {
            "Creating"
        } else {
            "Extracting"
        };
        out.info(&format!("{verb:<11} {:<57} OK", output.path.display()));
    }));
    let state = RefCell::new(state);
    let result = rars::output_links::extract_arriving_with_links(
        archive,
        volumes,
        options,
        |meta| state.borrow_mut().open_entry(meta),
        |meta, link| state.borrow_mut().create_link(meta, link),
    );
    if let Err(error) = result {
        let _ = state.borrow_mut().publish_before_failure(&error);
        return Err(error);
    }
    let state = state.into_inner();
    let skipped_links = state.skipped_links;
    let kept = state.kept_existing;
    let outputs = state.publish()?;
    restore_output_metadata(&outputs)?;
    Ok(Extracted {
        warnings: skipped_links > 0,
        all_kept: kept > 0 && outputs.iter().all(|output| output.meta.is_directory),
    })
}

fn test_or_print<V>(
    command: Command,
    out: Out,
    archive: &Archive,
    volumes: V,
    options: ArchiveReadOptions<'_>,
    select: &dyn Fn(&rars::ExtractedEntryMeta) -> bool,
) -> rars::Result<bool>
where
    V: Iterator<Item = rars::Result<Archive>> + Send,
{
    // A member has passed its checksum once the next one starts, or the run ends.
    let pending: RefCell<Option<String>> = RefCell::new(None);
    let passed = || {
        if let Some(name) = pending.borrow_mut().take() {
            out.info(&format!("{:<11} {name:<57} OK", "Testing"));
        }
    };
    let mut visit = |meta: &rars::ExtractedEntryMeta| -> bool {
        passed();
        let chosen = select(meta);
        if chosen && command == Command::Test {
            *pending.borrow_mut() = Some(display_name(&meta.name));
        }
        chosen
    };
    let visit = RefCell::new(&mut visit);
    rars::output_links::extract_arriving_with_links(
        archive,
        volumes,
        options,
        |meta| {
            let chosen = (visit.borrow_mut())(meta);
            Ok(if chosen && command == Command::Print {
                Box::new(std::io::stdout()) as Box<dyn Write>
            } else {
                Box::new(std::io::sink())
            })
        },
        |meta, _link| {
            (visit.borrow_mut())(meta);
            Ok(())
        },
    )?;
    passed();
    Ok(false)
}

fn report_failure(out: Out, archive: &Archive, path: &Path, error: &rars::Error) -> i32 {
    let member = rars::output_staging::failed_entry_name(error).map(display_name);
    if let Some(number) = missing_volume(error) {
        let name = archive
            .volume_path(path, number.saturating_sub(1))
            .unwrap_or_else(|| path.to_path_buf());
        out.error(&format!("Cannot find volume {}", name.display()));
        out.info("Total errors: 1");
        return MISSING_VOLUME;
    }
    let member = member.unwrap_or_else(|| path.display().to_string());
    let code = match error.kind() {
        ErrorKind::ChecksumMismatch | ErrorKind::InvalidArchive => {
            out.error(&format!("{member:<20} - checksum error"));
            CHECKSUM
        }
        ErrorKind::PasswordRequired | ErrorKind::BadPassword => {
            out.error(&format!("Incorrect password for {member}"));
            BAD_PASSWORD
        }
        _ => {
            out.error(&format!("ERROR: {error}"));
            FATAL
        }
    };
    out.info("Total errors: 1");
    code
}

fn missing_volume(error: &rars::Error) -> Option<usize> {
    match error {
        rars::Error::InVolume { number, source } if **source == rars::Error::MissingVolume => {
            Some(*number)
        }
        rars::Error::AtEntry { source, .. }
        | rars::Error::AtArchiveOffset { source, .. }
        | rars::Error::InVolume { source, .. } => missing_volume(source),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation(args: &[&str]) -> Invocation {
        parse(args.iter().map(OsString::from)).unwrap().unwrap()
    }

    #[test]
    fn the_last_word_ending_in_a_separator_is_the_destination() {
        let parsed = invocation(&["x", "-o+", "-p-", "set.part1.rar", "*.txt", "out/"]);
        assert_eq!(parsed.command, Command::Extract { flat: false });
        assert_eq!(parsed.overwrite, Overwrite::Always);
        assert_eq!(parsed.password, PasswordSwitch::Never);
        assert_eq!(parsed.archive, PathBuf::from("set.part1.rar"));
        assert_eq!(parsed.masks, vec![b"*.txt".to_vec()]);
        assert_eq!(parsed.destination, PathBuf::from("out/"));
    }

    #[test]
    fn switches_after_a_double_dash_are_names() {
        let parsed = invocation(&["p", "-inul", "-pSecret", "--", "a.rar", "-odd.txt"]);
        assert!(parsed.silent);
        assert_eq!(
            parsed.password,
            PasswordSwitch::Given(Zeroizing::new(b"Secret".to_vec()))
        );
        assert_eq!(parsed.masks, vec![b"-odd.txt".to_vec()]);
    }

    #[test]
    fn y_does_not_undo_an_explicit_keep() {
        assert_eq!(
            invocation(&["x", "-o-", "-y", "a.rar"]).overwrite,
            Overwrite::Never
        );
        assert_eq!(
            invocation(&["x", "-y", "a.rar"]).overwrite,
            Overwrite::Always
        );
    }

    #[test]
    fn help_and_bad_commands() {
        assert!(parse(Vec::<OsString>::new()).unwrap().is_none());
        assert!(parse(["-inul", "-?"].map(OsString::from))
            .unwrap()
            .is_none());
        assert!(parse(["q", "a.rar"].map(OsString::from)).is_err());
        assert!(parse(["x"].map(OsString::from)).is_err());
    }

    #[test]
    fn masks_match_paths_or_bare_names() {
        let masks = |list: &[&str]| {
            list.iter()
                .map(|m| m.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        assert!(selected(&masks(&[]), b"any/thing"));
        assert!(selected(&masks(&["*.txt"]), b"sub/a.txt"));
        assert!(selected(&masks(&["sub/a.txt"]), br"sub\a.txt"));
        assert!(!selected(&masks(&["other/*.txt"]), b"sub/a.txt"));
        assert!(selected(&masks(&["s?b/*"]), b"sub/b.bin"));
        assert!(!selected(&masks(&["a.txt"]), b"sub/b.txt"));
    }
}
