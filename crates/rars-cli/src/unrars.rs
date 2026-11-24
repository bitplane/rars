//! `unrars`: the part of unrar's command line that other programs call.
//!
//! The commands, switches, output lines and exit codes follow what callers
//! such as python-rarfile and SABnzbd send and parse, as observed from unrar
//! run as a black box. Like unrar, it accepts switches it does not know.

use crate::output::{restore_output_metadata, ExtractedOutput, OverwritePolicy};
use crate::password::Password;
use crate::{display_bytes_lossy, lock, ExtractOutputState, KeptBroken};
use rars::{Archive, ArchiveReadOptions, ArchiveReader, ErrorKind};
use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
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
const READ_ERROR: i32 = 12;

#[doc(hidden)]
pub fn unrars_main() {
    std::process::exit(unrars_run(std::env::args_os().skip(1)));
}

/// Runs `unrars` on `args`, which leave out the program name, and returns the
/// exit code where [`unrars_main`] exits with it. The Python package's
/// `unrars` command runs through this.
#[doc(hidden)]
pub fn unrars_run(args: impl IntoIterator<Item = OsString>) -> i32 {
    let code = match parse(args) {
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
    code
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
    /// `-kb`: keep a damaged file with what could be read of it, written
    /// where it lands, and read past damaged headers.
    keep_broken: bool,
    /// `-ver`: older copies of a file kept by `rar -ver` are wanted too.
    versions: bool,
    /// `-vp`: ask before each later volume, and wait for the answer.
    pause_volumes: bool,
    /// `-v` with `l`: list every volume of a set, not only the one named.
    all_volumes: bool,
    /// May hold `*` and `?`, matched against the files in its directory.
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
        versions: false,
        pause_volumes: false,
        all_volumes: false,
        archive: PathBuf::from(words.next().ok_or(())?),
        masks: Vec::new(),
        destination: PathBuf::new(),
    };
    let mut rest: Vec<OsString> = words.collect();
    // The last word is where to extract to if it ends in a separator, or,
    // extracting, if it names a directory that is already there.
    let extracting = matches!(command, Command::Extract { .. });
    if let Some(destination) =
        rest.pop_if(|word| ends_with_separator(word) || (extracting && Path::new(word).is_dir()))
    {
        invocation.destination = PathBuf::from(destination);
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
            b"vp" => invocation.pause_volumes = true,
            b"v" => invocation.all_volumes = true,
            _ if lower.starts_with(b"ver") => invocation.versions = true,
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
  -kb     Keep broken extracted files
  -ver    Extract older file versions too
  -v      List every volume of a set (l, v)
  -vp     Ask before each later volume, and wait for the answer on stdin
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

/// What a run has come to, over every archive it read.
#[derive(Default)]
struct Tally {
    /// The errors unrar counts in its closing "Total errors" line.
    errors: usize,
    /// The exit code: the first error's, unless that was only a warning.
    code: i32,
    /// Archives that had members to work on.
    worked: usize,
}

impl Tally {
    fn fail(&mut self, code: i32) {
        if self.code == OK || (self.code == WARNING && code != OK) {
            self.code = code;
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
    let mut password = match &invocation.password {
        PasswordSwitch::Given(password) => Some(password.clone()),
        PasswordSwitch::Prompt => match prompt_password() {
            Some(password) => Some(password),
            None => return USAGE,
        },
        PasswordSwitch::Unset | PasswordSwitch::Never => None,
    };
    let mut tally = Tally::default();
    // Volumes already read as part of a set an earlier archive started.
    let mut read = HashSet::new();
    for path in archive_paths(&invocation.archive) {
        if !read.contains(&path) {
            run_archive(invocation, out, &path, &mut password, &mut tally, &mut read);
        }
    }
    if tally.errors > 0 {
        out.info(&format!("Total errors: {}", tally.errors));
    }
    if tally.code != OK {
        return tally.code;
    }
    if tally.worked == 0 {
        out.info("No files to extract");
        return NO_FILES;
    }
    if invocation.done && matches!(invocation.command, Command::Extract { .. } | Command::Test) {
        out.info("All OK");
    }
    OK
}

/// Lists, extracts, tests or prints one archive, or the volume set it starts.
fn run_archive(
    invocation: &Invocation,
    out: Out,
    path: &Path,
    password: &mut Option<Password>,
    tally: &mut Tally,
    read: &mut HashSet<PathBuf>,
) {
    let may_ask = invocation.password == PasswordSwitch::Unset;
    let mut path = path.to_path_buf();
    let mut archive = match open_archive(&path, password, may_ask) {
        Ok(archive) => archive,
        Err(error) => {
            if let Some(code) = report_open_failure(out, &path, &error) {
                tally.fail(code);
            }
            return;
        }
    };
    let listing = matches!(invocation.command, Command::List { .. });
    // Named by a later volume, a set is read from its first, as unrar does.
    if !listing && archive.is_first_volume() == Some(false) {
        let first = first_volume(&path, &archive).filter(|first| first.is_file());
        if let Some(first) = first {
            match open_archive(&first, password, may_ask) {
                Ok(first_archive) if first_archive.is_first_volume() == Some(true) => {
                    read.insert(path);
                    path = first;
                    archive = first_archive;
                }
                _ => {}
            }
        }
    }
    let path = path.as_path();
    if may_ask
        && !listing
        && password.is_none()
        && archive.members().any(|member| member.meta.is_encrypted)
    {
        *password = prompt_password();
    }
    match invocation.command {
        Command::List { bare } => {
            let password = password.as_deref().map(Vec::as_slice);
            list_volumes(invocation, out, path, archive, password, bare, tally);
            tally.worked += 1;
        }
        _ => run_members(
            invocation,
            out,
            path,
            &archive,
            password.as_deref().map(Vec::as_slice),
            tally,
            read,
        ),
    }
}

/// The first volume of the set a later volume belongs to, named as RAR names
/// it beside that volume.
fn first_volume(path: &Path, archive: &Archive) -> Option<PathBuf> {
    match archive.volume_naming() {
        rars::volume_name::VolumeNaming::Part => {
            let width = rars::volume_name::part_width(path)?;
            rars::volume_name::part_style(path, 0, width)
        }
        rars::volume_name::VolumeNaming::Old => {
            let upper = path
                .extension()
                .and_then(|extension| extension.as_encoded_bytes().first())
                .is_some_and(u8::is_ascii_uppercase);
            Some(path.with_extension(if upper { "RAR" } else { "rar" }))
        }
    }
}

/// Lists an archive and, with `-v`, each later volume of its set in turn,
/// then their grand total.
fn list_volumes(
    invocation: &Invocation,
    out: Out,
    path: &Path,
    archive: Archive,
    password: Option<&[u8]>,
    bare: bool,
    tally: &mut Tally,
) {
    let mut totals = (0, 0);
    let mut listed = 0;
    let mut next = Some((path.to_path_buf(), archive.clone()));
    while let Some((volume_path, volume)) = next.take() {
        if report_header_damage(out, &volume) > 0 {
            tally.fail(CHECKSUM);
        }
        let (size, count) = list(invocation, &volume_path, &volume, bare);
        totals = (totals.0 + size, totals.1 + count);
        listed += 1;
        if report_truncation(out, volume.truncation()) {
            tally.fail(WARNING);
        }
        if !invocation.all_volumes || !volume.is_volume() {
            break;
        }
        let Some(later) = archive
            .volume_path(path, listed)
            .filter(|later| later.is_file())
        else {
            break;
        };
        match read_archive(&later, password) {
            Ok(volume) => next = Some((later, volume)),
            Err(error) => {
                if let Some(code) = report_open_failure(out, &later, &error) {
                    tally.fail(code);
                }
            }
        }
    }
    if invocation.all_volumes && !bare {
        // unrar sets the grand total one column left of each volume's.
        println!("{:>20}{:>21}", totals.0, totals.1);
    }
    if !bare {
        println!();
    }
}

/// The archives a name stands for. Like unrar, `*` and `?` in its file name
/// are matched against the files in its directory, so a quoted `*.rar`
/// reads every archive there.
fn archive_paths(archive: &Path) -> Vec<PathBuf> {
    let path = archive_path(archive);
    let pattern = match archive.file_name() {
        Some(name) if !path.exists() && has_wildcard(name.as_encoded_bytes()) => {
            name.as_encoded_bytes()
        }
        _ => return vec![path],
    };
    let dir = archive.parent().filter(|dir| !dir.as_os_str().is_empty());
    let Ok(entries) = std::fs::read_dir(dir.unwrap_or(Path::new("."))) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| wildcard(pattern, entry.file_name().as_encoded_bytes()))
        .map(|entry| match dir {
            Some(dir) => dir.join(entry.file_name()),
            None => PathBuf::from(entry.file_name()),
        })
        .filter(|path| path.is_file())
        .collect();
    found.sort();
    found
}

fn has_wildcard(text: &[u8]) -> bool {
    text.iter().any(|&byte| byte == b'*' || byte == b'?')
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

/// Whether testing or extracting reads past damage: always where `-kb` keeps
/// what it reads, and where the archive, or a volume after it, may be
/// damaged. Members are then read one at a time, so an archive that parsed
/// clean is read without it.
fn salvaging(invocation: &Invocation, archive: &Archive) -> bool {
    invocation.keep_broken
        || archive.is_volume()
        || archive.truncation().is_some()
        || !archive.header_damage().is_empty()
}

fn open_archive(
    path: &Path,
    password: &mut Option<Password>,
    may_ask: bool,
) -> rars::Result<Archive> {
    let read =
        |password: &Option<Password>| read_archive(path, password.as_deref().map(Vec::as_slice));
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

/// Reads an archive or volume, as unrar does, for whatever it still holds:
/// past damaged headers, and up to where a cut file ends.
///
/// A password that fits none of its files' password checks fails each of
/// those files as it is reached, as with unrar, rather than the whole
/// archive: only encrypted headers need it to be right before anything can
/// be read.
fn read_archive(path: &Path, password: Option<&[u8]>) -> rars::Result<Archive> {
    let read = |password: Option<&[u8]>| {
        ArchiveReader::read_path_with_options(
            path,
            ArchiveReadOptions::with_optional_password(password).with_salvage(true),
        )
    };
    match read(password) {
        Err(error) if password.is_some() && error.kind() == ErrorKind::BadPassword => {
            read(None).map_err(|_| error)
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

/// Reports an archive that could not be opened, returning the exit code it
/// fails the run with: `None` when it only has no files to give.
fn report_open_failure(out: Out, path: &Path, error: &rars::Error) -> Option<i32> {
    match error.kind() {
        ErrorKind::Io => {
            out.error(&format!("Cannot open {}", path.display()));
            out.error(&io_reason(error));
            None
        }
        ErrorKind::UnsupportedFormat | ErrorKind::InvalidArchive => {
            out.error(&format!("{} is not RAR archive", path.display()));
            None
        }
        ErrorKind::PasswordRequired | ErrorKind::BadPassword => {
            out.error(&format!("Incorrect password for {}", path.display()));
            Some(BAD_PASSWORD)
        }
        _ => {
            out.error(&format!("ERROR: {error}"));
            Some(FATAL)
        }
    }
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

/// Lists one archive or volume, returning the size and count of the files
/// that start in it.
fn list(invocation: &Invocation, path: &Path, archive: &Archive, bare: bool) -> (u64, usize) {
    // unrar lists the older copies `rar -ver` kept, `-ver` or not.
    let members: Vec<_> = archive
        .members()
        .filter(|member| selected(&invocation.masks, &member.meta.name))
        .map(|member| member.meta.clone())
        .collect();
    if bare {
        for meta in &members {
            println!("{}", display_name(&meta.name));
        }
    }
    // A member continued from an earlier volume counts where it starts.
    let starting = members.iter().filter(|meta| !meta.is_split_before);
    let totals = (
        starting.clone().map(|meta| meta.unpacked_size).sum(),
        starting.count(),
    );
    if bare {
        return totals;
    }
    println!(
        "\nArchive: {}\nDetails: {}\n",
        path.display(),
        details(archive)
    );
    println!(" Attributes      Size     Date    Time   Name");
    println!("----------- ---------  ---------- -----  ----");
    for meta in &members {
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
    println!(" {:<10} {:>9}{:>21}", "", totals.0, totals.1);
    totals
}

/// The listing's `Details:` line: the format, then what unrar notes about the archive.
fn details(archive: &Archive) -> String {
    let mut details = match archive.family() {
        rars::ArchiveFamily::Rar13 => "RAR 1.4",
        rars::ArchiveFamily::Rar15To40 => "RAR 4",
        rars::ArchiveFamily::Rar50Plus => "RAR 5",
        _ => "RAR",
    }
    .to_string();
    if archive.is_volume() {
        match archive.volume_index() {
            Some(index) => details.push_str(&format!(", volume {}", index + 1)),
            None => details.push_str(", volume"),
        }
    }
    details
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

/// Which members a run is after: those its masks select and, of a file
/// `rar -ver` kept older copies of, only the latest unless `-ver` asks for all.
struct Wanted<'i> {
    masks: &'i [Vec<u8>],
    versions: bool,
    /// Names of the older copies in the volumes read so far.
    older: Mutex<HashSet<Vec<u8>>>,
    /// Members chosen so far.
    matched: AtomicUsize,
}

impl<'i> Wanted<'i> {
    fn new(invocation: &'i Invocation) -> Self {
        Self {
            masks: &invocation.masks,
            versions: invocation.versions,
            older: Mutex::default(),
            matched: AtomicUsize::new(0),
        }
    }

    /// Notes the older copies of files in a volume, before its members are read.
    fn note_versions(&self, archive: &Archive) {
        if let Archive::Rar50Plus(archive) = archive {
            lock(&self.older).extend(
                archive
                    .files()
                    .filter(|file| file.version.is_some())
                    .map(|file| file.name.clone()),
            );
        }
    }

    fn wants(&self, name: &[u8]) -> bool {
        (self.versions || !lock(&self.older).contains(name)) && selected(self.masks, name)
    }

    /// Whether the run wants a member it has reached, counting it if so.
    fn choose(&self, name: &[u8]) -> bool {
        let wanted = self.wants(name);
        if wanted {
            self.matched.fetch_add(1, Ordering::Relaxed);
        }
        wanted
    }
}

/// Whether any mask selects a member, as unrar matches them:
///
/// - a mask with no wildcards is a path from the archive root, and selects a
///   directory's contents with it;
/// - a mask with wildcards and no path is matched against the member's own
///   name, in any directory;
/// - a mask with wildcards and a path is matched against the whole path, and
///   its `*` reaches into subdirectories.
fn selected(masks: &[Vec<u8>], name: &[u8]) -> bool {
    if masks.is_empty() {
        return true;
    }
    let name: Vec<u8> = name
        .iter()
        .map(|&byte| if byte == b'\\' { b'/' } else { byte })
        .collect();
    masks.iter().any(|mask| {
        // Only Windows reads a backslash in a mask as a separator.
        let mut mask: Vec<u8> = mask
            .iter()
            .map(|&byte| {
                if cfg!(windows) && byte == b'\\' {
                    b'/'
                } else {
                    byte
                }
            })
            .collect();
        while mask.len() > 1 && mask.ends_with(b"/") {
            mask.pop();
        }
        mask_selects(&mask, &name)
    })
}

fn mask_selects(mask: &[u8], name: &[u8]) -> bool {
    if !has_wildcard(mask) {
        return name.len() >= mask.len()
            && same_bytes(&name[..mask.len()], mask)
            && (name.len() == mask.len() || name[mask.len()] == b'/');
    }
    let subject = if mask.contains(&b'/') {
        name
    } else {
        name.rsplit(|&byte| byte == b'/').next().unwrap_or(name)
    };
    let base = subject
        .rsplit(|&byte| byte == b'/')
        .next()
        .unwrap_or(subject);
    // As on DOS, `name.*` also matches `name`, and `*.` only names without an extension.
    wildcard(mask, subject)
        || mask
            .strip_suffix(b".*")
            .is_some_and(|stem| wildcard(stem, subject))
        || mask.strip_suffix(b".").is_some_and(|stem| {
            !stem.ends_with(b".") && !base.contains(&b'.') && wildcard(stem, subject)
        })
}

/// Names compare exactly, except that Windows ignores ASCII case as its filesystems do.
fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    if cfg!(windows) {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

/// `*` matches any run of bytes and `?` any one byte.
fn wildcard(mask: &[u8], name: &[u8]) -> bool {
    let (mut m, mut n) = (0, 0);
    let mut star = None;
    while n < name.len() {
        if m < mask.len() && mask[m] == b'*' {
            star = Some((m, n));
            m += 1;
        } else if m < mask.len() && (mask[m] == b'?' || same_bytes(&mask[m..=m], &name[n..=n])) {
            m += 1;
            n += 1;
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
    tally: &mut Tally,
    read: &mut HashSet<PathBuf>,
) {
    let options = ArchiveReadOptions::with_optional_password(password)
        .with_salvage(salvaging(invocation, archive));
    let command = invocation.command;
    let announce = move |volume: &Path| match command {
        Command::Extract { .. } => out.info(&format!("\nExtracting from {}\n", volume.display())),
        Command::Test => out.info(&format!("\nTesting archive {}\n", volume.display())),
        _ => {}
    };
    announce(path);
    read.insert(path.to_path_buf());
    let wanted = Wanted::new(invocation);
    wanted.note_versions(archive);
    let later_wanted = &wanted;
    let header_errors = AtomicUsize::new(report_header_damage(out, archive));
    let later_header_errors = &header_errors;
    let mut index = 1;
    // The first volume that ends early, of those after the first.
    let truncated = Mutex::new(None);
    let later_truncation = &truncated;
    let later_volumes = Mutex::new(Vec::new());
    let read_later = &later_volumes;
    let pause = invocation.pause_volumes;
    let stdin_closed = AtomicBool::new(false);
    let closed = &stdin_closed;
    let volumes = std::iter::from_fn(move || {
        let next = archive.volume_path(path, index)?;
        if pause {
            match ask_for_volume(out, &next) {
                Answer::Continue => {}
                Answer::Quit => return None,
                Answer::Closed => {
                    closed.store(true, Ordering::Relaxed);
                    return None;
                }
            }
        }
        if !next.exists() {
            return None;
        }
        index += 1;
        announce(&next);
        let volume = read_archive(&next, password);
        lock(read_later).push(next);
        if let Ok(volume) = &volume {
            later_header_errors.fetch_add(report_header_damage(out, volume), Ordering::Relaxed);
            later_wanted.note_versions(volume);
        }
        if let Some(truncation) = volume.as_ref().ok().and_then(Archive::truncation) {
            lock(later_truncation).get_or_insert_with(|| truncation.clone());
        }
        Some(volume)
    });
    let failures = Failures::new(&wanted, archive, path);
    let result = match command {
        Command::Extract { .. } => extract(invocation, out, archive, volumes, options, &failures),
        _ => {
            test_or_print(command, out, archive, volumes, options, &failures).map(|()| Extracted {
                warnings: false,
                all_kept: false,
            })
        }
    };
    read.extend(
        later_volumes
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner),
    );
    let header_errors = header_errors.into_inner();
    let member_errors = failures.count.into_inner();
    tally.errors += header_errors + member_errors;
    if member_errors > 0 {
        tally.fail(failures.code.into_inner());
    }
    match result {
        Ok(Extracted { warnings, all_kept }) => {
            let later = truncated
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner);
            let truncated = report_truncation(out, archive.truncation().or(later.as_ref()));
            tally.errors += usize::from(truncated);
            if header_errors > 0 {
                tally.fail(CHECKSUM);
            }
            if truncated || warnings {
                tally.fail(WARNING);
            }
            if wanted.matched.into_inner() > 0 && !all_kept {
                tally.worked += 1;
            }
        }
        Err(_) if stdin_closed.into_inner() => {
            out.error("Read error in the file stdin");
            out.info("Program aborted");
            tally.fail(READ_ERROR);
            tally.worked += 1;
        }
        Err(error) => {
            tally.errors += 1;
            tally.fail(report_failure(out, archive, path, &error));
            if header_errors > 0 {
                tally.fail(CHECKSUM);
            }
            tally.worked += 1;
        }
    }
}

/// What the caller said when `-vp` asked for the next volume.
enum Answer {
    Continue,
    Quit,
    /// Nothing more can be read from stdin.
    Closed,
}

/// `-vp`: asks on stderr before the next volume is opened and waits for an
/// answer on stdin, terminal or not, so a caller can hold the run until the
/// volume is there.
fn ask_for_volume(out: Out, next: &Path) -> Answer {
    if !out.silent {
        eprint!("\nInsert disk with {} [C]ontinue, [Q]uit ", next.display());
        let _ = std::io::stderr().flush();
    }
    let mut answer = String::new();
    match std::io::stdin().read_line(&mut answer) {
        Ok(0) | Err(_) => Answer::Closed,
        Ok(_) if answer.trim_start().starts_with(['q', 'Q']) => Answer::Quit,
        Ok(_) => Answer::Continue,
    }
}

struct Extracted {
    /// Finished with a warning, such as a link it left out.
    warnings: bool,
    /// `-o-` kept every selected file that was already there, so nothing was written.
    all_kept: bool,
}

/// The members a run failed on and went past. As unrar does, it reports each
/// one it wants and carries on to the next, and passes over the failures of
/// those it doesn't want without a word.
struct Failures<'r> {
    wanted: &'r Wanted<'r>,
    /// The set's first volume, to name the others by.
    archive: &'r Archive,
    path: &'r Path,
    count: AtomicUsize,
    /// The exit code of the first.
    code: AtomicI32,
    /// Failed members whose output is yet to be dropped.
    failed: Mutex<Vec<Vec<u8>>>,
    /// One of our own callbacks failed, and its error ends the run.
    callback_failed: AtomicBool,
}

/// What to do about a member that failed.
enum Failure {
    /// End the run with its error.
    Abort,
    /// Not a member the run wants: go on without a word.
    Unwanted,
    /// Report this line and go on.
    Report(String),
}

impl<'r> Failures<'r> {
    fn new(wanted: &'r Wanted<'r>, archive: &'r Archive, path: &'r Path) -> Self {
        Self {
            wanted,
            archive,
            path,
            count: AtomicUsize::new(0),
            code: AtomicI32::new(OK),
            failed: Mutex::default(),
            callback_failed: AtomicBool::new(false),
        }
    }

    /// Counts a member that failed if the run wants it, giving its error line.
    fn fail(&self, member: &rars::ArchiveMember, error: &rars::Error) -> Failure {
        // Reading the archive or writing the output failing ends the run.
        if self.callback_failed.load(Ordering::Relaxed) || error.kind() == ErrorKind::Io {
            return Failure::Abort;
        }
        if !self.wanted.wants(&member.meta.name) {
            return Failure::Unwanted;
        }
        // It may have failed before its output opened.
        self.wanted.matched.fetch_add(1, Ordering::Relaxed);
        let (line, code) = member_error_line(
            self.archive,
            self.path,
            &display_name(&member.meta.name),
            error,
        );
        let _ = self
            .code
            .compare_exchange(OK, code, Ordering::Relaxed, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        Failure::Report(line)
    }

    /// Notes that one of our callbacks failed, so its error is not gone past.
    fn callback<T>(&self, result: rars::Result<T>) -> rars::Result<T> {
        if result.is_err() {
            self.callback_failed.store(true, Ordering::Relaxed);
        }
        result
    }

    fn take_failed(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *lock(&self.failed))
    }
}

/// What `-kb` keeps: a member the library fails on after delivering its
/// bytes keeps its output, and its error is reported once that is in place,
/// after the file's line as unrar reports it.
#[derive(Default)]
struct KeepBroken {
    kept: KeptBroken,
    /// The error lines of kept members not yet in place, by member name.
    pending: Mutex<Vec<(Vec<u8>, String)>>,
}

fn extract<V>(
    invocation: &Invocation,
    out: Out,
    archive: &Archive,
    volumes: V,
    options: ArchiveReadOptions<'_>,
    failures: &Failures<'_>,
) -> rars::Result<Extracted>
where
    V: Iterator<Item = rars::Result<Archive>> + Send,
{
    let policy = match invocation.overwrite {
        Overwrite::Always => OverwritePolicy::Always,
        Overwrite::Never | Overwrite::Ask => OverwritePolicy::Never,
        Overwrite::Rename => OverwritePolicy::Rename,
    };
    let keep = KeepBroken::default();
    let broken = &keep;
    let mut state = ExtractOutputState::new(
        &invocation.destination,
        policy,
        invocation.keep_broken,
        invocation.command == (Command::Extract { flat: true }),
        archive.family(),
    );
    state.skip_existing = policy == OverwritePolicy::Never;
    state.selected = Some(Box::new(|meta: &rars::ExtractedEntryMeta| {
        failures.wanted.choose(&meta.name)
    }));
    state.on_published = Some(Box::new(move |output: &ExtractedOutput| {
        let verb = if output.meta.is_directory {
            "Creating"
        } else {
            "Extracting"
        };
        let pending = {
            let mut pending = lock(&broken.pending);
            pending
                .iter()
                .position(|(name, _)| *name == output.meta.name)
                .map(|index| pending.remove(index).1)
        };
        match pending {
            Some(line) => {
                out.info(&format!("{verb:<11} {}", output.path.display()));
                out.error(&line);
            }
            None => out.info(&format!("{verb:<11} {:<57} OK", output.path.display())),
        }
    }));
    let keep_broken = invocation.keep_broken;
    // Goes past a failed member. `-kb` keeps what was read of it; otherwise
    // its output is dropped before the next member opens.
    let handler = |member: &rars::ArchiveMember, error: &rars::Error| {
        let line = match failures.fail(member, error) {
            Failure::Abort => return Ok(rars::ExtractionErrorAction::Abort),
            Failure::Unwanted => return Ok(rars::ExtractionErrorAction::Continue),
            Failure::Report(line) => line,
        };
        let name = &member.meta.name;
        if !is_password_error(error) && broken.kept.keep(name) {
            lock(&broken.pending).push((name.clone(), line));
        } else {
            out.error(&line);
            lock(&failures.failed).push(name.clone());
        }
        Ok(rars::ExtractionErrorAction::Continue)
    };
    let state = RefCell::new(state);
    let result = rars::output_links::extract_arriving_with_links(
        archive,
        volumes,
        options.with_member_error_handler(&handler),
        |meta| {
            let mut state = state.borrow_mut();
            state.discard_failed(&failures.take_failed());
            let opened = if keep_broken {
                broken.kept.open(&mut state, meta)
            } else {
                state.open_entry(meta)
            };
            failures
                .callback(opened)
                .map(|writer| writer as Box<dyn Write>)
        },
        |meta, link| {
            broken.kept.close();
            let mut state = state.borrow_mut();
            state.discard_failed(&failures.take_failed());
            failures.callback(state.create_link(meta, link))
        },
    );
    state.borrow_mut().discard_failed(&failures.take_failed());
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

fn is_password_error(error: &rars::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::PasswordRequired | ErrorKind::BadPassword
    )
}

fn test_or_print<V>(
    command: Command,
    out: Out,
    archive: &Archive,
    volumes: V,
    options: ArchiveReadOptions<'_>,
    failures: &Failures<'_>,
) -> rars::Result<()>
where
    V: Iterator<Item = rars::Result<Archive>> + Send,
{
    // A member has passed its checksum once the next one starts, or the run
    // ends, with no error for it.
    let pending: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    let settle = |failed: Option<&[u8]>| {
        if let Some(name) = lock(&pending).take() {
            let name_text = display_name(&name);
            if failed == Some(name.as_slice()) {
                out.info(&format!("{:<11} {name_text}", "Testing"));
            } else {
                out.info(&format!("{:<11} {name_text:<57} OK", "Testing"));
            }
        }
    };
    let visit = |meta: &rars::ExtractedEntryMeta| -> bool {
        settle(None);
        let chosen = failures.wanted.choose(&meta.name);
        if chosen && command == Command::Test {
            *lock(&pending) = Some(meta.name.clone());
        }
        chosen
    };
    let handler = |member: &rars::ArchiveMember, error: &rars::Error| {
        match failures.fail(member, error) {
            Failure::Abort => return Ok(rars::ExtractionErrorAction::Abort),
            Failure::Unwanted => {}
            Failure::Report(line) => {
                settle(Some(&member.meta.name));
                out.error(&line);
            }
        }
        Ok(rars::ExtractionErrorAction::Continue)
    };
    rars::output_links::extract_arriving_with_links(
        archive,
        volumes,
        options.with_member_error_handler(&handler),
        |meta| {
            let chosen = visit(meta);
            Ok(if chosen && command == Command::Print {
                Box::new(std::io::stdout()) as Box<dyn Write>
            } else {
                Box::new(std::io::sink())
            })
        },
        |meta, _link| {
            visit(meta);
            Ok(())
        },
    )?;
    settle(None);
    Ok(())
}

/// Says that an archive ends early, as unrar does, after its members are done.
///
/// unrar says nothing about a file that stops at a block boundary, so neither
/// does this when the cut can't have lost a member.
fn report_truncation(out: Out, truncation: Option<&rars::Truncation>) -> bool {
    let Some(truncation) = truncation else {
        return false;
    };
    if truncation.members_complete && !truncation.started {
        return false;
    }
    out.error("Unexpected end of archive");
    match &truncation.block {
        rars::TruncatedBlock::RecoveryRecord => {
            out.error("Truncated at the service block: recovery record");
        }
        rars::TruncatedBlock::Service(name) if !name.is_empty() => {
            out.error(&format!(
                "Truncated at the service block: {}",
                display_name(name)
            ));
        }
        _ => {}
    }
    true
}

/// Reports a failure that ended the run, returning its exit code.
fn report_failure(out: Out, archive: &Archive, path: &Path, error: &rars::Error) -> i32 {
    let member = rars::output_staging::failed_entry_name(error).map(display_name);
    if let Some(index) = missing_volume(error) {
        let name = archive
            .volume_path(path, index)
            .unwrap_or_else(|| path.to_path_buf());
        out.error(&format!("Cannot find volume {}", name.display()));
        return MISSING_VOLUME;
    }
    let member = member.unwrap_or_else(|| path.display().to_string());
    let (line, code) = member_error_line(archive, path, &member, error);
    out.error(&line);
    code
}

/// What unrar says about a member it failed on, and the exit code it gives.
///
/// `archive` and `path` are the first volume's, to name a damaged later one by.
fn member_error_line(
    archive: &Archive,
    path: &Path,
    member: &str,
    error: &rars::Error,
) -> (String, i32) {
    match error.kind() {
        ErrorKind::ChecksumMismatch | ErrorKind::InvalidArchive => {
            let line = format!("{member:<20} - checksum error");
            // unrar first names the volume whose packed data failed its own checksum.
            match damaged_volume(error).and_then(|index| archive.volume_path(path, index)) {
                Some(volume) => (
                    format!(
                        "{member:<20} : packed data checksum error in volume {}\n{line}",
                        volume.display()
                    ),
                    CHECKSUM,
                ),
                None => (line, CHECKSUM),
            }
        }
        ErrorKind::PasswordRequired | ErrorKind::BadPassword => {
            (format!("Incorrect password for {member}"), BAD_PASSWORD)
        }
        // Such as a compression method from a later version, or one that
        // damage made up.
        ErrorKind::UnsupportedFeature | ErrorKind::UnsupportedFormat => (
            format!("Unknown method in {member}\nYou may need a newer version of RAR."),
            FATAL,
        ),
        _ => (format!("ERROR: {error}"), FATAL),
    }
}

/// Reports the damaged headers read past as unrar does, returning the
/// errors unrar would count for them.
fn report_header_damage(out: Out, archive: &Archive) -> usize {
    let mut errors = 0;
    for damage in archive.header_damage() {
        let Some(name) = header_member(archive, damage.offset) else {
            out.error("Corrupt header is found");
            if damage.offset == main_header_offset(archive) {
                out.error("Main archive header is corrupt");
            }
            errors += 1;
            continue;
        };
        if archive.family() == rars::ArchiveFamily::Rar50Plus {
            out.error("Corrupt header is found");
        }
        out.error(&format!(
            "{} - the file header is corrupt",
            display_name(name)
        ));
        // unrar counts a damaged file header as two errors.
        errors += 2;
    }
    errors
}

/// Where the main archive header starts: straight after the signature.
fn main_header_offset(archive: &Archive) -> u64 {
    let signature = match archive.family() {
        rars::ArchiveFamily::Rar50Plus => 8,
        _ => 7,
    };
    (archive.sfx_offset() + signature) as u64
}

/// The name of the file whose header is at `offset`.
fn header_member(archive: &Archive, offset: u64) -> Option<&[u8]> {
    match archive {
        Archive::Rar15To40(archive) => archive
            .files()
            .find(|file| file.block.offset as u64 == offset)
            .map(|file| file.name.as_slice()),
        Archive::Rar50Plus(archive) => archive
            .files()
            .find(|file| file.block.offset as u64 == offset)
            .map(|file| file.name.as_slice()),
        _ => None,
    }
}

/// The volume whose packed data failed the checksum its header gives for it,
/// when that is why a split member failed.
fn damaged_volume(error: &rars::Error) -> Option<usize> {
    match error {
        rars::Error::InVolume { index, source }
            if matches!(
                **source,
                rars::Error::Crc32Mismatch { .. } | rars::Error::HashMismatch { .. }
            ) =>
        {
            Some(*index)
        }
        rars::Error::AtEntry { source, .. }
        | rars::Error::AtArchiveOffset { source, .. }
        | rars::Error::InVolume { source, .. } => damaged_volume(source),
        _ => None,
    }
}

fn missing_volume(error: &rars::Error) -> Option<usize> {
    match error {
        rars::Error::InVolume { index, source } if **source == rars::Error::MissingVolume => {
            Some(*index)
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

    /// Issue #564, as unrar matches masks.
    #[test]
    fn masks_match_as_unrar_does() {
        let matches =
            |mask: &str, name: &str| selected(&[mask.as_bytes().to_vec()], name.as_bytes());
        // A plain name is a path from the root, and takes a directory's contents.
        assert!(matches("a.txt", "a.txt"));
        assert!(!matches("a.txt", "sub/a.txt"));
        assert!(matches("sub", "sub"));
        assert!(matches("sub", "sub/deeper/a.txt"));
        assert!(!matches("sub", "subway.txt"));
        assert!(matches("sub/deeper", "sub/deeper/a.txt"));
        assert!(!matches("deeper", "sub/deeper"));
        // Wildcards without a path match the name in any directory, and only it.
        assert!(matches("*.txt", "sub/deeper/a.txt"));
        assert!(matches("s*", "sub"));
        assert!(!matches("s*", "sub/a.txt"));
        assert!(matches("?.txt", "sub/b.txt"));
        // With a path, `*` reaches into subdirectories.
        assert!(matches("sub/*.txt", "sub/deeper/a.txt"));
        assert!(matches("*/a.txt", "sub/deeper/a.txt"));
        assert!(!matches("*/a.txt", "a.txt"));
        // DOS rules for extensions.
        assert!(matches("*.*", "sub"));
        assert!(matches("sub.*", "sub"));
        assert!(matches("*.", "sub/deeper"));
        assert!(!matches("*.", "a.txt"));
        // A separator at the end changes nothing.
        assert!(matches("sub/", "sub/a.txt"));
        // Case and backslashes in masks are the host's.
        assert_eq!(matches("A.TXT", "a.txt"), cfg!(windows));
        assert_eq!(matches(r"sub\a.txt", "sub/a.txt"), cfg!(windows));
    }

    #[test]
    fn an_existing_directory_ends_the_masks() {
        // A directory that is there, named without a trailing separator.
        let dir = env!("CARGO_MANIFEST_DIR");
        let parsed = invocation(&["x", "a.rar", "*.txt", dir]);
        assert_eq!(parsed.destination, PathBuf::from(dir));
        assert_eq!(parsed.masks, vec![b"*.txt".to_vec()]);
        // Only extraction has a destination to find.
        let parsed = invocation(&["t", "a.rar", dir]);
        assert_eq!(parsed.destination, PathBuf::new());
        assert!(invocation(&["x", "-ver", "a.rar"]).versions);
    }
}
