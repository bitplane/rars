//! `unrars`: the part of unrar's command line that other programs call.
//!
//! The commands, switches, output lines and exit codes follow what callers
//! such as python-rarfile and SABnzbd send and parse, as observed from unrar
//! run as a black box. Like unrar, it accepts switches it does not know.

use crate::output::{restore_output_metadata, ExtractedOutput, OverwritePolicy};
use crate::password::Password;
use crate::{display_bytes_lossy, lock};
use rars::extract_engine::ExtractEngine;
use rars::output_links::Settled;
use rars::{Archive, ArchiveReadOptions, ArchiveReader, ErrorKind};
use std::collections::HashSet;
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use zeroize::Zeroizing;

mod progress;
use progress::{Counted, Opened, Progress};

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
    STDOUT_CLOSED.store(false, Ordering::Relaxed);
    let code = match parse(args) {
        Ok(Some(invocation)) => run(&invocation),
        Ok(None) => {
            write_stdout(format_args!("{}", usage()));
            OK
        }
        Err(Refused::Usage) => {
            write_stdout(format_args!("{}", usage()));
            USAGE
        }
        Err(Refused::Switch(switch)) => {
            write_stderr(format_args!(
                "ERROR: unrars does not support the -{} switch yet\n",
                String::from_utf8_lossy(&switch)
            ));
            USAGE
        }
    };
    if let Err(error) = std::io::stdout().flush() {
        note_stdout_error(&error);
    }
    if stdout_closed() {
        return BROKEN_PIPE;
    }
    code
}

/// The status unrar ends with when the reader of its stdout goes away: it
/// dies of SIGPIPE, which a shell reports as 128 + 13. Raising the signal
/// needs `unsafe`, so this exits with the number instead.
const BROKEN_PIPE: i32 = 141;

/// Set once whatever reads stdout has closed it. The run then writes
/// nothing more, to stdout or stderr, and stops.
static STDOUT_CLOSED: AtomicBool = AtomicBool::new(false);

fn stdout_closed() -> bool {
    STDOUT_CLOSED.load(Ordering::Relaxed)
}

fn note_stdout_error(error: &std::io::Error) {
    if error.kind() == std::io::ErrorKind::BrokenPipe {
        STDOUT_CLOSED.store(true, Ordering::Relaxed);
    }
}

/// Writes to stdout, noting a closed pipe rather than panicking as `print!` does.
fn write_stdout(text: std::fmt::Arguments<'_>) {
    if stdout_closed() {
        return;
    }
    if let Err(error) = std::io::stdout().lock().write_fmt(text) {
        note_stdout_error(&error);
    }
}

/// Writes to stderr, quietly once stdout is gone, and never panicking.
fn write_stderr(text: std::fmt::Arguments<'_>) {
    if !stdout_closed() {
        let _ = std::io::stderr().lock().write_fmt(text);
    }
}

/// `p`'s output: stdout, which stops the run once its reader has gone.
struct PrintedMember;

impl Write for PrintedMember {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if stdout_closed() {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        std::io::stdout()
            .write(bytes)
            .inspect_err(note_stdout_error)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush().inspect_err(note_stdout_error)
    }
}

/// Fails a member's open once stdout is gone, so the run stops there.
fn check_stdout() -> rars::Result<()> {
    if stdout_closed() {
        return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    /// `x` keeps stored paths; `e` writes every file straight into the destination.
    Extract {
        flat: bool,
    },
    Test,
    Print,
    List(ListStyle),
}

/// How `l` and its kin show an archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListStyle {
    /// `l`: attributes, size, date and name.
    Plain,
    /// `v`: packed size, ratio and checksum as well.
    Verbose,
    /// `lt`: a block of fields for each member; `lta` for service blocks too.
    Technical { all: bool },
    /// `lb`: names only.
    Bare,
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
    /// Off with `-idp`: the running percentage on each member's line.
    percentages: bool,
    /// `-kb`: keep a damaged file with what could be read of it, written
    /// where it lands, and read past damaged headers.
    keep_broken: bool,
    /// `-ver`: older copies of a file kept by `rar -ver` are wanted too.
    versions: bool,
    /// `-vp`: ask before each later volume, and wait for the answer.
    pause_volumes: bool,
    /// `-v` with `l`: list every volume of a set, not only the one named.
    all_volumes: bool,
    /// `-n`: only members these masks select.
    include: Vec<Vec<u8>>,
    /// `-x`: never members these masks select.
    exclude: Vec<Vec<u8>>,
    /// `-ap`: members under this path in the archive are extracted without it.
    inside: Option<Vec<u8>>,
    /// `-ad`: extract into a directory named after the archive.
    archive_directory: bool,
    /// `-ol-`: leave symbolic links out.
    skip_symlinks: bool,
    /// `-ai`: set no file or directory modes.
    ignore_attributes: bool,
    /// `-ierr`: every message on stderr.
    stderr_only: bool,
    /// May hold `*` and `?`, matched against the files in its directory.
    archive: PathBuf,
    masks: Vec<Vec<u8>>,
    destination: PathBuf,
}

impl Invocation {
    /// Whether the masks, `-n` and `-x` select a member. As with unrar, `-ap`
    /// leaves out only the directory it names; members outside it are
    /// extracted where they are.
    fn selects(&self, name: &[u8]) -> bool {
        selected(&self.masks, name)
            && (self.include.is_empty() || selected(&self.include, name))
            && !(!self.exclude.is_empty() && selected(&self.exclude, name))
            && self
                .inside
                .as_ref()
                .is_none_or(|inside| strip_inside(inside, name).is_none_or(|rest| !rest.is_empty()))
    }

    /// The name a member is written under: without the `-ap` path.
    fn output_name<'n>(&self, name: &'n [u8]) -> &'n [u8] {
        self.inside
            .as_ref()
            .and_then(|inside| strip_inside(inside, name))
            .unwrap_or(name)
    }

    /// Where an archive's members go: the destination, and with `-ad` a
    /// directory named after the archive.
    fn destination_for(&self, archive: &Path) -> PathBuf {
        match archive.file_stem() {
            Some(stem) if self.archive_directory => self.destination.join(stem),
            _ => self.destination.clone(),
        }
    }
}

/// What of `name` follows the `-ap` path `inside`, when it is under it.
fn strip_inside<'n>(inside: &[u8], name: &'n [u8]) -> Option<&'n [u8]> {
    let separator = |byte: &u8| *byte == b'/' || *byte == b'\\';
    if name.len() < inside.len()
        || !name
            .iter()
            .zip(inside)
            .all(|(&left, &right)| left == right || (separator(&left) && right == b'/'))
    {
        return None;
    }
    match name.get(inside.len()) {
        None => Some(&name[name.len()..]),
        Some(byte) if separator(byte) => Some(&name[inside.len() + 1..]),
        Some(_) => None,
    }
}

/// Why a command line is refused.
#[derive(Debug, PartialEq, Eq)]
enum Refused {
    /// One unrar would refuse too.
    Usage,
    /// A switch that changes which files are written, or where, that unrars
    /// can't honour yet. Ignoring it would write what the caller asked not to.
    Switch(Vec<u8>),
}

impl From<()> for Refused {
    fn from((): ()) -> Self {
        Self::Usage
    }
}

/// Masks from a switch's argument: the mask itself, or `@` and a list file.
fn switch_masks(argument: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    match argument.strip_prefix(b"@") {
        Some(list) => read_mask_list(list),
        None if argument.is_empty() => Err(()),
        None => Ok(vec![argument.to_vec()]),
    }
}

/// The masks in a list file, one to a line.
fn read_mask_list(list: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    let list =
        std::fs::read(OsString::from(String::from_utf8_lossy(list).as_ref())).map_err(|_| ())?;
    Ok(list
        .split(|&byte| byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .map(<[u8]>::to_vec)
        .collect())
}

/// Switches unrars refuses rather than ignores: they filter by time, size,
/// attributes or freshness, rename what is written, or allow absolute paths
/// and links.
fn refused_switch(lower: &[u8]) -> bool {
    matches!(
        lower,
        b"f" | b"u" | b"cl" | b"cu" | b"ad1" | b"ad2" | b"ola"
    ) || [&b"ta"[..], b"tb", b"tn", b"to", b"sl", b"sm", b"ep", b"e+"]
        .iter()
        .any(|prefix| lower.starts_with(prefix) && lower != b"ep")
        || (lower.starts_with(b"e") && lower.len() > 1 && lower[1].is_ascii_digit())
}

/// `Ok(None)` asks for the usage text.
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Invocation>, Refused> {
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
        "l" => Command::List(ListStyle::Plain),
        "v" => Command::List(ListStyle::Verbose),
        "lt" | "vt" => Command::List(ListStyle::Technical { all: false }),
        "lta" | "vta" => Command::List(ListStyle::Technical { all: true }),
        "lb" | "vb" => Command::List(ListStyle::Bare),
        _ => return Err(Refused::Usage),
    };
    let mut invocation = Invocation {
        command,
        overwrite: Overwrite::Ask,
        password: PasswordSwitch::Unset,
        silent: false,
        quiet: false,
        banner: true,
        done: true,
        percentages: true,
        keep_broken: false,
        versions: false,
        pause_volumes: false,
        all_volumes: false,
        include: Vec::new(),
        exclude: Vec::new(),
        inside: None,
        archive_directory: false,
        skip_symlinks: false,
        ignore_attributes: false,
        stderr_only: false,
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
            Some(list) => invocation.masks.extend(read_mask_list(list)?),
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
            b"ad" => invocation.archive_directory = true,
            b"ep" => {
                if let Command::Extract { flat } = &mut invocation.command {
                    *flat = true;
                }
            }
            b"ol-" => invocation.skip_symlinks = true,
            b"ai" => invocation.ignore_attributes = true,
            b"ierr" => invocation.stderr_only = true,
            _ if refused_switch(&lower) => return Err(Refused::Switch(raw.to_vec())),
            // Masks and paths keep their case.
            _ if lower.starts_with(b"x") => invocation.exclude.extend(switch_masks(&raw[1..])?),
            _ if lower.starts_with(b"n") => invocation.include.extend(switch_masks(&raw[1..])?),
            _ if lower.starts_with(b"ap") => {
                let mut inside: Vec<u8> = raw[2..]
                    .iter()
                    .map(|&byte| if byte == b'\\' { b'/' } else { byte })
                    .collect();
                while inside.ends_with(b"/") {
                    inside.pop();
                }
                // A path in the archive, whether or not it starts at its root.
                let start = inside.iter().take_while(|&&byte| byte == b'/').count();
                inside.drain(..start);
                invocation.inside = (!inside.is_empty()).then_some(inside);
            }
            _ if lower.starts_with(b"op") && raw.len() > 2 => {
                invocation.destination =
                    PathBuf::from(OsString::from(String::from_utf8_lossy(&raw[2..]).as_ref()));
            }
            _ if lower.starts_with(b"ver") => invocation.versions = true,
            _ if lower.starts_with(b"id") => {
                for flag in &lower[2..] {
                    match flag {
                        b'c' => invocation.banner = false,
                        b'd' => invocation.done = false,
                        b'p' => invocation.percentages = false,
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
  -x<f>   Exclude files matching <f>; -x@<list> for a list of masks
  -n<f>   Include only files matching <f>; -n@<list> for a list of masks
  -ap<p>  Extract files under <p> in the archive without it
  -ad     Extract into a directory named after the archive
  -ep     Extract without paths, as e does
  -op<p>  Extract into <p>
  -ol-    Leave symbolic links out
  -ai     Ignore file attributes: set no file or directory modes
  -ierr   Send all messages to stderr
  -inul   No messages
  -idq    Errors only; -idc no banner; -idd no closing \"All OK\";
          -idp no percentages
  --      End of switches

Switches that filter by time, size, attributes or freshness (-ta, -tb, -tn,
-to, -sl, -sm, -e, -f, -u), change names (-cl, -cu) or allow absolute paths
and links (-ad1, -ad2, -ep1 to -ep4, -ola) are refused. Other unrar switches
are accepted and ignored.
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

/// Where messages go: unrar puts progress on stdout and errors on stderr,
/// or everything on stderr with `-ierr`.
#[derive(Clone, Copy)]
struct Out {
    silent: bool,
    quiet: bool,
    stderr_only: bool,
}

impl Out {
    fn info(self, line: &str) {
        if !self.silent && !self.quiet {
            self.print(format_args!("{line}\n"));
        }
    }

    /// Listings and the banner, which `-idq` leaves alone.
    fn print(self, text: std::fmt::Arguments<'_>) {
        if self.stderr_only {
            write_stderr(text);
        } else {
            write_stdout(text);
        }
    }

    fn error(self, line: &str) {
        if !self.silent {
            write_stderr(format_args!("{line}\n"));
        }
    }

    /// Part of a member's line, shown at once rather than when the line ends.
    fn progress(self, text: std::fmt::Arguments<'_>) {
        if self.silent || self.quiet {
            return;
        }
        self.print(text);
        if !self.stderr_only {
            if let Err(error) = std::io::stdout().flush() {
                note_stdout_error(&error);
            }
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
    /// Stdin closed while unrar would still be asking on it: the run stops.
    aborted: bool,
}

impl Tally {
    /// Stops the run because stdin closed while asking on it, as unrar does.
    /// `gap` is the blank lines unrar leaves before saying so.
    fn abort(&mut self, out: Out, gap: &str) {
        out.error("Read error in the file stdin");
        out.info(&format!("{gap}Program aborted"));
        self.fail(READ_ERROR);
        self.aborted = true;
    }

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
        stderr_only: invocation.stderr_only,
    };
    let quiet_command = matches!(
        invocation.command,
        Command::List(ListStyle::Bare) | Command::Print
    );
    if invocation.banner && !quiet_command && !out.silent && !out.quiet {
        out.print(format_args!("{}", banner()));
    }
    let mut password = match &invocation.password {
        PasswordSwitch::Given(password) => Some(password.clone()),
        PasswordSwitch::Prompt => match prompt_password(None) {
            Some(password) => Some(password),
            None => {
                out.error("Read error in the file stdin");
                return READ_ERROR;
            }
        },
        PasswordSwitch::Unset | PasswordSwitch::Never => None,
    };
    let mut tally = Tally::default();
    // Volumes already read as part of a set an earlier archive started.
    let mut read = HashSet::new();
    for path in archive_paths(&invocation.archive) {
        if stdout_closed() {
            return BROKEN_PIPE;
        }
        if !read.contains(&path) {
            run_archive(invocation, out, &path, &mut password, &mut tally, &mut read);
        }
        if tally.aborted {
            break;
        }
    }
    if stdout_closed() {
        return BROKEN_PIPE;
    }
    if tally.aborted {
        return tally.code;
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
    let mut archive = match open_archive(out, &path, password, may_ask) {
        Err(StdinClosed) => return tally.abort(out, "\n\n"),
        Ok(Ok(archive)) => archive,
        Ok(Err(error)) => {
            if let Some(code) = report_open_failure(out, &path, &error) {
                tally.fail(code);
            }
            let listing =
                matches!(invocation.command, Command::List(style) if style != ListStyle::Bare);
            if listing && needs_password(&error) {
                list_locked_headers(out, &path);
            }
            return;
        }
    };
    let listing = matches!(invocation.command, Command::List { .. });
    // Named by a later volume, a set is read from its first, as unrar does.
    if !listing && archive.is_first_volume() == Some(false) {
        let first = first_volume(&path, &archive).filter(|first| first.is_file());
        if let Some(first) = first {
            match open_archive(out, &first, password, may_ask) {
                Err(StdinClosed) => return tally.abort(out, "\n\n"),
                Ok(Ok(first_archive)) if first_archive.is_first_volume() == Some(true) => {
                    // unrar names the volume it was given before going back.
                    match invocation.command {
                        Command::Extract { .. } => {
                            out.info(&format!("\nExtracting from {}", path.display()));
                        }
                        Command::Test => out.info(&format!("\nTesting archive {}", path.display())),
                        _ => {}
                    }
                    read.insert(path);
                    path = first;
                    archive = first_archive;
                }
                _ => {}
            }
        }
    }
    let path = path.as_path();
    if !listing {
        // The archive comment, then the first volume's line, come before
        // any password prompt for a member, as unrar prints them.
        if matches!(invocation.command, Command::Extract { .. } | Command::Test) {
            let given = password.as_deref().map(Vec::as_slice);
            if let Some(comment) = comment_text(&archive, given) {
                out.info(&format!("\nArchive comment:\n{comment}"));
            }
        }
        announce(out, invocation.command, path);
    }
    if may_ask && !listing && password.is_none() {
        let locked = archive
            .members()
            .find(|member| member.meta.is_encrypted && invocation.selects(&member.meta.name));
        if let Some(member) = locked {
            let name = display_name(&member.meta.name);
            *password = prompt_password(Some(&name));
            // unrar asks again while the password fails the member's check.
            let file = archive
                .as_rar50()
                .and_then(|archive| archive.files().find(|file| file.name == member.meta.name));
            while let (Some(given), Some(file)) = (password.as_deref(), file) {
                if file.password_matches(given).ok().flatten() != Some(false) {
                    break;
                }
                incorrect_password(out);
                *password = prompt_password(Some(&name));
                if password.is_none() {
                    return tally.abort(out, "\n");
                }
            }
        }
    }
    match invocation.command {
        Command::List(style) => {
            let password = password.as_deref().map(Vec::as_slice);
            list_volumes(invocation, out, path, archive, password, style, tally);
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

/// Asks for a password, for `name` if given, as unrar does: on a terminal
/// without echo, otherwise from a line of stdin, so a caller can pipe it in.
fn prompt_password(name: Option<&str>) -> Option<Password> {
    let prompt = match name {
        Some(name) => format!("\nEnter password (will not be echoed) for {name}: "),
        None => "\nEnter password (will not be echoed): ".to_string(),
    };
    if std::io::stdin().is_terminal() {
        let line = rpassword::prompt_password(prompt).ok()?;
        return Some(Zeroizing::new(line.into_bytes()));
    }
    write_stderr(format_args!("{prompt}"));
    let _ = std::io::stderr().flush();
    let mut line = Zeroizing::new(String::new());
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => {
            let password = line.trim_end_matches(['\n', '\r']);
            Some(Zeroizing::new(password.as_bytes().to_vec()))
        }
    }
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

/// Stdin closed while asking again for a password.
struct StdinClosed;

/// Opens an archive, asking for the password its headers need if it may, and
/// asking again, as unrar does, while the password given is wrong.
fn open_archive(
    out: Out,
    path: &Path,
    password: &mut Option<Password>,
    may_ask: bool,
) -> Result<rars::Result<Archive>, StdinClosed> {
    let read =
        |password: &Option<Password>| read_archive(path, password.as_deref().map(Vec::as_slice));
    match read(password) {
        Err(error) if may_ask && password.is_none() && needs_password(&error) => {
            let name = path.as_os_str().to_string_lossy();
            *password = prompt_password(Some(&name));
            if password.is_none() {
                return Ok(Err(error));
            }
            loop {
                match read(password) {
                    Err(error) if error.kind() == ErrorKind::BadPassword => {
                        incorrect_password(out);
                        *password = prompt_password(Some(&name));
                        if password.is_none() {
                            return Err(StdinClosed);
                        }
                    }
                    result => return Ok(result),
                }
            }
        }
        result => Ok(result),
    }
}

/// What unrar says before asking again for a password that was wrong.
fn incorrect_password(out: Out) {
    if !out.silent {
        write_stderr(format_args!("\nThe specified password is incorrect."));
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
        // RAR 1.5-4 headers carry no password check, so unrar can't tell a
        // wrong password from damage.
        ErrorKind::PasswordRequired | ErrorKind::BadPassword
            if detected_family(path) == Some(rars::ArchiveFamily::Rar15To40) =>
        {
            out.error(&format!(
                "Checksum error in the encrypted file {}. Corrupt file or wrong password.",
                path.display()
            ));
            Some(CHECKSUM)
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

/// What a listing's members add up to.
#[derive(Clone, Copy, Default)]
struct Totals {
    size: u64,
    packed: u64,
    count: usize,
}

impl Totals {
    fn add(&mut self, other: Self) {
        self.size += other.size;
        self.packed += other.packed;
        self.count += other.count;
    }
}

/// Lists an archive and, with `-v`, each later volume of its set in turn,
/// then their grand total. The archive comment comes first.
fn list_volumes(
    invocation: &Invocation,
    out: Out,
    path: &Path,
    archive: Archive,
    password: Option<&[u8]>,
    style: ListStyle,
    tally: &mut Tally,
) {
    if style != ListStyle::Bare {
        if let Some(comment) = comment_text(&archive, password) {
            out.print(format_args!("\nArchive comment:\n{comment}\n"));
        }
    }
    let mut totals = Totals::default();
    let mut listed = 0;
    let mut next = Some((path.to_path_buf(), archive.clone()));
    while let Some((volume_path, volume)) = next.take() {
        if report_header_damage(out, &volume) > 0 {
            tally.fail(CHECKSUM);
        }
        totals.add(list(invocation, out, &volume_path, &volume, style));
        listed += 1;
        if report_truncation(out, volume.family(), volume.truncation()) {
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
    // unrar sets the grand total one column left of each volume's.
    if invocation.all_volumes {
        match style {
            ListStyle::Plain => {
                out.print(format_args!("{:>21}{:>21}\n", totals.size, totals.count));
            }
            ListStyle::Verbose => out.print(format_args!(
                "{:>21} {:>10} {:>4}{:>31}\n",
                totals.size,
                totals.packed,
                ratio(totals.size, totals.packed),
                totals.count
            )),
            ListStyle::Technical { .. } | ListStyle::Bare => {}
        }
    }
    if !matches!(style, ListStyle::Bare | ListStyle::Technical { .. }) {
        out.print(format_args!("\n"));
    }
}

/// The archive comment as unrar shows it: control codes as they are, except
/// escape, which shows as `'\033'`, and the C1 controls, which show as `?`,
/// so the comment can't drive a terminal.
fn comment_text(archive: &Archive, password: Option<&[u8]>) -> Option<String> {
    let options = ArchiveReadOptions::with_optional_password(password);
    let comment = archive.comment_with_options(options).ok()??;
    let text = utf16_comment(archive.family(), &comment)
        .unwrap_or_else(|| String::from_utf8_lossy(&comment).into_owned());
    Some(shown_comment(&text))
}

/// Escape as unrar shows it, and C1 controls (U+0080–U+009F) as `?`: some
/// terminals act on those, U+009B in particular, without an escape byte.
fn shown_comment(text: &str) -> String {
    let mut shown = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\u{1b}' => shown.push_str("'\\033'"),
            '\u{80}'..='\u{9f}' => shown.push('?'),
            c => shown.push(c),
        }
    }
    shown
}

/// A RAR 3 comment written as UTF-16, as RAR 3.x on Linux writes it: an even
/// number of bytes, at least half of whose high bytes are zero, which text in
/// any byte encoding doesn't have.
fn utf16_comment(family: rars::ArchiveFamily, bytes: &[u8]) -> Option<String> {
    if family != rars::ArchiveFamily::Rar15To40
        || bytes.is_empty()
        || !bytes.len().is_multiple_of(2)
    {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    let narrow = units.iter().filter(|&&unit| unit < 0x100).count();
    if narrow * 2 < units.len() {
        return None;
    }
    Some(
        String::from_utf16_lossy(&units)
            .trim_end_matches('\0')
            .to_string(),
    )
}

/// What `l` shows of an archive whose headers need a password it hasn't got.
fn list_locked_headers(out: Out, path: &Path) {
    let format = match detected_family(path) {
        Some(rars::ArchiveFamily::Rar50Plus) => "RAR 5",
        _ => "RAR 1.5",
    };
    out.print(format_args!(
        "\nArchive: {}\nDetails: {format}, encrypted headers\n  0 files\n\n",
        path.display()
    ));
}

/// The format family an archive's signature names, read from its start.
fn detected_family(path: &Path) -> Option<rars::ArchiveFamily> {
    std::fs::File::open(path)
        .and_then(|file| {
            use std::io::Read;
            let mut prefix = Vec::new();
            file.take(1 << 20).read_to_end(&mut prefix)?;
            Ok(prefix)
        })
        .ok()
        .and_then(|prefix| ArchiveReader::detect(&prefix).ok())
        .map(|signature| signature.family)
}

/// Lists one archive or volume, returning what the files that start in it
/// add up to.
fn list(
    invocation: &Invocation,
    out: Out,
    path: &Path,
    archive: &Archive,
    style: ListStyle,
) -> Totals {
    // unrar lists the older copies `rar -ver` kept, `-ver` or not.
    let members: Vec<_> = archive
        .member_refs()
        .filter(|member| invocation.selects(member.name_bytes()))
        .collect();
    let mut totals = Totals::default();
    for member in &members {
        let meta = member.to_owned().meta;
        // A member continued from an earlier volume counts where it starts.
        if !meta.is_split_before {
            totals.size += meta.unpacked_size;
            totals.count += 1;
        }
        totals.packed += meta.packed_size;
    }
    if style == ListStyle::Bare {
        for member in &members {
            out.print(format_args!("{}\n", display_name(member.name_bytes())));
        }
        return totals;
    }
    out.print(format_args!(
        "\nArchive: {}\nDetails: {}\n\n",
        path.display(),
        details(archive)
    ));
    match style {
        ListStyle::Technical { all } => {
            list_technical(out, archive, &members, all, &|name| {
                invocation.selects(name)
            });
            return totals;
        }
        ListStyle::Verbose => {
            out.print(format_args!(
                " Attributes       Size     Packed Ratio    Date    Time   Checksum  Name\n"
            ));
            out.print(format_args!("{VERBOSE_RULE}\n"));
        }
        _ => {
            out.print(format_args!(
                " Attributes       Size     Date    Time   Name\n"
            ));
            out.print(format_args!("{PLAIN_RULE}\n"));
        }
    }
    for member in &members {
        let meta = member.to_owned().meta;
        let marker = if meta.is_encrypted { '*' } else { ' ' };
        let (date, time) = match meta
            .stored_modification_time()
            .and_then(|time| time.local_calendar_fields())
        {
            Some((year, month, day, hour, minute, _)) => (
                format!("{year:04}-{month:02}-{day:02}"),
                format!("{hour:02}:{minute:02}"),
            ),
            None => ("????-??-??".to_string(), "??:??".to_string()),
        };
        let name = display_name(&meta.name);
        let attributes = attributes(&meta);
        if style == ListStyle::Verbose {
            let checksum = match (meta.is_directory, member_crc(*member)) {
                (false, Some((crc, _))) => format!("{crc:08X}"),
                _ => String::new(),
            };
            out.print(format_args!(
                "{marker}{attributes:<10} {:>10} {:>10} {:>4}  {date} {time}  {checksum:<8}  {name}\n",
                meta.unpacked_size,
                meta.packed_size,
                split_ratio(&meta),
            ));
        } else {
            out.print(format_args!(
                "{marker}{attributes:<10} {:>10}  {date} {time}  {name}\n",
                meta.unpacked_size
            ));
        }
    }
    if style == ListStyle::Verbose {
        out.print(format_args!("{VERBOSE_RULE}\n"));
        out.print(format_args!(
            "{:>22} {:>10} {:>4}{:>31}\n",
            totals.size,
            totals.packed,
            ratio(totals.size, totals.packed),
            totals.count
        ));
    } else {
        out.print(format_args!("{PLAIN_RULE}\n"));
        out.print(format_args!("{:>22}{:>21}\n", totals.size, totals.count));
    }
    totals
}

const PLAIN_RULE: &str = "----------- ----------  ---------- -----  ----";
const VERBOSE_RULE: &str =
    "----------- ---------- ---------- ----- ---------- -----  --------  ----";

/// The packed size as a share of the unpacked, as unrar rounds it.
fn ratio(size: u64, packed: u64) -> String {
    if size == 0 {
        return "0%".to_string();
    }
    format!("{}%", u128::from(packed) * 100 / u128::from(size))
}

/// A member's ratio, or unrar's arrows for one split across volumes.
fn split_ratio(meta: &rars::ArchiveMemberMeta) -> String {
    match (meta.is_split_before, meta.is_split_after) {
        (true, true) => "<->".to_string(),
        (true, false) => "<--".to_string(),
        (false, true) => "-->".to_string(),
        (false, false) => ratio(meta.unpacked_size, meta.packed_size),
    }
}

/// A member's stored CRC32, and whether it is keyed by the password.
fn member_crc(member: rars::ArchiveMemberRef<'_>) -> Option<(u32, bool)> {
    match member {
        rars::ArchiveMemberRef::Rar50Plus(file) => {
            let mac = file
                .encryption
                .as_ref()
                .is_some_and(|encryption| encryption.flags & 0x0002 != 0);
            file.data_crc32.map(|crc| (crc, mac))
        }
        rars::ArchiveMemberRef::Rar15To40(file) => Some((file.file_crc, false)),
        _ => None,
    }
}

/// `lt`: a block of fields for each member, and with `lta` for each RAR 5
/// service block too.
fn list_technical(
    out: Out,
    archive: &Archive,
    members: &[rars::ArchiveMemberRef<'_>],
    all: bool,
    selects: &dyn Fn(&[u8]) -> bool,
) {
    // As unrar does, `lta` lists services where they are among the files,
    // then the archive's end.
    let ended = match archive {
        Archive::Rar50Plus(archive) if all => {
            let mut ended = false;
            for block in &archive.blocks {
                match block {
                    rars::rar50::Block::File(file) if selects(&file.name) => {
                        technical_entry(out, rars::ArchiveMemberRef::Rar50Plus(file), false);
                    }
                    rars::rar50::Block::Service(service) => {
                        technical_entry(out, rars::ArchiveMemberRef::Rar50Plus(service), true);
                    }
                    rars::rar50::Block::End(_) => ended = true,
                    _ => {}
                }
            }
            ended
        }
        Archive::Rar15To40(archive) if all => {
            let mut ended = false;
            for block in &archive.blocks {
                match block {
                    rars::rar15_40::Block::File(file) if selects(&file.name) => {
                        technical_entry(out, rars::ArchiveMemberRef::Rar15To40(file), false);
                    }
                    rars::rar15_40::Block::NewSub(service) => {
                        technical_entry(
                            out,
                            rars::ArchiveMemberRef::Rar15To40(&service.file),
                            true,
                        );
                    }
                    rars::rar15_40::Block::End(_) => ended = true,
                    _ => {}
                }
            }
            ended
        }
        _ => {
            for member in members {
                technical_entry(out, *member, false);
            }
            false
        }
    };
    if ended {
        out.print(format_args!("{:>12}: EOF\n\n", "Service"));
    }
}

fn technical_entry(out: Out, member: rars::ArchiveMemberRef<'_>, service: bool) {
    let meta = member.to_owned().meta;
    let field = |label: &str, value: &dyn std::fmt::Display| {
        out.print(format_args!("{label:>12}: {value}\n"));
    };
    field("Name", &display_name(&meta.name));
    let link = match member {
        rars::ArchiveMemberRef::Rar50Plus(file) => file.redirection.as_ref(),
        _ => None,
    };
    let kind = if service {
        "Service"
    } else if meta.is_directory {
        "Directory"
    } else {
        match link.map(|link| link.redirection_type) {
            Some(1) => "Unix symbolic link",
            Some(2) => "Windows symbolic link",
            Some(3) => "Windows junction",
            Some(4) => "Hard link",
            Some(5) => "File reference",
            Some(_) => "Link",
            None => "File",
        }
    };
    field("Type", &kind);
    if let Some(link) = link {
        field("Target", &display_name(&link.target_name));
    }
    if !meta.is_directory {
        field("Size", &meta.unpacked_size);
        field("Packed size", &meta.packed_size);
        field("Ratio", &split_ratio(&meta));
    }
    if let rars::ArchiveMemberRef::Rar50Plus(file) = member {
        if let Ok(Some(record)) = file.recovery_record() {
            field("RR%", &format!("{}%", record.percent));
        }
    }
    let calendar = match member {
        // unrar reads a DOS time of 0, which services have, as day 0 of
        // month 0 of 1980.
        rars::ArchiveMemberRef::Rar15To40(file) if file.file_time == 0 => {
            Some((1979, 11, 30, 0, 0, 0))
        }
        _ => meta
            .stored_modification_time()
            .and_then(|time| time.local_calendar_fields()),
    };
    if let Some((year, month, day, hour, minute, second)) = calendar {
        let nanoseconds = meta
            .modification_time()
            .map_or(0, rars::Timestamp::nanoseconds);
        field(
            "mtime",
            &format!(
                "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02},{nanoseconds:09}"
            ),
        );
    }
    if service {
        field("Attributes", &".B");
    } else {
        field("Attributes", &attributes(&meta));
    }
    if !meta.is_directory {
        // A part that goes on into the next volume has the checksum of its
        // packed data.
        match member_crc(member) {
            Some((crc, _)) if meta.is_split_after => field("Pack-CRC32", &format!("{crc:08X}")),
            Some((crc, true)) => field("CRC32 MAC", &format!("{crc:08X}")),
            Some((crc, false)) => field("CRC32", &format!("{crc:08X}")),
            None => {}
        }
    }
    if let Some(host) = host_os(&meta) {
        field("Host OS", &host);
    }
    if let Some(compression) = compression(member, meta.is_directory) {
        field("Compression", &compression);
    }
    let mut flags = String::new();
    if member.is_solid() {
        flags.push_str("solid ");
    }
    if meta.is_encrypted {
        flags.push_str("encrypted ");
    }
    if !flags.is_empty() {
        field("Flags", &flags);
    }
    out.print(format_args!("\n"));
}

fn host_os(meta: &rars::ArchiveMemberMeta) -> Option<&'static str> {
    let host = meta.host_os?;
    Some(match (meta.family, host) {
        (rars::ArchiveFamily::Rar50Plus, 0) => "Windows",
        (rars::ArchiveFamily::Rar50Plus, 1) => "Unix",
        (rars::ArchiveFamily::Rar15To40, 0) => "MS DOS",
        (rars::ArchiveFamily::Rar15To40, 1) => "OS/2",
        (rars::ArchiveFamily::Rar15To40, 2) => "Windows",
        (rars::ArchiveFamily::Rar15To40, 3) => "Unix",
        (rars::ArchiveFamily::Rar15To40, 4) => "Mac OS",
        (rars::ArchiveFamily::Rar15To40, 5) => "BeOS",
        _ => return None,
    })
}

/// The compression line: format and decoder version, method and dictionary.
fn compression(member: rars::ArchiveMemberRef<'_>, directory: bool) -> Option<String> {
    let (format, method, dictionary) = match member {
        rars::ArchiveMemberRef::Rar50Plus(file) => {
            let info = file.decoded_compression_info().ok()?;
            let format = match info.algorithm_version {
                0 => "RAR 5.0(v50)",
                _ => "RAR 7.0(v70)",
            };
            (format.to_string(), info.method, info.dictionary_size)
        }
        rars::ArchiveMemberRef::Rar15To40(file) => {
            // Dictionary bits in the file flags: 64 KiB doubled each step.
            let bits = (file.block.flags >> 5) & 7;
            (
                format!("RAR 1.5(v{})", file.unp_ver),
                file.method.saturating_sub(0x30),
                (64 * 1024) << bits,
            )
        }
        _ => return None,
    };
    if directory {
        return Some(format!("{format} -m{method}"));
    }
    Some(format!(
        "{format} -m{method} -md={}",
        dictionary_size(dictionary)
    ))
}

/// A dictionary size as unrar writes it: `128k`, `4m`, `1g`.
fn dictionary_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    match bytes {
        _ if bytes >= KIB * KIB * KIB && bytes.is_multiple_of(KIB * KIB * KIB) => {
            format!("{}g", bytes / (KIB * KIB * KIB))
        }
        _ if bytes >= KIB * KIB && bytes.is_multiple_of(KIB * KIB) => {
            format!("{}m", bytes / (KIB * KIB))
        }
        _ => format!("{}k", bytes / KIB),
    }
}

/// The listing's `Details:` line: the format, then what unrar notes about
/// the archive, in unrar's order.
fn details(archive: &Archive) -> String {
    let mut details = vec![match archive.family() {
        rars::ArchiveFamily::Rar13 => "RAR 1.4".to_string(),
        rars::ArchiveFamily::Rar15To40 => "RAR 1.5".to_string(),
        rars::ArchiveFamily::Rar50Plus => "RAR 5".to_string(),
        _ => "RAR".to_string(),
    }];
    let (solid, recovery, locked, encrypted) = match archive {
        Archive::Rar50Plus(archive) => (
            archive.main.is_solid(),
            archive.main.has_recovery_record(),
            archive.main.is_locked(),
            archive.main.encrypted_headers,
        ),
        Archive::Rar15To40(archive) => (
            archive.main.is_solid(),
            archive.main.has_recovery_record(),
            // MHD_LOCK.
            archive.main.flags & 0x0004 != 0,
            archive.main.has_encrypted_headers(),
        ),
        _ => (false, false, false, false),
    };
    if solid {
        details.push("solid".to_string());
    }
    if archive.is_volume() {
        // unrar numbers RAR 5 volumes only.
        match archive.volume_index() {
            Some(index) if archive.family() == rars::ArchiveFamily::Rar50Plus => {
                details.push(format!("volume {}", index + 1));
            }
            _ => details.push("volume".to_string()),
        }
    }
    if recovery {
        details.push("recovery record".to_string());
    }
    if locked {
        details.push("lock".to_string());
    }
    if encrypted {
        details.push("encrypted headers".to_string());
    }
    details.join(", ")
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
    invocation: &'i Invocation,
    /// Names of the older copies in the volumes read so far.
    older: Mutex<HashSet<Vec<u8>>>,
    /// Members chosen so far.
    matched: AtomicUsize,
}

impl<'i> Wanted<'i> {
    fn new(invocation: &'i Invocation) -> Self {
        Self {
            invocation,
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
        (self.invocation.versions || !lock(&self.older).contains(name))
            && self.invocation.selects(name)
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
    let announce = move |volume: &Path| announce(out, command, volume);
    // The first volume's line is already out.
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
    let progress = Arc::new(Progress::new(out, invocation.percentages, path, archive));
    let volume_progress = Arc::clone(&progress);
    let volumes = std::iter::from_fn(move || {
        let next = archive.volume_path(path, index)?;
        volume_progress.volume_wanted();
        if pause {
            match ask_for_volume(out, &next) {
                Answer::Continue => {}
                Answer::Quit => {
                    volume_progress.volume_missing();
                    return None;
                }
                Answer::Closed => {
                    volume_progress.volume_missing();
                    closed.store(true, Ordering::Relaxed);
                    return None;
                }
            }
        }
        if !next.exists() {
            volume_progress.volume_missing();
            return None;
        }
        volume_progress.volume_found();
        index += 1;
        announce(&next);
        let volume = read_archive(&next, password);
        lock(read_later).push(next.clone());
        if let Ok(volume) = &volume {
            later_header_errors.fetch_add(report_header_damage(out, volume), Ordering::Relaxed);
            later_wanted.note_versions(volume);
        }
        if let Some(truncation) = volume.as_ref().ok().and_then(Archive::truncation) {
            lock(later_truncation).get_or_insert_with(|| truncation.clone());
        }
        volume_progress.volume_starts(&next, volume.as_ref().ok());
        Some(volume)
    });
    let failures = Failures::new(&wanted, archive, path);
    let result = match command {
        Command::Extract { .. } => extract(
            invocation, out, archive, volumes, options, &failures, &progress,
        ),
        _ => test_or_print(command, archive, volumes, options, &failures, &progress).map(|()| {
            Extracted {
                warnings: false,
                all_kept: false,
            }
        }),
    };
    // A split member a missing volume cut short, which unrar reports too.
    let cut = match &result {
        Err(error) if missing_volume(error).is_some() && !stdin_closed.load(Ordering::Relaxed) => {
            progress.cut_short()
        }
        _ => None,
    };
    progress.stop();
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
            let truncated = report_truncation(
                out,
                archive.family(),
                archive.truncation().or(later.as_ref()),
            );
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
        Err(_) if stdin_closed.into_inner() => tally.abort(out, ""),
        Err(error) => {
            tally.errors += 1;
            tally.fail(report_failure(out, archive, path, &error));
            if let Some((member, encrypted)) = cut {
                let member = display_name(&member);
                out.error(
                    &if encrypted && archive.family() != rars::ArchiveFamily::Rar50Plus {
                        encrypted_checksum_line(&member)
                    } else {
                        format!("{member:<20} - checksum error")
                    },
                );
                tally.errors += 1;
            }
            if header_errors > 0 {
                tally.fail(CHECKSUM);
            }
            tally.worked += 1;
        }
    }
}

/// The line that starts each volume's members: `Extracting from` or
/// `Testing archive`.
fn announce(out: Out, command: Command, volume: &Path) {
    match command {
        Command::Extract { .. } => out.info(&format!("\nExtracting from {}\n", volume.display())),
        Command::Test => out.info(&format!("\nTesting archive {}\n", volume.display())),
        _ => {}
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
        write_stderr(format_args!(
            "\nInsert disk with {} [C]ontinue, [Q]uit ",
            next.display()
        ));
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
            member.meta.is_encrypted,
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

    /// Whether a member failed before any of its data was read: a RAR 5
    /// password is checked first. unrar prints no line for such a member.
    fn refused(&self, error: &rars::Error) -> bool {
        self.archive.family() == rars::ArchiveFamily::Rar50Plus && is_password_error(error)
    }
}

fn extract<V>(
    invocation: &Invocation,
    out: Out,
    archive: &Archive,
    volumes: V,
    options: ArchiveReadOptions<'_>,
    failures: &Failures<'_>,
    progress: &Arc<Progress>,
) -> rars::Result<Extracted>
where
    V: Iterator<Item = rars::Result<Archive>> + Send,
{
    let policy = match invocation.overwrite {
        Overwrite::Always => OverwritePolicy::Always,
        Overwrite::Never | Overwrite::Ask => OverwritePolicy::Never,
        Overwrite::Rename => OverwritePolicy::Rename,
    };
    let destination = invocation.destination_for(failures.path);
    let mut state = ExtractEngine::new(
        &destination,
        policy,
        invocation.keep_broken,
        invocation.command == (Command::Extract { flat: true }),
        archive.family(),
    );
    crate::output::print_engine_warnings(&mut state);
    if policy == OverwritePolicy::Never {
        state.skip_existing();
    }
    if invocation.ignore_attributes {
        state.ignore_modes();
    }
    if invocation.skip_symlinks {
        state.skip_symlinks();
    }
    // As with unrar, a later member on the same path replaces an earlier one,
    // as `-ap` can make happen.
    state.allow_overwrite_repeats();
    if policy == OverwritePolicy::Rename {
        // A renamed member's line ends as it is published.
        state.publish_on_calling_thread();
    }
    let published = Arc::clone(progress);
    state.report_to(Box::new(move |output: &ExtractedOutput| {
        published.published(&output.meta.name, &output.path);
    }));
    // Goes past a failed member. `-kb` keeps what was read of it; otherwise
    // its output is dropped as it settles.
    let handler = |member: &rars::ArchiveMember, error: &rars::Error| {
        let line = match failures.fail(member, error) {
            Failure::Abort => return Ok(rars::ExtractionErrorAction::Abort),
            Failure::Unwanted => return Ok(rars::ExtractionErrorAction::Continue),
            Failure::Report(line) => line,
        };
        progress.fail(&member.meta.name, failures.refused(error));
        out.error(&line);
        Ok(rars::ExtractionErrorAction::Continue)
    };
    let state = Mutex::new(state);
    // Starts the line of a member whose output has just opened, if it has one.
    let opened = |state: &ExtractEngine<'_>, before: usize, member: &[u8], link: bool| {
        if state.opened() == before {
            progress.pass(member);
            return;
        }
        let output = state.last_opened().expect("an output opened");
        let shown = output.path.display().to_string();
        if output.meta.is_directory {
            progress.whole("Creating", member, &shown);
            return;
        }
        // Staged, an output `-or` renames gets its name when it is published.
        let renamed = policy == OverwritePolicy::Rename
            && !state.in_place()
            && std::fs::symlink_metadata(&output.path).is_ok();
        let how = match (renamed, link) {
            (true, _) => Opened::Renamed,
            (false, true) => Opened::Link,
            (false, false) => Opened::File,
        };
        progress.start("Extracting", member, &output.meta.name, shown, how);
    };
    let result = rars::output_links::settle_in_order(
        options.with_member_error_handler(&handler),
        |meta| {
            let mut state = lock(&state);
            check_stdout().map_err(|error| state.refuse(error))?;
            // The library has moved past the member before.
            progress.settle();
            if !failures.wanted.choose(&meta.name) {
                progress.pass(&meta.name);
                return Ok(state.pass_over());
            }
            let written = written(invocation, meta);
            let before = state.opened();
            let writer = failures.callback(state.open_settled(&written))?;
            opened(&state, before, &meta.name, false);
            Ok(Box::new(Counted {
                writer,
                progress: Arc::clone(progress),
            }) as Box<dyn Write + Send>)
        },
        |meta, link| {
            progress.settle();
            if !failures.wanted.choose(&meta.name) {
                progress.pass(&meta.name);
                return Ok(());
            }
            let link = match link {
                rars::ExtractedLink::HardLink { target } => rars::ExtractedLink::HardLink {
                    target: invocation.output_name(target),
                },
                rars::ExtractedLink::FileCopy { target } => rars::ExtractedLink::FileCopy {
                    target: invocation.output_name(target),
                },
                link => link,
            };
            let mut state = lock(&state);
            let before = state.opened();
            failures.callback(state.create_link(&written(invocation, meta), link))?;
            opened(&state, before, &meta.name, true);
            Ok(())
        },
        |_, outcome| {
            // Salvage is on for any volume set; only `-kb` keeps a broken member.
            let verified = outcome == Settled::Verified
                || (outcome == Settled::KeptBroken && invocation.keep_broken);
            if verified {
                // Its line ends before publishing it can name a renamed output.
                progress.settle();
            }
            if failures.callback(lock(&state).settle(verified))? {
                failures.callback_failed.store(true, Ordering::Relaxed);
            }
            Ok(())
        },
        |read, open, link| {
            rars::output_links::extract_arriving_with_links(archive, volumes, read, open, link)
        },
    );
    let result = result.and_then(|()| lock(&state).queued_failure());
    if let Err(error) = result {
        let _ = lock(&state).publish_verified_and_wait();
        return Err(error);
    }
    progress.settle();
    let state = state
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let skipped_links = state.skipped_links();
    let kept = state.kept_existing();
    let outputs = state.publish()?;
    restore_output_metadata(&outputs)?;
    Ok(Extracted {
        warnings: skipped_links > 0,
        all_kept: kept > 0 && outputs.iter().all(|output| output.meta.is_directory),
    })
}

/// A member as it is written: without the `-ap` path.
fn written<'m>(
    invocation: &Invocation,
    meta: &'m rars::ExtractedEntryMeta,
) -> std::borrow::Cow<'m, rars::ExtractedEntryMeta> {
    let name = invocation.output_name(&meta.name);
    if name.len() == meta.name.len() {
        return std::borrow::Cow::Borrowed(meta);
    }
    let mut meta = meta.clone();
    meta.name = name.to_vec();
    std::borrow::Cow::Owned(meta)
}

fn is_password_error(error: &rars::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::PasswordRequired | ErrorKind::BadPassword
    )
}

fn test_or_print<V>(
    command: Command,
    archive: &Archive,
    volumes: V,
    options: ArchiveReadOptions<'_>,
    failures: &Failures<'_>,
    progress: &Arc<Progress>,
) -> rars::Result<()>
where
    V: Iterator<Item = rars::Result<Archive>> + Send,
{
    // A member has passed its checksum once the next one starts, or the run
    // ends, with no error for it.
    let visit = |meta: &rars::ExtractedEntryMeta, link: bool| -> bool {
        progress.settle();
        let chosen = failures.wanted.choose(&meta.name);
        if !chosen || command != Command::Test {
            progress.pass(&meta.name);
        } else if meta.is_directory {
            progress.whole("Testing", &meta.name, &display_name(&meta.name));
        } else {
            let how = if link { Opened::Link } else { Opened::File };
            progress.start(
                "Testing",
                &meta.name,
                &meta.name,
                display_name(&meta.name),
                how,
            );
        }
        chosen
    };
    let handler = |member: &rars::ArchiveMember, error: &rars::Error| {
        match failures.fail(member, error) {
            Failure::Abort => return Ok(rars::ExtractionErrorAction::Abort),
            Failure::Unwanted => {}
            Failure::Report(line) => {
                progress.fail(&member.meta.name, failures.refused(error));
                progress.out.error(&line);
            }
        }
        Ok(rars::ExtractionErrorAction::Continue)
    };
    rars::output_links::extract_arriving_with_links(
        archive,
        volumes,
        options.with_member_error_handler(&handler),
        |meta| {
            check_stdout()?;
            let chosen = visit(meta, false);
            Ok(if chosen && command == Command::Print {
                Box::new(PrintedMember) as Box<dyn Write>
            } else {
                Box::new(Counted {
                    writer: Box::new(std::io::sink()),
                    progress: Arc::clone(progress),
                })
            })
        },
        |meta, _link| {
            visit(meta, true);
            Ok(())
        },
    )?;
    progress.settle();
    Ok(())
}

/// Says that an archive ends early, as unrar does, after its members are done.
///
/// unrar says nothing about a file that stops at a block boundary, so neither
/// does this when the cut can't have lost a member. Nor does it about a
/// RAR 1.4 archive or volume cut short anywhere: the member the cut is in
/// fails its checksum, and that's all.
fn report_truncation(
    out: Out,
    family: rars::ArchiveFamily,
    truncation: Option<&rars::Truncation>,
) -> bool {
    let Some(truncation) = truncation else {
        return false;
    };
    if family == rars::ArchiveFamily::Rar13 {
        return false;
    }
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
    let (line, code) = member_error_line(archive, path, &member, false, error);
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
    encrypted: bool,
    error: &rars::Error,
) -> (String, i32) {
    let legacy = archive.family() != rars::ArchiveFamily::Rar50Plus;
    match error.kind() {
        ErrorKind::ChecksumMismatch | ErrorKind::InvalidArchive => {
            let line = if legacy && encrypted {
                encrypted_checksum_line(member)
            } else {
                format!("{member:<20} - checksum error")
            };
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
        // RAR 1.5-4 store no password check, so a wrong password and a
        // damaged member look the same, and unrar says so.
        ErrorKind::BadPassword if legacy => (encrypted_checksum_line(member), CHECKSUM),
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

/// A RAR 1.5-4 encrypted member that fails its checksum, which may be a
/// wrong password as easily as damage.
fn encrypted_checksum_line(member: &str) -> String {
    format!("Checksum error in the encrypted file {member}. Corrupt file or wrong password.")
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
    #[test]
    fn comments_cannot_drive_a_terminal() {
        assert_eq!(
            super::shown_comment("a\u{1b}[2Jb\u{9b}2Jc\td\n"),
            "a'\\033'[2Jb?2Jc\td\n"
        );
    }

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
