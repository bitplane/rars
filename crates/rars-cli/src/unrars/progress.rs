//! The `Extracting` and `Testing` lines of `unrars`, with unrar's running
//! percentage.

use super::{display_name, lock, Out};
use rars::Archive;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// The `Extracting` or `Testing` line of the member being read, printed as
/// unrar prints it: started once the member's data starts, its percentage
/// redrawn with backspaces as the data is written, and ended with `OK`, or
/// left for the error, once the member is done. A member split across
/// volumes goes on in a `...` line after each volume's `Extracting from`
/// line. Terminal or not, the bytes are the same.
///
/// The percentage is how far into the archive or volume set the member's
/// data reaches, as unrar's is its place in the files it reads, out of the
/// [`Progress::total`] unrar takes. The library reports the unpacked bytes
/// it writes rather than the packed bytes it has read, so a member's share
/// is spread evenly over its unpacked bytes: exact at each member's end, an
/// estimate within it. No header says how much of a split member each volume
/// holds, so within one of its parts the estimate moves a packed byte for
/// each unpacked byte, up to the part's end, where it is exact again.
pub(super) struct Progress {
    pub(super) out: Out,
    percentages: bool,
    /// What the percentage is out of: the size of the archive, less what
    /// follows its members (a recovery record, quick open information), or
    /// the size of the volumes of a set there were at the start; less
    /// [`UNCOUNTED`] either way.
    total: u64,
    state: Mutex<ProgressState>,
}

#[derive(Default)]
struct ProgressState {
    /// Where the volume being read starts within the set, and its size.
    base: u64,
    size: u64,
    /// That volume's members, in order.
    spans: Vec<Span>,
    /// The first of `spans` not reached yet.
    cursor: usize,
    line: Option<Line>,
    /// A member that has verified, whose line waits for the name it is
    /// published under: see [`Line::renamed`].
    verified: Option<Line>,
}

/// Where a member lies in the set.
#[derive(Clone)]
struct Span {
    name: Vec<u8>,
    /// From where the entry before it ends, so its header counts with it.
    start: u64,
    /// Where its data ends in this volume.
    end: u64,
    unpacked: u64,
    split_before: bool,
    split_after: bool,
}

struct Line {
    /// `Extracting` or `Testing`, then `...` for a part in a later volume.
    verb: &'static str,
    /// The member's name in the archive, which a continued line shows.
    member: Vec<u8>,
    /// What the line names: the output's path, or the member's name.
    shown: String,
    /// The name its output is written under, for `-or` to find it by.
    output: Vec<u8>,
    /// Printed so far. A line starts once the member's data does, so a
    /// member refused before any is read, for its password, has none.
    begun: bool,
    /// With `-or`, a file that is already there is written under a new name,
    /// chosen when its output is published, so its line waits for that.
    renamed: bool,
    /// A file, whose line shows a percentage; a link's shows none.
    data: bool,
    span: Option<Span>,
    /// Unpacked bytes written since the span began.
    written: u64,
    /// The percentage last printed on this line.
    percent: Option<u64>,
    /// Its text has ended for the next volume's `Extracting from` line.
    ended: bool,
    /// Everything there is of it has been read: the next volume is missing.
    exhausted: bool,
}

impl Line {
    /// How far into the set the member has got.
    fn position(&self, done: bool) -> Option<u64> {
        let span = self.span.as_ref()?;
        let length = span.end.saturating_sub(span.start);
        let reached = if done || self.exhausted {
            length
        } else if span.split_before || span.split_after {
            self.written.min(length)
        } else if span.unpacked == 0 {
            0
        } else {
            let share = u128::from(length) * u128::from(self.written.min(span.unpacked))
                / u128::from(span.unpacked);
            share as u64
        };
        Some(span.start + reached)
    }
}

impl Progress {
    pub(super) fn new(out: Out, percentages: bool, path: &Path, archive: &Archive) -> Self {
        let size = file_size(path);
        let mut total = size;
        if archive.is_volume() {
            // As unrar does, count the volumes there are now.
            for index in 1.. {
                match archive.volume_path(path, index) {
                    Some(later) if later.is_file() => total += file_size(&later),
                    _ => break,
                }
            }
        } else {
            // unrar leaves out what an archive holds after its members, but
            // not what each volume of a set does.
            total = total.saturating_sub(trailing(archive));
        }
        let state = ProgressState {
            size,
            spans: spans(archive, 0, size),
            ..ProgressState::default()
        };
        Self {
            out,
            percentages,
            total: total.saturating_sub(UNCOUNTED),
            state: Mutex::new(state),
        }
    }

    fn percent(&self, position: u64) -> u64 {
        if self.total == 0 {
            return 100;
        }
        (u128::from(position) * 100 / u128::from(self.total)).min(100) as u64
    }

    /// Opens a member's line. `output` is the name it is written under and
    /// `shown` what the line calls it.
    pub(super) fn start(
        &self,
        verb: &'static str,
        member: &[u8],
        output: &[u8],
        shown: String,
        opened: Opened,
    ) {
        let mut state = lock(&self.state);
        self.settle_line(&mut state);
        let span = state.reach(member);
        state.line = Some(Line {
            verb,
            member: member.to_vec(),
            shown,
            output: output.to_vec(),
            begun: false,
            renamed: opened == Opened::Renamed,
            data: opened != Opened::Link,
            span,
            written: 0,
            percent: None,
            ended: false,
            exhausted: false,
        });
    }

    /// A member with no data to show, such as a directory, in one line.
    pub(super) fn whole(&self, verb: &str, member: &[u8], shown: &str) {
        let mut state = lock(&self.state);
        self.settle_line(&mut state);
        state.reach(member);
        self.out
            .progress(format_args!("{verb:<11} {shown:<57} OK\n"));
    }

    /// Passes a member the run doesn't show.
    pub(super) fn pass(&self, member: &[u8]) {
        let mut state = lock(&self.state);
        self.settle_line(&mut state);
        state.reach(member);
    }

    /// Prints the start of `line` if it hasn't been.
    fn reveal(&self, line: &mut Line) {
        if line.begun {
            return;
        }
        line.begun = true;
        line.renamed = false;
        // Room for the percentage, which `OK` replaces.
        let tail = if self.percentages { "     " } else { "" };
        self.out
            .progress(format_args!("{:<11} {:<56}{tail}", line.verb, line.shown));
    }

    /// Prints the percentage `line` has reached, `done` or not, unless the
    /// line already shows it.
    fn show(&self, line: &mut Line, done: bool) {
        if line.ended {
            return;
        }
        self.reveal(line);
        if !self.percentages || !line.data {
            return;
        }
        let Some(position) = line.position(done) else {
            return;
        };
        let percent = self.percent(position);
        if line.percent == Some(percent) {
            return;
        }
        line.percent = Some(percent);
        self.out
            .progress(format_args!("\u{8}\u{8}\u{8}\u{8}{percent:>3}%"));
    }

    /// Notes unpacked bytes written for the member whose line is open.
    fn advance(&self, bytes: u64) {
        let mut state = lock(&self.state);
        if let Some(line) = &mut state.line {
            line.written += bytes;
            if !line.renamed {
                self.show(line, false);
            }
        }
    }

    /// Ends the open line with `OK`: the library has moved past its member,
    /// so it verified.
    pub(super) fn settle(&self) {
        let mut state = lock(&self.state);
        self.settle_line(&mut state);
    }

    fn settle_line(&self, state: &mut ProgressState) {
        let Some(mut line) = state.line.take() else {
            return;
        };
        if line.renamed {
            state.verified = Some(line);
        } else if !line.ended {
            self.show(&mut line, true);
            self.finish_ok();
        }
    }

    fn finish_ok(&self) {
        if self.percentages {
            self.out
                .progress(format_args!("\u{8}\u{8}\u{8}\u{8}\u{8}  OK \n"));
        } else {
            self.out.progress(format_args!("  OK \n"));
        }
    }

    /// Ends the open line for its member's error, which follows on stderr,
    /// with the percentage its data reaches, as unrar has read it all by
    /// then. `quiet` leaves out the line of a member none of whose data was
    /// read. The line open may be another member's, verified before `member`
    /// failed without opening.
    pub(super) fn fail(&self, member: &[u8], quiet: bool) {
        let mut state = lock(&self.state);
        match state.line.take() {
            Some(line) if line.member == member && quiet && !line.begun => {}
            Some(mut line) if line.member == member => {
                self.show(&mut line, true);
                if !line.ended {
                    self.out.progress(format_args!("\n"));
                }
            }
            line => {
                state.line = line;
                self.settle_line(&mut state);
            }
        }
    }

    /// Ends the open line, whatever its state, when the run stops.
    pub(super) fn stop(&self) {
        let mut state = lock(&self.state);
        if let Some(line) = state.line.take() {
            if line.begun && !line.ended {
                self.out.progress(format_args!("\n"));
            }
        }
    }

    /// The output of a verified member is in place, under `path`.
    pub(super) fn published(&self, output: &[u8], path: &Path) {
        let mut state = lock(&self.state);
        let Some(mut line) = state.verified.take_if(|line| line.output == output) else {
            return;
        };
        line.shown = renamed(&line.shown, path);
        self.show(&mut line, true);
        self.finish_ok();
    }

    /// The library has asked for the next volume, so a member that ends in
    /// the one before has verified.
    pub(super) fn volume_wanted(&self) {
        let mut state = lock(&self.state);
        let split = |line: &Line| line.span.as_ref().is_some_and(|span| span.split_after);
        if !state.line.as_ref().is_some_and(split) {
            self.settle_line(&mut state);
        }
    }

    /// The next volume is there: the line of a member going on into it shows
    /// how far it got and ends for the volume's `Extracting from` line.
    pub(super) fn volume_found(&self) {
        let mut state = lock(&self.state);
        if let Some(line) = &mut state.line {
            self.show(line, true);
            if !line.ended {
                self.out.progress(format_args!("\n"));
                line.ended = true;
            }
        }
    }

    /// The next volume isn't there. Having looked for it, unrar has read
    /// the whole of the volume before.
    pub(super) fn volume_missing(&self) {
        let mut state = lock(&self.state);
        let end = state.base + state.size;
        if let Some(mut line) = state.line.take() {
            if let Some(span) = &mut line.span {
                span.end = end;
            }
            line.exhausted = true;
            self.show(&mut line, true);
            state.line = Some(line);
        }
    }

    /// The next volume has been read, after its `Extracting from` line. A
    /// member going on into it gets its `...` line.
    pub(super) fn volume_starts(&self, path: &Path, volume: Option<&Archive>) {
        let mut state = lock(&self.state);
        let base = state.base + state.size;
        let size = file_size(path);
        state.base = base;
        state.size = size;
        state.spans = volume
            .map(|volume| spans(volume, base, size))
            .unwrap_or_default();
        state.cursor = 0;
        let Some(mut line) = state.line.take() else {
            return;
        };
        let continued = state
            .spans
            .first()
            .filter(|span| span.split_before && span.name == line.member)
            .cloned();
        let Some(span) = continued else {
            return;
        };
        state.cursor = 1;
        line.verb = "...";
        line.shown = display_name(&line.member);
        line.span = Some(span);
        line.written = 0;
        line.percent = None;
        line.begun = false;
        line.ended = false;
        line.exhausted = false;
        self.reveal(&mut line);
        state.line = Some(line);
    }
}

impl ProgressState {
    /// Moves on to `member`, the next of the volume's members by that name.
    fn reach(&mut self, member: &[u8]) -> Option<Span> {
        let found = self.spans[self.cursor.min(self.spans.len())..]
            .iter()
            .position(|span| !span.split_before && span.name == member)?;
        let index = self.cursor + found;
        self.cursor = index + 1;
        Some(self.spans[index].clone())
    }
}

/// `planned`, the path a line was to show, with the file name `published`
/// ended up with, keeping the separators the rest of it was written with.
fn renamed(planned: &str, published: &Path) -> String {
    let old = Path::new(planned)
        .file_name()
        .map(|name| name.to_string_lossy());
    let new = published.file_name().map(|name| name.to_string_lossy());
    match (old, new) {
        (Some(old), Some(new)) if planned.ends_with(old.as_ref()) => {
            format!("{}{new}", &planned[..planned.len() - old.len()])
        }
        _ => published.display().to_string(),
    }
}

/// How a member's output opened, for its line.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Opened {
    File,
    Link,
    /// A file `-or` will write under a new name.
    Renamed,
}

/// What a volume holds between its last member's data and its end block,
/// such as a recovery record or quick open information.
fn trailing(archive: &Archive) -> u64 {
    let (data_end, end) = match archive {
        Archive::Rar50Plus(archive) => (
            archive.files().last().map(|file| file.block.data_range.end),
            archive.blocks.iter().find_map(|block| match block {
                rars::rar50::Block::End(end) => Some(end.block.offset),
                _ => None,
            }),
        ),
        Archive::Rar15To40(archive) => (
            archive.files().last().map(|file| file.packed_range.end),
            archive.blocks.iter().find_map(|block| match block {
                rars::rar15_40::Block::End(end) => Some(end.block.offset),
                _ => None,
            }),
        ),
        _ => (None, None),
    };
    match (data_end, end) {
        (Some(data_end), Some(end)) => end.saturating_sub(data_end) as u64,
        _ => 0,
    }
}

/// What unrar leaves out of the size its percentages are out of, whatever
/// the format, the archive's headers or how many volumes it has.
const UNCOUNTED: u64 = 23;

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |metadata| metadata.len())
}

/// Where each member of a volume lies in the set, the volume starting at `base`.
fn spans(archive: &Archive, base: u64, size: u64) -> Vec<Span> {
    let count = archive.member_refs().count();
    let mut previous = 0;
    archive
        .member_refs()
        .enumerate()
        .map(|(index, member)| {
            let meta = member.to_owned().meta;
            let end = match member {
                rars::ArchiveMemberRef::Rar13(entry) => entry.packed_range.end,
                rars::ArchiveMemberRef::Rar15To40(file) => file.packed_range.end,
                rars::ArchiveMemberRef::Rar50Plus(file) => file.block.data_range.end,
                _ => previous as usize,
            } as u64;
            // What follows the last member, such as the end block or a
            // recovery record, is read with it, unless it goes on.
            let end = if index + 1 == count && !meta.is_split_after {
                size
            } else {
                end.min(size)
            }
            .max(previous);
            let span = Span {
                name: member.name_bytes().to_vec(),
                start: base + previous,
                end: base + end,
                unpacked: meta.unpacked_size,
                split_before: meta.is_split_before,
                split_after: meta.is_split_after,
            };
            previous = end;
            span
        })
        .collect()
}

/// A member's output, counting what is written to it for its line.
pub(super) struct Counted {
    pub(super) writer: Box<dyn Write>,
    pub(super) progress: Arc<Progress>,
}

impl Write for Counted {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.writer.write(bytes)?;
        self.progress.advance(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
