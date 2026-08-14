//! Hands every archive shape the writers can produce to the decoders people
//! actually use, and checks the bytes come back.
//!
//! Every corruption this project has shipped lived in the same blind spot: our
//! reader accepted what our writer produced, the suite went green, and nobody
//! else looked until a user did. The RAR 2.0 checksum bug, the 7-Zip
//! incompatibility of issue #19, the 0.5.1 `--store` RAR 5 archives, the RAR
//! 3.0 PPMd streams unrar refuses, the RAR 1.5 flag straddle. Reference tests
//! existed for some of it, but every one of them was `#[ignore]`, so the gate
//! never ran a single one.
//!
//! This runs by default and skips only when no decoder can be found. Set
//! `RARS_REQUIRE_EXTERNAL_DECODERS=1` to turn a skip into a failure; the
//! release gate sets it, so a runner that loses its decoders goes red instead
//! of quietly testing nothing.
//!
//! A decoder is calibrated before it is trusted: it has to test a genuine
//! WinRAR archive of the same family first. Debian's `7zip` package ships the
//! RAR handler with the decompressor removed, so it rejects WinRAR's own
//! archives; without the probe it would fail every compressed cell and read as
//! a hundred bugs in rars.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

/// The password every encrypted cell uses. Its only job is to be the same on
/// both sides of the pipe.
const PASSWORD: &str = "matrix-secret";

fn fixtures(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rars/tests/fixtures")
        .join(relative)
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// xorshift64, so the same bytes come out on every machine and a failure can
/// be reproduced from the seed alone.
struct Noise(u64);

impl Noise {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() >> 24) as u8).collect()
    }
}

/// Real data cut into 4 KiB windows with noise between them.
///
/// PPMd fails on this and not on plain text, plain noise, or a repetitive
/// binary: what breaks it is a wide symbol alphabet in data that still
/// compresses, which is what a real executable looks like and what a synthetic
/// payload keeps missing. 320 KiB is the smallest size that reproduced.
fn mixed_payload(len: usize) -> Vec<u8> {
    let sources = [
        fs::read(fixtures("rar15_40/ppmd/binary_64k.bin")).unwrap(),
        fs::read(fixtures("rar15_40/ppmd/escape_64k.bin")).unwrap(),
        fs::read(fixtures("rar15_40/ppmd/lorem_127k.txt")).unwrap(),
    ];
    let mut noise = Noise(0x2545_F491_4F6C_DD1D);
    let mut out = Vec::with_capacity(len);
    let mut round = 0usize;
    while out.len() < len {
        let source = &sources[round % sources.len()];
        let offset = (noise.next() % (source.len() - 4096) as u64) as usize;
        out.extend_from_slice(&source[offset..offset + 4096]);
        out.extend_from_slice(&noise.bytes(1024));
        round += 1;
    }
    out.truncate(len);
    out
}

/// Which files a cell compresses. Cells that do not need the expensive payload
/// do not pay for it.
#[derive(Clone, Copy, PartialEq)]
enum Inputs {
    /// Text, code and noise as separate members: the everyday shape, and the
    /// only one that exercises multi-member and solid framing.
    Standard,
    /// One member of the data PPMd mishandles.
    PpmdStress,
    /// One member, large enough to split. The legacy volume writers take a
    /// single input file and refuse more.
    Single,
}

impl Inputs {
    fn files(self) -> Vec<(&'static str, Vec<u8>)> {
        match self {
            Inputs::Standard => {
                let text = fs::read(fixtures("rar15_40/ppmd/lorem_127k.txt")).unwrap();
                let code = fs::read(fixtures("rar15_40/ppmd/binary_64k.bin")).unwrap();
                vec![
                    ("text.txt", text[..49_152].to_vec()),
                    ("code.bin", code),
                    ("noise.bin", Noise(0x9E37_79B9_7F4A_7C15).bytes(16_384)),
                ]
            }
            Inputs::PpmdStress => vec![("mixed.bin", mixed_payload(320 * 1024))],
            Inputs::Single => vec![("one.bin", mixed_payload(192 * 1024))],
        }
    }
}

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Flavour {
    /// Roshal's reference decoder, and `rar` itself, which take the same flags.
    Unrar,
    SevenZip,
}

struct Decoder {
    program: &'static str,
    flavour: Flavour,
}

impl Decoder {
    /// `-p-` and a closed stdin, because both tools prompt for a password on a
    /// header they cannot read, and a prompt in a test is a hang.
    fn command(&self, password: Option<&str>) -> Command {
        let mut command = Command::new(self.program);
        command.stdin(Stdio::null());
        match self.flavour {
            Flavour::Unrar => {
                command.arg(match password {
                    Some(password) => format!("-p{password}"),
                    None => "-p-".to_string(),
                });
            }
            Flavour::SevenZip => {
                command.args(["-bso0", "-bsp0"]);
                command.arg(format!("-p{}", password.unwrap_or_default()));
            }
        }
        command
    }

    fn test(&self, archive: &Path, password: Option<&str>) -> Output {
        let mut command = self.command(password);
        command.arg("t").arg(archive);
        command.output().unwrap()
    }

    fn extract(&self, archive: &Path, into: &Path, password: Option<&str>) -> Output {
        let mut command = self.command(password);
        command.arg("x").arg("-y");
        match self.flavour {
            Flavour::Unrar => {
                command.arg(archive).arg(format!("{}/", into.display()));
            }
            Flavour::SevenZip => {
                command.arg(format!("-o{}", into.display())).arg(archive);
            }
        }
        command.output().unwrap()
    }

    fn is_installed(&self) -> bool {
        match Command::new(self.program)
            .arg("--help")
            .stdin(Stdio::null())
            .output()
        {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => panic!("failed to run {}: {error}", self.program),
        }
    }
}

/// `rar` is listed after `unrar` because it is the same decoder with a licence
/// attached; whichever is installed will do. `7zz` is the official build and
/// `7z` is usually the distribution one, which is worth trying and usually
/// fails calibration.
const DECODERS: &[Decoder] = &[
    Decoder {
        program: "unrar",
        flavour: Flavour::Unrar,
    },
    Decoder {
        program: "rar",
        flavour: Flavour::Unrar,
    },
    Decoder {
        program: "7zz",
        flavour: Flavour::SevenZip,
    },
    Decoder {
        program: "7z",
        flavour: Flavour::SevenZip,
    },
];

/// A genuine WinRAR archive of the same family, compressed rather than stored,
/// used to ask a decoder whether it can read this format before its opinion of
/// ours counts for anything.
fn vendor_archive(format: &str) -> PathBuf {
    fixtures(match format {
        "rar14" => "rar13/README.RAR",
        "rar15" => "rar15_40/rar154/readme_154_normal.rar",
        "rar20" => "rar15_40/rar250/BIGLZ.RAR",
        "rar29" | "rar30" | "rar40" => "rar15_40/ppmd/ppmd_lorem_rar300.rar",
        "rar50" | "rar70" => "rar50/m3_default.rar",
        other => panic!("no vendor archive for {other}"),
    })
}

/// The decoders that pass calibration for this format, plus a line about each
/// one that did not, so an empty list is never a mystery.
fn calibrated(format: &str) -> Vec<&'static Decoder> {
    let vendor = vendor_archive(format);
    DECODERS
        .iter()
        .filter(|decoder| decoder.is_installed())
        .filter(|decoder| {
            let output = decoder.test(&vendor, None);
            if !output.status.success() {
                // Captured on purpose, unlike the skip in `run_matrix`. One
                // decoder dropping out while another still covers the format
                // is routine, and eight lines of it on every `cargo test` would
                // train people to ignore the output that matters.
                eprintln!(
                    "{format}: ignoring {} — it cannot test WinRAR's own {}",
                    decoder.program,
                    vendor.file_name().unwrap().to_string_lossy()
                );
            }
            output.status.success()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------

/// How much of a decoder's opinion counts.
#[derive(Clone, Copy, PartialEq)]
enum Judge {
    /// Exit status and extracted bytes both have to be right.
    Everything,
    /// Only the bytes. For the one case where a decoder rejects WinRAR's own
    /// archives too, so its exit status says nothing about ours.
    ExtractedBytes,
}

/// One archive shape: the flags a user would type, and the formats that accept
/// them.
///
/// The format list is an assertion, not a filter. If `rars add` refuses a cell
/// the test fails, so a capability that quietly narrows cannot quietly shrink
/// the matrix with it.
struct Cell {
    name: &'static str,
    flags: &'static [&'static str],
    inputs: Inputs,
    formats: &'static [&'static str],
    judge: Judge,
}

const ALL: &[&str] = &[
    "rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70",
];
const FILTERED: &[&str] = &["rar29", "rar30", "rar40"];
const MODERN: &[&str] = &["rar50", "rar70"];

const CELLS: &[Cell] = &[
    Cell {
        name: "store",
        flags: &["--store"],
        inputs: Inputs::Standard,
        formats: ALL,
        judge: Judge::Everything,
    },
    Cell {
        name: "level-1",
        flags: &["--level", "1"],
        inputs: Inputs::Standard,
        formats: ALL,
        judge: Judge::Everything,
    },
    Cell {
        name: "level-5",
        flags: &["--level", "5"],
        inputs: Inputs::Standard,
        formats: ALL,
        judge: Judge::Everything,
    },
    Cell {
        name: "level-5-solid",
        flags: &["--level", "5", "--solid"],
        inputs: Inputs::Standard,
        formats: ALL,
        judge: Judge::Everything,
    },
    Cell {
        name: "level-5-no-filter",
        flags: &["--level", "5", "--no-filter"],
        inputs: Inputs::Standard,
        formats: ALL,
        judge: Judge::Everything,
    },
    Cell {
        name: "dict-4m",
        flags: &["--level", "5", "--dict-size", "4m"],
        inputs: Inputs::Standard,
        formats: &[
            "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70",
        ],
        judge: Judge::Everything,
    },
    Cell {
        name: "comment",
        flags: &["--level", "5", "--comment", "an archive comment"],
        inputs: Inputs::Standard,
        formats: ALL,
        judge: Judge::Everything,
    },
    Cell {
        name: "file-comment",
        flags: &["--level", "5", "--file-comment", "a file comment"],
        inputs: Inputs::Standard,
        formats: &["rar14", "rar50", "rar70"],
        judge: Judge::Everything,
    },
    // unrar checks the comment CRC a second time without exempting comments,
    // and fails WinRAR 2.02's own `rar202/comment_nopsw.rar` in exactly the
    // same way. Our block is byte-identical to WinRAR's, pinned by
    // `a_written_file_comment_matches_the_block_winrar_writes`, so unrar's exit
    // status says nothing here and the bytes are what to judge.
    Cell {
        name: "file-comment-old-style",
        flags: &["--level", "5", "--file-comment", "a file comment"],
        inputs: Inputs::Standard,
        formats: &["rar15", "rar20", "rar29"],
        judge: Judge::ExtractedBytes,
    },
    // Encryption. The stored cell is here because 0.5.1 shipped a `--store`
    // RAR 5 bug that compression hid.
    Cell {
        name: "store-encrypted",
        flags: &["--store", "-p", PASSWORD],
        inputs: Inputs::Standard,
        formats: ALL,
        judge: Judge::Everything,
    },
    Cell {
        name: "level-5-encrypted",
        flags: &["--level", "5", "-p", PASSWORD],
        inputs: Inputs::Standard,
        formats: ALL,
        judge: Judge::Everything,
    },
    Cell {
        name: "level-5-solid-encrypted",
        flags: &["--level", "5", "--solid", "-p", PASSWORD],
        inputs: Inputs::Standard,
        formats: ALL,
        judge: Judge::Everything,
    },
    Cell {
        name: "encrypted-headers",
        flags: &["--level", "5", "-p", PASSWORD, "--encrypt-headers"],
        inputs: Inputs::Standard,
        formats: &["rar30", "rar40", "rar50", "rar70"],
        judge: Judge::Everything,
    },
    // Filters.
    Cell {
        name: "auto-filter",
        flags: &["--level", "5", "--auto-filter"],
        inputs: Inputs::Standard,
        formats: &["rar29", "rar30", "rar40", "rar50", "rar70"],
        judge: Judge::Everything,
    },
    Cell {
        name: "delta-filter",
        flags: &["--level", "5", "--delta-filter", "4"],
        inputs: Inputs::Standard,
        formats: &["rar29", "rar30", "rar40", "rar50", "rar70"],
        judge: Judge::Everything,
    },
    Cell {
        name: "e8-filter",
        flags: &["--level", "5", "--e8-filter"],
        inputs: Inputs::Standard,
        formats: &["rar29", "rar30", "rar40", "rar50", "rar70"],
        judge: Judge::Everything,
    },
    Cell {
        name: "e8e9-filter",
        flags: &["--level", "5", "--e8e9-filter"],
        inputs: Inputs::Standard,
        formats: &["rar29", "rar30", "rar40", "rar50", "rar70"],
        judge: Judge::Everything,
    },
    Cell {
        name: "itanium-filter",
        flags: &["--level", "5", "--itanium-filter"],
        inputs: Inputs::Standard,
        formats: FILTERED,
        judge: Judge::Everything,
    },
    // 1920 rather than 640: the width is a byte stride, so it has to divide
    // into RGB triples.
    Cell {
        name: "rgb-filter",
        flags: &["--level", "5", "--rgb-filter", "1920"],
        inputs: Inputs::Standard,
        formats: FILTERED,
        judge: Judge::Everything,
    },
    Cell {
        name: "audio-filter",
        flags: &["--level", "5", "--audio-filter", "2"],
        inputs: Inputs::Standard,
        formats: FILTERED,
        judge: Judge::Everything,
    },
    Cell {
        name: "arm-filter",
        flags: &["--level", "5", "--arm-filter"],
        inputs: Inputs::Standard,
        formats: MODERN,
        judge: Judge::Everything,
    },
    Cell {
        name: "filter-solid",
        flags: &["--level", "5", "--solid", "--e8e9-filter"],
        inputs: Inputs::Standard,
        formats: FILTERED,
        judge: Judge::Everything,
    },
    // PPMd, on both the everyday payload and the one that breaks it.
    Cell {
        name: "ppmd",
        flags: &["--ppmd"],
        inputs: Inputs::Standard,
        formats: FILTERED,
        judge: Judge::Everything,
    },
    Cell {
        name: "ppmd-solid",
        flags: &["--ppmd", "--solid"],
        inputs: Inputs::Standard,
        formats: FILTERED,
        judge: Judge::Everything,
    },
    Cell {
        name: "ppmd-mixed",
        flags: &["--ppmd"],
        inputs: Inputs::PpmdStress,
        formats: FILTERED,
        judge: Judge::Everything,
    },
    Cell {
        name: "ppmd-mixed-encrypted",
        flags: &["--ppmd", "-p", PASSWORD],
        inputs: Inputs::PpmdStress,
        formats: FILTERED,
        judge: Judge::Everything,
    },
    // RAR 5 service records.
    Cell {
        name: "quick-open",
        flags: &["--level", "5", "--quick-open"],
        inputs: Inputs::Standard,
        formats: MODERN,
        judge: Judge::Everything,
    },
    Cell {
        name: "recovery-record",
        flags: &["--level", "5", "--recovery-percent", "5"],
        inputs: Inputs::Standard,
        formats: MODERN,
        judge: Judge::Everything,
    },
    Cell {
        name: "archive-name",
        flags: &["--level", "5", "--archive-name", "inner.rar"],
        inputs: Inputs::Standard,
        formats: MODERN,
        judge: Judge::Everything,
    },
    // Volumes. One input file, because that is all the legacy volume writers
    // take.
    Cell {
        name: "volumes",
        flags: &["--level", "5", "--volume-size", "64k"],
        inputs: Inputs::Single,
        formats: ALL,
        judge: Judge::Everything,
    },
    // Not rar14, which refuses encryption in a volume set rather than writing
    // something it cannot honour.
    Cell {
        name: "volumes-encrypted",
        flags: &["--level", "5", "--volume-size", "64k", "-p", PASSWORD],
        inputs: Inputs::Single,
        formats: &[
            "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70",
        ],
        judge: Judge::Everything,
    },
];

/// The password a cell asks for, read back out of its own flags so the two
/// cannot drift apart.
fn password_of(cell: &Cell) -> Option<&'static str> {
    cell.flags
        .iter()
        .position(|flag| *flag == "-p")
        .map(|index| cell.flags[index + 1])
}

// ---------------------------------------------------------------------------
// What a decoder cannot judge, and what we already know is wrong
// ---------------------------------------------------------------------------

/// Something a decoder does not implement, proved by a genuine WinRAR archive
/// it fails the same way. Calibration only shows a decoder can read the format
/// at all; a feature inside it is a separate question.
struct Limitation {
    decoder: &'static str,
    formats: &'static [&'static str],
    cells: &'static [&'static str],
    /// The WinRAR archive the decoder also refuses. Without one of these, a
    /// row here is an excuse rather than a fact.
    proof: &'static str,
}

const LIMITATIONS: &[Limitation] = &[Limitation {
    decoder: "7zz",
    formats: &["rar15", "rar20"],
    cells: &[
        "store-encrypted",
        "level-5-encrypted",
        "level-5-solid-encrypted",
        "volumes-encrypted",
    ],
    proof: "rar15_40/rar154/readme_154_password.rar",
}];

/// Archive shapes a decoder rejects today, and the task that will make it stop.
///
/// The list is exact. A cell that starts passing fails the test as loudly as
/// one that starts failing, so a fix has to come back here and delete its rows
/// rather than leaving a stale claim of brokenness behind. That is the whole
/// point: this is a debt register, not a suppression list, and it only ever
/// shrinks.
struct Known {
    formats: &'static [&'static str],
    cells: &'static [&'static str],
    decoder: &'static str,
    task: &'static str,
}

const KNOWN_BAD: &[Known] = &[
    // #59. PPMd on data with a wide symbol alphabet. rar29 packs the same
    // bytes and unrar accepts those, so the difference is in what the header
    // declares rather than in the stream.
    Known {
        formats: &["rar30", "rar40"],
        cells: &["ppmd-mixed", "ppmd-mixed-encrypted"],
        decoder: "unrar",
        task: "#59",
    },
    // #64. Legacy streams 7-Zip refuses and unrar accepts, most likely issue
    // #19's incomplete Huffman tables in the encoders the fix never reached.
    Known {
        formats: &["rar20"],
        cells: &[
            "level-1",
            "level-5",
            "level-5-solid",
            "level-5-no-filter",
            "dict-4m",
            "comment",
            "file-comment-old-style",
        ],
        decoder: "7zz",
        task: "#64",
    },
    Known {
        formats: &["rar29", "rar30", "rar40"],
        cells: &[
            "level-1",
            "level-5-solid",
            "level-5-solid-encrypted",
            "delta-filter",
            "e8-filter",
            "e8e9-filter",
            "itanium-filter",
            "rgb-filter",
            "audio-filter",
            "filter-solid",
            "ppmd-solid",
        ],
        decoder: "7zz",
        task: "#64",
    },
    // #65. A member that continues across a volume boundary. Every format that
    // writes volumes has it.
    Known {
        formats: &["rar20", "rar29", "rar30", "rar40", "rar50", "rar70"],
        cells: &["volumes", "volumes-encrypted"],
        decoder: "7zz",
        task: "#65",
    },
    // #66. RAR 3.x and 4.x header encryption, which 7-Zip cannot open at all.
    Known {
        formats: &["rar30", "rar40"],
        cells: &["encrypted-headers"],
        decoder: "7zz",
        task: "#66",
    },
];

impl Known {
    fn matches(&self, format: &str, cell: &str, decoder: &str) -> bool {
        self.decoder == decoder && self.formats.contains(&format) && self.cells.contains(&cell)
    }
}

// ---------------------------------------------------------------------------
// Running a cell
// ---------------------------------------------------------------------------

fn scratch(label: &str) -> PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    let root = ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("rars-matrix-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        root
    });
    let path = root.join(label);
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

/// The volume a decoder should be pointed at: the whole archive, or the first
/// part of the set. RAR 5 volumes are `name.partNN.rar` and the legacy ones are
/// `name.rar` plus `name.rNN`, so in both cases the first name in sort order is
/// the one to open.
fn first_volume(directory: &Path, stem: &str) -> PathBuf {
    let single = directory.join(format!("{stem}.rar"));
    if single.exists() {
        return single;
    }
    let mut parts: Vec<PathBuf> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&format!("{stem}.part")))
        })
        .collect();
    parts.sort();
    parts
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("the writer produced no archive for {stem}"))
}

fn run_matrix(format: &str) {
    let decoders = calibrated(format);
    if decoders.is_empty() {
        let message = format!(
            "no external decoder can read {format}: install unrar, or the official 7zz from \
             github.com/ip7z/7zip (a distribution 7zip package usually ships without the RAR \
             decompressor)"
        );
        assert!(
            std::env::var_os("RARS_REQUIRE_EXTERNAL_DECODERS").is_none(),
            "{message}"
        );
        // Straight at the process handle rather than through `eprintln!`, which
        // the test harness captures and then throws away for a test that
        // passes. A skip nobody sees is the failure mode this whole file exists
        // to close.
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED the {format} write matrix: {message}"
        );
        return;
    }

    let mut failures = Vec::new();
    for cell in CELLS.iter().filter(|cell| cell.formats.contains(&format)) {
        let workspace = scratch(&format!("{format}-{}", cell.name));
        let files = cell.inputs.files();
        for (name, bytes) in &files {
            fs::write(workspace.join(name), bytes).unwrap();
        }

        // Run in the input directory and name the inputs relatively, so the
        // members are stored under bare names and the comparison below can
        // find them.
        let mut command = Command::new(env!("CARGO_BIN_EXE_rars"));
        command
            .current_dir(&workspace)
            .stdin(Stdio::null())
            .arg("add")
            .args(["--format", format])
            .args(cell.flags)
            .args(["--progress", "never"])
            .arg("out.rar")
            .args(files.iter().map(|(name, _)| *name));
        let written = command.output().unwrap();
        assert!(
            written.status.success(),
            "{format}/{}: the writer refused a combination the matrix claims it supports\n{}",
            cell.name,
            String::from_utf8_lossy(&written.stderr)
        );

        let archive = first_volume(&workspace, "out");
        let password = password_of(cell);

        for decoder in &decoders {
            if LIMITATIONS.iter().any(|limit| {
                limit.decoder == decoder.program
                    && limit.formats.contains(&format)
                    && limit.cells.contains(&cell.name)
            }) {
                continue;
            }

            let verdict = judge(decoder, cell, &archive, password, &files);
            let known = KNOWN_BAD
                .iter()
                .find(|known| known.matches(format, cell.name, decoder.program));
            match (verdict, known) {
                (Ok(()), None) => {}
                (Err(complaint), None) => failures.push(format!(
                    "{format}/{} under {}: {complaint}",
                    cell.name, decoder.program
                )),
                (Err(_), Some(_)) => {}
                (Ok(()), Some(known)) => failures.push(format!(
                    "{format}/{} under {}: it passes now. Delete its KNOWN_BAD row, and {} with it \
                     if that was the last one.",
                    cell.name, decoder.program, known.task
                )),
            }
        }

        let _ = fs::remove_dir_all(&workspace);
    }

    assert!(
        failures.is_empty(),
        "{} of {} {format} archives did not survive an external decoder:\n\n{}",
        failures.len(),
        CELLS.iter().filter(|c| c.formats.contains(&format)).count(),
        failures.join("\n\n")
    );
}

/// What one decoder makes of one archive. Returns the complaint rather than
/// panicking, so a run reports every cell that broke instead of the first.
fn judge(
    decoder: &Decoder,
    cell: &Cell,
    archive: &Path,
    password: Option<&str>,
    files: &[(&'static str, Vec<u8>)],
) -> Result<(), String> {
    if cell.judge == Judge::Everything {
        let tested = decoder.test(archive, password);
        if !tested.status.success() {
            return Err(format!(
                "it rejected the archive\n{}",
                indent(&tested.stdout, &tested.stderr)
            ));
        }
    }

    // Testing only checks the archive against its own checksums, so it passes
    // an archive that is wrong in the same way twice. Extracting and comparing
    // is what catches that.
    let extracted = archive
        .parent()
        .unwrap()
        .join(format!("x-{}", decoder.program));
    fs::create_dir_all(&extracted).unwrap();
    let unpacked = decoder.extract(archive, &extracted, password);
    if !unpacked.status.success() && cell.judge == Judge::Everything {
        return Err(format!(
            "it failed to extract\n{}",
            indent(&unpacked.stdout, &unpacked.stderr)
        ));
    }

    for (name, expected) in files {
        let actual = match fs::read(extracted.join(name)) {
            Ok(actual) => actual,
            Err(error) => return Err(format!("it did not write {name}: {error}")),
        };
        if actual.len() != expected.len() {
            return Err(format!(
                "it extracted {name} at {} bytes, not {}",
                actual.len(),
                expected.len()
            ));
        }
        if let Some(offset) = actual
            .iter()
            .zip(expected)
            .position(|(actual, expected)| actual != expected)
        {
            return Err(format!("it extracted {name} wrong from byte {offset}"));
        }
    }
    Ok(())
}

fn indent(stdout: &[u8], stderr: &[u8]) -> String {
    let mut out = String::new();
    for line in String::from_utf8_lossy(stdout)
        .lines()
        .chain(String::from_utf8_lossy(stderr).lines())
        .filter(|line| !line.trim().is_empty())
    {
        out.push_str("    ");
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Keeps `LIMITATIONS` honest. Each row claims a decoder cannot read something
/// WinRAR itself writes, and this is where that claim has to hold up. If the
/// decoder learns the feature, the row starts hiding real failures, and this
/// test is what says so.
#[test]
fn every_claimed_decoder_limitation_still_holds() {
    for limit in LIMITATIONS {
        let Some(decoder) = DECODERS
            .iter()
            .find(|decoder| decoder.program == limit.decoder && decoder.is_installed())
        else {
            continue;
        };
        let proof = fixtures(limit.proof);
        let output = decoder.test(&proof, Some("password"));
        assert!(
            !output.status.success(),
            "{} reads {} now, so it can judge {:?} on {:?} after all",
            limit.decoder,
            limit.proof,
            limit.cells,
            limit.formats
        );
    }
}

// One test per format, so they run in parallel and a failure names the family
// before you read a line of output.

#[test]
fn rar14_archives_survive_an_external_decoder() {
    run_matrix("rar14");
}

#[test]
fn rar15_archives_survive_an_external_decoder() {
    run_matrix("rar15");
}

#[test]
fn rar20_archives_survive_an_external_decoder() {
    run_matrix("rar20");
}

#[test]
fn rar29_archives_survive_an_external_decoder() {
    run_matrix("rar29");
}

#[test]
fn rar30_archives_survive_an_external_decoder() {
    run_matrix("rar30");
}

#[test]
fn rar40_archives_survive_an_external_decoder() {
    run_matrix("rar40");
}

#[test]
fn rar50_archives_survive_an_external_decoder() {
    run_matrix("rar50");
}

#[test]
fn rar70_archives_survive_an_external_decoder() {
    run_matrix("rar70");
}
