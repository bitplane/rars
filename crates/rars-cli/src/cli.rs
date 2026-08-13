use clap::{Args, Parser, Subcommand, ValueEnum};
use rars::ArchiveVersion;

#[derive(Parser)]
#[command(
    name = "rars",
    version,
    about = "Pure-Rust RAR archive toolkit",
    long_about = "rars reads, writes, and repairs RAR archives across the RAR 1.3 through RAR 7.x family.",
    after_help = "Exit codes:\n  \
                  0  success\n  \
                  1  operation failed\n  \
                  2  invalid command line\n  \
                  3  password required, wrong password, or corrupt encrypted data",
    propagate_version = true,
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    /// Worker threads for parallel compression and extraction (default: all available cores)
    #[arg(long, value_name = "N", global = true, value_parser = crate::parse_thread_count)]
    pub threads: Option<usize>,
    /// Progress reporting mode for long-running operations
    #[arg(long, value_enum, default_value_t = ProgressMode::Auto, global = true)]
    pub progress: ProgressMode,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ProgressMode {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Command {
    /// Display archive metadata
    Info(InfoArgs),
    /// Verify archive integrity by extracting to a sink
    Test(TestArgs),
    /// Extract archive contents
    #[command(visible_alias = "x")]
    Extract(ExtractArgs),
    /// Repair a damaged archive using its recovery record
    Repair(RepairArgs),
    /// Create a new archive
    #[command(visible_alias = "a")]
    Add(AddArgs),
}

#[derive(Args)]
pub(crate) struct PasswordArgs {
    /// Archive password (visible in process list — prefer --password-file or the TTY prompt)
    #[arg(short = 'p', long, value_name = "PASSWORD")]
    pub password: Option<String>,
    /// Read password from file ("-" for stdin); trailing newlines are stripped
    #[arg(long, value_name = "PATH", conflicts_with = "password")]
    pub password_file: Option<String>,
}

#[derive(Args)]
pub(crate) struct ReadOptionsArgs {
    /// Maximum RAR 5 filtered member size to buffer while decoding (e.g. 512m, 1g)
    #[arg(long, value_name = "SIZE", value_parser = crate::parse_size_string)]
    pub rar50_buffered_decode_limit: Option<usize>,
}

#[derive(Args)]
pub(crate) struct InfoArgs {
    #[command(flatten)]
    pub password: PasswordArgs,
    /// Show all raw block/header fields (the developer-style dump)
    #[arg(short = 'v', long)]
    pub verbose: bool,
    /// One or more archive paths
    #[arg(value_name = "ARCHIVE", required = true)]
    pub paths: Vec<String>,
}

#[derive(Args)]
pub(crate) struct TestArgs {
    #[command(flatten)]
    pub password: PasswordArgs,
    #[command(flatten)]
    pub read_options: ReadOptionsArgs,
    /// Archive path (first volume of a multi-part set), optionally followed by sibling parts
    #[arg(value_name = "ARCHIVE", required = true)]
    pub paths: Vec<String>,
}

#[derive(Args)]
pub(crate) struct ExtractArgs {
    #[command(flatten)]
    pub password: PasswordArgs,
    #[command(flatten)]
    pub read_options: ReadOptionsArgs,
    /// Behaviour when an extracted file already exists on disk
    #[arg(long, value_enum, default_value_t = OverwriteCli::Never)]
    pub overwrite: OverwriteCli,
    /// Archive (and optional sibling parts) followed by an output directory
    #[arg(value_name = "PATH", required = true, num_args = 2..)]
    pub paths: Vec<String>,
}

#[derive(Args)]
pub(crate) struct RepairArgs {
    #[command(flatten)]
    pub password: PasswordArgs,
    /// Either <archive> <repaired-archive>, or <rar-parts-and-rev-files...> <outdir>
    #[arg(value_name = "PATH", required = true, num_args = 2..)]
    pub paths: Vec<String>,
}

#[derive(Args)]
pub(crate) struct AddArgs {
    #[command(flatten)]
    pub password: PasswordArgs,
    /// Target archive format (default: rar50, the modern widely-compatible format)
    #[arg(long, value_enum, default_value_t = TargetFormat::Rar50)]
    pub format: TargetFormat,
    /// Store files without compression (equivalent to --level 0)
    #[arg(long)]
    pub store: bool,
    /// Compression level (0..5; 0 implies --store)
    #[arg(long, value_name = "LEVEL")]
    pub level: Option<u8>,
    /// Dictionary size (e.g. 4m, 128k; RAR 1.5+)
    #[arg(long, value_name = "SIZE", value_parser = crate::parse_size_string)]
    pub dict_size: Option<usize>,
    /// Maximum total compression working memory (default: 256m)
    ///
    /// Left unset rather than defaulted here, so a volume set below RAR 5, which
    /// is still built in memory, can tell an explicit request from a default and
    /// refuse the one it cannot honour.
    #[arg(long, value_name = "SIZE", value_parser = crate::parse_size_string)]
    pub memory_limit: Option<usize>,
    /// Directory for temporary compressed payloads (RAR 5+)
    #[arg(long, value_name = "PATH")]
    pub temp_dir: Option<String>,
    /// Use solid compression (treats inputs as one continuous stream)
    #[arg(long)]
    pub solid: bool,
    /// Encrypt archive headers (RAR 3.x/4.x and RAR 5+) (requires --password)
    #[arg(long = "encrypt-headers")]
    pub encrypt_headers: bool,
    /// Emit a quick-open service block (RAR 5+ only)
    #[arg(long = "quick-open")]
    pub quick_open: bool,
    /// Archive-level comment
    #[arg(long, value_name = "TEXT")]
    pub comment: Option<String>,
    /// Archive name to embed in archive metadata service (RAR 5+)
    #[arg(long = "archive-name", value_name = "NAME")]
    pub archive_name: Option<String>,
    /// Per-file comment (not RAR 3.x/4.x)
    #[arg(long = "file-comment", value_name = "TEXT")]
    pub file_comment: Option<String>,
    /// Add a recovery record at the given percentage (1..100; RAR 5+)
    #[arg(long = "recovery-percent", value_name = "PERCENT")]
    pub recovery_percent: Option<u64>,
    /// Split archive into volumes of this size
    #[arg(long = "volume-size", value_name = "SIZE", value_parser = crate::parse_size_string)]
    pub volume_size: Option<usize>,
    /// Delta filter with the given channel count (RAR 2.9+)
    #[arg(long = "delta-filter", value_name = "CHANNELS")]
    pub delta_filter: Option<usize>,
    /// E8 x86 call filter (RAR 2.9+)
    #[arg(long = "e8-filter", conflicts_with = "e8e9_filter")]
    pub e8_filter: bool,
    /// E8E9 x86 call/jump filter (RAR 2.9+)
    #[arg(long = "e8e9-filter")]
    pub e8e9_filter: bool,
    /// Itanium filter (RAR 2.9/3.x/4.x only)
    #[arg(long = "itanium-filter")]
    pub itanium_filter: bool,
    /// RGB image filter with the given pixel width (RAR 2.9/3.x/4.x only)
    #[arg(long = "rgb-filter", value_name = "WIDTH")]
    pub rgb_filter: Option<usize>,
    /// Audio filter with the given channel count (RAR 2.9/3.x/4.x only)
    #[arg(long = "audio-filter", value_name = "CHANNELS")]
    pub audio_filter: Option<usize>,
    /// ARM filter (RAR 5+ only)
    #[arg(long = "arm-filter")]
    pub arm_filter: bool,
    /// Auto-detect data filter (RAR 5+ does this by default)
    #[arg(long = "auto-filter")]
    pub auto_filter: bool,
    /// Skip filter detection, compressing the data as it is (RAR 2.9+; the
    /// older formats never look, so the flag passes without comment there)
    #[arg(long = "no-filter", conflicts_with = "auto_filter")]
    pub no_filter: bool,
    /// Use the PPMd compression algorithm (RAR 2.9/3.x/4.x only)
    ///
    /// Cannot be combined with --auto-filter: choosing a filter means measuring
    /// candidates through LZ, which forcing PPMd leaves nothing to measure.
    #[arg(long)]
    pub ppmd: bool,
    /// Output archive path
    #[arg(value_name = "ARCHIVE")]
    pub archive: String,
    /// Files (and directories) to add to the archive
    #[arg(value_name = "FILE", required = true)]
    pub files: Vec<String>,
}

#[derive(Copy, Clone, ValueEnum)]
pub(crate) enum TargetFormat {
    Rar14,
    Rar15,
    Rar20,
    Rar29,
    Rar30,
    Rar40,
    Rar50,
    Rar70,
}

impl TargetFormat {
    pub(crate) fn archive_version(self) -> ArchiveVersion {
        match self {
            Self::Rar14 => ArchiveVersion::Rar14,
            Self::Rar15 => ArchiveVersion::Rar15,
            Self::Rar20 => ArchiveVersion::Rar20,
            Self::Rar29 => ArchiveVersion::Rar29,
            Self::Rar30 => ArchiveVersion::Rar30,
            Self::Rar40 => ArchiveVersion::Rar40,
            Self::Rar50 => ArchiveVersion::Rar50,
            Self::Rar70 => ArchiveVersion::Rar70,
        }
    }

    /// The `--format` value for a version, if the argument accepts one.
    /// ArchiveVersion::Rar13 has no spelling here, so it is never suggested.
    pub(crate) fn from_archive_version(version: ArchiveVersion) -> Option<Self> {
        match version {
            ArchiveVersion::Rar14 => Some(Self::Rar14),
            ArchiveVersion::Rar15 => Some(Self::Rar15),
            ArchiveVersion::Rar20 => Some(Self::Rar20),
            ArchiveVersion::Rar29 => Some(Self::Rar29),
            ArchiveVersion::Rar30 => Some(Self::Rar30),
            ArchiveVersion::Rar40 => Some(Self::Rar40),
            ArchiveVersion::Rar50 => Some(Self::Rar50),
            ArchiveVersion::Rar70 => Some(Self::Rar70),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
pub(crate) enum OverwriteCli {
    Never,
    Always,
}

impl From<OverwriteCli> for crate::output::OverwritePolicy {
    fn from(value: OverwriteCli) -> Self {
        match value {
            OverwriteCli::Never => Self::Never,
            OverwriteCli::Always => Self::Always,
        }
    }
}

pub(crate) fn parse() -> Cli {
    match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            use clap::error::ErrorKind;
            let message = err.to_string();
            match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    print!("{message}");
                    std::process::exit(0);
                }
                _ => {
                    eprint!("{message}");
                    std::process::exit(2);
                }
            }
        }
    }
}
