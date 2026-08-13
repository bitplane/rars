//! Turning a library refusal into one the user can act on.
//!
//! The library knows which formats can do what and says so in its own words:
//! "header encryption is not supported by rar15". The user asked for that with
//! a flag, so the flag is what they need to see, along with a format that would
//! have worked. Both come from the library's own capability data, so the two
//! cannot drift the way a hand-maintained list of messages does.

use crate::cli::TargetFormat;
use crate::error::CliError;
use rars::{ArchiveVersion, Feature, FilterKind, PlanShape, WriterOption};

/// The flag that asks for `option`, as this command's arguments spell it.
///
/// Exhaustive over `WriterOption`, so a new one has to be given a flag here
/// before the CLI will build.
pub(crate) fn flag_for(option: WriterOption, asked: &AskedFilters) -> &'static str {
    match option {
        WriterOption::Feature(Feature::Solid) => "--solid",
        WriterOption::Feature(Feature::HeaderEncryption) => "--encrypt-headers",
        WriterOption::Feature(Feature::QuickOpen) => "--quick-open",
        WriterOption::CompressionLevel => "--level",
        WriterOption::CompressionMethod => "--ppmd",
        WriterOption::DictionarySize => "--dict-size",
        WriterOption::Filter => asked.flag(),
        WriterOption::RecoveryRecord => "--recovery-percent",
        WriterOption::VolumeSize => "--volume-size",
        WriterOption::ArchiveComment => "--comment",
        WriterOption::FileComment => "--file-comment",
        WriterOption::ArchiveMetadata => "--archive-name",
        WriterOption::Password => "--password",
        WriterOption::MemoryLimit => "--memory-limit",
        WriterOption::TempDir => "--temp-dir",
        // WriterOption is non_exhaustive in the library, so this arm cannot be
        // dropped, but every variant above is named deliberately.
        _ => "that option",
    }
}

/// Which filter flag the user typed, so a refusal names it rather than listing
/// every filter flag that exists.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AskedFilters {
    pub(crate) delta: bool,
    pub(crate) e8: bool,
    pub(crate) e8e9: bool,
    pub(crate) itanium: bool,
    pub(crate) rgb: bool,
    pub(crate) audio: bool,
    pub(crate) arm: bool,
}

impl AskedFilters {
    fn flag(&self) -> &'static str {
        if self.delta {
            "--delta-filter"
        } else if self.e8e9 {
            "--e8e9-filter"
        } else if self.e8 {
            "--e8-filter"
        } else if self.itanium {
            "--itanium-filter"
        } else if self.rgb {
            "--rgb-filter"
        } else if self.audio {
            "--audio-filter"
        } else if self.arm {
            "--arm-filter"
        } else {
            "--auto-filter"
        }
    }

    pub(crate) fn count(&self) -> usize {
        usize::from(self.delta)
            + usize::from(self.e8 || self.e8e9)
            + usize::from(self.itanium)
            + usize::from(self.rgb)
            + usize::from(self.audio)
            + usize::from(self.arm)
    }
}

/// The filter each flag names, so a refusal can say which formats write it.
pub(crate) fn asked_filter_kind(filters: &AskedFilters) -> Option<FilterKind> {
    if filters.itanium {
        Some(FilterKind::Itanium)
    } else if filters.rgb {
        Some(FilterKind::Rgb { width: 3, pos_r: 0 })
    } else if filters.audio {
        Some(FilterKind::Audio { channels: 1 })
    } else if filters.arm {
        Some(FilterKind::Arm)
    } else if filters.e8 || filters.e8e9 {
        Some(FilterKind::E8)
    } else if filters.delta {
        Some(FilterKind::Delta { channels: 1 })
    } else {
        None
    }
}

/// Refuses a filter this format has no way to encode.
///
/// Separate from the option table because every filtering format has filters;
/// what differs is which ones, and the two families are complementary rather
/// than nested, so the suggestion is worth making.
pub(crate) fn reject_unsupported_filter(
    target: ArchiveVersion,
    filters: &AskedFilters,
) -> Result<(), CliError> {
    let Some(kind) = asked_filter_kind(filters) else {
        return Ok(());
    };
    if kind.is_supported_by(target) {
        return Ok(());
    }
    let names = format_list(rars::formats_supporting_filter(kind), target);
    Err(CliError::usage(format!(
        "{} is not supported by --format {target}{names}",
        flag_for(WriterOption::Filter, filters),
    )))
}

/// Refuses more than one explicit filter.
///
/// A member carries one transform, so naming two is asking for something no
/// format can do, whichever formats they are.
pub(crate) fn reject_multiple_filters(filters: &AskedFilters) -> Result<(), CliError> {
    if filters.count() > 1 {
        return Err(CliError::usage(
            "only one filter can be asked for at a time",
        ));
    }
    Ok(())
}

/// Refuses a filter or an engine choice on an archive that is not compressed.
///
/// Both exist to make compression go further, so with `--store` they ask for
/// nothing. Saying so beats writing an archive that quietly ignored the flag.
pub(crate) fn reject_coding_without_compression(
    filters: &AskedFilters,
    auto_filter: bool,
    ppmd: bool,
) -> Result<(), CliError> {
    let flag = if ppmd {
        "--ppmd"
    } else if filters.count() > 0 || auto_filter {
        flag_for(WriterOption::Filter, filters)
    } else {
        return Ok(());
    };
    Err(CliError::usage(format!(
        "{flag} needs something to compress; drop --store or --level 0"
    )))
}

/// Refuses the filter requests a solid archive cannot honour.
///
/// RAR 5 and RAR 7 code solid members as one chain and skip the filter search
/// entirely, so neither a named filter nor `--auto-filter` reaches them; both
/// used to be taken and dropped. RAR 2.9 does apply a named filter inside the
/// chain, so only the search is refused there: measuring candidates means
/// encoding each one against the history so far.
pub(crate) fn reject_filter_with_solid(
    target: ArchiveVersion,
    filters: &AskedFilters,
    auto_filter: bool,
    solid: bool,
) -> Result<(), CliError> {
    if !solid {
        return Ok(());
    }
    let searches_only = target.family() != rars::ArchiveFamily::Rar50Plus;
    let searching = auto_filter && filters.count() == 0;
    let refused = if searches_only {
        searching
    } else {
        filters.count() > 0 || auto_filter
    };
    if !refused {
        return Ok(());
    }
    // Pointing at a named filter only helps where one would be accepted.
    let because = if searches_only {
        "; name a filter instead"
    } else {
        "; solid members share one dictionary"
    };
    Err(CliError::usage(format!(
        "{} cannot be used with --solid{because}",
        flag_for(WriterOption::Filter, filters),
    )))
}

/// Formats the user could have asked for instead, in `--format` spelling.
///
/// Computed from the library rather than written down, so a writer that gains a
/// feature does not leave a stale suggestion behind. Only formats `--format`
/// actually accepts are offered.
fn alternatives(option: WriterOption, shape: PlanShape, exclude: ArchiveVersion) -> String {
    format_list(rars::formats_supporting(option, shape), exclude)
}

fn format_list(targets: Vec<ArchiveVersion>, exclude: ArchiveVersion) -> String {
    let names: Vec<_> = targets
        .into_iter()
        .filter(|&target| target != exclude)
        .filter(|&target| TargetFormat::from_archive_version(target).is_some())
        .map(|target| format!("--format {target}"))
        .collect();
    match names.len() {
        0 => String::new(),
        1 => format!("; use {}", names[0]),
        _ => format!(
            "; use {} or {}",
            names[..names.len() - 1].join(", "),
            names[names.len() - 1]
        ),
    }
}

/// Renders a library refusal in the command line's own terms.
///
/// Anything that is not a refusal passes through: those already say what went
/// wrong in terms the user can see, like a missing file or a bad password.
pub(crate) fn map_write_error(
    error: rars::Error,
    shape: PlanShape,
    filters: &AskedFilters,
) -> CliError {
    match error {
        rars::Error::UnsupportedWriterOption {
            target,
            option,
            because,
        } => CliError::usage(format!(
            "{} is not supported by --format {target}{}{}",
            flag_for(option, filters),
            because.map(|why| format!(" ({why})")).unwrap_or_default(),
            alternatives(option, shape, target),
        )),
        other => CliError::general(other.to_string()),
    }
}

/// Refuses anything the chosen format cannot do, before any input is read.
///
/// The writers check this too, but only once they are writing, and by then the
/// command line has read every input it was given. A refusal is worth arriving
/// before the reading, not after it.
pub(crate) fn reject_unsupported(
    target: ArchiveVersion,
    shape: PlanShape,
    filters: &AskedFilters,
    asked: &[(WriterOption, bool)],
) -> Result<(), CliError> {
    for &(option, wanted) in asked {
        if wanted && !rars::supports(target, option, shape) {
            return Err(map_write_error(
                rars::Error::UnsupportedWriterOption {
                    target,
                    option,
                    because: None,
                },
                shape,
                filters,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_the_flag_that_was_typed() {
        let filters = AskedFilters {
            rgb: true,
            ..AskedFilters::default()
        };
        let error = reject_unsupported_filter(ArchiveVersion::Rar50, &filters).unwrap_err();
        assert_eq!(
            error.to_string(),
            "--rgb-filter is not supported by --format rar50; \
             use --format rar29, --format rar30 or --format rar40"
        );
    }

    #[test]
    fn a_refusal_offers_only_formats_the_argument_accepts() {
        let error = reject_unsupported(
            ArchiveVersion::Rar15,
            PlanShape::new(),
            &AskedFilters::default(),
            &[(WriterOption::Feature(Feature::HeaderEncryption), true)],
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "--encrypt-headers is not supported by --format rar15; \
             use --format rar30, --format rar40, --format rar50 or --format rar70"
        );
        // rar13 exists in the library but --format does not accept it, so it is
        // never suggested.
        assert!(!error.to_string().contains("rar13"));
    }

    #[test]
    fn what_the_format_can_do_is_not_refused() {
        assert!(reject_unsupported(
            ArchiveVersion::Rar50,
            PlanShape::new().compressed(true),
            &AskedFilters::default(),
            &[
                (WriterOption::Feature(Feature::Solid), true),
                (WriterOption::RecoveryRecord, true),
                (WriterOption::ArchiveMetadata, true),
            ],
        )
        .is_ok());
    }
}
