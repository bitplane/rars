//! What each format's writer can be asked for, and one place that says no.
//!
//! Capability is data here, keyed by format and by the shape of the archive
//! being built, and a refusal names the option, the format, and why.

use crate::error::{Error, Result};
use crate::features::{Feature, FeatureSet};
use crate::filter::FilterPolicy;
use crate::version::{ArchiveFamily, ArchiveVersion};

/// How the members of an archive are coded.
///
/// The three arms are the three questions a writer has to answer before it
/// touches a member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemberCoding {
    /// Store every member as it is.
    Stored,
    /// Compress, letting the writer decide how. The RAR 2.9 family looks for a
    /// filter unless PPMd was asked for; RAR 1.3 to 2.0 have none to look for.
    #[default]
    Compressed,
    /// Compress under a filter policy the caller named. RAR 2.9 and later only.
    Filtered(FilterPolicy),
}

impl MemberCoding {
    pub fn compresses(&self) -> bool {
        !matches!(self, Self::Stored)
    }

    pub fn is_filtered(&self) -> bool {
        matches!(self, Self::Filtered(_))
    }

    /// The shape of archive this coding produces, so validation and the
    /// capability table are asked the same question the writer will answer.
    pub fn shape(&self) -> PlanShape {
        PlanShape::new()
            .compressed(self.compresses())
            .filtered(self.is_filtered())
    }
}

/// What kind of archive is being built. Capability answers depend on this as
/// well as on the format: RAR 5 will write a file comment into a stored archive
/// but not a compressed one, for instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct PlanShape {
    pub compressed: bool,
    pub volumes: bool,
    pub filtered: bool,
}

impl PlanShape {
    pub const fn new() -> Self {
        Self {
            compressed: false,
            volumes: false,
            filtered: false,
        }
    }

    pub const fn compressed(mut self, compressed: bool) -> Self {
        self.compressed = compressed;
        self
    }

    pub const fn volumes(mut self, volumes: bool) -> Self {
        self.volumes = volumes;
        self
    }

    pub const fn filtered(mut self, filtered: bool) -> Self {
        self.filtered = filtered;
        self
    }

    /// Every combination, for exhaustively checking capability answers.
    pub fn all() -> Vec<Self> {
        let mut shapes = Vec::with_capacity(8);
        for compressed in [false, true] {
            for volumes in [false, true] {
                for filtered in [false, true] {
                    shapes.push(Self {
                        compressed,
                        volumes,
                        filtered,
                    });
                }
            }
        }
        shapes
    }
}

pub use crate::writer_option::WriterOption;

/// The features this format can honour for an archive of this shape.
///
/// Deliberately blind to what the caller asked for.
pub fn supported_features(target: ArchiveVersion, shape: PlanShape) -> FeatureSet {
    FeatureSet {
        solid: supports(target, WriterOption::Feature(Feature::Solid), shape),
        header_encryption: supports(
            target,
            WriterOption::Feature(Feature::HeaderEncryption),
            shape,
        ),
        quick_open: supports(target, WriterOption::Feature(Feature::QuickOpen), shape),
        blake2sp: supports(target, WriterOption::Feature(Feature::Blake2sp), shape),
    }
}

/// Whether this format's writer can honour `option` for an archive of this
/// shape.
pub fn supports(target: ArchiveVersion, option: WriterOption, shape: PlanShape) -> bool {
    if !cfg!(feature = "encryption")
        && matches!(
            option,
            WriterOption::Password | WriterOption::Feature(Feature::HeaderEncryption)
        )
    {
        return false;
    }

    let family = target.family();
    match option {
        // Solid means compressing members against each other, so there has to
        // be compression for it to mean anything.
        WriterOption::Feature(Feature::Solid) => shape.compressed,
        WriterOption::Feature(Feature::HeaderEncryption) => matches!(
            target,
            ArchiveVersion::Rar29
                | ArchiveVersion::Rar30
                | ArchiveVersion::Rar40
                | ArchiveVersion::Rar50
                | ArchiveVersion::Rar70
        ),
        // Quick-open indexes headers, so it cannot cover encrypted ones, and
        // no volume writer emits the index.
        WriterOption::Feature(Feature::QuickOpen) => {
            family == ArchiveFamily::Rar50Plus && !shape.volumes
        }
        // The hash record arrived with RAR 5.
        WriterOption::Feature(Feature::Blake2sp) => family == ArchiveFamily::Rar50Plus,
        WriterOption::CompressionLevel => true,
        // PPMd arrived with RAR 2.9 and left again with RAR 5. A split set
        // takes the automatic choice only: the volume writer is handed the
        // method, but asking for one across volumes has never been tested.
        WriterOption::CompressionMethod => {
            matches!(
                target,
                ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
            ) && !shape.volumes
        }
        WriterOption::DictionarySize => !family_is(family, ArchiveFamily::Rar13),
        // RAR 1.3 and 1.5 have no filters at all; RAR 2.0 predates the VM. The
        // legacy volume writer is handed a policy, but a named filter across
        // a split set has never been tested, so a set searches on its own.
        WriterOption::Filter => {
            !matches!(
                target,
                ArchiveVersion::Rar13
                    | ArchiveVersion::Rar14
                    | ArchiveVersion::Rar15
                    | ArchiveVersion::Rar20
            ) && (family == ArchiveFamily::Rar50Plus || !shape.volumes)
        }
        WriterOption::RecoveryRecord => {
            cfg!(feature = "recovery") && family == ArchiveFamily::Rar50Plus
        }
        WriterOption::VolumeSize => true,
        // A CMT block goes in the first volume. An old-style comment has no
        // volume layout here, and the RAR 5 volume writer refuses comments.
        WriterOption::ArchiveComment => {
            !shape.volumes
                || matches!(
                    target,
                    ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
                )
        }
        // Embedded legacy file comments and RAR5 service comments are supported
        // for single archives; volume writers cannot retain their association.
        WriterOption::FileComment => !shape.volumes,
        WriterOption::ArchiveMetadata => family == ArchiveFamily::Rar50Plus && !shape.volumes,
        // RAR 1.3's volume writer has nowhere to carry the encryption state
        // from one volume to the next.
        WriterOption::Password => !(family_is(family, ArchiveFamily::Rar13) && shape.volumes),
        // Every writer compresses to a budget: RAR 5 sizes its blocks by
        // it, and the older ones use it to decide how many members to have in
        // flight. A legacy volume set is the exception: it writes one member
        // at a time, streaming a large one into the volumes.
        WriterOption::MemoryLimit => family == ArchiveFamily::Rar50Plus || !shape.volumes,
        // RAR 5 spools its members; RAR 1.5 to 4.x spool a large one when the
        // output cannot seek back to patch its header, RAR 1.3 whatever the
        // output, a volume set included. A RAR 1.5 to 4.x set can always seek.
        WriterOption::TempDir => {
            family == ArchiveFamily::Rar50Plus
                || family_is(family, ArchiveFamily::Rar13)
                || (matches!(
                    target,
                    ArchiveVersion::Rar13
                        | ArchiveVersion::Rar14
                        | ArchiveVersion::Rar15
                        | ArchiveVersion::Rar20
                        | ArchiveVersion::Rar29
                        | ArchiveVersion::Rar30
                        | ArchiveVersion::Rar40
                ) && !shape.volumes)
        }
    }
}

const fn family_is(family: ArchiveFamily, other: ArchiveFamily) -> bool {
    matches!(
        (family, other),
        (ArchiveFamily::Rar13, ArchiveFamily::Rar13)
            | (ArchiveFamily::Rar15To40, ArchiveFamily::Rar15To40)
            | (ArchiveFamily::Rar50Plus, ArchiveFamily::Rar50Plus)
    )
}

/// Every format whose writer can honour `option` for an archive of this shape.
///
/// Computed rather than stored, so a writer that gains a feature does not leave
/// a stale list behind in an error message.
pub fn formats_supporting(option: WriterOption, shape: PlanShape) -> Vec<ArchiveVersion> {
    ArchiveVersion::ALL
        .into_iter()
        .filter(|&target| supports(target, option, shape))
        .collect()
}

/// Refuses the first feature this format cannot honour.
pub fn validate_features(
    target: ArchiveVersion,
    asked: FeatureSet,
    shape: PlanShape,
) -> Result<()> {
    if asked.header_encryption {
        crate::crypto::require_encryption()?;
    }

    match asked.first_unsupported(supported_features(target, shape)) {
        Some(feature) => Err(Error::UnsupportedWriterOption {
            target,
            option: WriterOption::Feature(feature),
            because: None,
        }),
        None => Ok(()),
    }
}

/// Refuses a compression level outside the range every format shares.
pub fn validate_compression_level(target: ArchiveVersion, level: Option<u8>) -> Result<()> {
    match level {
        None | Some(0..=5) => Ok(()),
        Some(_) => Err(Error::UnsupportedWriterOption {
            target,
            option: WriterOption::CompressionLevel,
            because: Some("levels run from 0 to 5"),
        }),
    }
}

/// Refuses an option this format cannot honour for this shape of archive.
pub fn validate_option(
    target: ArchiveVersion,
    option: WriterOption,
    shape: PlanShape,
) -> Result<()> {
    if !cfg!(feature = "encryption")
        && matches!(
            option,
            WriterOption::Password | WriterOption::Feature(Feature::HeaderEncryption)
        )
    {
        return Err(Error::FeatureDisabled {
            feature: "encryption",
        });
    }
    if !cfg!(feature = "recovery") && matches!(option, WriterOption::RecoveryRecord) {
        return Err(Error::FeatureDisabled {
            feature: "recovery",
        });
    }
    if supports(target, option, shape) {
        Ok(())
    } else {
        Err(Error::UnsupportedWriterOption {
            target,
            option,
            because: None,
        })
    }
}

/// Whether a compressed member should be written as stored bytes instead.
///
/// Compression that does not shrink a member costs the reader time for nothing.
/// The formats disagree about when that trade is worth making, so what differs
/// between them is parameters here rather than three separate rules.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StoreFallback {
    /// Members below this size stay compressed. Where a stored member costs
    /// enough header of its own, swapping a small one can lose more than the
    /// compression was wasting.
    pub(crate) min_size: u64,
    /// Whether a solid member may be swapped. RAR 5 runs one dictionary across
    /// every member and cannot go back on what it has already fed in; the
    /// RAR 1.5 family rebuilds its encoder at that point instead.
    pub(crate) allow_solid: bool,
    /// A filter the caller named is not discarded because the result did not
    /// shrink. They asked for it.
    pub(crate) filter_requested: bool,
}

impl StoreFallback {
    pub(crate) const fn new() -> Self {
        Self {
            min_size: 0,
            allow_solid: false,
            filter_requested: false,
        }
    }

    pub(crate) const fn min_size(mut self, size: u64) -> Self {
        self.min_size = size;
        self
    }

    pub(crate) const fn allow_solid(mut self, allow: bool) -> Self {
        self.allow_solid = allow;
        self
    }

    pub(crate) const fn filter_requested(mut self, requested: bool) -> Self {
        self.filter_requested = requested;
        self
    }

    pub(crate) fn applies(&self, solid: bool, unpacked: u64, packed: u64) -> bool {
        if packed < unpacked || self.filter_requested {
            return false;
        }
        if solid && !self.allow_solid {
            return false;
        }
        unpacked >= self.min_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capability table and the validator have to agree everywhere, or a
    /// caller can be told an option is available and then refused it.
    #[test]
    fn asking_and_validating_agree_for_every_combination() {
        for target in ArchiveVersion::ALL {
            for option in WriterOption::ALL {
                for shape in PlanShape::all() {
                    let supported = supports(target, option, shape);
                    let validated = validate_option(target, option, shape);
                    assert_eq!(
                        supported,
                        validated.is_ok(),
                        "{target} {option:?} {shape:?}: supports={supported} validate={validated:?}"
                    );
                    if let Err(Error::UnsupportedWriterOption { option: named, .. }) = validated {
                        assert_eq!(named, option, "the refusal named the wrong option");
                    }
                }
            }
        }
    }

    /// The format-support cells of `docs/writer-limits.md`, pinned so a
    /// writer that gains or loses one has to update the table too.
    #[test]
    #[cfg(all(feature = "encryption", feature = "recovery"))]
    fn writer_limits_table_matches_what_each_format_supports() {
        const WRITER_LIMITS_TABLE: &str = "\
            rar13 single  solid password --- -------- memory temp\n\
            rar13 volumes solid -------- --- -------- ------ temp\n\
            rar14 single  solid password --- -------- memory temp\n\
            rar14 volumes solid -------- --- -------- ------ temp\n\
            rar15 single  solid password --- -------- memory temp\n\
            rar15 volumes solid password --- -------- ------ ----\n\
            rar20 single  solid password --- -------- memory temp\n\
            rar20 volumes solid password --- -------- ------ ----\n\
            rar29 single  solid password -hp -------- memory temp\n\
            rar29 volumes solid password -hp -------- ------ ----\n\
            rar30 single  solid password -hp -------- memory temp\n\
            rar30 volumes solid password -hp -------- ------ ----\n\
            rar40 single  solid password -hp -------- memory temp\n\
            rar40 volumes solid password -hp -------- ------ ----\n\
            rar50 single  solid password -hp recovery memory temp\n\
            rar50 volumes solid password -hp recovery memory temp\n\
            rar70 single  solid password -hp recovery memory temp\n\
            rar70 volumes solid password -hp recovery memory temp\n\
        ";
        let columns = [
            ("solid", WriterOption::Feature(Feature::Solid)),
            ("password", WriterOption::Password),
            ("-hp", WriterOption::Feature(Feature::HeaderEncryption)),
            ("recovery", WriterOption::RecoveryRecord),
            ("memory", WriterOption::MemoryLimit),
            ("temp", WriterOption::TempDir),
        ];
        let mut table = String::new();
        for target in ArchiveVersion::ALL {
            for volumes in [false, true] {
                let shape = PlanShape::new().compressed(true).volumes(volumes);
                let shape_name = if volumes { "volumes" } else { "single" };
                table.push_str(&format!("{target:<6} {shape_name:<7}"));
                for (name, option) in columns {
                    if supports(target, option, shape) {
                        table.push_str(&format!(" {name}"));
                    } else {
                        table.push_str(&format!(" {}", "-".repeat(name.len())));
                    }
                }
                table.push('\n');
            }
        }
        assert_eq!(table, WRITER_LIMITS_TABLE, "\n{table}");
    }

    /// A refusal is only useful if it can point somewhere, so every option has
    /// to be available on at least one format.
    #[test]
    fn every_option_is_supported_by_some_format() {
        for option in WriterOption::ALL {
            assert!(!option.name().is_empty());
            let disabled = match option {
                WriterOption::Password | WriterOption::Feature(Feature::HeaderEncryption) => {
                    !cfg!(feature = "encryption")
                }
                WriterOption::RecoveryRecord => !cfg!(feature = "recovery"),
                _ => false,
            };
            assert_eq!(
                PlanShape::all()
                    .into_iter()
                    .any(|shape| !formats_supporting(option, shape).is_empty()),
                !disabled,
                "{option:?} must have a supporting format exactly when its capability is enabled"
            );
        }
    }

    #[test]
    fn feature_capability_matches_the_per_option_answer() {
        for target in ArchiveVersion::ALL {
            for shape in PlanShape::all() {
                let features = supported_features(target, shape);
                for feature in Feature::ALL {
                    assert_eq!(
                        feature_of(features, feature),
                        supports(target, WriterOption::Feature(feature), shape),
                        "{target} {feature:?} {shape:?}"
                    );
                }
            }
        }
    }

    fn feature_of(set: FeatureSet, feature: Feature) -> bool {
        match feature {
            Feature::Solid => set.solid,
            Feature::HeaderEncryption => set.header_encryption,
            Feature::QuickOpen => set.quick_open,
            Feature::Blake2sp => set.blake2sp,
        }
    }

    #[test]
    fn a_member_is_only_stored_when_compressing_it_gained_nothing() {
        let plain = StoreFallback::new();
        assert!(plain.applies(false, 100, 100));
        assert!(plain.applies(false, 100, 120));
        assert!(!plain.applies(false, 100, 99));

        // A named filter survives a result that did not shrink.
        assert!(!plain.filter_requested(true).applies(false, 100, 200));

        // Solid is refused unless the format can rebuild its chain.
        assert!(!plain.applies(true, 100, 100));
        assert!(plain.allow_solid(true).applies(true, 100, 100));

        // The floor keeps small members compressed.
        let floored = plain.min_size(1024);
        assert!(!floored.applies(false, 1023, 1023));
        assert!(floored.applies(false, 1024, 1024));
    }

    #[test]
    fn a_level_above_five_is_refused_by_name() {
        let refused = validate_compression_level(ArchiveVersion::Rar50, Some(9));
        assert!(matches!(
            refused,
            Err(Error::UnsupportedWriterOption {
                option: WriterOption::CompressionLevel,
                ..
            })
        ));
        assert!(validate_compression_level(ArchiveVersion::Rar50, Some(5)).is_ok());
        assert!(validate_compression_level(ArchiveVersion::Rar50, None).is_ok());
    }
}
