//! What each format's writer can be asked for, and one place that says no.
//!
//! Every writer used to answer this for itself, in about thirty functions that
//! nearly all ended the same way: build the set of features this shape of
//! archive is allowed, compare it with what the caller asked for, and on a
//! mismatch return a fixed string that never said which option was the problem.
//! A caller who asked for two things and could only have one was told "writer
//! feature is not supported" and left to work out which.
//!
//! So capability is data here, keyed by format and by the shape of the archive
//! being built, and a refusal names the option, the format, and why.

use crate::error::{Error, Result};
use crate::features::{Feature, FeatureSet};
use crate::filter::FilterPolicy;
use crate::version::{ArchiveFamily, ArchiveVersion};

/// How the members of an archive are coded.
///
/// The three arms are the three questions a writer has to answer before it
/// touches a member, and they used to be three entry points per format that
/// differed in a handful of lines each.
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

/// Something a caller can ask a writer for, that a format may not be able to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriterOption {
    Feature(Feature),
    CompressionLevel,
    /// An engine other than the format's default, which today means PPMd.
    CompressionMethod,
    DictionarySize,
    Filter,
    RecoveryRecord,
    VolumeSize,
    ArchiveComment,
    FileComment,
    ArchiveMetadata,
    Password,
    MemoryLimit,
    TempDir,
}

impl WriterOption {
    pub const ALL: [Self; 15] = [
        Self::Feature(Feature::Solid),
        Self::Feature(Feature::HeaderEncryption),
        Self::Feature(Feature::QuickOpen),
        Self::CompressionLevel,
        Self::CompressionMethod,
        Self::DictionarySize,
        Self::Filter,
        Self::RecoveryRecord,
        Self::VolumeSize,
        Self::ArchiveComment,
        Self::FileComment,
        Self::ArchiveMetadata,
        Self::Password,
        Self::MemoryLimit,
        Self::TempDir,
    ];

    /// How this option is named in a library message. The command line
    /// substitutes the flag the user actually typed.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Feature(feature) => feature.name(),
            Self::CompressionLevel => "a compression level",
            Self::CompressionMethod => "an alternative compression method",
            Self::DictionarySize => "a dictionary size",
            Self::Filter => "a data filter",
            Self::RecoveryRecord => "a recovery record",
            Self::VolumeSize => "splitting into volumes",
            Self::ArchiveComment => "an archive comment",
            Self::FileComment => "a per-file comment",
            Self::ArchiveMetadata => "archive metadata",
            Self::Password => "encryption",
            Self::MemoryLimit => "a memory limit",
            Self::TempDir => "a temporary directory",
        }
    }
}

/// The features this format can honour for an archive of this shape.
///
/// Deliberately blind to what the caller asked for. The check this replaced
/// built its "allowed" set partly out of the request itself, which in several
/// places decayed into assigning a flag to itself, so the flag was accepted
/// whatever it said.
pub fn supported_features(target: ArchiveVersion, shape: PlanShape) -> FeatureSet {
    FeatureSet {
        solid: supports(target, WriterOption::Feature(Feature::Solid), shape),
        header_encryption: supports(
            target,
            WriterOption::Feature(Feature::HeaderEncryption),
            shape,
        ),
        quick_open: supports(target, WriterOption::Feature(Feature::QuickOpen), shape),
    }
}

/// Whether this format's writer can honour `option` for an archive of this
/// shape.
pub fn supports(target: ArchiveVersion, option: WriterOption, shape: PlanShape) -> bool {
    let family = target.family();
    match option {
        // Solid means compressing members against each other, so there has to
        // be compression for it to mean anything.
        WriterOption::Feature(Feature::Solid) => shape.compressed,
        WriterOption::Feature(Feature::HeaderEncryption) => matches!(
            target,
            ArchiveVersion::Rar30
                | ArchiveVersion::Rar40
                | ArchiveVersion::Rar50
                | ArchiveVersion::Rar70
        ),
        // Quick-open indexes headers, so it cannot cover encrypted ones.
        WriterOption::Feature(Feature::QuickOpen) => family == ArchiveFamily::Rar50Plus,
        WriterOption::CompressionLevel => true,
        // PPMd arrived with RAR 2.9 and left again with RAR 5.
        WriterOption::CompressionMethod => matches!(
            target,
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
        ),
        WriterOption::DictionarySize => !family_is(family, ArchiveFamily::Rar13),
        // RAR 1.3 and 1.5 have no filters at all; RAR 2.0 predates the VM. The
        // legacy volume writer takes a payload rather than a policy, so a
        // filter cannot be asked for across a split set.
        WriterOption::Filter => {
            !matches!(
                target,
                ArchiveVersion::Rar13
                    | ArchiveVersion::Rar14
                    | ArchiveVersion::Rar15
                    | ArchiveVersion::Rar20
            ) && (family == ArchiveFamily::Rar50Plus || !shape.volumes)
        }
        WriterOption::RecoveryRecord => family == ArchiveFamily::Rar50Plus,
        WriterOption::VolumeSize => true,
        // The legacy volume writer emits the split member and nothing else, so
        // a comment has nowhere to go in a split set.
        WriterOption::ArchiveComment => family == ArchiveFamily::Rar50Plus || !shape.volumes,
        // RAR 3.x and 4.x moved file comments into a form this writer does not
        // emit. RAR 5 carries them as a service record, which the legacy
        // writers cannot split across volumes.
        WriterOption::FileComment => {
            !matches!(target, ArchiveVersion::Rar30 | ArchiveVersion::Rar40)
                && (family == ArchiveFamily::Rar50Plus || !shape.volumes)
        }
        WriterOption::ArchiveMetadata => family == ArchiveFamily::Rar50Plus,
        WriterOption::Password => true,
        // Every writer compresses to a budget now: RAR 5 sizes its blocks by
        // it, and the older ones use it to decide how many members to have in
        // flight. A legacy volume set is the exception, still built in memory.
        WriterOption::MemoryLimit => family == ArchiveFamily::Rar50Plus || !shape.volumes,
        // Only the RAR 5 engine spills to disk.
        WriterOption::TempDir => family == ArchiveFamily::Rar50Plus,
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
    pub(crate) min_size: usize,
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

    pub(crate) const fn min_size(mut self, size: usize) -> Self {
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

    pub(crate) fn applies(&self, solid: bool, unpacked: usize, packed: usize) -> bool {
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

    /// A refusal is only useful if it can point somewhere, so every option has
    /// to be available on at least one format.
    #[test]
    fn every_option_is_supported_by_some_format() {
        for option in WriterOption::ALL {
            assert!(!option.name().is_empty());
            assert!(
                PlanShape::all()
                    .into_iter()
                    .any(|shape| !formats_supporting(option, shape).is_empty()),
                "{option:?} is supported by nothing, so a refusal could not point anywhere"
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
