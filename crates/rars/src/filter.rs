//! Data filters: the reversible transforms a writer applies to a member before
//! compressing it, so the encoder sees something it can match on.
//!
//! Every RAR family that has filters at all draws from this set, but no family
//! encodes all of it. RAR 5 has four builtin filter types; the RAR 2.9 family
//! ships six filters as RarVM programs; delta and the two x86 filters are the
//! only ones common to both. Asking a writer for a filter it cannot encode is
//! rejected when the archive is written, not when the filter is named, because
//! the format is chosen at the same moment and often from the same argument.

use std::ops::Range;

/// A reversible transform applied to a member before it is compressed.
///
/// Deliberately not `#[non_exhaustive]`: each format converts this into its own
/// narrower set with an exhaustive match and no wildcard arm, so an eighth
/// filter has to be decided about everywhere before the crate will build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterKind {
    /// Splits the member into `channels` planes and stores each plane as
    /// differences, which turns a smooth ramp into a run of near-zero bytes.
    Delta { channels: usize },
    /// Rewrites x86 `E8` call targets from relative to absolute, so the same
    /// call made from different places becomes the same bytes.
    E8,
    /// As [`FilterKind::E8`], also converting `E9` jumps.
    E8E9,
    /// The ARM equivalent, rewriting `BL` branch targets.
    Arm,
    /// The Itanium equivalent. RAR 2.9 family only.
    Itanium,
    /// De-interleaves `width`-byte pixels and predicts each channel from its
    /// neighbours. RAR 2.9 family only.
    Rgb { width: usize, pos_r: usize },
    /// Predicts each sample from the previous ones in the same channel.
    /// RAR 2.9 family only.
    Audio { channels: usize },
}

impl FilterKind {
    /// What this filter is called when a writer has to refuse it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Delta { .. } => "the delta filter",
            Self::E8 => "the x86 E8 filter",
            Self::E8E9 => "the x86 E8/E9 filter",
            Self::Arm => "the ARM filter",
            Self::Itanium => "the Itanium filter",
            Self::Rgb { .. } => "the RGB filter",
            Self::Audio { .. } => "the audio filter",
        }
    }
}

/// A filter and the bytes it covers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FilterSpec {
    pub kind: FilterKind,
    /// The bytes the filter covers. `None` covers the whole member.
    pub range: Option<Range<usize>>,
}

impl FilterSpec {
    pub const fn whole(kind: FilterKind) -> Self {
        Self { kind, range: None }
    }

    pub const fn range(kind: FilterKind, range: Range<usize>) -> Self {
        Self {
            kind,
            range: Some(range),
        }
    }
}

impl From<FilterKind> for FilterSpec {
    fn from(kind: FilterKind) -> Self {
        Self::whole(kind)
    }
}

/// How a writer decides which filter, if any, to apply to a member.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FilterPolicy {
    /// Compress the member as it stands.
    #[default]
    None,
    /// Look for a filter that makes the member compress smaller, and use one
    /// only if it does.
    Auto,
    /// Apply this filter whether or not it pays off.
    Explicit(FilterSpec),
}

impl FilterPolicy {
    /// The common case: one filter over the whole member.
    pub const fn explicit(kind: FilterKind) -> Self {
        Self::Explicit(FilterSpec::whole(kind))
    }
}

/// A filter the target format has no way to encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedFilterKind(pub FilterKind);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::rar29::Rar29Filter;
    use crate::codec::rar50::Rar50Filter;

    /// Exhaustive by construction: a new filter has to be added here, and the
    /// two conversions below then have to say what each format does with it.
    const ALL: [FilterKind; 7] = [
        FilterKind::Delta { channels: 1 },
        FilterKind::E8,
        FilterKind::E8E9,
        FilterKind::Arm,
        FilterKind::Itanium,
        FilterKind::Rgb { width: 3, pos_r: 0 },
        FilterKind::Audio { channels: 1 },
    ];

    #[test]
    fn every_filter_is_named_and_accepted_by_at_least_one_format() {
        for kind in ALL {
            assert!(
                !kind.name().is_empty(),
                "{kind:?} has no name to refuse it by"
            );
            assert!(
                Rar50Filter::try_from(kind).is_ok() || Rar29Filter::try_from(kind).is_ok(),
                "{kind:?} is a filter no format can write"
            );
        }
    }

    /// The two families are complementary rather than nested, which is why a
    /// rejection is worth naming the format that does support the filter.
    #[test]
    fn the_two_families_each_have_what_the_other_lacks() {
        assert!(Rar50Filter::try_from(FilterKind::Arm).is_ok());
        assert!(Rar29Filter::try_from(FilterKind::Arm).is_err());
        for kind in [
            FilterKind::Itanium,
            FilterKind::Rgb { width: 3, pos_r: 0 },
            FilterKind::Audio { channels: 1 },
        ] {
            assert!(Rar29Filter::try_from(kind).is_ok(), "{kind:?}");
            assert_eq!(
                Rar50Filter::try_from(kind),
                Err(UnsupportedFilterKind(kind)),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn a_policy_defaults_to_leaving_the_data_alone() {
        assert_eq!(FilterPolicy::default(), FilterPolicy::None);
        assert_eq!(
            FilterPolicy::explicit(FilterKind::E8),
            FilterPolicy::Explicit(FilterSpec::whole(FilterKind::E8))
        );
    }
}
