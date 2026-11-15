//! Codec settings and execution decisions, resolved before scheduling work.

use super::FilterPolicy;
use crate::codec::rar50::EncodeOptions;
use crate::streaming::preparation::Records;
use crate::{Result, WriterResources};

/// How much of a run one filter search covers when a member is too large to
/// search whole. Larger dictionaries make longer runs, and this keeps each
/// search inside the one-thread default budget at every level.
pub(super) const FILTER_SEARCH_BYTES: usize = 4 * 1024 * 1024;

/// The most one filter search covers: a run, or a piece of one.
fn search_piece(settings: &CompressPlan) -> u64 {
    super::compress::run_size(settings).min(FILTER_SEARCH_BYTES) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FallbackReason {
    AutomaticFilterWorkspace {
        required: u64,
        limit: u64,
    },
    /// The requested filter is applied to each run instead of the member.
    ExplicitFilterWorkspace {
        required: u64,
        limit: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Execution {
    WholeMember,
    /// `run_filters` when each run's filter search fits the budget too, and
    /// always for an explicit filter, which each run applies without a search.
    Blocks {
        fallback: FallbackReason,
        run_filters: bool,
    },
}

#[derive(Debug, Clone, Copy)]
pub(super) struct MemberPlan {
    pub(super) execution: Execution,
    /// Whole-member workspace or one streaming job's workspace, never both.
    pub(super) workspace: u64,
}

pub(super) enum ExecutionPlan {
    Stored,
    Blocks { workspace: u64 },
    IndependentMembers(Records<MemberPlan>),
}

impl ExecutionPlan {
    #[cfg(test)]
    pub(super) fn new(
        settings: &CompressPlan,
        sizes: impl ExactSizeIterator<Item = u64>,
        limit: u64,
    ) -> Self {
        Self::with_resources(settings, sizes, &WriterResources::new(limit)).unwrap()
    }

    pub(super) fn with_resources(
        settings: &CompressPlan,
        sizes: impl ExactSizeIterator<Item = u64>,
        resources: &WriterResources,
    ) -> Result<Self> {
        // Output follows from these decisions, so they use the budget for one
        // job, which a thread count never changes.
        let limit = resources.planning_memory_limit();
        // Select the requested mode before estimating its active workspace.
        if settings.method == 0 {
            return Ok(Self::Stored);
        }
        let whole_members = !settings.solid
            && (settings.filter_policy != FilterPolicy::None || settings.candidates.len() > 1);
        if !whole_members {
            // A solid job's window can span members; an independent one cannot.
            let largest = if settings.solid {
                sizes.fold(0u64, u64::saturating_add)
            } else {
                sizes.max().unwrap_or(0)
            };
            return Ok(Self::Blocks {
                workspace: streaming_workspace(settings, true, largest),
            });
        }
        Ok(Self::IndependentMembers(Records::collect(
            sizes.map(|size| {
                let required = if size == 0 {
                    0
                } else {
                    whole_member_workspace(size, settings)
                };
                let fallback = match &settings.filter_policy {
                    _ if required <= limit => None,
                    FilterPolicy::Auto => {
                        Some(FallbackReason::AutomaticFilterWorkspace { required, limit })
                    }
                    // A range the member cannot hold is left to fail as it
                    // would whole.
                    FilterPolicy::Explicit(spec) if spec_fits(spec, size) => {
                        Some(FallbackReason::ExplicitFilterWorkspace { required, limit })
                    }
                    _ => None,
                };
                let Some(fallback) = fallback else {
                    return Ok(MemberPlan {
                        execution: Execution::WholeMember,
                        workspace: required,
                    });
                };
                let blocks = streaming_workspace(settings, false, size);
                // Fallback uses only the base encoder candidate. Automatic
                // filters search each run as if it were a member of its own
                // when that fits; an explicit filter is coded the same way,
                // without the search, so it is charged the same.
                let search = whole_member_workspace(size.min(search_piece(settings)), settings);
                let run_filters = search <= limit
                    || matches!(fallback, FallbackReason::ExplicitFilterWorkspace { .. });
                Ok(MemberPlan {
                    execution: Execution::Blocks {
                        fallback,
                        run_filters,
                    },
                    workspace: if run_filters {
                        blocks.max(search)
                    } else {
                        blocks
                    },
                })
            }),
            resources,
        )?))
    }

    #[cfg(test)]
    fn members(&self) -> &[MemberPlan] {
        match self {
            Self::IndependentMembers(members) => members,
            _ => panic!("expected independent member plan"),
        }
    }
}

fn spec_fits(spec: &crate::FilterSpec, size: u64) -> bool {
    spec.range
        .as_ref()
        .is_none_or(|range| range.start < range.end && range.end as u64 <= size)
}

/// A job never holds more than its input, so small members are not charged a 1 MiB block.
fn streaming_workspace(settings: &CompressPlan, include_candidates: bool, input: u64) -> u64 {
    let optimal = settings.encode_options.optimal_parse
        || (include_candidates
            && settings
                .candidates
                .iter()
                .any(|options| options.optimal_parse));
    super::streaming_lz_workspace(
        settings.dictionary_size,
        input.min(crate::codec::rar50::MAX_LZ_BLOCK_SIZE as u64) as usize,
        optimal,
    )
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub(super) struct CompressPlan {
    pub(super) algorithm_version: u8,
    pub(super) encode_options: EncodeOptions,
    pub(super) dictionary_size: u64,
    pub(super) block_size: usize,
    pub(super) solid: bool,
    /// The RAR 5 compression method. Method zero means the members are stored
    /// verbatim, so nothing is compressed at all.
    pub(super) method: u8,
    /// Multi-candidate encoding needs the whole member at once. Automatic
    /// filters search the whole member when it fits the memory budget, and
    /// each run of it when it does not.
    pub(super) filter_policy: FilterPolicy,
    pub(super) candidates: Records<EncodeOptions>,
}

/// Working memory a member needs to be filtered as a whole: the member, the
/// filtered copy, and the candidate packed outputs being compared.
pub(super) fn whole_member_workspace(input_size: u64, plan: &CompressPlan) -> u64 {
    let optimal = plan.encode_options.optimal_parse
        || plan.candidates.iter().any(|options| options.optimal_parse);
    let reach = plan
        .candidates
        .iter()
        .map(|options| options.max_match_distance as u64)
        .chain(std::iter::once(
            plan.encode_options.max_match_distance as u64,
        ))
        .max()
        .unwrap_or(0)
        .min(input_size)
        .max(crate::codec::rar50::LZ_BLOCK_SIZE as u64);
    let block = input_size.min(crate::codec::rar50::MAX_LZ_BLOCK_SIZE as u64) as usize;
    // Input, transformed input and competing packed outputs stay live alongside
    // the finder and the per-block token/parse workspace, not instead of them.
    input_size.saturating_mul(4).saturating_add(if optimal {
        super::tree_lz_workspace(reach, block)
    } else {
        super::streaming_lz_workspace(reach, block, false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> CompressPlan {
        let encode_options = EncodeOptions::new(8).with_max_match_distance(128 * 1024);
        CompressPlan {
            algorithm_version: 0,
            encode_options,
            dictionary_size: 128 * 1024,
            block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![encode_options].into(),
        }
    }

    #[test]
    fn automatic_fallback_records_the_admission_boundary_and_reason() {
        let settings = settings();
        let size = 2 * 1024 * 1024;
        let required = whole_member_workspace(size, &settings);
        let at_limit = ExecutionPlan::new(&settings, [size].into_iter(), required);
        assert_eq!(at_limit.members()[0].execution, Execution::WholeMember);
        let below = ExecutionPlan::new(&settings, [size].into_iter(), required - 1);
        assert_eq!(
            below.members()[0].execution,
            Execution::Blocks {
                fallback: FallbackReason::AutomaticFilterWorkspace {
                    required,
                    limit: required - 1
                },
                run_filters: true,
            }
        );
        // Charged for one run's filter search, which is smaller than the member.
        let search = whole_member_workspace(search_piece(&settings), &settings);
        assert_eq!(below.members()[0].workspace, search);
        assert!(search < required);

        // A member no longer than one search cannot search a part of itself.
        let size = search_piece(&settings);
        let required = whole_member_workspace(size, &settings);
        let below = ExecutionPlan::new(&settings, [size].into_iter(), required - 1);
        assert!(matches!(
            below.members()[0].execution,
            Execution::Blocks {
                run_filters: false,
                ..
            }
        ));
    }

    #[test]
    fn explicit_filters_fall_back_to_filtered_runs() {
        let mut settings = settings();
        let delta = crate::FilterKind::Delta { channels: 1 };
        settings.filter_policy = FilterPolicy::Explicit(crate::FilterSpec::whole(delta));
        let size = 2 * search_piece(&settings);
        let required = whole_member_workspace(size, &settings);
        let at_limit = ExecutionPlan::new(&settings, [size].into_iter(), required);
        assert_eq!(at_limit.members()[0].execution, Execution::WholeMember);
        // Even when a run's search would not fit, the filter is still applied.
        for limit in [required - 1, 1] {
            let below = ExecutionPlan::new(&settings, [size].into_iter(), limit);
            assert_eq!(
                below.members()[0].execution,
                Execution::Blocks {
                    fallback: FallbackReason::ExplicitFilterWorkspace { required, limit },
                    run_filters: true,
                }
            );
        }
        // A range past the member's end fails whole, as it always has.
        settings.filter_policy =
            FilterPolicy::Explicit(crate::FilterSpec::range(delta, 0..size as usize + 1));
        let past = ExecutionPlan::new(&settings, [size].into_iter(), 1);
        assert_eq!(past.members()[0].execution, Execution::WholeMember);
    }

    #[test]
    fn candidate_trials_cannot_silently_fall_back() {
        let mut settings = settings();
        settings.filter_policy = FilterPolicy::None;
        settings
            .candidates
            .push_growing(settings.encode_options)
            .unwrap();
        let execution = ExecutionPlan::new(&settings, [16].into_iter(), 1);
        assert_eq!(execution.members()[0].execution, Execution::WholeMember);
        assert!(execution.members()[0].workspace > 1);
    }

    #[test]
    fn streaming_blocks_are_charged_for_the_input_not_a_full_block() {
        let mut settings = settings();
        settings.filter_policy = FilterPolicy::None;
        settings.encode_options = settings.encode_options.with_optimal_parse(true);
        settings.candidates = vec![settings.encode_options].into();
        let member = 160 * 1024;
        let charge = |input: u64| {
            super::super::streaming_lz_workspace(settings.dictionary_size, input as usize, true)
        };
        let full = charge(crate::codec::rar50::MAX_LZ_BLOCK_SIZE as u64);
        for (solid, expected) in [(false, charge(member)), (true, charge(2 * member))] {
            settings.solid = solid;
            let plan = ExecutionPlan::new(&settings, [member, member].into_iter(), u64::MAX);
            assert!(matches!(plan, ExecutionPlan::Blocks { workspace } if workspace == expected));
            assert!(expected < full);
        }
        settings.solid = false;
        let large = ExecutionPlan::new(&settings, [16 * 1024 * 1024].into_iter(), u64::MAX);
        assert!(matches!(large, ExecutionPlan::Blocks { workspace } if workspace == full));
    }

    #[test]
    fn stored_empty_and_solid_modes_do_not_acquire_whole_member_workspace() {
        let mut settings = settings();
        let empty = ExecutionPlan::new(&settings, [0].into_iter(), 0);
        assert_eq!(empty.members()[0].workspace, 0);
        assert_eq!(empty.members()[0].execution, Execution::WholeMember);
        settings.method = 0;
        let stored = ExecutionPlan::new(&settings, [u64::MAX].into_iter(), 0);
        assert!(matches!(stored, ExecutionPlan::Stored));
        settings.method = 1;
        settings.solid = true;
        let solid = ExecutionPlan::new(&settings, [16, u64::MAX].into_iter(), u64::MAX);
        assert!(matches!(solid, ExecutionPlan::Blocks { workspace } if workspace > 0));
    }

    #[test]
    fn independent_member_planning_respects_the_execution_ledger() {
        let ledger = crate::codec::workspace::Allowance::limited(0);
        let resources = WriterResources::default().with_execution_allowance(ledger.clone());
        let error = ExecutionPlan::with_resources(&settings(), [1].into_iter(), &resources)
            .err()
            .unwrap();
        assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
        assert_eq!(ledger.used(), 0);
    }
}
