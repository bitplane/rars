//! Codec settings and execution decisions, resolved before scheduling work.

use super::FilterPolicy;
use crate::codec::rar50::EncodeOptions;
use crate::streaming::preparation::Records;
use crate::{Result, WriterResources};

/// How much of a run one filter search covers when a member is too large to
/// search whole. Larger dictionaries make longer runs, and this keeps each
/// search inside the default routing limit at every level.
pub(super) const FILTER_SEARCH_BYTES: usize = 4 * 1024 * 1024;

#[cfg(test)]
std::thread_local! {
    static FILTER_SEARCH_HERE: std::cell::Cell<usize> = const { std::cell::Cell::new(FILTER_SEARCH_BYTES) };
}

/// [`FILTER_SEARCH_BYTES`], or what a test lowered it to on this thread, so a
/// member crosses it without coding 4 MiB in a debug build.
pub(super) fn filter_search_bytes() -> usize {
    #[cfg(test)]
    {
        FILTER_SEARCH_HERE.get()
    }
    #[cfg(not(test))]
    {
        FILTER_SEARCH_BYTES
    }
}

/// Runs `run` with filter searches covering at most `bytes`, on this thread
/// and on the workers of the pool it runs in.
#[cfg(test)]
pub(super) fn with_filter_search_bytes<T: Send>(bytes: usize, run: impl FnOnce() -> T + Send) -> T {
    let was = FILTER_SEARCH_HERE.replace(bytes);
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    let result = rayon::ThreadPoolBuilder::new()
        .num_threads(rayon::current_num_threads())
        .start_handler(move |_| FILTER_SEARCH_HERE.set(bytes))
        .build()
        .unwrap()
        .install(run);
    #[cfg(any(
        not(feature = "parallel"),
        all(target_arch = "wasm32", target_os = "unknown")
    ))]
    let result = run();
    FILTER_SEARCH_HERE.set(was);
    result
}

/// The most one filter search covers: a run, or a piece of one.
fn search_piece(options: EncodeOptions) -> u64 {
    super::compress::run_size_for_distance(options.max_match_distance).min(filter_search_bytes())
        as u64
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
    /// The member goes out as it is packed, which only runs can do.
    InPlace,
    /// The member fits whole but codes the same in runs, which run in
    /// parallel where a whole member runs on one thread: see
    /// [`codes_alike_in_runs`].
    LazyRuns,
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
    /// What one of its block jobs is admitted for: see [`block_admission`].
    /// A whole member is admitted for its `workspace`.
    pub(super) admission: u64,
}

pub(super) enum ExecutionPlan {
    Stored,
    /// `run_filters` when the members share one solid window and each run's
    /// filter search fits the budget beside it.
    Blocks {
        workspace: u64,
        /// What each job is admitted for: see [`block_admission`].
        admission: u64,
        run_filters: bool,
    },
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
        // The default routing threshold stays at 256 MiB to preserve
        // whole-member and filter choices as the dictionary budget changes.
        let limit = resources.routing_memory_limit();
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
            let workspace = streaming_workspace(settings, true, largest);
            // A solid chain cannot search a member whole: its members code
            // against each other. It searches each run on its own instead, as
            // a member too large to search whole does, when that fits.
            let piece = largest.min(search_piece(settings.encode_options));
            let run_filters = settings.solid
                && settings.filter_policy == FilterPolicy::Auto
                && whole_member_routing_workspace(piece, settings) <= limit;
            let search = run_search_workspace(piece, settings);
            return Ok(Self::Blocks {
                workspace: if run_filters {
                    workspace.max(search)
                } else {
                    workspace
                },
                admission: block_admission(
                    workspace,
                    settings.encode_options,
                    largest,
                    run_filters,
                ),
                run_filters,
            });
        }
        Ok(Self::IndependentMembers(Records::collect(
            sizes.map(|size| {
                let required = whole_member_workspace(size, settings);
                let routing = whole_member_routing_workspace(size, settings);
                // A run's search is a piece of the member's, so it fits too.
                if routing <= limit && codes_alike_in_runs(settings, size) {
                    return Ok(MemberPlan::in_runs(
                        settings,
                        size,
                        FallbackReason::LazyRuns,
                        limit,
                    ));
                }
                let fallback = match &settings.filter_policy {
                    _ if routing <= limit => None,
                    FilterPolicy::Auto => Some(FallbackReason::AutomaticFilterWorkspace {
                        required: routing,
                        limit,
                    }),
                    // A range the member cannot hold is left to fail as it
                    // would whole.
                    FilterPolicy::Explicit(spec) if spec_fits(spec, size) => {
                        Some(FallbackReason::ExplicitFilterWorkspace {
                            required: routing,
                            limit,
                        })
                    }
                    _ => None,
                };
                let Some(fallback) = fallback else {
                    return Ok(MemberPlan {
                        execution: Execution::WholeMember,
                        workspace: required,
                        admission: required,
                    });
                };
                Ok(MemberPlan::in_runs(settings, size, fallback, limit))
            }),
            resources,
        )?))
    }

    /// Coded whole, an explicit-filter member could not go out as it is packed.
    pub(super) fn in_place(
        &mut self,
        settings: &CompressPlan,
        member: usize,
        size: u64,
        resources: &WriterResources,
    ) {
        let (Self::IndependentMembers(members), FilterPolicy::Explicit(spec)) =
            (self, &settings.filter_policy)
        else {
            return;
        };
        if members[member].execution == Execution::WholeMember && spec_fits(spec, size) {
            members[member] = MemberPlan::in_runs(
                settings,
                size,
                FallbackReason::InPlace,
                resources.routing_memory_limit(),
            );
        }
    }

    #[cfg(test)]
    fn members(&self) -> &[MemberPlan] {
        match self {
            Self::IndependentMembers(members) => members,
            _ => panic!("expected independent member plan"),
        }
    }
}

impl MemberPlan {
    fn in_runs(settings: &CompressPlan, size: u64, fallback: FallbackReason, limit: u64) -> Self {
        let blocks = streaming_workspace(settings, false, size);
        // Fallback uses only the base encoder candidate. Automatic filters
        // search each run as if it were a member of its own when that fits; an
        // explicit filter is coded the same way, without the search, so it is
        // charged the same.
        let search =
            run_search_workspace(size.min(search_piece(settings.encode_options)), settings);
        let routing = whole_member_routing_workspace(
            size.min(search_piece(settings.encode_options)),
            settings,
        );
        let run_filters =
            routing <= limit || matches!(settings.filter_policy, FilterPolicy::Explicit(_));
        Self {
            execution: Execution::Blocks {
                fallback,
                run_filters,
            },
            workspace: if run_filters {
                blocks.max(search)
            } else {
                blocks
            },
            admission: block_admission(blocks, settings.encode_options, size, run_filters),
        }
    }
}

/// Whether a member that fits whole packs to the same bytes run by run, so
/// it can take the runs.
///
/// The whole path parses the member with one finder on one thread (#545). The
/// runs path parses each run against a finder seeded from the dictionary before
/// it, and runs as many runs at once as there are threads.
///
/// The two agree when the parse is the lazy one, which walks hash chains on
/// both paths, and the member is longer than one filter search, which the
/// whole path then makes a piece at a time on the grid the runs are searched
/// on ([`super::filter_policy`]'s `choose_owned_filter`). One difference
/// is left: a member mostly of text is judged so whole and left unsearched,
/// where each of its runs is judged by its own samples, so a run of code
/// inside it is searched.
///
/// The shortest-path parse searches a tree on one path and can walk chains
/// over a member's short last run on the other, so its members stay whole.
/// A member trying several encoder settings needs them whole, and an
/// explicit filter is applied over the whole member at once.
fn codes_alike_in_runs(settings: &CompressPlan, size: u64) -> bool {
    settings.filter_policy == FilterPolicy::Auto
        && !settings.encode_options.optimal_parse
        && matches!(&settings.candidates[..], [only] if !only.optimal_parse)
        && size > filter_search_bytes() as u64
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
    if optimal {
        super::streaming_lz_workspace(
            settings.dictionary_size,
            input.min(crate::codec::rar50::MAX_LZ_BLOCK_SIZE as u64) as usize,
            true,
        )
    } else {
        lazy_streaming_workspace(settings.encode_options, input)
    }
}

/// The window and packed run remain live beside the codec's block scratch.
pub(super) fn lazy_streaming_workspace(options: EncodeOptions, input: u64) -> u64 {
    let run = input.min(super::compress::run_size_for_distance(options.max_match_distance) as u64);
    let history = input.min(options.max_match_distance as u64);
    let window = history.saturating_add(run);
    let block = run.min(crate::codec::rar50::MAX_LZ_BLOCK_SIZE as u64) as usize;
    crate::codec::rar50::lazy_parse_workspace(
        options,
        usize::try_from(window).unwrap_or(usize::MAX),
        block,
    )
    .saturating_add(window)
    .saturating_add(run.saturating_mul(2))
}

/// What a full block job holds, for fitting the dictionary.
///
/// A job's peak is the larger of its two phases, plus what the coordinator
/// keeps for it through both:
///
/// - **Coding the run.** The streaming charge, which #407 measured job by job:
///   finder links over the window, the window itself and up to a block's
///   worth of match runs, worst on noise of two to four symbols.
/// - **Searching its filters.** One search at a time per job, over a piece of
///   at most [`FILTER_SEARCH_BYTES`] coded without history: the same parts
///   over the piece, plus its filtered copy and the packed finalists. The
///   routing estimate prices this search as a whole member, with the tree's
///   coefficients and four copies of the piece.
/// - **Held by the coordinator.** The member's history kept for its next run,
///   and the run's bytes while its filters are searched.
///
/// Live allocation peaks in MiB, counted by a global allocator over a whole
/// write at one thread under the default budget, where each wave holds one
/// job, on members two and a half runs long with filters searched (the
/// fitted-dictionary matrix in `tests/charge_covers_peak.rs`):
///
/// ```text
/// input                level 3, 4 MiB   level 4, 8 MiB   level 5, 16 MiB
/// text                       48.6             81.7             153.6
/// binary records             43.2             75.3             147.3
/// all zeros                  65.7             97.8             169.7
/// 64-symbol literals         54.7             91.2             165.3
/// two-symbol noise          127.7            176.0             233.3
/// three-symbol noise        131.4            180.3             237.0
/// charged here           151 (143 unfiltered)  179           251
/// ```
pub(super) fn block_admission(
    code: u64,
    options: EncodeOptions,
    input: u64,
    run_filters: bool,
) -> u64 {
    let run = super::compress::run_size_for_distance(options.max_match_distance) as u64;
    let search = if run_filters {
        let piece = input.min(search_piece(options));
        if options.optimal_parse {
            super::streaming_lz_workspace(
                piece,
                piece.min(crate::codec::rar50::MAX_LZ_BLOCK_SIZE as u64) as usize,
                true,
            )
            .saturating_add(piece.saturating_mul(2))
        } else {
            lazy_whole_member_workspace(piece, options)
        }
    } else {
        0
    };
    let history = (options.max_match_distance as u64).min(input);
    code.max(search)
        .saturating_add(history)
        .saturating_add(run.min(input))
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
    /// Hash members with BLAKE2sp as well as CRC32, for an archive that
    /// stores the hash.
    pub(super) blake2sp: bool,
}

/// Working memory a member needs to be filtered as a whole: the member, the
/// filtered copy, and the candidate packed outputs being compared.
///
/// This is what a member coded whole is admitted for, not what routes it:
/// see [`whole_member_routing_workspace`].
pub(super) fn whole_member_workspace(input_size: u64, plan: &CompressPlan) -> u64 {
    if input_size == 0 {
        return 0;
    }
    lazy_member_workspace(input_size, plan).unwrap_or_else(|| {
        let (reach, block) = whole_member_parse_extent(input_size, plan);
        input_size
            .saturating_mul(4)
            .saturating_add(super::whole_member_tree_workspace(reach, block))
    })
}

/// What a run's filter search is charged as a member of its own. It is also
/// what each run's job reserves under an execution ledger, beside the run's
/// coding, so it keeps the routing estimate rather than
/// [`whole_member_workspace`].
fn run_search_workspace(piece: u64, plan: &CompressPlan) -> u64 {
    if piece == 0 {
        return 0;
    }
    lazy_member_workspace(piece, plan)
        .unwrap_or_else(|| whole_member_routing_workspace(piece, plan))
}

/// The most a lazy candidate holds coding `input` whole, or `None` when any
/// candidate parses by shortest path.
fn lazy_member_workspace(input: u64, plan: &CompressPlan) -> Option<u64> {
    (!plan.encode_options.optimal_parse
        && plan.candidates.iter().all(|options| !options.optimal_parse))
    .then(|| {
        plan.candidates
            .iter()
            .copied()
            .chain(std::iter::once(plan.encode_options))
            .map(|options| lazy_whole_member_workspace(input, options))
            .max()
            .unwrap_or(0)
    })
}

fn lazy_whole_member_workspace(input: u64, options: EncodeOptions) -> u64 {
    let block = input.min(crate::codec::rar50::MAX_LZ_BLOCK_SIZE as u64) as usize;
    crate::codec::rar50::lazy_parse_workspace(
        options,
        usize::try_from(input).unwrap_or(usize::MAX),
        block,
    )
    .saturating_add(input.saturating_mul(4))
}

/// Routing is part of the archive's encoding plan, so it uses a fixed estimate,
/// kept apart from the [`whole_member_workspace`] a member is admitted for so
/// that what a member is charged never moves it between paths.
fn whole_member_routing_workspace(input_size: u64, plan: &CompressPlan) -> u64 {
    if input_size == 0 {
        return 0;
    }
    let optimal = plan.encode_options.optimal_parse
        || plan.candidates.iter().any(|options| options.optimal_parse);
    let (reach, block) = whole_member_parse_extent(input_size, plan);
    // Input, transformed input and competing packed outputs stay live alongside
    // the finder and the per-block token/parse workspace, not instead of them.
    input_size.saturating_mul(4).saturating_add(if optimal {
        super::tree_lz_workspace(reach, block)
    } else {
        super::streaming_lz_workspace(reach, block, false)
    })
}

/// How far back a whole member's parse reaches, and its largest block.
fn whole_member_parse_extent(input_size: u64, plan: &CompressPlan) -> (u64, usize) {
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
    (reach, block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::{DEFAULT_WRITER_MEMORY_LIMIT, DEFAULT_WRITER_PLANNING_LIMIT};

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
            blake2sp: true,
        }
    }

    #[test]
    fn automatic_fallback_records_the_admission_boundary_and_reason() {
        let settings = settings();
        let size = 2 * 1024 * 1024;
        let required = whole_member_routing_workspace(size, &settings);
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
        let search =
            whole_member_routing_workspace(search_piece(settings.encode_options), &settings);
        assert_eq!(
            below.members()[0].workspace,
            run_search_workspace(search_piece(settings.encode_options), &settings)
        );
        assert!(search < required);

        // A member no longer than one search cannot search a part of itself.
        let size = search_piece(settings.encode_options);
        let required = whole_member_routing_workspace(size, &settings);
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
    fn a_lazy_member_longer_than_one_search_takes_its_runs() {
        let settings = settings();
        assert!(!settings.encode_options.optimal_parse);
        let search = filter_search_bytes() as u64;
        let long = ExecutionPlan::new(&settings, [search + 1].into_iter(), u64::MAX);
        assert_eq!(
            long.members()[0].execution,
            Execution::Blocks {
                fallback: FallbackReason::LazyRuns,
                run_filters: true,
            }
        );
        // One search long, the whole member is searched as one piece, which
        // its runs are not.
        let short = ExecutionPlan::new(&settings, [search].into_iter(), u64::MAX);
        assert_eq!(short.members()[0].execution, Execution::WholeMember);
        // The shortest-path parse searches a tree whole and can walk chains
        // over the last run, so it stays whole.
        let mut optimal = settings.clone();
        optimal.encode_options = optimal.encode_options.with_optimal_parse(true);
        optimal.candidates = vec![optimal.encode_options].into();
        let optimal = ExecutionPlan::new(&optimal, [search + 1].into_iter(), u64::MAX);
        assert_eq!(optimal.members()[0].execution, Execution::WholeMember);
    }

    #[test]
    fn explicit_filters_fall_back_to_filtered_runs() {
        let mut settings = settings();
        let delta = crate::FilterKind::Delta { channels: 1 };
        settings.filter_policy = FilterPolicy::Explicit(crate::FilterSpec::whole(delta));
        let size = 2 * search_piece(settings.encode_options);
        let required = whole_member_routing_workspace(size, &settings);
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
        // A range past the member's end fails whole.
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
            assert!(
                matches!(plan, ExecutionPlan::Blocks { workspace, .. } if workspace == expected)
            );
            assert!(expected < full);
        }
        settings.solid = false;
        let large = ExecutionPlan::new(&settings, [16 * 1024 * 1024].into_iter(), u64::MAX);
        assert!(matches!(large, ExecutionPlan::Blocks { workspace, .. } if workspace == full));
    }

    #[test]
    fn a_solid_chain_searches_each_run_when_the_search_fits() {
        let mut settings = settings();
        settings.solid = true;
        let sizes = || [3 * 1024 * 1024u64, 5 * 1024 * 1024].into_iter();
        let streaming = streaming_workspace(&settings, true, 8 * 1024 * 1024);
        let search =
            whole_member_routing_workspace(search_piece(settings.encode_options), &settings);
        assert!(search > streaming);

        // The search is charged beside the chain, and decides nothing about
        // the output when it does not fit.
        let roomy = ExecutionPlan::new(&settings, sizes(), search);
        assert!(matches!(
            roomy,
            ExecutionPlan::Blocks { workspace, run_filters: true, .. } if workspace == run_search_workspace(search_piece(settings.encode_options), &settings).max(streaming)
        ));
        let tight = ExecutionPlan::new(&settings, sizes(), search - 1);
        assert!(matches!(
            tight,
            ExecutionPlan::Blocks { workspace, run_filters: false, .. } if workspace == streaming
        ));

        // Only the automatic policy searches. A chain has nowhere to put a
        // filter named for the whole archive, and none was asked for here.
        settings.filter_policy = FilterPolicy::None;
        let unfiltered = ExecutionPlan::new(&settings, sizes(), u64::MAX);
        assert!(matches!(
            unfiltered,
            ExecutionPlan::Blocks { workspace, run_filters: false, .. } if workspace == streaming
        ));

        // Members that do not share a window are planned one by one, and
        // never as a chain.
        settings.solid = false;
        let apart = ExecutionPlan::new(&settings, sizes(), u64::MAX);
        assert!(matches!(
            apart,
            ExecutionPlan::Blocks {
                run_filters: false,
                ..
            }
        ));
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
        assert!(matches!(solid, ExecutionPlan::Blocks { workspace, .. } if workspace > 0));
    }

    /// #315's acceptance: with automatic filters at level 3, the default
    /// budget admits a job per thread at every thread count, where the
    /// planning charge admitted 5 of 8 and 21 of 32.
    #[test]
    fn filtered_jobs_fill_every_thread_of_the_default_budget() {
        use crate::streaming::DEFAULT_WRITER_MEMORY_PER_THREAD;
        let dictionary = 4 * 1024 * 1024;
        let options =
            super::super::filter_policy::encode_options_for_level(Some(3), dictionary).unwrap();
        let settings = CompressPlan {
            encode_options: options,
            dictionary_size: dictionary,
            candidates: vec![options].into(),
            blake2sp: true,
            ..settings()
        };
        let size = 256 * 1024 * 1024;
        for threads in 1..=32u64 {
            let budget =
                DEFAULT_WRITER_MEMORY_LIMIT + (threads - 1) * DEFAULT_WRITER_MEMORY_PER_THREAD;
            let resources = WriterResources::default().with_memory_limit(budget);
            let plan =
                ExecutionPlan::with_resources(&settings, [size].into_iter(), &resources).unwrap();
            let member = plan.members()[0];
            assert_eq!(
                member.execution,
                Execution::Blocks {
                    fallback: FallbackReason::AutomaticFilterWorkspace {
                        required: whole_member_routing_workspace(size, &settings),
                        limit: resources.routing_memory_limit(),
                    },
                    run_filters: true,
                }
            );
            assert!(budget / member.admission >= threads);
            match threads {
                8 => assert_eq!(budget / member.workspace, 5),
                32 => assert_eq!(budget / member.workspace, 21),
                _ => {}
            }
        }
    }

    /// The job a default writer plans for one large member at `level`, and
    /// what it is admitted for, with `resources` deciding the plan as a write
    /// would.
    fn default_job(level: u8, solid: bool, resources: &WriterResources) -> (CompressPlan, u64) {
        let features = crate::FeatureSet {
            solid,
            ..crate::FeatureSet::default()
        };
        let options = super::super::WriterOptions::new(crate::ArchiveVersion::Rar50, features)
            .with_compression_level(level);
        let size = 1 << 30;
        let settings = super::super::compression_plan(
            options,
            FilterPolicy::Auto,
            size,
            resources.planning_memory_limit(),
            resources,
        )
        .unwrap();
        let admission = match ExecutionPlan::with_resources(
            &settings,
            [size].into_iter(),
            resources,
        )
        .unwrap()
        {
            ExecutionPlan::Blocks {
                admission,
                run_filters,
                ..
            } => {
                // Level 1 searches no filters.
                assert_eq!(run_filters, level > 1, "level {level}, solid {solid}");
                admission
            }
            ExecutionPlan::IndependentMembers(members) => {
                assert!(
                    matches!(
                        members[0].execution,
                        Execution::Blocks { run_filters, .. } if run_filters == (level > 1)
                    ),
                    "level {level}, solid {solid}"
                );
                members[0].admission
            }
            ExecutionPlan::Stored => panic!("level {level} stored"),
        };
        (settings, admission)
    }

    /// The default planning budget is the largest admission a default plan
    /// makes, rounded up to a MiB: level 5's, at its fitted 16 MiB dictionary
    /// with filters searched. If that charge moves, this fails until the
    /// constant follows it. The one-thread default budget is that, or the
    /// routing threshold when it is less.
    #[test]
    fn the_one_thread_default_is_the_largest_default_admission() {
        const MIB: u64 = 1024 * 1024;
        let resources = WriterResources::with_default_planning(DEFAULT_WRITER_MEMORY_LIMIT);
        let mut largest = (0, 0);
        for level in 1..=5 {
            for solid in [false, true] {
                let (_, admission) = default_job(level, solid, &resources);
                largest = largest.max((admission, level));
            }
        }
        assert_eq!(largest.1, 5);
        assert_eq!(
            largest.0.next_multiple_of(MIB),
            DEFAULT_WRITER_PLANNING_LIMIT
        );
        assert_eq!(
            DEFAULT_WRITER_MEMORY_LIMIT,
            DEFAULT_WRITER_PLANNING_LIMIT.max(resources.routing_memory_limit())
        );
    }

    #[test]
    fn one_default_thread_admits_a_level_5_job_unclamped() {
        let resources = WriterResources::with_default_planning(DEFAULT_WRITER_MEMORY_LIMIT);
        let (settings, admission) = default_job(5, false, &resources);
        assert_eq!(settings.dictionary_size, 16 * 1024 * 1024);
        assert!(admission <= resources.memory_limit());
        let permit = resources
            .try_acquire_serialising(admission)
            .unwrap()
            .expect("an idle budget admits the job");
        assert_eq!(permit.bytes(), admission);
        drop(permit);

        let tight = WriterResources::default().with_memory_limit(admission - 1);
        let (planned, charge) = default_job(5, false, &tight);
        assert_eq!(planned.dictionary_size, settings.dictionary_size / 2);
        assert!(charge <= tight.memory_limit());
    }

    #[test]
    fn default_planning_keeps_the_whole_member_threshold() {
        const MIB: u64 = 1024 * 1024;
        let resources = WriterResources::with_default_planning(DEFAULT_WRITER_MEMORY_LIMIT);
        let (settings, _) = default_job(3, false, &resources);
        let size = 8 * MIB;
        let required = whole_member_routing_workspace(size, &settings);
        assert!(required > 256 * MIB);
        let default_with_limit = resources.with_memory_limit(DEFAULT_WRITER_MEMORY_LIMIT);
        for resources in [WriterResources::default(), default_with_limit] {
            let plan =
                ExecutionPlan::with_resources(&settings, [size].into_iter(), &resources).unwrap();
            assert_eq!(
                plan.members()[0].execution,
                Execution::Blocks {
                    fallback: FallbackReason::AutomaticFilterWorkspace {
                        required,
                        limit: 256 * MIB,
                    },
                    run_filters: true,
                }
            );
        }
        let custom = ExecutionPlan::new(&settings, [size].into_iter(), required);
        assert_eq!(custom.members()[0].execution, Execution::WholeMember);
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
