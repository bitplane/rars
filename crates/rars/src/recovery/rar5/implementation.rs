use super::checksum::{crc64_update, CRC64_XZ_INIT};
#[cfg(test)]
use super::{crc64_rar_state, crc64_xz};
use super::{Error, Result};

use crate::codec::workspace::{Allowance, Budget, Buffer};
const FIELD_SIZE: usize = 65_535;
const FIELD_MASK: u32 = 0xffff;
const PRIMITIVE_POLYNOMIAL: u32 = 0x1100b;
const ZERO_LOG_SENTINEL: u32 = (FIELD_SIZE * 2) as u32;
const MAX_WINRAR602_DATA_SHARDS: u64 = 200;
const KIB: u64 = 1024;
const RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE: u64 = 0x48;
/// Resident parity a record rebuild may allocate. The archive itself is
/// already in memory by the time a rebuild starts, so this bounds the extra.
const MAX_REBUILD_PARITY_BYTES: u64 = 256 * 1024 * 1024;
/// Solve/reconstruction allocations and resident rebuild workspace a repair
/// may admit however small its input. Input and parsed record storage, shared
/// GF tables, final collected archive output, allocator overhead and control
/// storage are outside this bound.
const REPAIR_WORKSPACE_FLOOR_BYTES: u64 = 256 * 1024 * 1024;
/// Genuine geometry needs about twice the bytes it was given: damaged shards
/// are bounded by the parity supplied for them, and padding by the data. Only
/// a record declaring far more than it carries can exceed this multiple.
const REPAIR_WORKSPACE_INPUT_FACTOR: u64 = 4;

fn repair_workspace_limit(input_bytes: u64) -> u64 {
    REPAIR_WORKSPACE_FLOOR_BYTES.max(input_bytes.saturating_mul(REPAIR_WORKSPACE_INPUT_FACTOR))
}

fn repair_workspace_sum(parts: &[u64]) -> Result<u64> {
    parts.iter().try_fold(0u64, |total, &bytes| {
        total.checked_add(bytes).ok_or(Error::PlanOverflow)
    })
}

fn repair_workspace_product(count: u64, width: u64) -> Result<u64> {
    count.checked_mul(width).ok_or(Error::PlanOverflow)
}

fn admit_repair_workspace(required: u64, input_bytes: u64) -> Result<()> {
    admit_repair_workspace_with_limit(required, repair_workspace_limit(input_bytes))
}

fn admit_repair_workspace_with_limit(required: u64, limit: u64) -> Result<()> {
    if required > limit {
        return Err(Error::RepairWorkspaceLimitExceeded { limit, required });
    }
    Ok(())
}

/// Count a conservative sum, rather than requiring individual vectors to fit.
/// Inversion holds the original equations, a working copy and the inverse at
/// once. RHS rows and pivot copies are counted too, together with returned
/// shard buffers and their descriptors. Metadata is small but
/// counted using the maximum growth of the damaged-index vector.
fn repair_solve_workspace_required(
    data_count: usize,
    damaged_count: usize,
    shard_len: usize,
    output_bytes: u64,
    read_scratch: usize,
) -> Result<u64> {
    let data_count = data_count as u64;
    let damaged_count = damaged_count as u64;
    let matrix_cells = repair_workspace_product(damaged_count, damaged_count)?;
    let row_descriptors = (6 * std::mem::size_of::<Vec<u16>>()
        + std::mem::size_of::<(std::ops::Range<usize>, Vec<u8>)>()
        + 4 * std::mem::size_of::<u16>()) as u64;
    let metadata = (std::mem::size_of::<Vec<u8>>()
        + 2 * std::mem::size_of::<usize>()
        + std::mem::size_of::<bool>()) as u64;
    repair_workspace_sum(&[
        repair_workspace_product(matrix_cells, 3 * std::mem::size_of::<u16>() as u64)?,
        repair_workspace_product(damaged_count, shard_len as u64)?,
        repair_workspace_product(damaged_count, row_descriptors)?,
        repair_workspace_product(data_count, metadata)?,
        output_bytes,
        read_scratch as u64,
    ])
}

use crate::progress::ProgressReporter;
use crate::{WriteOperation, WriteProgressEvent};

fn shared_gf16() -> &'static Gf16 {
    static GF16: std::sync::OnceLock<Gf16> = std::sync::OnceLock::new();
    GF16.get_or_init(Gf16::new)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct InlineRecoveryPlan {
    pub data_shards: u64,
    pub recovery_shards: u64,
    pub group_count: u64,
    pub header_size: u64,
    pub shard_size: u64,
}

impl InlineRecoveryPlan {
    pub fn payload_size(self) -> Result<u64> {
        self.recovery_shards
            .checked_mul(self.shard_size)
            .ok_or(Error::PlanOverflow)
    }
}

pub fn plan_inline_recovery(
    archive_size: u64,
    recovery_percent: u64,
) -> Result<InlineRecoveryPlan> {
    let pct = recovery_percent.min(100);
    let data_shards = if archive_size >= 200 * KIB {
        MAX_WINRAR602_DATA_SHARDS
    } else {
        archive_size.div_ceil(KIB).max(1)
    };
    let mut recovery_shards = (2 * pct * data_shards) / 200;
    recovery_shards = recovery_shards.min(data_shards);
    if recovery_shards == 0 && archive_size < 200 * KIB {
        recovery_shards = 1;
    }
    let mut group_count = archive_size.div_ceil(data_shards);
    group_count += group_count & 1;
    // data_shards is capped at 200 and group_count is at most
    // ceil(size / 200) + 1 for large inputs, so both additions fit at u64::MAX.
    let header_size = data_shards * 8 + RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE;
    let shard_size = header_size + group_count;

    Ok(InlineRecoveryPlan {
        data_shards,
        recovery_shards,
        group_count,
        header_size,
        shard_size,
    })
}

pub fn split_prefix_shard_ranges(
    prefix_len: usize,
    plan: InlineRecoveryPlan,
) -> Result<Vec<std::ops::Range<usize>>> {
    let data_shards = usize::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
    let group_count = usize::try_from(plan.group_count).map_err(|_| Error::PlanOverflow)?;
    let capacity = data_shards
        .checked_mul(group_count)
        .ok_or(Error::PlanOverflow)?;
    if prefix_len > capacity {
        return Err(Error::PrefixExceedsPlan);
    }

    let mut ranges = Vec::with_capacity(data_shards);
    for shard_index in 0..data_shards {
        // Every shard index is below data_shards, whose full product with
        // group_count was admitted above.
        let start = (shard_index * group_count).min(prefix_len);
        let end = start.saturating_add(group_count).min(prefix_len);
        ranges.push(start..end);
    }
    Ok(ranges)
}

pub fn split_prefix_shards(prefix: &[u8], plan: InlineRecoveryPlan) -> Result<Vec<Vec<u8>>> {
    let group_count = usize::try_from(plan.group_count).map_err(|_| Error::PlanOverflow)?;
    let ranges = split_prefix_shard_ranges(prefix.len(), plan)?;
    let mut shards = Vec::with_capacity(ranges.len());
    for range in ranges {
        let mut shard = vec![0u8; group_count];
        if range.start < range.end {
            shard[..range.end - range.start].copy_from_slice(&prefix[range]);
        }
        shards.push(shard);
    }
    Ok(shards)
}

pub fn encode_inline_recovery_parity(
    archive_prefix: &[u8],
    recovery_percent: u64,
) -> Result<(InlineRecoveryPlan, Vec<Vec<u8>>)> {
    let plan = plan_inline_recovery(archive_prefix.len() as u64, recovery_percent)?;
    let shards = split_prefix_shards(archive_prefix, plan)?;
    let shard_refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
    // Planning caps recovery_shards at 200.
    let parity = encode_parity_shards(&shard_refs, plan.recovery_shards as usize)?;
    Ok((plan, parity))
}

pub fn build_structural_inline_recovery_data(
    archive_prefix: &[u8],
    recovery_percent: u64,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    build_streamed_inline_recovery(
        &mut std::io::Cursor::new(archive_prefix),
        archive_prefix.len() as u64,
        recovery_percent,
        RecoveryMemoryMode::Resident,
        None,
        &mut out,
        None,
        1,
    )?;
    Ok(out)
}

/// Builds recovery payload bytes with the geometry of `plan`, so a record
/// rebuilt during repair keeps the shape the archive was written with.
#[cfg(test)]
pub(crate) fn build_inline_recovery_data_for_plan(
    archive_prefix: &[u8],
    plan: InlineRecoveryPlan,
) -> Result<Vec<u8>> {
    build_inline_recovery_data_for_plan_with_control(
        archive_prefix,
        plan,
        &crate::read_control::ReadControl::default(),
    )
}

pub(crate) fn build_inline_recovery_data_for_plan_with_control(
    archive_prefix: &[u8],
    plan: InlineRecoveryPlan,
    control: &crate::read_control::ReadControl,
) -> Result<Vec<u8>> {
    check_repair(control)?;
    let mut out = Vec::new();
    build_streamed_inline_recovery_for_plan(
        &mut control.reader(std::io::Cursor::new(archive_prefix)),
        archive_prefix.len() as u64,
        plan,
        RecoveryMemoryMode::Resident,
        None,
        &mut out,
        None,
        1,
    )
    .map_err(|error| {
        if matches!(
            control.finish::<()>(Err(error.clone().into())),
            Err(crate::Error::Cancelled)
        ) {
            Error::Cancelled
        } else {
            error
        }
    })?;
    check_repair(control)?;
    Ok(out)
}

/// Read buffer size for streaming recovery passes. Even, so words never
/// straddle a chunk boundary.
pub(crate) const RECOVERY_IO_BLOCK: usize = 256 * 1024;
/// Striped mode never claims more than this, however large the budget is.
#[cfg(any(test, feature = "write"))]
const STRIPE_BUDGET_CAP: u64 = 64 * 1024 * 1024;
/// Below this a stripe pass seeks far more than it reads, so rather than
/// thrash we report what striping would actually cost and let the caller
/// refuse the job.
#[cfg(any(test, feature = "write"))]
const MIN_STRIPE_LEN: u64 = 4 * 1024;

/// How a recovery pass holds parity while it works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryMemoryMode {
    /// Every parity row stays in memory and the body is read straight
    /// through. Needs `recovery_shards * group_count` bytes.
    Resident,
    /// Parity is built one column stripe at a time and spilled to scratch
    /// storage, so memory is bounded regardless of archive size. Costs one
    /// seek per data shard per stripe.
    // Reader repair uses resident parity; writers select bounded stripes.
    #[cfg_attr(not(any(test, feature = "write")), expect(dead_code))]
    Striped { stripe_len: usize },
}

/// Picks a memory mode for `plan` under `memory_limit`, returning the mode and
/// the number of bytes the caller should reserve for it.
#[cfg(any(test, feature = "write"))]
pub(crate) fn choose_recovery_memory_mode(
    plan: InlineRecoveryPlan,
    memory_limit: u64,
) -> Result<(RecoveryMemoryMode, u64)> {
    let parity_bytes = plan
        .recovery_shards
        .checked_mul(plan.group_count)
        .ok_or(Error::PlanOverflow)?;
    let resident_bytes = parity_bytes.saturating_add(RECOVERY_IO_BLOCK as u64);
    if resident_bytes <= memory_limit {
        return Ok((RecoveryMemoryMode::Resident, resident_bytes));
    }

    // One buffer per parity row plus one for the data being read.
    let rows = plan.recovery_shards.saturating_add(1).max(1);
    let budget = memory_limit.min(STRIPE_BUDGET_CAP);
    let mut stripe_len = (budget / rows).min(plan.group_count) & !1;
    if stripe_len < MIN_STRIPE_LEN {
        stripe_len = MIN_STRIPE_LEN.min(plan.group_count.max(2));
    }
    stripe_len = stripe_len.max(2);
    // The budget caps this width at 64 MiB on every supported host.
    let stripe_len_usize = stripe_len as usize;
    let required = rows.saturating_mul(stripe_len);
    Ok((
        RecoveryMemoryMode::Striped {
            stripe_len: stripe_len_usize,
        },
        required,
    ))
}

/// Choose a phase geometry from actual managed capacity as well as the legacy
/// workspace policy. Both parity construction and later chunk framing must fit.
#[cfg(any(test, feature = "write"))]
pub(crate) fn choose_recovery_capacity_mode(
    plan: InlineRecoveryPlan,
    memory_limit: u64,
    allowance: &crate::codec::workspace::Limited,
) -> Result<(RecoveryMemoryMode, u64)> {
    use crate::codec::workspace::Limited;
    let rows = plan.recovery_shards;
    let descriptor = std::mem::size_of::<Buffer<u8, Limited>>() as u64;
    let fixed = rows
        .saturating_mul(descriptor)
        .saturating_add(rows.saturating_mul(plan.data_shards).saturating_mul(2))
        .saturating_add(plan.data_shards.saturating_mul(8));
    let io = plan.group_count.max(1).min(RECOVERY_IO_BLOCK as u64);
    let framing = fixed.saturating_add(io).saturating_add(plan.header_size);
    let parity_descriptors = rows.saturating_mul(descriptor);
    let resident = framing
        .saturating_add(parity_descriptors)
        .saturating_add(rows.saturating_mul(plan.group_count));
    let (legacy_mode, legacy_required) = choose_recovery_memory_mode(plan, memory_limit)?;
    if matches!(legacy_mode, RecoveryMemoryMode::Resident) && resident <= allowance.available() {
        return Ok((RecoveryMemoryMode::Resident, legacy_required));
    }
    let stripe_fixed = fixed.saturating_add(parity_descriptors);
    let minimum =
        framing.max(stripe_fixed.saturating_add(rows.saturating_add(1).saturating_mul(2)));
    allowance.check_capacity(minimum)?;
    let width = allowance
        .available()
        .saturating_sub(stripe_fixed)
        .min(memory_limit.min(STRIPE_BUDGET_CAP))
        / rows.saturating_add(1);
    let stripe_len = width.min(plan.group_count).max(2) & !1;
    Ok((
        RecoveryMemoryMode::Striped {
            stripe_len: stripe_len as usize,
        },
        rows.saturating_add(1).saturating_mul(stripe_len),
    ))
}

/// What a streaming recovery pass produced, so the caller can frame the
/// service block around the payload it just wrote.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamedRecoveryOutput {
    #[cfg_attr(not(any(test, feature = "write")), expect(dead_code))]
    pub(crate) plan: InlineRecoveryPlan,
    #[cfg_attr(not(any(test, feature = "write")), expect(dead_code))]
    pub(crate) payload_len: u64,
    #[cfg_attr(not(any(test, feature = "write")), expect(dead_code))]
    pub(crate) payload_crc32: u32,
}

pub(crate) trait ReadSeek: std::io::Read + std::io::Seek {}
impl<T: std::io::Read + std::io::Seek> ReadSeek for T {}

pub(crate) trait ReadWriteSeek: std::io::Read + std::io::Write + std::io::Seek {}
impl<T: std::io::Read + std::io::Write + std::io::Seek> ReadWriteSeek for T {}

/// Builds the inline recovery payload for `body` and writes it to `sink`.
///
/// The body is read exactly once to build parity, then each parity row is
/// framed into a `{RB}` chunk. Output is byte-identical to computing the whole
/// thing in memory; only the working set differs.
///
/// `parity_scratch` must be supplied for [`RecoveryMemoryMode::Striped`] and
/// is where partial parity lives between stripes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_streamed_inline_recovery(
    body: &mut dyn ReadSeek,
    body_len: u64,
    recovery_percent: u64,
    mode: RecoveryMemoryMode,
    parity_scratch: Option<&mut dyn ReadWriteSeek>,
    sink: &mut dyn std::io::Write,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
) -> Result<StreamedRecoveryOutput> {
    let plan = plan_inline_recovery(body_len, recovery_percent)?;
    build_streamed_inline_recovery_for_plan(
        body,
        body_len,
        plan,
        mode,
        parity_scratch,
        sink,
        progress,
        pass,
    )
}

/// Same as [`build_streamed_inline_recovery`] with the geometry supplied
/// rather than derived from a percentage.
///
/// Repair needs this: WinRAR accepts recovery percentages up to 1000%, which
/// [`plan_inline_recovery`] never produces, so a record rebuilt from surviving
/// chunks has to take its geometry from those chunks.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_streamed_inline_recovery_for_plan(
    body: &mut dyn ReadSeek,
    body_len: u64,
    plan: InlineRecoveryPlan,
    mode: RecoveryMemoryMode,
    parity_scratch: Option<&mut dyn ReadWriteSeek>,
    sink: &mut dyn std::io::Write,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
) -> Result<StreamedRecoveryOutput> {
    streamed_recovery_with_allowance(
        body,
        body_len,
        plan,
        mode,
        parity_scratch,
        sink,
        progress,
        pass,
        &Allowance::default(),
    )
}

/// Checks that [`streamed_recovery_with_allowance`] can write `plan`, and
/// returns its payload size.
///
/// A chunk header stores the shard size in 32 bits and the shard counts in
/// 16. With 200 data shards, the shard size caps what one record protects at
/// 858,993,124,400 bytes. A writer checks this when it lays out the archive,
/// before any of it is written.
pub(crate) fn check_streamable_plan(plan: InlineRecoveryPlan) -> Result<u64> {
    let payload_len = plan.payload_size()?;
    if plan.header_size
        != RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE
            .checked_add(plan.data_shards.checked_mul(8).ok_or(Error::PlanOverflow)?)
            .ok_or(Error::PlanOverflow)?
    {
        return Err(Error::PlanOverflow);
    }
    if plan.shard_size
        != plan
            .header_size
            .checked_add(plan.group_count)
            .ok_or(Error::PlanOverflow)?
    {
        return Err(Error::PlanOverflow);
    }
    u32::try_from(plan.shard_size).map_err(|_| Error::PlanOverflow)?;
    u16::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
    u16::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?;
    Ok(payload_len)
}

/// The most bytes one streamed recovery record protects: 200 data shards of
/// `u32::MAX` bytes less the chunk header, with the group count kept even.
#[cfg(test)]
pub(crate) const MAX_STREAMED_RECOVERY_PREFIX: u64 = MAX_WINRAR602_DATA_SHARDS
    * ((u32::MAX as u64 - (RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE + 8 * MAX_WINRAR602_DATA_SHARDS))
        & !1);

#[allow(clippy::too_many_arguments)]
pub(crate) fn streamed_recovery_with_allowance<B: Budget>(
    body: &mut dyn ReadSeek,
    body_len: u64,
    plan: InlineRecoveryPlan,
    mode: RecoveryMemoryMode,
    parity_scratch: Option<&mut dyn ReadWriteSeek>,
    sink: &mut dyn std::io::Write,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
    allowance: &B,
) -> Result<StreamedRecoveryOutput> {
    check_recovery_cancelled(progress)?;
    // Fail on unrepresentable geometry before doing any work.
    let payload_len = check_streamable_plan(plan)?;
    // The check admitted every one of these narrowings, and shard_size >=
    // header_size.
    let total_size = plan.shard_size as u32;
    let header_size_u32 = plan.header_size as u32;
    let data_shards_u16 = plan.data_shards as u16;
    let recovery_shards_u16 = plan.recovery_shards as u16;
    // Both shard counts fit u16; group_count and header_size are bounded by
    // the admitted u32 shard_size. All four fit native usize, including i386.
    let data_shards = plan.data_shards as usize;
    let recovery_shards = plan.recovery_shards as usize;
    let group_count = plan.group_count as usize;
    let header_size = plan.header_size as usize;
    if body_len > plan.group_count.saturating_mul(plan.data_shards) {
        return Err(Error::PrefixExceedsPlan);
    }

    if let Some(progress) = progress {
        progress.report(WriteProgressEvent::OperationStarted {
            operation: WriteOperation::Recovery,
            total_bytes: Some(payload_len),
            total_entries: None,
            pass,
        });
    }

    // Phase A budget is the parity bytes; phase B adds the chunk headers.
    // group_count <= shard_size and payload_size admitted the product of
    // recovery_shards and shard_size above.
    let encode_units = plan.recovery_shards * plan.group_count;
    let report = |completed: u64| {
        check_recovery_cancelled(progress)?;
        if let Some(progress) = progress {
            progress.report(WriteProgressEvent::Advanced {
                operation: WriteOperation::Recovery,
                completed_bytes: completed.min(payload_len),
                total_bytes: payload_len,
                pass,
            });
        }
        check_recovery_cancelled(progress)
    };

    check_recovery_cancelled(progress)?;
    let field = shared_gf16();
    let gf = field.view();
    let matrix = encoder_matrix_with_allowance(data_shards, recovery_shards, &gf, allowance)?;
    let mut shard_states = Buffer::filled(data_shards, 0u64, allowance)?;

    let mut rows = match mode {
        RecoveryMemoryMode::Resident => {
            let parity = encode_parity_resident(
                body,
                body_len,
                &plan,
                &matrix,
                &mut shard_states,
                encode_units,
                &report,
                allowance,
            )?;
            ParityRows::Resident(parity)
        }
        RecoveryMemoryMode::Striped { stripe_len } => {
            let scratch = parity_scratch.ok_or(Error::PlanOverflow)?;
            encode_parity_striped(
                body,
                body_len,
                &plan,
                &matrix,
                &mut shard_states,
                stripe_len,
                scratch,
                encode_units,
                &report,
                allowance,
            )?;
            ParityRows::Spooled {
                scratch,
                group_count: plan.group_count,
            }
        }
    };

    // Every chunk repeats the CRC state of parity row 0, so it has to be
    // known before the first chunk can be framed.
    let mut buffer = Buffer::filled(RECOVERY_IO_BLOCK.min(group_count.max(1)), 0u8, allowance)?;
    let mut final_state = 0u64;
    rows.for_each_chunk(0, &mut buffer, |chunk| {
        final_state = crc64_update(chunk, final_state);
    })?;

    let chunk_data_extent = body_len
        .saturating_sub(
            plan.group_count
                .saturating_mul(plan.data_shards.saturating_sub(1)),
        )
        .min(plan.group_count);
    // The extent cannot exceed group_count, already bounded by shard_size.
    let chunk_data_extent_u32 = chunk_data_extent as u32;

    let mut payload_crc32 = crate::crc32::Crc32::new();
    let mut written = 0u64;
    for shard_index in 0..recovery_shards {
        check_recovery_cancelled(progress)?;
        let mut header = Buffer::filled(header_size, 0u8, allowance)?;
        // The validated header size is exactly 0x48 + 8 * data_shards.
        // Writing its fields directly removes impossible short writes to a
        // fixed-size in-memory Cursor while retaining the RAR wire layout.
        header[0x00..0x04].copy_from_slice(b"{RB}");
        header[0x0c..0x10].copy_from_slice(&total_size.to_le_bytes());
        header[0x10..0x14].copy_from_slice(&header_size_u32.to_le_bytes());
        header[0x14] = 1;
        header[0x15] = 1;
        header[0x1e..0x22].copy_from_slice(&chunk_data_extent_u32.to_le_bytes());
        header[0x22..0x2a].copy_from_slice(&body_len.to_le_bytes());
        header[0x2a..0x32].copy_from_slice(&plan.group_count.to_le_bytes());
        header[0x32..0x3a].copy_from_slice(&plan.shard_size.to_le_bytes());
        header[0x3a..0x3c].copy_from_slice(&data_shards_u16.to_le_bytes());
        header[0x3c..0x3e].copy_from_slice(&recovery_shards_u16.to_le_bytes());
        header[0x3e..0x40].copy_from_slice(&(shard_index as u16).to_le_bytes());
        for (index, &state) in shard_states.iter().enumerate() {
            header[0x40 + index * 8..0x48 + index * 8].copy_from_slice(&state.to_le_bytes());
        }
        header[header_size - 8..].copy_from_slice(&final_state.to_le_bytes());
        // The chunk CRC covers everything from 0x0c onwards, so compute it
        // over the header and the parity row before either is emitted.
        let mut chunk_crc = crc64_update(&header[0x0c..], CRC64_XZ_INIT);
        rows.for_each_chunk(shard_index, &mut buffer, |chunk| {
            chunk_crc = crc64_update(chunk, chunk_crc);
        })?;
        header[0x04..0x0c].copy_from_slice(&(chunk_crc ^ CRC64_XZ_INIT).to_le_bytes());

        sink.write_all(&header)?;
        payload_crc32.update(&header);
        written += header.len() as u64;

        let mut sink_error = None;
        rows.for_each_chunk(shard_index, &mut buffer, |chunk| {
            if sink_error.is_some() {
                return;
            }
            if let Err(error) = sink.write_all(chunk) {
                sink_error = Some(error);
                return;
            }
            payload_crc32.update(chunk);
        })?;
        if let Some(error) = sink_error {
            return Err(error.into());
        }
        written += plan.group_count;

        report(encode_units + (shard_index as u64 + 1) * plan.header_size)?;
    }

    debug_assert_eq!(written, payload_len);
    if let Some(progress) = progress {
        progress.report(WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Recovery,
            total_bytes: Some(payload_len),
            total_entries: None,
            pass,
        });
    }

    Ok(StreamedRecoveryOutput {
        plan,
        payload_len,
        payload_crc32: payload_crc32.finish(),
    })
}

fn check_recovery_cancelled(progress: Option<ProgressReporter<'_>>) -> Result<()> {
    if progress.is_some_and(ProgressReporter::is_cancelled) {
        return Err(Error::Cancelled);
    }
    Ok(())
}

fn rows_with_allowance<B: Budget>(
    rows: usize,
    width: usize,
    allowance: &B,
) -> Result<Buffer<Buffer<u8, B>, B>> {
    let mut out = Buffer::with_capacity(rows, allowance)?;
    for _ in 0..rows {
        out.push_admitted(Buffer::filled(width, 0u8, allowance)?);
    }
    Ok(out)
}

fn encoder_matrix_with_allowance<B: Budget>(
    data_shards: usize,
    recovery_shards: usize,
    gf: &GfView<'_>,
    allowance: &B,
) -> Result<Buffer<Buffer<u16, B>, B>> {
    if data_shards == 0
        || recovery_shards == 0
        || data_shards
            .checked_add(recovery_shards)
            .is_none_or(|sum| sum > FIELD_SIZE)
    {
        return Err(Error::TooManyShards);
    }
    let mut matrix = Buffer::with_capacity(recovery_shards, allowance)?;
    for i in 0..recovery_shards {
        let mut row = Buffer::filled(data_shards, 0u16, allowance)?;
        for (j, cell) in row.iter_mut().enumerate() {
            *cell = gf.inv(((i + data_shards) ^ j) as u16)?;
        }
        matrix.push_admitted(row);
    }
    Ok(matrix)
}

/// Parity rows, wherever they happen to live.
enum ParityRows<'a, B: Budget> {
    Resident(Buffer<Buffer<u8, B>, B>),
    Spooled {
        scratch: &'a mut dyn ReadWriteSeek,
        group_count: u64,
    },
}

impl<B: Budget> ParityRows<'_, B> {
    /// Feeds row `index` to `visit` in buffer-sized pieces.
    fn for_each_chunk(
        &mut self,
        index: usize,
        buffer: &mut [u8],
        mut visit: impl FnMut(&[u8]),
    ) -> Result<()> {
        match self {
            Self::Resident(rows) => {
                let row = &rows[index];
                if !row.is_empty() {
                    visit(row);
                }
                Ok(())
            }
            Self::Spooled {
                scratch,
                group_count,
            } => {
                // The admitted payload contains every recovery row, and the
                // caller supplies only row zero or an in-range shard index.
                let start = index as u64 * *group_count;
                scratch.seek(std::io::SeekFrom::Start(start))?;
                let mut remaining = *group_count;
                while remaining != 0 {
                    let want = remaining.min(buffer.len() as u64) as usize;
                    scratch.read_exact(&mut buffer[..want])?;
                    visit(&buffer[..want]);
                    remaining -= want as u64;
                }
                Ok(())
            }
        }
    }
}

/// Accumulates `coefficient * source` into `destination` over GF(2^16).
///
/// A trailing odd byte is treated as the low half of a word whose high half is
/// the zero padding every shard carries.
fn accumulate_scaled(destination: &mut [u8], source: &[u8], coefficient: u16) {
    if coefficient == 0 {
        return;
    }
    debug_assert!(destination.len() >= source.len().next_multiple_of(2));
    let mut tables = [[0u16; 256]; 2];
    fill_scale_tables(&mut tables, coefficient);
    let [low, high] = &tables;
    let (words, tail) = source.as_chunks::<2>();
    for (target, word) in destination.as_chunks_mut::<2>().0.iter_mut().zip(words) {
        let product = low[word[0] as usize] ^ high[word[1] as usize];
        target[0] ^= product as u8;
        target[1] ^= (product >> 8) as u8;
    }
    if let [tail] = tail {
        let product = low[*tail as usize];
        let offset = source.len() - 1;
        destination[offset] ^= product as u8;
        destination[offset + 1] ^= (product >> 8) as u8;
    }
}

/// Two byte-indexed tables replace a log and exp lookup per word: `c * x == lo[x & 0xff] ^ hi[x >> 8]`.
fn fill_scale_tables(tables: &mut [[u16; 256]; 2], coefficient: u16) {
    let mut product = u32::from(coefficient);
    for table in tables.iter_mut() {
        table[0] = 0;
        for bit in 0..8 {
            // Multiplication is linear over GF(2), so setting `bit` adds its
            // product to every entry below it.
            let (lower, upper) = table.split_at_mut(1 << bit);
            for (entry, base) in upper[..lower.len()].iter_mut().zip(lower.iter()) {
                *entry = base ^ product as u16;
            }
            product = times_x(product);
        }
    }
}

/// Several tasks per worker, so a slow core holds up a pass by one small task.
const PARITY_TASKS_PER_WORKER: usize = 4;

/// Parity bytes (source bytes times rows) below which waking another worker costs more than it saves.
const MIN_PARITY_WORK_PER_WORKER: usize = if cfg!(test) { 64 } else { 16 * 1024 };

/// Returns `(workers, column width)`; `None` keeps the work on this thread.
fn parity_work_split(
    rows: usize,
    threads: usize,
    span: usize,
    min_work_per_worker: usize,
) -> Option<(usize, usize)> {
    let workers = threads.min(span.saturating_mul(rows) / min_work_per_worker.max(1));
    if workers <= 1 || rows == 0 {
        return None;
    }
    let chunks = (workers * PARITY_TASKS_PER_WORKER).div_ceil(rows);
    // Even widths keep every chunk on whole 16-bit symbols.
    Some((workers, span.div_ceil(chunks).next_multiple_of(2).min(span)))
}

/// A refused task list leaves the work on this thread rather than failing the write.
fn accumulate_shard<B: Budget>(
    parity: &mut [Buffer<u8, B>],
    offset: usize,
    source: &[u8],
    matrix: &[Buffer<u16, B>],
    shard_index: usize,
    allowance: &B,
) {
    let threads = if crate::parallel::may_nest() {
        crate::parallel::threads()
    } else {
        1
    };
    let tasks = parity_work_split(
        parity.len(),
        threads,
        source.len(),
        MIN_PARITY_WORK_PER_WORKER,
    )
    .and_then(|(workers, width)| {
        let chunks = source.len().div_ceil(width);
        let tasks = Buffer::with_capacity(parity.len() * chunks, allowance).ok()?;
        Some((workers, width, tasks))
    });
    let Some((workers, width, mut tasks)) = tasks else {
        for (row, parity_row) in matrix.iter().zip(parity.iter_mut()) {
            accumulate_scaled(&mut parity_row[offset..], source, row[shard_index]);
        }
        return;
    };
    for (row, parity_row) in matrix.iter().zip(parity.iter_mut()) {
        let mut rest = &mut parity_row[offset..];
        let mut start = 0;
        while start < source.len() {
            let end = (start + width).min(source.len());
            // The last chunk keeps the rest of the row, where an odd tail's
            // zero-padded high byte lands.
            let destination = if end == source.len() {
                std::mem::take(&mut rest)
            } else {
                let (destination, tail) = std::mem::take(&mut rest).split_at_mut(width);
                rest = tail;
                destination
            };
            tasks.push_admitted(std::sync::Mutex::new((
                destination,
                start..end,
                row[shard_index],
            )));
            start = end;
        }
    }
    // Workers stay within the thread cap and pull tasks rather than splitting them up front.
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut workers = vec![(); workers.min(tasks.len())];
    crate::parallel::for_each_mut(&mut workers, |_, _| loop {
        let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some(task) = tasks.get(index) else {
            return;
        };
        let mut task = task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (destination, columns, coefficient) = &mut *task;
        accumulate_scaled(destination, &source[columns.clone()], *coefficient);
    });
}

/// Single forward pass over the body, holding every parity row in memory.
#[allow(clippy::too_many_arguments)]
fn encode_parity_resident<B: Budget>(
    body: &mut dyn ReadSeek,
    body_len: u64,
    plan: &InlineRecoveryPlan,
    matrix: &[Buffer<u16, B>],
    shard_states: &mut [u64],
    encode_units: u64,
    report: &dyn Fn(u64) -> Result<()>,
    allowance: &B,
) -> Result<Buffer<Buffer<u8, B>, B>> {
    // The streaming entry point admitted these as native-size values.
    let group_count = plan.group_count as usize;
    let recovery_shards = plan.recovery_shards as usize;
    let mut parity = rows_with_allowance(recovery_shards, group_count, allowance)?;
    if group_count == 0 || body_len == 0 {
        return Ok(parity);
    }

    let mut buffer = Buffer::filled(RECOVERY_IO_BLOCK.min(group_count), 0u8, allowance)?;
    body.seek(std::io::SeekFrom::Start(0))?;

    let mut consumed = 0u64;
    for (shard_index, state) in shard_states.iter_mut().enumerate() {
        // The wire limits admit at most u16::MAX data shards of u32-sized
        // groups, so every data-shard offset fits u64.
        let shard_start = shard_index as u64 * plan.group_count;
        if shard_start >= body_len {
            break;
        }
        let shard_bytes = plan.group_count.min(body_len - shard_start);

        let mut offset = 0u64;
        while offset < shard_bytes {
            let want = (shard_bytes - offset).min(buffer.len() as u64) as usize;
            body.read_exact(&mut buffer[..want])?;
            *state = crc64_update(&buffer[..want], *state);

            accumulate_shard(
                &mut parity,
                offset as usize,
                &buffer[..want],
                matrix,
                shard_index,
                allowance,
            );

            offset += want as u64;
            consumed += want as u64;
            report(scaled_progress(consumed, body_len, encode_units))?;
        }
    }

    Ok(parity)
}

/// Column-stripe pass: bounded memory, one seek per data shard per stripe,
/// and the body still read exactly once in total.
#[allow(clippy::too_many_arguments)]
fn encode_parity_striped<B: Budget>(
    body: &mut dyn ReadSeek,
    body_len: u64,
    plan: &InlineRecoveryPlan,
    matrix: &[Buffer<u16, B>],
    shard_states: &mut [u64],
    stripe_len: usize,
    scratch: &mut dyn ReadWriteSeek,
    encode_units: u64,
    report: &dyn Fn(u64) -> Result<()>,
    allowance: &B,
) -> Result<()> {
    let recovery_shards = plan.recovery_shards as usize;
    if plan.group_count == 0 {
        return Ok(());
    }
    let stripe_len = stripe_len.max(2);
    let mut stripe = rows_with_allowance(recovery_shards, stripe_len, allowance)?;
    let mut buffer = Buffer::filled(stripe_len, 0u8, allowance)?;
    let mut consumed = 0u64;

    let mut column = 0u64;
    while column < plan.group_count {
        let width = (plan.group_count - column).min(stripe_len as u64);
        let width_usize = width as usize;
        for row in stripe.iter_mut() {
            row[..width_usize].fill(0);
        }

        for (shard_index, state) in shard_states.iter_mut().enumerate() {
            let shard_start = shard_index as u64 * plan.group_count;
            let shard_bytes = plan.group_count.min(body_len.saturating_sub(shard_start));
            if column >= shard_bytes {
                continue;
            }
            let span = width.min(shard_bytes - column);
            let span_usize = span as usize;

            body.seek(std::io::SeekFrom::Start(shard_start + column))?;
            body.read_exact(&mut buffer[..span_usize])?;
            *state = crc64_update(&buffer[..span_usize], *state);

            accumulate_shard(
                &mut stripe,
                0,
                &buffer[..span_usize],
                matrix,
                shard_index,
                allowance,
            );

            consumed += span;
            report(scaled_progress(consumed, body_len, encode_units))?;
        }

        for (shard_index, stripe_row) in stripe.iter().enumerate() {
            // position is within an admitted row of the complete payload.
            let position = shard_index as u64 * plan.group_count + column;
            scratch.seek(std::io::SeekFrom::Start(position))?;
            scratch.write_all(&stripe_row[..width_usize])?;
        }

        column += width;
    }

    Ok(())
}

fn scaled_progress(consumed: u64, total: u64, units: u64) -> u64 {
    // Both callers report only after consuming body bytes, so total is nonzero.
    ((consumed as u128 * units as u128) / total as u128) as u64
}

#[derive(Debug, Clone)]
struct InlineRecoveryChunk {
    plan: InlineRecoveryPlan,
    protected_size: u64,
    shard_index: usize,
    data_shard_states: Vec<u64>,
    parity: Vec<u8>,
}

#[derive(Debug, Clone)]
struct FoundInlineRecoveryChunk {
    offset: usize,
    chunk: InlineRecoveryChunk,
}

pub fn repair_inline_recovery_prefix(
    archive_prefix: &[u8],
    recovery_data: &[u8],
) -> Result<Vec<u8>> {
    repair_inline_recovery_prefix_with_control(
        archive_prefix,
        recovery_data,
        &crate::read_control::ReadControl::default(),
    )
}

pub(crate) fn repair_inline_recovery_prefix_with_control(
    archive_prefix: &[u8],
    recovery_data: &[u8],
    control: &crate::read_control::ReadControl,
) -> Result<Vec<u8>> {
    check_repair(control)?;
    // The range path keeps empty shards and zero padding virtual. In particular,
    // healthy prefixes must not allocate data_shards * group_count bytes merely
    // because a recovery header describes that much capacity.
    let repaired_shards = repair_inline_recovery_prefix_shards_with_control(
        archive_prefix.len(),
        recovery_data,
        |range| Ok(archive_prefix[range].to_vec()),
        control,
    )?;
    check_repair(control)?;
    let mut repaired = archive_prefix.to_vec();
    for (range, shard) in repaired_shards {
        check_repair(control)?;
        repaired[range].copy_from_slice(&shard);
    }
    Ok(repaired)
}

/// Repair damaged RAR5 inline-recovery data shards without materializing the
/// whole protected prefix.
///
/// `read_range` receives byte ranges relative to the protected prefix and must
/// return the current bytes for each requested range. The returned pairs contain
/// only the damaged prefix ranges that need to be written back.
///
/// An admission ceiling of four times `protected_size` plus the recovery data,
/// and at least 256 MiB, covers solve matrices and their working
/// copies, row descriptors, RHS/pivot/read scratch and returned repaired shard
/// buffers. Input and parsed recovery records, shared field tables, final
/// collected archive output, allocator overhead and control storage are excluded.
/// This is not a process-RAM limit. Oversized solves return
/// [`Error::RepairWorkspaceLimitExceeded`] before allocating their matrices.
/// Requested range scratch is admitted before discovery calls `read_range`;
/// additional allocations made by the caller's callback are outside the ceiling.
pub fn repair_inline_recovery_prefix_shards<F>(
    protected_size: usize,
    recovery_data: &[u8],
    read_range: F,
) -> Result<Vec<(std::ops::Range<usize>, Vec<u8>)>>
where
    F: FnMut(std::ops::Range<usize>) -> Result<Vec<u8>>,
{
    repair_inline_recovery_prefix_shards_with_control(
        protected_size,
        recovery_data,
        read_range,
        &crate::read_control::ReadControl::default(),
    )
}

pub(crate) fn repair_inline_recovery_prefix_shards_with_control<F>(
    protected_size: usize,
    recovery_data: &[u8],
    read_range: F,
    control: &crate::read_control::ReadControl,
) -> Result<Vec<(std::ops::Range<usize>, Vec<u8>)>>
where
    F: FnMut(std::ops::Range<usize>) -> Result<Vec<u8>>,
{
    repair_inline_recovery_prefix_shards_with_workspace_limit(
        protected_size,
        recovery_data,
        read_range,
        control,
        repair_workspace_limit((protected_size as u64).saturating_add(recovery_data.len() as u64)),
    )
}

fn repair_inline_recovery_prefix_shards_with_workspace_limit<F>(
    protected_size: usize,
    recovery_data: &[u8],
    mut read_range: F,
    control: &crate::read_control::ReadControl,
    workspace_limit: u64,
) -> Result<Vec<(std::ops::Range<usize>, Vec<u8>)>>
where
    F: FnMut(std::ops::Range<usize>) -> Result<Vec<u8>>,
{
    let mut poller = control.poller();
    check_repair(control)?;
    let chunks = parse_available_inline_recovery_chunks_with_control(recovery_data, control)?;
    let first = chunks.first().ok_or(Error::BadRecoveryChunk)?;
    if first.protected_size != protected_size as u64 {
        return Err(Error::BadRecoveryChunk);
    }
    if chunks.iter().any(|chunk| {
        chunk.plan != first.plan
            || chunk.protected_size != first.protected_size
            || chunk.data_shard_states != first.data_shard_states
    }) {
        return Err(Error::BadRecoveryChunk);
    }

    let plan = first.plan;
    let shard_len = usize::try_from(plan.group_count).map_err(|_| Error::PlanOverflow)?;
    let shard_ranges = split_prefix_shard_ranges(protected_size, plan)?;
    // Admit the largest requested range before CRC discovery asks the caller
    // to materialize it. Arbitrary additional callback allocations are outside
    // our policy; the requested byte range is bounded here.
    admit_repair_workspace_with_limit(
        repair_solve_workspace_required(
            shard_ranges.len(),
            0,
            shard_len,
            0,
            shard_len.min(protected_size),
        )?,
        workspace_limit,
    )?;
    let mut damaged = Vec::new();
    for (index, range) in shard_ranges.iter().enumerate() {
        poller.check(0).map_err(|_| Error::Cancelled)?;
        let shard = read_range(range.clone())?;
        if shard.len() != range.len() {
            return Err(Error::ShardSizeMismatch);
        }
        if repair_crc(&shard, 0, control)? != first.data_shard_states[index] {
            damaged.push(index);
        }
    }
    if damaged.is_empty() {
        return Ok(Vec::new());
    }
    if damaged.len() > chunks.len() {
        return Err(Error::TooManyDamagedShards);
    }

    let output_bytes = damaged.iter().try_fold(0u64, |bytes, &index| {
        bytes
            .checked_add(shard_ranges[index].len().next_multiple_of(2) as u64)
            .ok_or(Error::PlanOverflow)
    })?;
    admit_repair_workspace_with_limit(
        repair_solve_workspace_required(
            shard_ranges.len(),
            damaged.len(),
            shard_len,
            output_bytes,
            shard_len.min(protected_size),
        )?,
        workspace_limit,
    )?;

    let recovery_rows: Vec<_> = chunks[..damaged.len()]
        .iter()
        .map(|chunk| (chunk.shard_index, chunk.parity.as_slice()))
        .collect();
    let gf = shared_gf16();
    // Only damaged columns and available rows participate in the solve. A
    // high row index is an index, not a request to allocate preceding rows.
    let equations = recovery_equations(gf, shard_ranges.len(), &damaged, &recovery_rows, control)?;
    let inverse = invert_linear_system_matrix_with_control(gf, &equations, control)?;
    // Each row's right-hand side starts as its parity and has every surviving
    // shard folded out of it, leaving only the damaged shards' terms.
    let mut rhs = Vec::with_capacity(recovery_rows.len());
    for (_, parity) in &recovery_rows {
        check_repair(control)?;
        rhs.push(parity.to_vec());
    }
    let mut damaged_lookup = vec![false; shard_ranges.len()];
    for &index in &damaged {
        damaged_lookup[index] = true;
    }

    for (data_index, range) in shard_ranges.iter().enumerate() {
        if damaged_lookup[data_index] || range.is_empty() {
            continue;
        }
        check_repair(control)?;
        let shard = read_range(range.clone())?;
        if shard.len() != range.len() {
            return Err(Error::ShardSizeMismatch);
        }
        for (&(row, _), rhs) in recovery_rows.iter().zip(&mut rhs) {
            check_repair(control)?;
            let coefficient = recovery_coefficient(gf, shard_ranges.len(), row, data_index)?;
            accumulate_scaled(rhs, &shard, coefficient);
        }
    }

    // Whole words, so the folds never split one; the padding byte is dropped after.
    let mut repaired = damaged
        .iter()
        .map(|&index| vec![0; shard_ranges[index].len().next_multiple_of(2)])
        .collect::<Vec<_>>();
    fold_inverse(
        &inverse,
        &rhs,
        &mut repaired
            .iter_mut()
            .map(Vec::as_mut_slice)
            .collect::<Vec<_>>(),
        control,
    )?;
    for (output, &index) in repaired.iter_mut().zip(&damaged) {
        output.truncate(shard_ranges[index].len());
    }

    Ok(damaged
        .into_iter()
        .zip(repaired)
        .map(|(index, data)| (shard_ranges[index].clone(), data))
        .collect())
}

/// What a raw inline-recovery repair knows beyond the archive bytes.
#[derive(Debug, Clone, Default)]
pub(crate) struct InlineRepairOptions<'a> {
    pub control: crate::read_control::ReadControl,
    /// Password for header-encrypted archives, needed to frame a replacement
    /// end-of-archive header.
    pub password: Option<&'a [u8]>,
    /// Byte range holding this archive's recovery record, when a parsed
    /// archive already said where it lives.
    pub record_range: Option<std::ops::Range<usize>>,
}

/// Repair an archive's protected prefix and, when possible, incomplete inline
/// recovery records. Solves use the admission ceiling documented on
/// [`repair_inline_recovery_prefix_shards`]. Record rebuilding checks a separate
/// use of that ceiling, scaled by `input`, for its full encoder matrix,
/// resident parity, CRC/header and I/O scratch, row descriptors and growing
/// intermediate framed-record buffer. Input/parsed records, shared field
/// tables, final archive output and allocator/control overhead are excluded.
/// If rebuilding is too large, the repaired prefix is returned while the
/// incomplete recovery record is retained.
pub fn repair_inline_recovery_archive(input: &[u8]) -> Result<Vec<u8>> {
    Ok(repair_inline_recovery_archive_with_report(input, &InlineRepairOptions::default())?.0)
}

pub(crate) fn repair_inline_recovery_archive_with_report(
    input: &[u8],
    options: &InlineRepairOptions<'_>,
) -> Result<(Vec<u8>, crate::RecoveryRepairReport)> {
    let control = &options.control;
    check_repair(control)?;
    let chunks = select_record_chunks(
        find_inline_recovery_chunks_with_control(input, control)?,
        options.record_range.clone(),
    )?;
    let first = chunks.first().ok_or(Error::BadRecoveryChunk)?;
    let plan = first.chunk.plan;
    let protected_size =
        usize::try_from(first.chunk.protected_size).map_err(|_| Error::PlanOverflow)?;
    if protected_size > input.len() {
        return Err(Error::BadRecoveryChunk);
    }
    let mut recovery_data = Vec::with_capacity(
        chunks
            .iter()
            .map(|found| found.chunk.plan.shard_size as usize)
            .sum(),
    );
    for found in &chunks {
        check_repair(control)?;
        append_inline_recovery_chunk(input, found, &mut recovery_data);
    }
    let original_prefix = &input[..protected_size];
    let repaired_prefix =
        repair_inline_recovery_prefix_with_control(original_prefix, &recovery_data, control)?;
    let data_repaired = repaired_prefix != original_prefix;
    let mut indices = chunks
        .iter()
        .map(|found| found.chunk.shard_index)
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    let available = indices.len() as u64;
    let expected = plan.recovery_shards;
    let record_start = chunks
        .iter()
        .filter_map(|found| {
            let distance = found
                .chunk
                .shard_index
                .checked_mul(plan.shard_size as usize)?;
            found.offset.checked_sub(distance)
        })
        .min()
        .ok_or(Error::BadRecoveryChunk)?;
    if record_start < protected_size {
        return Err(Error::BadRecoveryChunk);
    }
    let payload_len = usize::try_from(plan.payload_size()?).map_err(|_| Error::PlanOverflow)?;
    let record_end = record_start
        .checked_add(payload_len)
        .ok_or(Error::PlanOverflow)?;

    // Splicing the repaired prefix back in is the floor. Whatever happens to
    // the record itself, the caller still gets the data repair.
    let prefix_only = || {
        let mut out = input.to_vec();
        out[..protected_size].copy_from_slice(&repaired_prefix);
        out
    };
    let record_complete = available == expected && record_end <= input.len();
    let mut recovery_record_rebuilt = false;
    let mut repaired = if record_complete {
        prefix_only()
    } else {
        match rebuild_inline_recovery_record_with_control(
            input,
            &repaired_prefix,
            record_start..record_end,
            plan,
            control,
        ) {
            Ok(rebuilt) => {
                recovery_record_rebuilt = true;
                rebuilt
            }
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(_) => prefix_only(),
        }
    };

    // An archive that stops where its recovery record does lost its
    // end-of-archive header along with whatever followed.
    let mut end_record_rebuilt = false;
    if (record_complete || recovery_record_rebuilt) && repaired.len() <= record_end {
        let mut read_options = crate::ArchiveReadOptions::with_optional_password(options.password);
        read_options.cancellation = control.cancellation();
        let end = crate::rar50::recovery_end_header(&repaired, read_options)
            .map_err(map_recovery_end_error)?;
        repaired.extend_from_slice(&end);
        end_record_rebuilt = true;
    }
    let report = crate::RecoveryRepairReport {
        changed: repaired != input,
        data_repaired,
        recovery_record_rebuilt,
        end_record_rebuilt,
        available_recovery_shards: Some(available),
        expected_recovery_shards: Some(expected),
    };
    check_repair(control)?;
    Ok((repaired, report))
}

fn map_recovery_end_error(error: crate::Error) -> Error {
    if error.kind() == crate::ErrorKind::Cancelled {
        Error::Cancelled
    } else {
        Error::BadRecoveryChunk
    }
}

/// Rebuilds the whole recovery record from the repaired prefix, replacing
/// `record` in the archive.
///
/// Admission counts the full encoder matrix, resident parity and the framed
/// record, including a growing Vec's old and replacement buffers. Limiting
/// parity alone leaves repeated headers and coefficients unbounded when a
/// small available chunk declares thousands of missing recovery rows.
/// Refusal costs the caller the rebuild and keeps the data repair.
fn rebuild_inline_recovery_record_with_control(
    input: &[u8],
    repaired_prefix: &[u8],
    record: std::ops::Range<usize>,
    plan: InlineRecoveryPlan,
    control: &crate::read_control::ReadControl,
) -> Result<Vec<u8>> {
    check_repair(control)?;
    admit_record_rebuild(plan, input.len() as u64)?;
    let rebuilt = build_inline_recovery_data_for_plan_with_control(repaired_prefix, plan, control)?;
    if rebuilt.len() != record.len() {
        return Err(Error::BadRecoveryChunk);
    }
    // record.start came from a parsed chunk within input, and the prefix
    // boundary was checked above.
    let gap = &input[repaired_prefix.len()..record.start];
    let mut out = Vec::with_capacity(input.len().max(record.end));
    out.extend_from_slice(repaired_prefix);
    out.extend_from_slice(gap);
    out.extend_from_slice(&rebuilt);
    if let Some(tail) = input.get(record.end..) {
        out.extend_from_slice(tail);
    }
    Ok(out)
}

/// Whether rebuilding a record of this geometry fits the repair workspace,
/// scaled by an archive of `input_len` bytes. The in-memory rebuild and the
/// streamed one both ask, so they refuse the same records.
fn admit_record_rebuild(plan: InlineRecoveryPlan, input_len: u64) -> Result<()> {
    let parity_bytes = plan
        .recovery_shards
        .checked_mul(plan.group_count)
        .ok_or(Error::PlanOverflow)?;
    if parity_bytes > MAX_REBUILD_PARITY_BYTES {
        return Err(Error::RebuildTooLarge);
    }
    let matrix_cells = repair_workspace_product(plan.data_shards, plan.recovery_shards)?;
    let row_descriptors = 2 * std::mem::size_of::<Buffer<u8>>() as u64;
    admit_repair_workspace(
        repair_workspace_sum(&[
            repair_workspace_product(matrix_cells, std::mem::size_of::<u16>() as u64)?,
            parity_bytes,
            repair_workspace_product(plan.recovery_shards, row_descriptors)?,
            repair_workspace_product(plan.data_shards, std::mem::size_of::<u64>() as u64)?,
            // At most twice the framed record capacity plus its previous buffer
            // while Vec growth replaces it. This is deliberately conservative.
            repair_workspace_product(plan.payload_size()?, 3)?,
            plan.group_count.max(1).min(RECOVERY_IO_BLOCK as u64),
            plan.header_size,
        ])?,
        input_len,
    )
}

/// Where a recovery record lies within the chunks that hold it, found as the
/// whole-archive repair finds them.
pub(crate) struct RecordLayout {
    pub(crate) plan: InlineRecoveryPlan,
    pub(crate) protected_size: usize,
    /// The record's payload, relative to the start of the chunks searched.
    pub(crate) record: std::ops::Range<usize>,
    /// The chunks belonging to the record, as the prefix repair takes them.
    pub(crate) recovery_data: Vec<u8>,
    pub(crate) available: u64,
}

/// Reads a byte range of whatever holds the chunks.
pub(crate) type ReadRange<'a> = &'a dyn Fn(std::ops::Range<usize>) -> Result<Vec<u8>>;

/// Lays out the record in the `len` bytes `read` serves (a recovery
/// service's stored payload, or a whole archive), choosing chunks as
/// [`repair_inline_recovery_archive_with_report`] does. Holds only the
/// chunks found.
pub(crate) fn record_layout(
    read: ReadRange<'_>,
    len: usize,
    control: &crate::read_control::ReadControl,
) -> Result<RecordLayout> {
    let found = select_record_chunks(find_inline_recovery_chunks_in(read, len, control)?, None)?;
    let first = found.first().ok_or(Error::BadRecoveryChunk)?;
    let plan = first.chunk.plan;
    let protected_size =
        usize::try_from(first.chunk.protected_size).map_err(|_| Error::PlanOverflow)?;
    let mut recovery_data = Vec::new();
    for chunk in &found {
        check_repair(control)?;
        let shard_size = chunk.chunk.plan.shard_size as usize;
        recovery_data.extend_from_slice(&read(chunk.offset..chunk.offset + shard_size)?);
    }
    let mut indices = found
        .iter()
        .map(|chunk| chunk.chunk.shard_index)
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    let start = found
        .iter()
        .filter_map(|chunk| {
            let distance = chunk
                .chunk
                .shard_index
                .checked_mul(plan.shard_size as usize)?;
            chunk.offset.checked_sub(distance)
        })
        .min()
        .ok_or(Error::BadRecoveryChunk)?;
    let payload_len = usize::try_from(plan.payload_size()?).map_err(|_| Error::PlanOverflow)?;
    let end = start.checked_add(payload_len).ok_or(Error::PlanOverflow)?;
    Ok(RecordLayout {
        plan,
        protected_size,
        record: start..end,
        recovery_data,
        available: indices.len() as u64,
    })
}

/// Whether [`write_rebuilt_record`] can rebuild this record for a prefix of
/// `body_len` bytes in an archive of `input_len`, decided before anything is
/// written: the workspace the in-memory rebuild is admitted to, and the
/// geometry the streamed builder checks.
pub(crate) fn record_rebuild_admitted(
    plan: InlineRecoveryPlan,
    body_len: u64,
    input_len: u64,
) -> bool {
    admit_record_rebuild(plan, input_len).is_ok()
        && plan
            .data_shards
            .checked_mul(8)
            .and_then(|bytes| RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE.checked_add(bytes))
            == Some(plan.header_size)
        && plan.header_size.checked_add(plan.group_count) == Some(plan.shard_size)
        && u32::try_from(plan.shard_size).is_ok()
        && u16::try_from(plan.data_shards).is_ok()
        && u16::try_from(plan.recovery_shards).is_ok()
        && body_len <= plan.group_count.saturating_mul(plan.data_shards)
}

/// Writes the record rebuilt from `body`, the repaired protected prefix, read
/// once. Parity is held, the prefix is not.
pub(crate) fn write_rebuilt_record(
    body: &mut dyn ReadSeek,
    body_len: u64,
    plan: InlineRecoveryPlan,
    sink: &mut dyn std::io::Write,
) -> Result<()> {
    build_streamed_inline_recovery_for_plan(
        body,
        body_len,
        plan,
        RecoveryMemoryMode::Resident,
        None,
        sink,
        None,
        0,
    )
    .map(drop)
}

/// Narrows found chunks down to the ones belonging to this archive's own
/// recovery record.
///
/// A stored archive nested inside this one carries `{RB}` chunks that parse
/// just as cleanly as ours, and taking the first one found picks the nested
/// record whenever it sits earlier in the file. This archive's record always
/// protects more bytes than anything stored inside it, so the largest
/// protected size wins. `record_range` settles it outright when a parsed
/// archive already said where the record is.
fn select_record_chunks(
    chunks: Vec<FoundInlineRecoveryChunk>,
    record_range: Option<std::ops::Range<usize>>,
) -> Result<Vec<FoundInlineRecoveryChunk>> {
    let mut chunks = match record_range {
        Some(range) => chunks
            .into_iter()
            .filter(|found| range.contains(&found.offset))
            .collect(),
        None => chunks,
    };
    let protected_size = chunks
        .iter()
        .map(|found| found.chunk.protected_size)
        .max()
        .ok_or(Error::BadRecoveryChunk)?;
    chunks.retain(|found| found.chunk.protected_size == protected_size);
    Ok(chunks)
}

fn find_inline_recovery_chunks_with_control(
    input: &[u8],
    control: &crate::read_control::ReadControl,
) -> Result<Vec<FoundInlineRecoveryChunk>> {
    find_inline_recovery_chunks_in(&|range| Ok(input[range].to_vec()), input.len(), control)
}

/// Finds every chunk that parses, scanning for `{RB}` and skipping past each
/// chunk found. Only the scan window and one candidate chunk are read at a
/// time. A candidate's header fields are checked before the chunk is read
/// for its CRC, so a stray marker in other data never reads a declared size
/// it cannot have; that decides nothing differently, as parsing makes the
/// same checks.
fn find_inline_recovery_chunks_in(
    read: ReadRange<'_>,
    len: usize,
    control: &crate::read_control::ReadControl,
) -> Result<Vec<FoundInlineRecoveryChunk>> {
    check_repair(control)?;
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    while let Some(start) = next_recovery_marker(read, offset, len, control)? {
        if let Some(chunk) = recovery_chunk_at(read, start, len, control)? {
            // Parsing already checked that this entire declared shard fits.
            let shard_size = chunk.plan.shard_size as usize;
            chunks.push(FoundInlineRecoveryChunk {
                offset: start,
                chunk,
            });
            offset = start + shard_size;
            continue;
        }
        check_repair(control)?;
        offset = start + 1;
    }
    if chunks.is_empty() {
        return Err(Error::BadRecoveryChunk);
    }
    Ok(chunks)
}

const MARKER_SCAN_WINDOW: usize = 64 * 1024;

/// The next `{RB}` at or after `from`, read in windows that overlap by three
/// bytes so a marker across two is still found.
fn next_recovery_marker(
    read: ReadRange<'_>,
    from: usize,
    len: usize,
    control: &crate::read_control::ReadControl,
) -> Result<Option<usize>> {
    let mut start = from;
    while start < len {
        check_repair(control)?;
        let end = (start + MARKER_SCAN_WINDOW + 3).min(len);
        if let Some(offset) = find_recovery_marker(&read(start..end)?) {
            return Ok(Some(start + offset));
        }
        start += MARKER_SCAN_WINDOW;
    }
    Ok(None)
}

/// The chunk at `start` when it parses; `None` for anything else.
fn recovery_chunk_at(
    read: ReadRange<'_>,
    start: usize,
    len: usize,
    control: &crate::read_control::ReadControl,
) -> Result<Option<InlineRecoveryChunk>> {
    let remaining = len - start;
    if remaining < 0x48 {
        return Ok(None);
    }
    let head = read(start..start + 0x48)?;
    let field = |at: usize, width: usize| {
        head[at..at + width]
            .iter()
            .rev()
            .fold(0u64, |value, &byte| (value << 8) | u64::from(byte))
    };
    let total_size = field(0x0c, 4);
    let header_size = field(0x10, 4);
    let data_shards = field(0x3a, 2);
    let recovery_shards = field(0x3c, 2);
    let plausible = header_size >= RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE
        && header_size <= total_size
        && total_size <= remaining as u64
        && head[0x14] == 1
        && head[0x15] == 1
        && field(0x2a, 8).is_multiple_of(2)
        && field(0x32, 8) == total_size
        && data_shards != 0
        && recovery_shards != 0
        && data_shards + recovery_shards <= FIELD_SIZE as u64
        && field(0x3e, 2) < recovery_shards
        && header_size == 0x48 + data_shards * 8;
    if !plausible {
        return Ok(None);
    }
    let chunk = read(start..start + total_size as usize)?;
    match parse_inline_recovery_chunk_with_control(&chunk, control) {
        Ok(chunk) => Ok(Some(chunk)),
        Err(Error::Cancelled) => Err(Error::Cancelled),
        Err(_) => Ok(None),
    }
}

fn find_recovery_marker(input: &[u8]) -> Option<usize> {
    memchr::memmem::find(input, b"{RB}")
}

fn append_inline_recovery_chunk(input: &[u8], found: &FoundInlineRecoveryChunk, out: &mut Vec<u8>) {
    // The scanner parsed this complete u32-sized shard from input[start..].
    let shard_size = found.chunk.plan.shard_size as usize;
    let start = found.offset;
    let end = start + shard_size;
    out.extend_from_slice(&input[start..end]);
}

/// Reconstruct equally padded data shards from available recovery rows.
///
/// Known shard lengths, missing-row availability and field dimensions are
/// validated before output allocation. An admission ceiling of four times the
/// supplied shard bytes, and at least 256 MiB, covers padded output, solve
/// matrices/copies and row/vector scratch. The caller's input, shared field
/// tables, allocator and control overhead are excluded; this is not a
/// process-RAM limit. Oversized reconstruction returns
/// [`Error::RepairWorkspaceLimitExceeded`].
pub fn reconstruct_data_shards(
    data_shards: &[Option<&[u8]>],
    recovery_shards: &[(usize, &[u8])],
) -> Result<Vec<Vec<u8>>> {
    if data_shards.is_empty() {
        return Err(Error::TooManyShards);
    }
    let shard_len = recovery_shards
        .first()
        .map(|(_, shard)| shard.len())
        .or_else(|| data_shards.iter().flatten().map(|shard| shard.len()).max())
        .ok_or(Error::TooManyDamagedShards)?;
    if !shard_len.is_multiple_of(2) {
        return Err(Error::OddShardSize);
    }
    if recovery_shards
        .iter()
        .any(|(_, shard)| shard.len() != shard_len)
    {
        return Err(Error::ShardSizeMismatch);
    }
    if data_shards
        .iter()
        .flatten()
        .any(|shard| shard.len() > shard_len)
    {
        return Err(Error::ShardSizeMismatch);
    }
    let missing_count = data_shards.iter().filter(|shard| shard.is_none()).count();
    if missing_count > recovery_shards.len() {
        return Err(Error::TooManyDamagedShards);
    }
    if data_shards.len() > FIELD_SIZE {
        return Err(Error::TooManyShards);
    }
    // Unused recovery rows need no field coefficients. Validate each selected
    // row without initializing the field or allocating any padded output.
    if recovery_shards[..missing_count].iter().any(|&(row, _)| {
        data_shards
            .len()
            .checked_add(row)
            .is_none_or(|position| position >= FIELD_SIZE)
    }) {
        return Err(Error::TooManyShards);
    }
    let padded_bytes = repair_workspace_product(data_shards.len() as u64, shard_len as u64)?;
    let input_bytes = data_shards
        .iter()
        .flatten()
        .map(|shard| shard.len())
        .chain(recovery_shards.iter().map(|(_, shard)| shard.len()))
        .fold(0u64, |total, len| total.saturating_add(len as u64));
    admit_repair_workspace(
        repair_solve_workspace_required(
            data_shards.len(),
            missing_count,
            shard_len,
            padded_bytes,
            0,
        )?,
        input_bytes,
    )?;

    let missing = data_shards
        .iter()
        .enumerate()
        .filter_map(|(index, shard)| shard.is_none().then_some(index))
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(data_shards.len());
    for shard in data_shards {
        let mut padded = vec![0; shard_len];
        if let Some(shard) = shard {
            padded[..shard.len()].copy_from_slice(shard);
        }
        out.push(padded);
    }
    if missing.is_empty() {
        return Ok(out);
    }
    recover_damaged_shards(&mut out, &missing, &recovery_shards[..missing.len()])?;
    Ok(out)
}

fn parse_available_inline_recovery_chunks_with_control(
    recovery_data: &[u8],
    control: &crate::read_control::ReadControl,
) -> Result<Vec<InlineRecoveryChunk>> {
    check_repair(control)?;
    Ok(
        find_inline_recovery_chunks_with_control(recovery_data, control)?
            .into_iter()
            .map(|found| found.chunk)
            .collect(),
    )
}

pub(crate) fn inline_recovery_chunk_counts_with_control(
    recovery_data: &[u8],
    control: &crate::read_control::ReadControl,
) -> Result<(u64, u64)> {
    check_repair(control)?;
    let chunks = parse_available_inline_recovery_chunks_with_control(recovery_data, control)?;
    let first = chunks.first().ok_or(Error::BadRecoveryChunk)?;
    let expected = first.plan.recovery_shards;
    let mut indices = chunks
        .iter()
        .map(|chunk| chunk.shard_index)
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    Ok((indices.len() as u64, expected))
}

fn parse_inline_recovery_chunk_with_control(
    input: &[u8],
    control: &crate::read_control::ReadControl,
) -> Result<InlineRecoveryChunk> {
    check_repair(control)?;
    if input.len() < 0x48 || &input[..4] != b"{RB}" {
        return Err(Error::BadRecoveryChunk);
    }
    // The fixed 0x48-byte prefix is present, so all fixed fields fit.
    let total_size = u32::from_le_bytes(input[0x0c..0x10].try_into().unwrap()) as u64;
    let header_size = u32::from_le_bytes(input[0x10..0x14].try_into().unwrap()) as u64;
    if header_size < RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE || header_size > total_size {
        return Err(Error::BadRecoveryChunk);
    }
    // Both values came from u32 fields, which fit usize on supported targets.
    let total_size_usize = total_size as usize;
    let header_size_usize = header_size as usize;
    if input.len() < total_size_usize {
        return Err(Error::BadRecoveryChunk);
    }
    let expected_crc = u64::from_le_bytes(input[0x04..0x0c].try_into().unwrap());
    let actual_crc = !repair_crc(&input[0x0c..total_size_usize], CRC64_XZ_INIT, control)?;
    if actual_crc != expected_crc {
        return Err(Error::BadRecoveryChunk);
    }
    if input[0x14] != 1 || input[0x15] != 1 {
        return Err(Error::BadRecoveryChunk);
    }

    let protected_size = u64::from_le_bytes(input[0x22..0x2a].try_into().unwrap());
    let group_count = u64::from_le_bytes(input[0x2a..0x32].try_into().unwrap());
    if !group_count.is_multiple_of(2) {
        return Err(Error::BadRecoveryChunk);
    }
    let shard_size = u64::from_le_bytes(input[0x32..0x3a].try_into().unwrap());
    let data_shards = u16::from_le_bytes(input[0x3a..0x3c].try_into().unwrap()) as u64;
    let recovery_shards = u16::from_le_bytes(input[0x3c..0x3e].try_into().unwrap()) as u64;
    if data_shards == 0 || recovery_shards == 0 || data_shards + recovery_shards > FIELD_SIZE as u64
    {
        return Err(Error::BadRecoveryChunk);
    }
    let shard_index = u16::from_le_bytes(input[0x3e..0x40].try_into().unwrap()) as usize;
    let plan = InlineRecoveryPlan {
        data_shards,
        recovery_shards,
        group_count,
        header_size,
        shard_size,
    };
    if shard_size != total_size
        || shard_index >= recovery_shards as usize
        || header_size_usize != 0x48 + data_shards as usize * 8
    {
        return Err(Error::BadRecoveryChunk);
    }

    let mut data_shard_states = Vec::with_capacity(data_shards as usize);
    let mut pos = 0x40;
    for _ in 0..data_shards {
        check_repair(control)?;
        data_shard_states.push(u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap()));
        pos += 8;
    }
    let _final_state = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap());
    let parity = input[header_size_usize..total_size_usize].to_vec();
    if parity.len() as u64 != group_count {
        return Err(Error::BadRecoveryChunk);
    }
    Ok(InlineRecoveryChunk {
        plan,
        protected_size,
        shard_index,
        data_shard_states,
        parity,
    })
}

fn recover_damaged_shards(
    data_shards: &mut [Vec<u8>],
    damaged: &[usize],
    recovery_shards: &[(usize, &[u8])],
) -> Result<()> {
    recover_damaged_shards_with_control(
        data_shards,
        damaged,
        recovery_shards,
        &crate::read_control::ReadControl::default(),
    )
}

fn recover_damaged_shards_with_control(
    data_shards: &mut [Vec<u8>],
    damaged: &[usize],
    recovery_shards: &[(usize, &[u8])],
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    let mut poller = control.poller();
    check_repair(control)?;
    let data_count = data_shards.len();
    let mut damaged_lookup = vec![false; data_count];
    for &data_index in damaged {
        poller.check(0).map_err(|_| Error::Cancelled)?;
        damaged_lookup[data_index] = true;
    }

    if recovery_shards.is_empty() {
        return Err(Error::TooManyDamagedShards);
    }
    let gf = shared_gf16();
    let equations = recovery_equations(gf, data_count, damaged, recovery_shards, control)?;
    let inverse = invert_linear_system_matrix_with_control(gf, &equations, control)?;

    let shard_len = data_shards.first().ok_or(Error::TooManyShards)?.len();
    let mut rhs = Vec::with_capacity(recovery_shards.len());
    for &(_, parity) in recovery_shards {
        check_repair(control)?;
        rhs.push(
            parity
                .get(..shard_len)
                .ok_or(Error::ShardSizeMismatch)?
                .to_vec(),
        );
    }
    for (data_index, shard) in data_shards.iter().enumerate() {
        if damaged_lookup[data_index] {
            continue;
        }
        for (&(row, _), rhs) in recovery_shards.iter().zip(&mut rhs) {
            check_repair(control)?;
            let coefficient = recovery_coefficient(gf, data_count, row, data_index)?;
            accumulate_scaled(rhs, shard, coefficient);
        }
    }

    let mut slots: Vec<_> = data_shards
        .iter_mut()
        .map(|shard| Some(shard.as_mut_slice()))
        .collect();
    let mut repaired = damaged
        .iter()
        .map(|&index| slots[index].take().ok_or(Error::BadRecoveryChunk))
        .collect::<Result<Vec<_>>>()?;
    for output in &mut repaired {
        output.fill(0);
    }
    fold_inverse(&inverse, &rhs, &mut repaired, control)
}

/// Whole-buffer folds keep the inverse on the same kernel as the parity encoder.
fn fold_inverse(
    inverse: &[Vec<u16>],
    rhs: &[Vec<u8>],
    repaired: &mut [&mut [u8]],
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    if inverse.len() != rhs.len()
        || repaired.len() != rhs.len()
        || inverse.iter().any(|row| row.len() != rhs.len())
    {
        return Err(Error::BadRecoveryChunk);
    }
    for (output, row) in repaired.iter_mut().zip(inverse) {
        debug_assert!(output.len().is_multiple_of(2));
        for (&coefficient, source) in row.iter().zip(rhs) {
            check_repair(control)?;
            let source = source.get(..output.len()).ok_or(Error::ShardSizeMismatch)?;
            accumulate_scaled(output, source, coefficient);
        }
    }
    Ok(())
}

fn recovery_coefficient(gf: &Gf16, data_count: usize, row: usize, column: usize) -> Result<u16> {
    let position = data_count
        .checked_add(row)
        .filter(|&position| position < FIELD_SIZE)
        .ok_or(Error::TooManyShards)?;
    if data_count == 0 || column >= data_count {
        return Err(Error::TooManyShards);
    }
    gf.inv((position ^ column) as u16)
}

fn recovery_equations(
    gf: &Gf16,
    data_count: usize,
    damaged: &[usize],
    recovery_shards: &[(usize, &[u8])],
    control: &crate::read_control::ReadControl,
) -> Result<Vec<Vec<u16>>> {
    let mut equations = Vec::with_capacity(recovery_shards.len());
    let mut poller = control.poller();
    check_repair(control)?;
    for &(row_index, _) in recovery_shards {
        // Validate the row even when no damaged columns were supplied.
        recovery_coefficient(gf, data_count, row_index, 0)?;
        let mut row = Vec::with_capacity(damaged.len());
        for &column in damaged {
            poller.check(0).map_err(|_| Error::Cancelled)?;
            row.push(recovery_coefficient(gf, data_count, row_index, column)?);
        }
        equations.push(row);
    }
    Ok(equations)
}

#[cfg(test)]
fn invert_linear_system_matrix(gf: &Gf16, matrix: &[Vec<u16>]) -> Result<Vec<Vec<u16>>> {
    invert_linear_system_matrix_with_control(
        gf,
        matrix,
        &crate::read_control::ReadControl::default(),
    )
}

fn invert_linear_system_matrix_with_control(
    gf: &Gf16,
    matrix: &[Vec<u16>],
    control: &crate::read_control::ReadControl,
) -> Result<Vec<Vec<u16>>> {
    let mut poller = control.poller();
    check_repair(control)?;
    let n = matrix.len();
    if matrix.iter().any(|row| row.len() != n) {
        return Err(Error::BadRecoveryChunk);
    }
    let mut matrix = matrix.to_vec();
    let mut inverse = vec![vec![0u16; n]; n];
    for (row, inverse_row) in inverse.iter_mut().enumerate() {
        poller.check(0).map_err(|_| Error::Cancelled)?;
        inverse_row[row] = 1;
    }

    for col in 0..n {
        poller.check(0).map_err(|_| Error::Cancelled)?;
        let pivot = (col..n)
            .find(|&row| matrix[row][col] != 0)
            .ok_or(Error::SingularElement)?;
        matrix.swap(col, pivot);
        inverse.swap(col, pivot);
        let inv = gf.inv(matrix[col][col])?;
        for value in &mut matrix[col] {
            poller.check(0).map_err(|_| Error::Cancelled)?;
            *value = gf.mul(*value, inv);
        }
        for value in &mut inverse[col] {
            poller.check(0).map_err(|_| Error::Cancelled)?;
            *value = gf.mul(*value, inv);
        }

        let pivot_matrix_row = matrix[col].clone();
        let pivot_inverse_row = inverse[col].clone();
        for row in 0..n {
            poller.check(0).map_err(|_| Error::Cancelled)?;
            if row == col {
                continue;
            }
            let factor = matrix[row][col];
            if factor == 0 {
                continue;
            }
            for (value, pivot) in matrix[row]
                .iter_mut()
                .zip(pivot_matrix_row.iter().copied())
                .skip(col)
            {
                poller.check(0).map_err(|_| Error::Cancelled)?;
                *value ^= gf.mul(factor, pivot);
            }
            for (value, pivot) in inverse[row]
                .iter_mut()
                .zip(pivot_inverse_row.iter().copied())
            {
                poller.check(0).map_err(|_| Error::Cancelled)?;
                *value ^= gf.mul(factor, pivot);
            }
        }
    }
    Ok(inverse)
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Gf16 {
    exp: Box<[u16]>,
    log: Box<[u32]>,
}

impl Gf16 {
    pub fn new() -> Self {
        let mut exp = vec![0u16; FIELD_SIZE * 4 + 1];
        let mut log = vec![0u32; FIELD_SIZE + 1];
        initialize_field(&mut exp, &mut log);
        Self {
            exp: exp.into_boxed_slice(),
            log: log.into_boxed_slice(),
        }
    }

    pub fn add(&self, left: u16, right: u16) -> u16 {
        left ^ right
    }

    fn view(&self) -> GfView<'_> {
        GfView {
            exp: &self.exp,
            log: &self.log,
        }
    }
    pub fn mul(&self, left: u16, right: u16) -> u16 {
        self.view().mul(left, right)
    }
    pub fn inv(&self, value: u16) -> Result<u16> {
        self.view().inv(value)
    }

    pub fn div(&self, numerator: u16, denominator: u16) -> Result<u16> {
        Ok(self.mul(numerator, self.inv(denominator)?))
    }
}

fn times_x(value: u32) -> u32 {
    let doubled = value << 1;
    if doubled > FIELD_MASK {
        doubled ^ PRIMITIVE_POLYNOMIAL
    } else {
        doubled
    }
}

fn initialize_field(exp: &mut [u16], log: &mut [u32]) {
    let mut value = 1u32;
    for power in 0..FIELD_SIZE {
        log[value as usize] = power as u32;
        exp[power] = value as u16;
        exp[power + FIELD_SIZE] = value as u16;
        value = times_x(value);
    }
    log[0] = ZERO_LOG_SENTINEL;
}
struct GfView<'a> {
    exp: &'a [u16],
    log: &'a [u32],
}
impl GfView<'_> {
    #[inline]
    fn mul(&self, left: u16, right: u16) -> u16 {
        if left == 0 || right == 0 {
            return 0;
        }
        let index = self.log[left as usize] + self.log[right as usize];
        self.exp[index as usize]
    }

    #[inline]
    fn inv(&self, value: u16) -> Result<u16> {
        if value == 0 {
            return Err(Error::SingularElement);
        }
        let index = FIELD_SIZE as u32 - self.log[value as usize];
        Ok(self.exp[index as usize])
    }
}

impl Default for Gf16 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn make_encoder_matrix(data_shards: usize, recovery_shards: usize) -> Result<Vec<Vec<u16>>> {
    if data_shards == 0
        || recovery_shards == 0
        || data_shards
            .checked_add(recovery_shards)
            .is_none_or(|total| total > FIELD_SIZE)
    {
        return Err(Error::TooManyShards);
    }
    let gf = shared_gf16();
    let mut matrix = vec![vec![0u16; data_shards]; recovery_shards];
    for (i, row) in matrix.iter_mut().enumerate() {
        for (j, cell) in row.iter_mut().enumerate() {
            let denominator = ((i + data_shards) ^ j) as u16;
            *cell = gf.inv(denominator)?;
        }
    }
    Ok(matrix)
}

pub fn encode_parity_shards(data: &[&[u8]], recovery_shards: usize) -> Result<Vec<Vec<u8>>> {
    let Some(first) = data.first() else {
        return Err(Error::TooManyShards);
    };
    if !first.len().is_multiple_of(2) {
        return Err(Error::OddShardSize);
    }
    if data.iter().any(|shard| shard.len() != first.len()) {
        return Err(Error::ShardSizeMismatch);
    }

    let matrix = make_encoder_matrix(data.len(), recovery_shards)?;
    let gf = shared_gf16();
    let mut parity = vec![vec![0u8; first.len()]; recovery_shards];
    for (recovery_index, row) in matrix.iter().enumerate() {
        for word_offset in (0..first.len()).step_by(2) {
            let mut symbol = 0u16;
            for (data_index, shard) in data.iter().enumerate() {
                let data_symbol = u16::from_le_bytes([shard[word_offset], shard[word_offset + 1]]);
                symbol ^= gf.mul(row[data_index], data_symbol);
            }
            parity[recovery_index][word_offset..word_offset + 2]
                .copy_from_slice(&symbol.to_le_bytes());
        }
    }
    Ok(parity)
}

/// The pre-streaming recovery writer, kept verbatim as the oracle for
/// byte-identity tests. If these two ever disagree, the streaming rewrite has
/// changed the format.
#[cfg(test)]
mod legacy_reference {
    use super::*;

    pub(super) fn build_structural_inline_recovery_data(
        archive_prefix: &[u8],
        recovery_percent: u64,
    ) -> Result<Vec<u8>> {
        let (plan, parity) = encode_inline_recovery_parity(archive_prefix, recovery_percent)?;
        let shard_ranges = split_prefix_shard_ranges(archive_prefix.len(), plan)?;
        let total_len = usize::try_from(plan.payload_size()?).map_err(|_| Error::PlanOverflow)?;
        let header_size = usize::try_from(plan.header_size).map_err(|_| Error::PlanOverflow)?;
        let shard_size = usize::try_from(plan.shard_size).map_err(|_| Error::PlanOverflow)?;
        let data_shards = usize::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
        let recovery_shards =
            usize::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?;
        let total_size = u32::try_from(plan.shard_size).map_err(|_| Error::PlanOverflow)?;
        let header_size_u32 = u32::try_from(plan.header_size).map_err(|_| Error::PlanOverflow)?;
        let data_shards_u16 = u16::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
        let recovery_shards_u16 =
            u16::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?;
        let chunk_data_extent = shard_ranges.last().map_or(0usize, std::ops::Range::len);
        let chunk_data_extent_u32 =
            u32::try_from(chunk_data_extent).map_err(|_| Error::PlanOverflow)?;
        let data_shard_states: Vec<u64> = shard_ranges
            .iter()
            .map(|range| crc64_rar_state(&archive_prefix[range.clone()]))
            .collect();
        let final_state = parity
            .first()
            .map(|payload| crc64_rar_state(payload))
            .unwrap_or(0);

        let mut out = Vec::with_capacity(total_len);
        for (shard_index, payload) in parity.iter().enumerate() {
            if payload.len() + header_size != shard_size {
                return Err(Error::PlanOverflow);
            }

            let chunk_start = out.len();
            out.extend_from_slice(b"{RB}");
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&total_size.to_le_bytes());
            out.extend_from_slice(&header_size_u32.to_le_bytes());
            out.push(1);
            out.push(1);
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&chunk_data_extent_u32.to_le_bytes());
            out.extend_from_slice(&(archive_prefix.len() as u64).to_le_bytes());
            out.extend_from_slice(&plan.group_count.to_le_bytes());
            out.extend_from_slice(&plan.shard_size.to_le_bytes());
            out.extend_from_slice(&data_shards_u16.to_le_bytes());
            out.extend_from_slice(&recovery_shards_u16.to_le_bytes());
            out.extend_from_slice(
                &u16::try_from(shard_index)
                    .map_err(|_| Error::PlanOverflow)?
                    .to_le_bytes(),
            );
            for &state in &data_shard_states {
                out.extend_from_slice(&state.to_le_bytes());
            }
            out.extend_from_slice(&final_state.to_le_bytes());
            if out.len() - chunk_start != header_size {
                return Err(Error::PlanOverflow);
            }
            out.extend_from_slice(payload);
            if out.len() - chunk_start != shard_size {
                return Err(Error::PlanOverflow);
            }

            let chunk_end = chunk_start
                .checked_add(shard_size)
                .ok_or(Error::PlanOverflow)?;
            let crc_start = chunk_start.checked_add(0x0c).ok_or(Error::PlanOverflow)?;
            let crc = crc64_xz(out.get(crc_start..chunk_end).ok_or(Error::PlanOverflow)?);
            let crc_field_start = chunk_start.checked_add(0x04).ok_or(Error::PlanOverflow)?;
            let crc_field_end = chunk_start.checked_add(0x0c).ok_or(Error::PlanOverflow)?;
            out.get_mut(crc_field_start..crc_field_end)
                .ok_or(Error::PlanOverflow)?
                .copy_from_slice(&crc.to_le_bytes());
        }
        if out.len() != total_len {
            return Err(Error::PlanOverflow);
        }
        debug_assert_eq!(parity.len(), recovery_shards);
        debug_assert_eq!(data_shard_states.len(), data_shards);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_inline_recovery_data_for_plan, build_structural_inline_recovery_data,
        check_streamable_plan, crc64_rar_state, crc64_xz, encode_inline_recovery_parity,
        encode_parity_shards, fold_inverse, invert_linear_system_matrix, make_encoder_matrix,
        plan_inline_recovery, reconstruct_data_shards, recovery_equations,
        repair_inline_recovery_archive, repair_inline_recovery_prefix,
        repair_inline_recovery_prefix_shards, shared_gf16, split_prefix_shard_ranges,
        split_prefix_shards, Error, Gf16, InlineRecoveryPlan, MAX_STREAMED_RECOVERY_PREFIX,
        MAX_WINRAR602_DATA_SHARDS,
    };

    fn recovery_test_bytes(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        (0..len)
            .map(|index| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                if index % 5 == 0 {
                    (index % 251) as u8
                } else {
                    (state >> 24) as u8
                }
            })
            .collect()
    }

    /// Sizes and percentages that between them cover an empty body, odd tails,
    /// the sub-200 KiB shard formula, the 200-shard switchover, and a body big
    /// enough to need many stripes.
    const RECOVERY_CASES: &[usize] = &[
        0,
        1,
        2,
        3,
        1023,
        1024,
        1025,
        2050,
        200 * 1024 - 1,
        200 * 1024,
        200 * 1024 + 1,
        1024 * 1024 + 7,
    ];

    #[test]
    fn aggregate_recovery_planning_selects_stripes_beside_retained_capacity() {
        let data = vec![7; 131072];
        let plan = super::plan_inline_recovery(data.len() as u64, 100).unwrap();
        let ledger = super::Allowance::limited(113_562);
        let retained = super::Buffer::filled(4096, 0u8, &ledger).unwrap();
        let (mode, required) =
            super::choose_recovery_capacity_mode(plan, 8 * 1024 * 1024, &ledger).unwrap();
        assert!(matches!(mode, super::RecoveryMemoryMode::Striped { .. }));
        assert!(required <= 8 * 1024 * 1024);
        let mut expected = Vec::new();
        super::build_streamed_inline_recovery(
            &mut std::io::Cursor::new(&data),
            data.len() as u64,
            100,
            super::RecoveryMemoryMode::Resident,
            None,
            &mut expected,
            None,
            1,
        )
        .unwrap();
        let mut actual = Vec::new();
        super::streamed_recovery_with_allowance(
            &mut std::io::Cursor::new(&data),
            data.len() as u64,
            plan,
            mode,
            Some(&mut std::io::Cursor::new(Vec::new())),
            &mut actual,
            None,
            1,
            &ledger,
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(ledger.used(), 4096);
        drop(retained);
        assert_eq!(ledger.used(), 0);
        let small = super::Allowance::limited(1);
        let error =
            super::choose_recovery_capacity_mode(plan, 8 * 1024 * 1024, &small).unwrap_err();
        assert_eq!(
            crate::Error::from(error).kind(),
            crate::ErrorKind::ResourceLimit
        );
        assert_eq!(small.used(), 0);
    }

    #[test]
    fn recovery_allowance_covers_parity_and_framing_in_both_modes() {
        use super::{streamed_recovery_with_allowance, Allowance, RecoveryMemoryMode};
        use std::io::Cursor;
        let data = recovery_test_bytes(200_003, 17);
        let plan = plan_inline_recovery(data.len() as u64, 10).unwrap();
        let expected =
            super::legacy_reference::build_structural_inline_recovery_data(&data, 10).unwrap();
        for mode in [
            RecoveryMemoryMode::Resident,
            RecoveryMemoryMode::Striped { stripe_len: 64 },
        ] {
            let mut successes = 0;
            let mut refusals = 0;
            for limit in [0, 1, 2048, 16384, 131072, 8 << 20] {
                let allowance = Allowance::limited(limit);
                let mut body = Cursor::new(&data);
                let mut scratch = Cursor::new(Vec::new());
                let mut output = Vec::new();
                let result = streamed_recovery_with_allowance(
                    &mut body,
                    data.len() as u64,
                    plan,
                    mode,
                    Some(&mut scratch),
                    &mut output,
                    None,
                    0,
                    &allowance,
                );
                match result {
                    Ok(built) => {
                        successes += 1;
                        assert_eq!(output, expected);
                        assert_eq!(built.payload_len, output.len() as u64);
                        assert_eq!(built.payload_crc32, crate::crc32::crc32(&output));
                    }
                    Err(error) => {
                        refusals += 1;
                        assert_eq!(
                            crate::Error::from(error).kind(),
                            crate::ErrorKind::ResourceLimit
                        );
                        if limit <= 1 {
                            assert_eq!(body.position(), 0);
                            assert!(output.is_empty());
                        }
                    }
                }
                assert_eq!(allowance.used(), 0, "{mode:?} limit={limit}");
            }
            assert!(successes > 0 && refusals >= 3);
        }
    }

    #[test]
    fn recovery_allowance_releases_every_owner_on_cancellation_and_io_failure() {
        use super::{streamed_recovery_with_allowance, Allowance, RecoveryMemoryMode};
        use std::io::{Cursor, Read, Seek, SeekFrom, Write};
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Progress {
            cancelled: AtomicBool,
            finished: AtomicBool,
        }
        impl crate::WriteProgress for Progress {
            fn report(&self, event: crate::WriteProgressEvent<'_>) {
                match event {
                    crate::WriteProgressEvent::Advanced { .. } => {
                        self.cancelled.store(true, Ordering::Relaxed)
                    }
                    crate::WriteProgressEvent::OperationFinished { .. } => {
                        self.finished.store(true, Ordering::Relaxed)
                    }
                    _ => {}
                }
            }
            fn is_cancelled(&self) -> bool {
                self.cancelled.load(Ordering::Relaxed)
            }
        }
        struct FailedScratch;
        impl Read for FailedScratch {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                unreachable!()
            }
        }
        impl Seek for FailedScratch {
            fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
                Ok(0)
            }
        }
        impl Write for FailedScratch {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let data = recovery_test_bytes(200_003, 17);
        let plan = plan_inline_recovery(data.len() as u64, 10).unwrap();
        let allowance = Allowance::limited(2 * 1048576);
        for mode in [
            RecoveryMemoryMode::Resident,
            RecoveryMemoryMode::Striped { stripe_len: 64 },
        ] {
            for initially_cancelled in [false, true] {
                let progress = Progress {
                    cancelled: AtomicBool::new(initially_cancelled),
                    finished: AtomicBool::new(false),
                };
                let mut body = Cursor::new(&data);
                let mut output = Vec::new();
                let result = streamed_recovery_with_allowance(
                    &mut body,
                    data.len() as u64,
                    plan,
                    mode,
                    Some(&mut Cursor::new(Vec::new())),
                    &mut output,
                    Some(crate::progress::ProgressReporter(&progress)),
                    0,
                    &allowance,
                );
                assert!(matches!(result, Err(Error::Cancelled)));
                assert!(!progress.finished.load(Ordering::Relaxed));
                assert!(output.is_empty());
                if initially_cancelled {
                    assert_eq!(body.position(), 0);
                }
                assert_eq!(allowance.used(), 0);
            }
            let error = streamed_recovery_with_allowance(
                &mut Cursor::new(&data[..7]),
                data.len() as u64,
                plan,
                mode,
                Some(&mut Cursor::new(Vec::new())),
                &mut Vec::new(),
                None,
                0,
                &allowance,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                Error::Io(std::io::ErrorKind::UnexpectedEof)
            ));
            assert_eq!(allowance.used(), 0);
            let error = streamed_recovery_with_allowance(
                &mut Cursor::new(&data),
                data.len() as u64,
                plan,
                mode,
                Some(&mut FailedScratch),
                &mut FailedScratch,
                None,
                0,
                &allowance,
            )
            .unwrap_err();
            assert!(matches!(error, Error::Io(std::io::ErrorKind::BrokenPipe)));
            assert_eq!(allowance.used(), 0);
            let mut output = Vec::new();
            streamed_recovery_with_allowance(
                &mut Cursor::new(&data),
                data.len() as u64,
                plan,
                mode,
                Some(&mut Cursor::new(Vec::new())),
                &mut output,
                None,
                0,
                &allowance,
            )
            .unwrap();
            assert!(!output.is_empty());
            assert_eq!(allowance.used(), 0);
        }
    }

    #[test]
    fn streamed_recovery_reports_parity_sink_failure_after_header() {
        use super::{streamed_recovery_with_allowance, Allowance, RecoveryMemoryMode};
        use std::io::{Cursor, Write};

        struct HeaderOnlySink {
            header_len: usize,
            written: usize,
        }
        impl Write for HeaderOnlySink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.written == self.header_len {
                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
                let count = bytes.len().min(self.header_len - self.written);
                self.written += count;
                Ok(count)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let body = vec![0x5a; 4096];
        let plan = plan_inline_recovery(body.len() as u64, 10).unwrap();
        for mode in [
            RecoveryMemoryMode::Resident,
            RecoveryMemoryMode::Striped { stripe_len: 64 },
        ] {
            let allowance = Allowance::limited(2 * 1048576);
            let mut sink = HeaderOnlySink {
                header_len: plan.header_size as usize,
                written: 0,
            };
            let error = streamed_recovery_with_allowance(
                &mut Cursor::new(&body),
                body.len() as u64,
                plan,
                mode,
                Some(&mut Cursor::new(Vec::new())),
                &mut sink,
                None,
                0,
                &allowance,
            )
            .unwrap_err();
            assert_eq!(error, Error::Io(std::io::ErrorKind::BrokenPipe));
            assert_eq!(sink.written, plan.header_size as usize);
            assert_eq!(allowance.used(), 0);
        }
    }

    #[test]
    fn striped_recovery_stops_writing_after_mid_row_sink_failure() {
        use std::io::{Cursor, Write};

        struct HeaderSink(usize);
        impl Write for HeaderSink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0 != 0 {
                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
                self.0 += bytes.len();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let body = vec![7; super::RECOVERY_IO_BLOCK + 2];
        let plan = InlineRecoveryPlan {
            data_shards: 1,
            recovery_shards: 1,
            group_count: body.len() as u64,
            header_size: 80,
            shard_size: 80 + body.len() as u64,
        };
        let mut sink = HeaderSink(0);
        let error = super::build_streamed_inline_recovery_for_plan(
            &mut Cursor::new(&body),
            body.len() as u64,
            plan,
            super::RecoveryMemoryMode::Striped { stripe_len: 4096 },
            Some(&mut Cursor::new(Vec::new())),
            &mut sink,
            None,
            1,
        )
        .unwrap_err();
        assert_eq!(error, Error::Io(std::io::ErrorKind::BrokenPipe));
        assert_eq!(sink.0, plan.header_size as usize);
    }

    #[test]
    fn striped_recovery_reports_scratch_read_failure_before_output() {
        use super::{streamed_recovery_with_allowance, Allowance, RecoveryMemoryMode};
        use std::io::{Cursor, Read, Seek, SeekFrom, Write};

        struct UnreadableScratch(Cursor<Vec<u8>>);
        impl Read for UnreadableScratch {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        impl Write for UnreadableScratch {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.write(bytes)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.flush()
            }
        }
        impl Seek for UnreadableScratch {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                self.0.seek(pos)
            }
        }

        let body = vec![0x5a; 4096];
        let plan = plan_inline_recovery(body.len() as u64, 10).unwrap();
        let allowance = Allowance::limited(2 * 1048576);
        let mut output = Vec::new();
        let error = streamed_recovery_with_allowance(
            &mut Cursor::new(&body),
            body.len() as u64,
            plan,
            RecoveryMemoryMode::Striped { stripe_len: 64 },
            Some(&mut UnreadableScratch(Cursor::new(Vec::new()))),
            &mut output,
            None,
            0,
            &allowance,
        )
        .unwrap_err();
        assert_eq!(error, Error::Io(std::io::ErrorKind::BrokenPipe));
        assert!(output.is_empty());
        assert_eq!(allowance.used(), 0);
    }

    #[test]
    fn striped_recovery_preserves_scratch_seek_failures() {
        use super::{streamed_recovery_with_allowance, Allowance, RecoveryMemoryMode};
        use std::io::{Cursor, Read, Seek, SeekFrom, Write};

        struct FaultScratch {
            data: Cursor<Vec<u8>>,
            reads: usize,
            fail_initial_seek: bool,
        }
        impl Read for FaultScratch {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                self.data.read(bytes)
            }
        }
        impl Write for FaultScratch {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.data.write(bytes)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.data.flush()
            }
        }
        impl Seek for FaultScratch {
            fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
                if self.fail_initial_seek || self.reads != 0 {
                    return Err(std::io::ErrorKind::PermissionDenied.into());
                }
                self.data.seek(from)
            }
        }

        let body = vec![0x5a; 4096];
        let plan = plan_inline_recovery(body.len() as u64, 10).unwrap();
        for fail_initial_seek in [true, false] {
            let allowance = Allowance::limited(2 * 1048576);
            let mut scratch = FaultScratch {
                data: Cursor::new(Vec::new()),
                reads: 0,
                fail_initial_seek,
            };
            let mut output = Vec::new();
            let error = streamed_recovery_with_allowance(
                &mut Cursor::new(&body),
                body.len() as u64,
                plan,
                RecoveryMemoryMode::Striped { stripe_len: 64 },
                Some(&mut scratch),
                &mut output,
                None,
                0,
                &allowance,
            )
            .unwrap_err();
            assert_eq!(error, Error::Io(std::io::ErrorKind::PermissionDenied));
            assert_eq!(scratch.reads == 0, fail_initial_seek);
            assert!(output.is_empty());
            assert_eq!(allowance.used(), 0);
        }
    }

    #[test]
    fn recovery_encoder_preserves_body_seek_failures() {
        use super::{streamed_recovery_with_allowance, Allowance, RecoveryMemoryMode};
        use std::io::{Cursor, Read, Seek, SeekFrom};

        struct UnseekableBody(Cursor<Vec<u8>>);
        impl Read for UnseekableBody {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                self.0.read(bytes)
            }
        }
        impl Seek for UnseekableBody {
            fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
                Err(std::io::ErrorKind::PermissionDenied.into())
            }
        }

        let body = vec![0x5a; 4096];
        let plan = plan_inline_recovery(body.len() as u64, 10).unwrap();
        for mode in [
            RecoveryMemoryMode::Resident,
            RecoveryMemoryMode::Striped { stripe_len: 64 },
        ] {
            let allowance = Allowance::limited(2 * 1048576);
            let mut output = Vec::new();
            let error = streamed_recovery_with_allowance(
                &mut UnseekableBody(Cursor::new(body.clone())),
                body.len() as u64,
                plan,
                mode,
                Some(&mut Cursor::new(Vec::new())),
                &mut output,
                None,
                0,
                &allowance,
            )
            .unwrap_err();
            assert_eq!(error, Error::Io(std::io::ErrorKind::PermissionDenied));
            assert!(output.is_empty());
            assert_eq!(allowance.used(), 0);
        }
    }

    #[test]
    fn streamed_recovery_rejects_invalid_plan_before_output() {
        use super::{streamed_recovery_with_allowance, Allowance, RecoveryMemoryMode};
        use std::io::Cursor;

        let body = vec![0x5a; 4096];
        let valid = plan_inline_recovery(body.len() as u64, 10).unwrap();
        let allowance = Allowance::limited(2 * 1048576);
        for (name, plan, expected) in [
            (
                "payload length overflow",
                InlineRecoveryPlan {
                    recovery_shards: u64::MAX,
                    ..valid
                },
                Error::PlanOverflow,
            ),
            (
                "header state multiplication overflow",
                InlineRecoveryPlan {
                    data_shards: u64::MAX,
                    ..valid
                },
                Error::PlanOverflow,
            ),
            (
                "header state addition overflow",
                InlineRecoveryPlan {
                    data_shards: (u64::MAX - 0x48) / 8 + 1,
                    ..valid
                },
                Error::PlanOverflow,
            ),
            (
                "shard length addition overflow",
                InlineRecoveryPlan {
                    group_count: u64::MAX,
                    ..valid
                },
                Error::PlanOverflow,
            ),
            (
                "u32 shard length",
                InlineRecoveryPlan {
                    group_count: u32::MAX as u64,
                    shard_size: u32::MAX as u64 + valid.header_size,
                    ..valid
                },
                Error::PlanOverflow,
            ),
            (
                "u16 data count",
                InlineRecoveryPlan {
                    data_shards: u16::MAX as u64 + 1,
                    group_count: 0,
                    header_size: 0x48 + 8 * (u16::MAX as u64 + 1),
                    shard_size: 0x48 + 8 * (u16::MAX as u64 + 1),
                    ..valid
                },
                Error::PlanOverflow,
            ),
            (
                "u16 recovery count",
                InlineRecoveryPlan {
                    recovery_shards: u16::MAX as u64 + 1,
                    ..valid
                },
                Error::PlanOverflow,
            ),
            (
                "header length",
                InlineRecoveryPlan {
                    header_size: valid.header_size + 1,
                    ..valid
                },
                Error::PlanOverflow,
            ),
            (
                "shard length",
                InlineRecoveryPlan {
                    shard_size: valid.shard_size + 1,
                    ..valid
                },
                Error::PlanOverflow,
            ),
            (
                "prefix capacity",
                InlineRecoveryPlan {
                    group_count: 2,
                    shard_size: valid.header_size + 2,
                    ..valid
                },
                Error::PrefixExceedsPlan,
            ),
            (
                "zero recovery shards",
                InlineRecoveryPlan {
                    recovery_shards: 0,
                    ..valid
                },
                Error::TooManyShards,
            ),
        ] {
            let mut output = Vec::new();
            let result = streamed_recovery_with_allowance(
                &mut Cursor::new(&body),
                body.len() as u64,
                plan,
                RecoveryMemoryMode::Resident,
                None,
                &mut output,
                None,
                0,
                &allowance,
            );
            assert_eq!(result.unwrap_err(), expected, "{name}");
            assert!(output.is_empty(), "{name}");
            assert_eq!(allowance.used(), 0, "{name}");
        }
        let mut output = Vec::new();
        assert_eq!(
            streamed_recovery_with_allowance(
                &mut Cursor::new(&body),
                body.len() as u64,
                valid,
                RecoveryMemoryMode::Striped { stripe_len: 64 },
                None,
                &mut output,
                None,
                0,
                &allowance,
            )
            .unwrap_err(),
            Error::PlanOverflow
        );
        assert!(output.is_empty());
        assert_eq!(allowance.used(), 0);
    }

    #[test]
    fn rar5_record_builder_preserves_plan_errors() {
        let plan = InlineRecoveryPlan {
            data_shards: 1,
            recovery_shards: 1,
            group_count: 0,
            header_size: 80,
            shard_size: 80,
        };
        assert_eq!(
            super::build_inline_recovery_data_for_plan_with_control(
                b"abc",
                plan,
                &crate::read_control::ReadControl::default()
            ),
            Err(Error::PrefixExceedsPlan)
        );
    }

    #[test]
    fn streamed_recovery_reports_progress_through_completion() {
        use std::io::Cursor;
        use std::sync::Mutex;

        #[derive(Default)]
        struct Progress(Mutex<Vec<(u8, u64)>>);
        impl crate::WriteProgress for Progress {
            fn report(&self, event: crate::WriteProgressEvent<'_>) {
                let item = match event {
                    crate::WriteProgressEvent::OperationStarted {
                        total_bytes: Some(total),
                        ..
                    } => (0, total),
                    crate::WriteProgressEvent::Advanced {
                        completed_bytes, ..
                    } => (1, completed_bytes),
                    crate::WriteProgressEvent::OperationFinished {
                        total_bytes: Some(total),
                        ..
                    } => (2, total),
                    _ => panic!("unexpected recovery progress event"),
                };
                self.0.lock().unwrap().push(item);
            }
        }

        let body = vec![0x5a; 4096];
        let progress = Progress::default();
        let mut output = Vec::new();
        let result = super::build_streamed_inline_recovery(
            &mut Cursor::new(&body),
            body.len() as u64,
            10,
            super::RecoveryMemoryMode::Resident,
            None,
            &mut output,
            Some(crate::progress::ProgressReporter(&progress)),
            3,
        )
        .unwrap();
        let events = progress.0.into_inner().unwrap();
        assert_eq!(events.first(), Some(&(0, result.payload_len)));
        assert_eq!(events.last(), Some(&(2, result.payload_len)));
        assert!(events[1..events.len() - 1]
            .iter()
            .all(|&(kind, bytes)| kind == 1 && bytes <= result.payload_len));
        assert!(events.len() > 2);
        assert_eq!(output.len() as u64, result.payload_len);
    }

    #[test]
    fn streamed_recovery_handles_empty_and_unused_data_shards() {
        use std::io::Cursor;

        for (body, plan) in [
            (
                &b""[..],
                InlineRecoveryPlan {
                    data_shards: 1,
                    recovery_shards: 1,
                    group_count: 2,
                    header_size: 80,
                    shard_size: 82,
                },
            ),
            (
                &b"abc"[..],
                InlineRecoveryPlan {
                    data_shards: 3,
                    recovery_shards: 1,
                    group_count: 4,
                    header_size: 96,
                    shard_size: 100,
                },
            ),
        ] {
            let mut output = Vec::new();
            super::build_streamed_inline_recovery_for_plan(
                &mut Cursor::new(body),
                body.len() as u64,
                plan,
                super::RecoveryMemoryMode::Resident,
                None,
                &mut output,
                None,
                1,
            )
            .unwrap();
            assert_eq!(
                repair_inline_recovery_prefix(body, &output),
                Ok(body.to_vec())
            );
        }
    }

    #[test]
    fn streamed_recovery_matches_the_legacy_writer_byte_for_byte() {
        for &len in RECOVERY_CASES {
            let body = recovery_test_bytes(len, len as u32);
            // High percentages on the large cases cost O(shards^2) work for no
            // extra coverage: the geometry is already pinned by the small ones.
            let percents: &[u64] = if len < 200 * 1024 {
                &[1, 5, 10, 50, 100]
            } else {
                &[1, 10]
            };
            for &percent in percents {
                let expected =
                    super::legacy_reference::build_structural_inline_recovery_data(&body, percent)
                        .unwrap();
                let produced = build_structural_inline_recovery_data(&body, percent).unwrap();
                assert_eq!(
                    produced, expected,
                    "streamed output differs for {len} bytes at {percent}%"
                );
            }
        }
    }

    #[test]
    fn striped_recovery_matches_resident_recovery_byte_for_byte() {
        // Small bodies get a deliberately tiny stripe so stripe boundaries land
        // everywhere; large ones use a realistic stripe, since their job is to
        // cover the 200-shard geometry rather than boundary arithmetic.
        for &len in RECOVERY_CASES {
            let body = recovery_test_bytes(len, len as u32 ^ 0x5555);
            let (stripe_len, percents): (usize, &[u64]) = if len <= 4096 {
                (64, &[1, 10, 100])
            } else {
                (4096, &[1, 10])
            };
            for &percent in percents {
                let expected = build_structural_inline_recovery_data(&body, percent).unwrap();

                let plan = plan_inline_recovery(body.len() as u64, percent).unwrap();
                let mut scratch = std::io::Cursor::new(vec![
                    0u8;
                    (plan.recovery_shards * plan.group_count)
                        as usize
                ]);
                let mut produced = Vec::new();
                let output = super::build_streamed_inline_recovery(
                    &mut std::io::Cursor::new(&body),
                    body.len() as u64,
                    percent,
                    super::RecoveryMemoryMode::Striped { stripe_len },
                    Some(&mut scratch),
                    &mut produced,
                    None,
                    1,
                )
                .unwrap();

                assert_eq!(
                    produced, expected,
                    "striped output differs for {len} bytes at {percent}%"
                );
                assert_eq!(output.plan, plan);
                assert_eq!(output.payload_len, produced.len() as u64);
                assert_eq!(output.payload_crc32, crate::crc32::crc32(&produced));
            }
        }
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn pooled_parity_matches_one_thread_byte_for_byte() {
        fn streamed(body: &[u8], percent: u64, mode: super::RecoveryMemoryMode) -> Vec<u8> {
            let plan = plan_inline_recovery(body.len() as u64, percent).unwrap();
            let mut scratch = std::io::Cursor::new(vec![
                0u8;
                (plan.recovery_shards * plan.group_count)
                    as usize
            ]);
            let mut produced = Vec::new();
            super::build_streamed_inline_recovery(
                &mut std::io::Cursor::new(body),
                body.len() as u64,
                percent,
                mode,
                Some(&mut scratch),
                &mut produced,
                None,
                1,
            )
            .unwrap();
            produced
        }
        let pool = crate::parallel::private_pool(8);
        // An odd body leaves the last data shard short and ending mid-symbol.
        for len in [1025, 3 * 200 * 1024 + 1, 1024 * 1024 + 7] {
            let body = recovery_test_bytes(len, len as u32 ^ 0x0bad);
            for percent in [1, 10] {
                let group_count = plan_inline_recovery(len as u64, percent)
                    .unwrap()
                    .group_count as usize;
                // 998 divides none of these group counts.
                assert_ne!(group_count % 998, 0);
                for mode in [
                    super::RecoveryMemoryMode::Resident,
                    super::RecoveryMemoryMode::Striped { stripe_len: 998 },
                ] {
                    let serial = {
                        let _one = crate::parallel::ThreadCap::set(Some(1));
                        streamed(&body, percent, mode)
                    };
                    let pooled = pool.install(|| streamed(&body, percent, mode));
                    assert_eq!(
                        pooled, serial,
                        "{mode:?} parity differs for {len} bytes at {percent}%"
                    );
                }
            }
        }
    }

    fn accumulate_scaled_by_log_exp(destination: &mut [u8], source: &[u8], coefficient: u16) {
        let gf = shared_gf16();
        for (offset, pair) in source.chunks(2).enumerate() {
            let value = u16::from_le_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
            let at = offset * 2;
            let current = u16::from_le_bytes([destination[at], destination[at + 1]]);
            destination[at..at + 2]
                .copy_from_slice(&(current ^ gf.mul(coefficient, value)).to_le_bytes());
        }
    }

    #[test]
    fn accumulate_scaled_matches_log_exp_multiplication() {
        use super::accumulate_scaled;
        let mut source = recovery_test_bytes(1031, 7);
        source[100..140].fill(0);
        for coefficient in [0, 1, 2, 0x00ff, 0x0100, 0x8000, 0xbeef, 0xffff] {
            for len in [0usize, 1, 2, 3, 40, 101, 1030, 1031] {
                let start = recovery_test_bytes(len.next_multiple_of(2), coefficient.into());
                let mut expected = start.clone();
                accumulate_scaled_by_log_exp(&mut expected, &source[..len], coefficient);
                let mut actual = start;
                accumulate_scaled(&mut actual, &source[..len], coefficient);
                assert_eq!(
                    actual, expected,
                    "coefficient {coefficient:#x}, {len} bytes"
                );
            }
        }
    }

    #[test]
    fn recovery_parity_fingerprints_are_unchanged() {
        // Lengths and CRC32s of records written before the table kernel.
        let mut found = Vec::new();
        for len in [1025usize, 3 * 200 * 1024 + 1] {
            let body = recovery_test_bytes(len, len as u32 ^ 0x5eed);
            for percent in [1u64, 10] {
                for mode in [
                    super::RecoveryMemoryMode::Resident,
                    super::RecoveryMemoryMode::Striped { stripe_len: 998 },
                ] {
                    let plan = plan_inline_recovery(len as u64, percent).unwrap();
                    let mut scratch = std::io::Cursor::new(vec![
                        0u8;
                        (plan.recovery_shards * plan.group_count)
                            as usize
                    ]);
                    let mut produced = Vec::new();
                    super::build_streamed_inline_recovery(
                        &mut std::io::Cursor::new(&body),
                        len as u64,
                        percent,
                        mode,
                        Some(&mut scratch),
                        &mut produced,
                        None,
                        1,
                    )
                    .unwrap();
                    found.push((produced.len(), crc32fast::hash(&produced)));
                }
            }
        }
        assert_eq!(
            found,
            [
                (602, 3_644_122_705),
                (602, 3_644_122_705),
                (602, 3_644_122_705),
                (602, 3_644_122_705),
                (9_492, 2_548_288_029),
                (9_492, 2_548_288_029),
                (94_920, 1_590_988_677),
                (94_920, 1_590_988_677),
            ]
        );
    }

    #[test]
    fn parity_work_splits_into_columns_across_the_workers_it_can_feed() {
        use super::parity_work_split;
        const MIB: usize = 1024 * 1024;
        // 1% recovery on 12 threads: 2 rows, each cut into 4 tasks per worker.
        assert_eq!(parity_work_split(2, 12, 6 * MIB, MIB), Some((12, MIB / 4)));
        // 5%: 10 rows; 48 tasks need 5 columns per row.
        assert_eq!(parity_work_split(10, 12, 5 * MIB, MIB), Some((12, MIB)));
        // Less work than the pool can take: only as many workers as it feeds.
        assert_eq!(parity_work_split(2, 12, 3 * MIB, MIB), Some((6, MIB / 4)));
        // Many rows and few workers: rows are not cut at all.
        assert_eq!(parity_work_split(16, 2, 3, 1), Some((2, 3)));
        // Chunks stay whole 16-bit symbols even when the span is odd.
        assert_eq!(parity_work_split(1, 2, 11, 1), Some((2, 2)));
        assert_eq!(parity_work_split(1, 2, 7, 1), Some((2, 2)));
        // No pool, no rows, or work for only one worker: serial.
        assert_eq!(parity_work_split(10, 1, 64 * MIB, 1), None);
        assert_eq!(parity_work_split(0, 12, 64 * MIB, 1), None);
        assert_eq!(parity_work_split(2, 12, MIB - 2, MIB), None);
    }

    #[test]
    fn recovery_memory_mode_switches_to_striping_under_pressure() {
        let plan = plan_inline_recovery(4 * 1024 * 1024, 10).unwrap();
        let parity_bytes = plan.recovery_shards * plan.group_count;

        let (mode, required) =
            super::choose_recovery_memory_mode(plan, parity_bytes + 1024 * 1024).unwrap();
        assert_eq!(mode, super::RecoveryMemoryMode::Resident);
        assert!(required >= parity_bytes);

        let limit = parity_bytes / 2;
        let (mode, required) = super::choose_recovery_memory_mode(plan, limit).unwrap();
        let super::RecoveryMemoryMode::Striped { stripe_len } = mode else {
            panic!("expected striped mode when parity does not fit");
        };
        assert!(stripe_len.is_multiple_of(2), "stripes must be word aligned");
        assert!(
            required <= limit,
            "striping must fit the budget it was given: {required} > {limit}"
        );
        assert!(required < parity_bytes);
        assert_eq!(
            super::choose_recovery_memory_mode(
                InlineRecoveryPlan {
                    recovery_shards: u64::MAX,
                    group_count: 2,
                    ..plan
                },
                u64::MAX,
            ),
            Err(Error::PlanOverflow)
        );
        let allowance = super::Allowance::limited(2 * 1048576);
        assert_eq!(
            super::choose_recovery_capacity_mode(
                InlineRecoveryPlan {
                    recovery_shards: u64::MAX,
                    group_count: 2,
                    ..plan
                },
                u64::MAX,
                &allowance,
            ),
            Err(Error::PlanOverflow)
        );
    }

    #[test]
    fn rar5_inline_recovery_plan_matches_fixture_formula_examples() {
        assert_eq!(
            plan_inline_recovery(65_681, 5).unwrap(),
            InlineRecoveryPlan {
                data_shards: 65,
                recovery_shards: 3,
                group_count: 1012,
                header_size: 592,
                shard_size: 1604,
            }
        );
        assert_eq!(
            plan_inline_recovery(65_681, 20).unwrap(),
            InlineRecoveryPlan {
                data_shards: 65,
                recovery_shards: 13,
                group_count: 1012,
                header_size: 592,
                shard_size: 1604,
            }
        );
    }

    #[test]
    fn the_streamed_plan_check_stops_where_the_shard_size_outgrows_32_bits() {
        assert_eq!(MAX_STREAMED_RECOVERY_PREFIX, 858_993_124_400);
        for percent in [1, 5, 100] {
            let largest = plan_inline_recovery(MAX_STREAMED_RECOVERY_PREFIX, percent).unwrap();
            assert_eq!(largest.shard_size, u64::from(u32::MAX) - 1);
            assert_eq!(
                check_streamable_plan(largest),
                Ok(largest.payload_size().unwrap())
            );
            let over = plan_inline_recovery(MAX_STREAMED_RECOVERY_PREFIX + 1, percent).unwrap();
            assert_eq!(over.shard_size, u64::from(u32::MAX) + 1);
            assert_eq!(check_streamable_plan(over), Err(Error::PlanOverflow));
        }
        assert_eq!(
            check_streamable_plan(plan_inline_recovery(u64::MAX, 5).unwrap()),
            Err(Error::PlanOverflow)
        );
    }

    #[test]
    fn rar5_inline_recovery_plan_handles_clamps_and_large_prefixes() {
        assert_eq!(
            plan_inline_recovery(0, 0).unwrap(),
            InlineRecoveryPlan {
                data_shards: 1,
                recovery_shards: 1,
                group_count: 0,
                header_size: 80,
                shard_size: 80,
            }
        );
        assert_eq!(
            plan_inline_recovery(200 * 1024, 1000).unwrap(),
            InlineRecoveryPlan {
                data_shards: 200,
                recovery_shards: 200,
                group_count: 1024,
                header_size: 1672,
                shard_size: 2696,
            }
        );
        let largest = plan_inline_recovery(u64::MAX, 1000).unwrap();
        assert_eq!(largest.data_shards, MAX_WINRAR602_DATA_SHARDS);
        assert_eq!(largest.header_size, 1672);
        assert_eq!(largest.group_count, u64::MAX.div_ceil(200) + 1);
        assert_eq!(
            largest.shard_size,
            largest.header_size + largest.group_count
        );
    }

    #[test]
    fn rar5_inline_recovery_plan_keeps_fixed_header_above_64k_groups() {
        let boundary = MAX_WINRAR602_DATA_SHARDS * 0x10000;
        assert_eq!(
            plan_inline_recovery(boundary, 1).unwrap(),
            InlineRecoveryPlan {
                data_shards: 200,
                recovery_shards: 2,
                group_count: 65_536,
                header_size: 1672,
                shard_size: 67_208,
            }
        );
        assert_eq!(
            plan_inline_recovery(boundary + 1, 1).unwrap(),
            InlineRecoveryPlan {
                data_shards: 200,
                recovery_shards: 2,
                group_count: 65_538,
                header_size: 1672,
                shard_size: 67_210,
            }
        );
    }

    #[test]
    fn rar5_recovery_planning_handles_zero_percent_and_tight_budgets() {
        let large = plan_inline_recovery(200 * 1024, 0).unwrap();
        assert_eq!(large.recovery_shards, 0);
        let body = vec![0; 200 * 1024];
        assert_eq!(
            encode_inline_recovery_parity(&body, 0),
            Err(Error::TooManyShards)
        );
        assert_eq!(
            build_structural_inline_recovery_data(&body, 0),
            Err(Error::TooManyShards)
        );

        let plan = plan_inline_recovery(4096, 10).unwrap();
        let (mode, _) = super::choose_recovery_memory_mode(plan, 0).unwrap();
        assert!(matches!(mode, super::RecoveryMemoryMode::Striped { .. }));

        let allowance = super::Allowance::limited(2 * 1048576);
        let (mode, required) =
            super::choose_recovery_capacity_mode(plan, 2 * 1048576, &allowance).unwrap();
        assert_eq!(mode, super::RecoveryMemoryMode::Resident);
        assert!(required <= allowance.available());
    }

    #[test]
    fn gf16_matches_rar5_polynomial_wrap() {
        let gf = Gf16::new();

        assert_eq!(gf.mul(0x8000, 2), 0x100b);
        assert_eq!(gf.mul(0, 0x1234), 0);
        assert_eq!(gf.mul(0x1234, 0), 0);
        assert_eq!(gf.mul(0, 0), 0);
        assert_eq!(gf.mul(1, 0x1234), 0x1234);
    }

    #[test]
    fn shared_gf16_reuses_field_tables() {
        let first = shared_gf16() as *const Gf16;
        let second = shared_gf16() as *const Gf16;

        assert_eq!(first, second);
        assert_eq!(shared_gf16().mul(0x8000, 2), 0x100b);
    }

    #[test]
    fn recovery_output_matches_fingerprints_from_the_bitwise_crc64() {
        let cases: &[(usize, u64, usize, u32)] = &[
            (1025, 10, 602, 2224291460),
            (200 * 1024 + 1, 1, 5396, 1605562733),
            (1024 * 1024 + 7, 10, 138320, 4006196453),
        ];
        for &(len, percent, output_len, fingerprint) in cases {
            let body = recovery_test_bytes(len, len as u32 ^ 0x5555);
            let output = build_structural_inline_recovery_data(&body, percent).unwrap();
            assert_eq!(output.len(), output_len, "{len} bytes at {percent}%");
            assert_eq!(
                crate::crc32::crc32(&output),
                fingerprint,
                "{len} bytes at {percent}%"
            );
        }
    }

    #[test]
    fn crc64_xz_matches_reference_vectors() {
        assert_eq!(crc64_xz(b""), 0);
        assert_eq!(crc64_xz(b"123456789"), 0x995d_c9bb_df19_39fa);
        assert_eq!(crc64_xz(b"testtesttest"), 0x7b1c_2d23_0ede_b436);
    }

    #[test]
    fn raw_crc64_state_matches_reference_vector() {
        assert_eq!(crc64_rar_state(b""), 0);
        assert_eq!(crc64_rar_state(b"te\x80st"), 0xb5db_f958_3a6e_ed4a);
    }

    #[test]
    fn rar5_prefix_split_produces_even_padded_data_shards() {
        let plan = InlineRecoveryPlan {
            data_shards: 3,
            recovery_shards: 1,
            group_count: 4,
            header_size: 96,
            shard_size: 100,
        };
        let shards = split_prefix_shards(b"abcdefghij", plan).unwrap();

        assert_eq!(
            shards,
            vec![b"abcd".to_vec(), b"efgh".to_vec(), b"ij\0\0".to_vec()]
        );
    }

    #[test]
    fn rar5_prefix_split_rejects_prefix_larger_than_plan_capacity() {
        let plan = InlineRecoveryPlan {
            data_shards: 2,
            recovery_shards: 1,
            group_count: 2,
            header_size: 88,
            shard_size: 90,
        };

        assert_eq!(
            split_prefix_shards(b"abcde", plan),
            Err(Error::PrefixExceedsPlan)
        );
        assert_eq!(
            split_prefix_shard_ranges(
                0,
                InlineRecoveryPlan {
                    group_count: usize::MAX as u64,
                    ..plan
                }
            ),
            Err(Error::PlanOverflow)
        );
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn rar5_prefix_split_rejects_unrepresentable_native_geometry() {
        let plan = InlineRecoveryPlan {
            data_shards: u32::MAX as u64 + 1,
            recovery_shards: 1,
            group_count: 1,
            header_size: 80,
            shard_size: 81,
        };
        assert_eq!(split_prefix_shard_ranges(0, plan), Err(Error::PlanOverflow));
        assert_eq!(
            split_prefix_shard_ranges(
                0,
                InlineRecoveryPlan {
                    data_shards: 1,
                    group_count: u32::MAX as u64 + 1,
                    ..plan
                }
            ),
            Err(Error::PlanOverflow)
        );
        assert_eq!(
            split_prefix_shards(
                b"",
                InlineRecoveryPlan {
                    data_shards: 1,
                    group_count: u32::MAX as u64 + 1,
                    ..plan
                }
            ),
            Err(Error::PlanOverflow)
        );
    }

    #[test]
    fn rar5_prefix_split_handles_extra_empty_data_shards() {
        let plan = InlineRecoveryPlan {
            data_shards: 3,
            recovery_shards: 1,
            group_count: 4,
            header_size: 96,
            shard_size: 100,
        };

        assert_eq!(
            split_prefix_shard_ranges(3, plan).unwrap(),
            vec![0..3, 3..3, 3..3]
        );
        assert_eq!(
            split_prefix_shards(b"abc", plan).unwrap(),
            vec![b"abc\0".to_vec(), vec![0; 4], vec![0; 4]]
        );
    }

    #[test]
    fn gf16_inverse_round_trips_nonzero_elements() {
        let gf = Gf16::new();

        for value in [1, 2, 3, 0x100b, 0x8000, 0xffff] {
            let inverse = gf.inv(value).unwrap();
            assert_eq!(gf.mul(value, inverse), 1);
        }
        assert_eq!(gf.inv(0), Err(Error::SingularElement));
    }

    #[test]
    fn gf16_public_arithmetic_matches_field_identities() {
        let gf = Gf16::default();
        assert_eq!(gf.add(0x1234, 0x1234), 0);
        assert_eq!(gf.add(0x1234, 0), 0x1234);
        assert_eq!(gf.div(0x1234, 1), Ok(0x1234));
        assert_eq!(gf.div(0, 0x1234), Ok(0));
        assert_eq!(gf.div(1, 0), Err(Error::SingularElement));
    }

    #[test]
    fn rar5_recovery_errors_display_and_preserve_typed_sources() {
        for error in [
            Error::Cancelled,
            Error::BadRecoveryChunk,
            Error::OddShardSize,
            Error::PlanOverflow,
            Error::PrefixExceedsPlan,
            Error::TooManyDamagedShards,
            Error::ShardSizeMismatch,
            Error::TooManyShards,
            Error::SingularElement,
            Error::RebuildTooLarge,
            Error::RepairWorkspaceLimitExceeded {
                limit: 1,
                required: 2,
            },
            Error::Io(std::io::ErrorKind::BrokenPipe),
        ] {
            assert!(!error.to_string().is_empty());
            assert!(std::error::Error::source(&error).is_none());
        }
        let typed = Error::TypedIo(Box::new(crate::Error::Cancelled));
        assert_eq!(typed.to_string(), crate::Error::Cancelled.to_string());
        assert!(std::error::Error::source(&typed).is_some());
    }

    #[test]
    fn rar5_cauchy_encoder_matrix_uses_inverse_xor_denominators() {
        let gf = Gf16::new();
        let matrix = make_encoder_matrix(3, 2).unwrap();

        assert_eq!(matrix.len(), 2);
        assert_eq!(matrix[0].len(), 3);
        for (i, row) in matrix.iter().enumerate() {
            for (j, &cell) in row.iter().enumerate() {
                let denominator = ((i + 3) ^ j) as u16;
                assert_eq!(gf.mul(cell, denominator), 1);
            }
        }
    }

    #[test]
    fn rar5_recovery_equations_do_not_materialize_unused_rows_or_columns() {
        let gf = shared_gf16();
        let equations = recovery_equations(
            gf,
            32_000,
            &[0, 31_999],
            &[(32_000, &[])],
            &crate::read_control::ReadControl::default(),
        )
        .unwrap();
        assert_eq!(
            equations,
            vec![vec![
                gf.inv(64_000).unwrap(),
                gf.inv(64_000 ^ 31_999).unwrap()
            ]]
        );
        assert_eq!(equations[0].capacity(), 2);
        assert_eq!(
            make_encoder_matrix(usize::MAX, 1),
            Err(Error::TooManyShards)
        );
    }

    #[test]
    fn rar5_repair_keeps_empty_shards_and_padding_virtual() {
        // A valid sparse record describes 8 MiB of padded data capacity, but
        // only one byte of real data and one available high-index parity row.
        let data_count = 2048usize;
        let row = data_count - 1;
        let group_count = 4096usize;
        let header_size = 0x48 + data_count * 8;
        let shard_size = header_size + group_count;
        let mut chunk = vec![0; shard_size];
        chunk[..4].copy_from_slice(b"{RB}");
        chunk[0x0c..0x10].copy_from_slice(&(shard_size as u32).to_le_bytes());
        chunk[0x10..0x14].copy_from_slice(&(header_size as u32).to_le_bytes());
        chunk[0x14] = 1;
        chunk[0x15] = 1;
        chunk[0x22..0x2a].copy_from_slice(&1u64.to_le_bytes());
        chunk[0x2a..0x32].copy_from_slice(&(group_count as u64).to_le_bytes());
        chunk[0x32..0x3a].copy_from_slice(&(shard_size as u64).to_le_bytes());
        chunk[0x3a..0x3c].copy_from_slice(&(data_count as u16).to_le_bytes());
        chunk[0x3c..0x3e].copy_from_slice(&(data_count as u16).to_le_bytes());
        chunk[0x3e..0x40].copy_from_slice(&(row as u16).to_le_bytes());
        chunk[0x40..0x48].copy_from_slice(&crc64_rar_state(b"a").to_le_bytes());
        let gf = shared_gf16();
        let parity = gf.mul(gf.inv((data_count + row) as u16).unwrap(), b'a' as u16);
        chunk[header_size..header_size + 2].copy_from_slice(&parity.to_le_bytes());
        let crc = crc64_xz(&chunk[0x0c..]);
        chunk[4..0x0c].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(repair_inline_recovery_prefix(b"a", &chunk).unwrap(), b"a");
        assert_eq!(repair_inline_recovery_prefix(b"b", &chunk).unwrap(), b"a");
        let mut empty_reads = 0;
        let repaired = repair_inline_recovery_prefix_shards(1, &chunk, |range| {
            assert!(range.len() <= 1);
            if range.is_empty() {
                empty_reads += 1;
            }
            Ok(b"b"[range].to_vec())
        })
        .unwrap();
        assert_eq!(repaired, vec![(0..1, b"a".to_vec())]);
        // Empty columns are checked once and never reread during RHS solving.
        assert_eq!(empty_reads, data_count - 1);
    }

    #[test]
    fn rar5_cauchy_encoder_matrix_rejects_impossible_shard_counts() {
        assert_eq!(make_encoder_matrix(0, 1), Err(Error::TooManyShards));
        assert_eq!(make_encoder_matrix(1, 0), Err(Error::TooManyShards));
        assert_eq!(make_encoder_matrix(65535, 1), Err(Error::TooManyShards));
    }

    #[test]
    fn rar5_recovery_inverse_matrix_solves_reused_equations() {
        let gf = shared_gf16();
        let equations = vec![vec![3, 5], vec![7, 11]];
        let expected = [0x1234, 0xabcd];
        let rhs = equations
            .iter()
            .map(|row| gf.mul(row[0], expected[0]) ^ gf.mul(row[1], expected[1]))
            .collect::<Vec<_>>();

        let rhs: Vec<_> = rhs
            .iter()
            .map(|value: &u16| value.to_le_bytes().to_vec())
            .collect();
        let inverse = invert_linear_system_matrix(gf, &equations).unwrap();
        let mut solved = [[0u8; 2]; 2];
        let [first, second] = &mut solved;
        fold_inverse(
            &inverse,
            &rhs,
            &mut [first, second],
            &crate::read_control::ReadControl::default(),
        )
        .unwrap();

        assert_eq!(solved.map(u16::from_le_bytes), expected);
    }

    #[test]
    fn rar5_recovery_matrix_rejects_non_square_inputs() {
        let gf = shared_gf16();
        assert_eq!(
            invert_linear_system_matrix(gf, &[vec![1], vec![1]]),
            Err(Error::BadRecoveryChunk)
        );
        let rhs = [vec![1, 0], vec![2, 0]];
        let [mut first, mut second] = [[0u8; 2]; 2];
        assert_eq!(
            fold_inverse(
                &[vec![1]],
                &rhs,
                &mut [&mut first, &mut second],
                &crate::read_control::ReadControl::default()
            ),
            Err(Error::BadRecoveryChunk)
        );
        assert_eq!(
            fold_inverse(
                &[vec![1], vec![1]],
                &rhs,
                &mut [&mut first, &mut second],
                &crate::read_control::ReadControl::default()
            ),
            Err(Error::BadRecoveryChunk)
        );
    }

    #[test]
    fn rar5_recovery_matrix_handles_zero_elimination_factors() {
        let gf = shared_gf16();
        assert_eq!(
            invert_linear_system_matrix(gf, &[vec![1, 0], vec![0, 1]]),
            Ok(vec![vec![1, 0], vec![0, 1]])
        );
    }

    #[test]
    fn rar5_budgeted_encoder_rejects_invalid_shard_counts() {
        let allowance = super::Allowance::default();
        let gf = shared_gf16().view();
        for (data, recovery) in [(0, 1), (1, 0), (usize::MAX, 1)] {
            assert_eq!(
                super::encoder_matrix_with_allowance(data, recovery, &gf, &allowance).unwrap_err(),
                Error::TooManyShards
            );
        }
    }

    #[test]
    fn rar5_parity_encoder_generates_systematic_recovery_shards() {
        let first = [1, 0, 2, 0, 3, 0, 4, 0];
        let parity = encode_parity_shards(&[&first], 1).unwrap();

        assert_eq!(parity, [first.to_vec()]);
    }

    #[test]
    fn rar5_parity_encoder_applies_cauchy_matrix_coefficients() {
        let gf = Gf16::new();
        let first = [1, 0, 2, 0];
        let second = [3, 0, 4, 0];
        let matrix = make_encoder_matrix(2, 2).unwrap();
        let parity = encode_parity_shards(&[&first, &second], 2).unwrap();

        for recovery_index in 0..2 {
            for word_index in 0..2 {
                let offset = word_index * 2;
                let left = u16::from_le_bytes([first[offset], first[offset + 1]]);
                let right = u16::from_le_bytes([second[offset], second[offset + 1]]);
                let expected = gf.mul(matrix[recovery_index][0], left)
                    ^ gf.mul(matrix[recovery_index][1], right);
                assert_eq!(
                    u16::from_le_bytes([
                        parity[recovery_index][offset],
                        parity[recovery_index][offset + 1],
                    ]),
                    expected
                );
            }
        }
    }

    #[test]
    fn rar5_inline_recovery_parity_splits_and_encodes_prefix() {
        let prefix = b"RAR5 inline recovery parity payload input";
        let (plan, parity) = encode_inline_recovery_parity(prefix, 10).unwrap();

        assert_eq!(plan, plan_inline_recovery(prefix.len() as u64, 10).unwrap());
        assert_eq!(parity.len(), plan.recovery_shards as usize);
        assert!(parity
            .iter()
            .all(|shard| shard.len() == plan.group_count as usize));

        let data_shards = split_prefix_shards(prefix, plan).unwrap();
        let shard_refs: Vec<&[u8]> = data_shards.iter().map(Vec::as_slice).collect();
        assert_eq!(
            parity,
            encode_parity_shards(&shard_refs, plan.recovery_shards as usize).unwrap()
        );
    }

    #[test]
    fn rar5_structural_inline_recovery_data_writes_chunks_and_crc64() {
        let prefix = b"RAR5 structural inline recovery data";
        let (plan, parity) = encode_inline_recovery_parity(prefix, 10).unwrap();
        let data = build_structural_inline_recovery_data(prefix, 10).unwrap();

        assert_eq!(data.len(), plan.payload_size().unwrap() as usize);
        for (shard_index, payload) in parity.iter().enumerate() {
            let chunk_start = shard_index * plan.shard_size as usize;
            let chunk = &data[chunk_start..chunk_start + plan.shard_size as usize];
            assert_eq!(&chunk[..4], b"{RB}");
            assert_eq!(
                u64::from_le_bytes(chunk[4..12].try_into().unwrap()),
                crc64_xz(&chunk[0x0c..])
            );
            assert_eq!(
                u32::from_le_bytes(chunk[0x0c..0x10].try_into().unwrap()) as u64,
                plan.shard_size
            );
            assert_eq!(
                u32::from_le_bytes(chunk[0x10..0x14].try_into().unwrap()) as u64,
                plan.header_size
            );
            assert_eq!(chunk[0x14], 1);
            assert_eq!(chunk[0x15], 1);
            assert_eq!(
                u64::from_le_bytes(chunk[0x22..0x2a].try_into().unwrap()),
                prefix.len() as u64
            );
            assert_eq!(
                u16::from_le_bytes(chunk[0x3e..0x40].try_into().unwrap()) as usize,
                shard_index
            );
            let shard_ranges = split_prefix_shard_ranges(prefix.len(), plan).unwrap();
            assert_eq!(
                u32::from_le_bytes(chunk[0x1e..0x22].try_into().unwrap()) as usize,
                shard_ranges.last().unwrap().len()
            );
            for (data_index, range) in shard_ranges.iter().enumerate() {
                let state_offset = 0x40 + data_index * 8;
                assert_eq!(
                    u64::from_le_bytes(chunk[state_offset..state_offset + 8].try_into().unwrap()),
                    crc64_rar_state(&prefix[range.clone()])
                );
            }
            assert_eq!(&chunk[plan.header_size as usize..], payload);
        }
    }

    #[test]
    fn rar5_structural_inline_recovery_round_trips_above_64k_groups() {
        let prefix_len = (MAX_WINRAR602_DATA_SHARDS * 0x10000 + 1) as usize;
        let prefix: Vec<u8> = (0..prefix_len).map(|index| index as u8).collect();
        let plan = plan_inline_recovery(prefix.len() as u64, 1).unwrap();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 1).unwrap();

        assert_eq!(plan.header_size, 1672);
        assert_eq!(plan.group_count, 65_538);
        assert_eq!(recovery_data.len(), plan.payload_size().unwrap() as usize);
        for shard_index in 0..plan.recovery_shards as usize {
            let chunk_start = shard_index * plan.shard_size as usize;
            let chunk_end = chunk_start + plan.shard_size as usize;
            let chunk = &recovery_data[chunk_start..chunk_end];
            assert_eq!(
                u32::from_le_bytes(chunk[0x0c..0x10].try_into().unwrap()) as u64,
                plan.shard_size
            );
            assert_eq!(
                u32::from_le_bytes(chunk[0x10..0x14].try_into().unwrap()) as u64,
                plan.header_size
            );
            assert_eq!(
                u64::from_le_bytes(chunk[0x04..0x0c].try_into().unwrap()),
                crc64_xz(&chunk[0x0c..])
            );
        }

        assert_eq!(
            repair_inline_recovery_prefix(&prefix, &recovery_data).unwrap(),
            prefix
        );
        let mut damaged = prefix.clone();
        damaged[0] ^= 0xff;
        assert_eq!(
            repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap(),
            prefix
        );
    }

    #[test]
    fn rar5_structural_inline_recovery_uses_shared_final_state() {
        let prefix: Vec<u8> = (0..(256 * 1024)).map(|index| index as u8).collect();
        let (plan, parity) = encode_inline_recovery_parity(&prefix, 20).unwrap();
        assert!(plan.recovery_shards > 1);
        let data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let expected = crc64_rar_state(&parity[0]);

        for shard_index in 0..plan.recovery_shards as usize {
            let chunk_start = shard_index * plan.shard_size as usize;
            let final_state_offset = chunk_start + 0x40 + plan.data_shards as usize * 8;
            assert_eq!(
                u64::from_le_bytes(
                    data[final_state_offset..final_state_offset + 8]
                        .try_into()
                        .unwrap()
                ),
                expected
            );
        }
    }

    #[test]
    fn rar5_inline_recovery_rejects_malformed_chunk_fields() {
        let valid = build_structural_inline_recovery_data(b"prefix", 10).unwrap();
        let parse = |chunk: &[u8]| {
            super::parse_inline_recovery_chunk_with_control(
                chunk,
                &crate::read_control::ReadControl::default(),
            )
            .unwrap_err()
        };
        let mut cases = Vec::new();
        cases.push(("short header", valid[..0x47].to_vec()));
        let mut wrong_magic = valid.clone();
        wrong_magic[0] = b'X';
        cases.push(("wrong magic", wrong_magic));
        let mut truncated = valid.clone();
        truncated.pop();
        cases.push(("truncated chunk", truncated));
        let mut bad_crc = valid.clone();
        bad_crc[0x40] ^= 1;
        cases.push(("bad CRC", bad_crc));

        let mut altered = |name, edit: fn(&mut Vec<u8>)| {
            let mut chunk = valid.clone();
            edit(&mut chunk);
            let crc = crc64_xz(&chunk[0x0c..]);
            chunk[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());
            cases.push((name, chunk));
        };
        altered("short declared header", |chunk| {
            chunk[0x10..0x14].copy_from_slice(&0x47u32.to_le_bytes())
        });
        altered("header larger than chunk", |chunk| {
            let size = u32::try_from(chunk.len()).unwrap() + 1;
            chunk[0x10..0x14].copy_from_slice(&size.to_le_bytes());
        });
        altered("wrong format version", |chunk| chunk[0x14] = 2);
        altered("wrong record version", |chunk| chunk[0x15] = 2);
        altered("wrong shard size", |chunk| chunk[0x32] ^= 1);
        altered("out-of-range shard index", |chunk| chunk[0x3e] = 1);
        altered("wrong data-state count", |chunk| chunk[0x3a] = 2);
        altered("no data shards", |chunk| {
            let parity_len = (chunk.len() - 0x48) as u64;
            chunk[0x10..0x14].copy_from_slice(&0x48u32.to_le_bytes());
            chunk[0x2a..0x32].copy_from_slice(&parity_len.to_le_bytes());
            chunk[0x3a..0x3c].copy_from_slice(&0u16.to_le_bytes());
        });
        altered("wrong parity length", |chunk| chunk[0x2a] ^= 2);
        altered("no recovery shards", |chunk| chunk[0x3c..0x3e].fill(0));

        for (name, chunk) in cases {
            assert_eq!(parse(&chunk), Error::BadRecoveryChunk, "{name}");
        }
    }

    #[test]
    fn rar5_recovery_scan_ignores_truncated_markers() {
        for data in [&b""[..], &b"{RB"[..], &b"noise{RB}"[..]] {
            assert_eq!(
                repair_inline_recovery_prefix(b"prefix", data),
                Err(Error::BadRecoveryChunk)
            );
        }
        let valid = build_structural_inline_recovery_data(b"prefix", 10).unwrap();
        let mut data = b"{RB}".to_vec();
        data.extend_from_slice(&valid);
        assert_eq!(
            repair_inline_recovery_prefix(b"prefix", &data),
            Ok(b"prefix".to_vec())
        );
    }

    #[test]
    fn rar5_repair_rejects_odd_gf16_shards() {
        let mut chunk = build_structural_inline_recovery_data(b"x", 10).unwrap();
        chunk.pop();
        let size = chunk.len() as u32;
        chunk[0x0c..0x10].copy_from_slice(&size.to_le_bytes());
        chunk[0x2a..0x32].copy_from_slice(&1u64.to_le_bytes());
        chunk[0x32..0x3a].copy_from_slice(&(size as u64).to_le_bytes());
        let crc = crc64_xz(&chunk[0x0c..]);
        chunk[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());

        assert_eq!(
            super::parse_inline_recovery_chunk_with_control(
                &chunk,
                &crate::read_control::ReadControl::default()
            )
            .unwrap_err(),
            Error::BadRecoveryChunk
        );
        assert_eq!(
            repair_inline_recovery_prefix(b"y", &chunk),
            Err(Error::BadRecoveryChunk)
        );
    }

    #[test]
    fn rar5_recovery_rejects_shard_counts_above_field_capacity() {
        let data_shards = 32_768u16;
        let recovery_shards = 32_768u16;
        let header_size = 0x48 + data_shards as usize * 8;
        let mut chunk = vec![0u8; header_size];
        chunk[..4].copy_from_slice(b"{RB}");
        chunk[0x0c..0x10].copy_from_slice(&(header_size as u32).to_le_bytes());
        chunk[0x10..0x14].copy_from_slice(&(header_size as u32).to_le_bytes());
        chunk[0x14] = 1;
        chunk[0x15] = 1;
        chunk[0x32..0x3a].copy_from_slice(&(header_size as u64).to_le_bytes());
        chunk[0x3a..0x3c].copy_from_slice(&data_shards.to_le_bytes());
        chunk[0x3c..0x3e].copy_from_slice(&recovery_shards.to_le_bytes());
        let crc = crc64_xz(&chunk[0x0c..]);
        chunk[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());

        assert_eq!(
            super::parse_inline_recovery_chunk_with_control(
                &chunk,
                &crate::read_control::ReadControl::default()
            )
            .unwrap_err(),
            Error::BadRecoveryChunk
        );
    }

    #[test]
    fn rar5_repair_rejects_inconsistent_recovery_chunks() {
        let prefix = recovery_test_bytes(32_000, 33);
        let plan = plan_inline_recovery(prefix.len() as u64, 20).unwrap();
        assert!(plan.recovery_shards > 2);
        let valid = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let start = plan.shard_size as usize;
        let end = start + plan.shard_size as usize;
        for (name, edit) in [
            ("states", 0x40),
            ("protected size", 0x22),
            ("recovery shard count", 0x3c),
        ] {
            let mut recovery_data = valid.clone();
            recovery_data[start + edit] ^= 1;
            let crc = crc64_xz(&recovery_data[start + 0x0c..end]);
            recovery_data[start + 0x04..start + 0x0c].copy_from_slice(&crc.to_le_bytes());

            assert_eq!(
                repair_inline_recovery_prefix(&prefix, &recovery_data),
                Err(Error::BadRecoveryChunk),
                "{name}"
            );
            assert_eq!(
                repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
                    Ok(prefix[range].to_vec())
                }),
                Err(Error::BadRecoveryChunk),
                "{name}"
            );
        }
    }

    #[test]
    fn rar5_prefix_repair_checks_protected_size_and_healthy_ranges() {
        let prefix = b"prefix";
        let recovery_data = build_structural_inline_recovery_data(prefix, 10).unwrap();
        assert_eq!(
            repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
                Ok(prefix[range].to_vec())
            }),
            Ok(Vec::new())
        );
        assert_eq!(
            repair_inline_recovery_prefix(b"prefix!", &recovery_data),
            Err(Error::BadRecoveryChunk)
        );
        assert_eq!(
            repair_inline_recovery_prefix_shards(prefix.len() + 1, &recovery_data, |_| {
                panic!("unexpected read after mismatched protected size")
            }),
            Err(Error::BadRecoveryChunk)
        );
    }

    #[test]
    fn rar5_range_repair_preserves_short_and_failed_callback_reads() {
        let prefix = recovery_test_bytes(32_000, 41);
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut damaged = prefix.clone();
        damaged[0] ^= 1;

        let short_first =
            repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
                Ok(damaged[range.start..range.end - 1].to_vec())
            });
        assert_eq!(short_first, Err(Error::ShardSizeMismatch));
        let failed_first =
            repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |_| {
                Err(Error::Io(std::io::ErrorKind::PermissionDenied))
            });
        assert_eq!(
            failed_first,
            Err(Error::Io(std::io::ErrorKind::PermissionDenied))
        );

        let mut reads = 0;
        let data_shards = plan_inline_recovery(prefix.len() as u64, 20)
            .unwrap()
            .data_shards as usize;
        let short_second =
            repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
                reads += 1;
                let end = if reads > data_shards {
                    range.end - 1
                } else {
                    range.end
                };
                Ok(damaged[range.start..end].to_vec())
            });
        assert_eq!(short_second, Err(Error::ShardSizeMismatch));
        assert!(reads > data_shards);

        reads = 0;
        let failed_second =
            repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
                reads += 1;
                if reads > data_shards {
                    Err(Error::Io(std::io::ErrorKind::PermissionDenied))
                } else {
                    Ok(damaged[range].to_vec())
                }
            });
        assert_eq!(
            failed_second,
            Err(Error::Io(std::io::ErrorKind::PermissionDenied))
        );
        assert!(reads > data_shards);
    }

    #[test]
    fn rar5_range_repair_rejects_damage_beyond_available_parity() {
        let prefix = recovery_test_bytes(10_000, 73);
        let plan = plan_inline_recovery(prefix.len() as u64, 10).unwrap();
        assert_eq!(plan.recovery_shards, 1);
        let recovery_data = build_structural_inline_recovery_data(&prefix, 10).unwrap();
        let mut damaged = prefix.clone();
        damaged[0] ^= 1;
        damaged[plan.group_count as usize] ^= 1;
        assert_eq!(
            repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
                Ok(damaged[range].to_vec())
            }),
            Err(Error::TooManyDamagedShards)
        );
    }

    #[test]
    fn rar5_prefix_repair_rejects_duplicate_parity_rows() {
        let prefix = recovery_test_bytes(10_000, 83);
        let plan = plan_inline_recovery(prefix.len() as u64, 20).unwrap();
        assert!(plan.recovery_shards >= 2);
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let first = &recovery_data[..plan.shard_size as usize];
        let duplicated = [first, first].concat();
        let mut damaged = prefix.clone();
        damaged[0] ^= 1;
        damaged[plan.group_count as usize] ^= 1;
        assert_eq!(
            repair_inline_recovery_prefix(&damaged, &duplicated),
            Err(Error::SingularElement)
        );
        assert_eq!(
            repair_inline_recovery_prefix_shards(prefix.len(), &duplicated, |range| {
                Ok(damaged[range].to_vec())
            }),
            Err(Error::SingularElement)
        );
    }

    #[test]
    fn rar5_range_repair_restores_short_final_shard() {
        let prefix = recovery_test_bytes(10_001, 79);
        let plan = plan_inline_recovery(prefix.len() as u64, 20).unwrap();
        let final_start = (plan.data_shards as usize - 1) * plan.group_count as usize;
        assert!(final_start < prefix.len());
        assert!((prefix.len() - final_start) % 2 == 1);
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut damaged = prefix.clone();
        damaged[final_start] ^= 1;
        let repaired =
            repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
                Ok(damaged[range].to_vec())
            })
            .unwrap();
        assert_eq!(
            repaired,
            vec![(final_start..prefix.len(), prefix[final_start..].to_vec())]
        );
    }

    #[test]
    fn rar5_parity_encoder_rejects_invalid_shard_shapes() {
        assert_eq!(encode_parity_shards(&[], 1), Err(Error::TooManyShards));
        assert_eq!(
            encode_parity_shards(&[&[1, 2, 3]], 1),
            Err(Error::OddShardSize)
        );
        assert_eq!(
            encode_parity_shards(&[&[1, 2], &[3, 4, 5, 6]], 1),
            Err(Error::ShardSizeMismatch)
        );
    }

    #[test]
    fn rar5_inline_recovery_repairs_single_damaged_data_shard() {
        let prefix: Vec<u8> = (0..32_000).map(|index| (index * 17) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut damaged = prefix.clone();
        damaged[1500..1537].fill(0xa5);

        let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

        assert_eq!(repaired, prefix);
    }

    #[test]
    fn rar5_inline_recovery_skips_damaged_recovery_chunks_if_enough_survive() {
        let prefix: Vec<u8> = (0..32_000).map(|index| (index * 13) as u8).collect();
        let mut recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        recovery_data[0x48] ^= 0xff;
        let mut damaged = prefix.clone();
        damaged[1024..1300].fill(0xa5);

        let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

        assert_eq!(repaired, prefix);
    }

    #[test]
    fn rar5_inline_recovery_repairs_multiple_damaged_data_shards() {
        let prefix: Vec<u8> = (0..128_000).map(|index| (index * 31) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut damaged = prefix.clone();
        damaged[100..500].fill(0x11);
        damaged[4_000..4_400].fill(0x22);
        damaged[9_000..9_400].fill(0x33);

        let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

        assert_eq!(repaired, prefix);
    }

    #[test]
    fn rar5_inline_recovery_returns_only_repaired_shard_ranges() {
        let prefix: Vec<u8> = (0..128_000).map(|index| (index * 29) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut damaged = prefix.clone();
        damaged[100..500].fill(0x11);
        damaged[9_000..9_400].fill(0x33);

        let repaired_shards =
            repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
                Ok(damaged[range].to_vec())
            })
            .unwrap();
        assert!(!repaired_shards.is_empty());

        let mut repaired = damaged;
        for (range, data) in repaired_shards {
            assert_eq!(range.len(), data.len());
            repaired[range].copy_from_slice(&data);
        }

        assert_eq!(repaired, prefix);
    }

    #[test]
    fn rar5_inline_recovery_archive_scans_chunks_and_repairs_prefix() {
        let prefix: Vec<u8> = (0..32_000).map(|index| (index * 13) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut archive = prefix.clone();
        archive.extend_from_slice(b"service header bytes before chunks");
        archive.extend_from_slice(&recovery_data);
        archive.extend_from_slice(b"end bytes");
        let mut damaged = archive.clone();
        damaged[256..320].fill(0x5a);

        let repaired = repair_inline_recovery_archive(&damaged).unwrap();

        assert_eq!(repaired, archive);
    }

    #[test]
    fn rar5_inline_recovery_rebuilds_a_record_above_one_hundred_percent() {
        // WinRAR takes -rr up to 1000%, so a record can hold more recovery
        // shards than data shards. plan_inline_recovery never produces one,
        // and a rebuild that works back from a percentage cannot match it.
        let prefix: Vec<u8> = (0..32_000).map(|index| (index * 13) as u8).collect();
        let mut plan = plan_inline_recovery(prefix.len() as u64, 100).unwrap();
        plan.recovery_shards = plan.data_shards * 3;
        let recovery_data = build_inline_recovery_data_for_plan(&prefix, plan).unwrap();
        let mut archive = prefix.clone();
        archive.extend_from_slice(b"service header bytes before chunks");
        let record_start = archive.len();
        archive.extend_from_slice(&recovery_data);
        archive.extend_from_slice(b"end bytes");

        let mut damaged = archive.clone();
        damaged[256..320].fill(0x5a);
        damaged[record_start + 0x48] ^= 0xff;

        let repaired = repair_inline_recovery_archive(&damaged).unwrap();

        assert_eq!(repaired, archive);
    }

    #[test]
    fn rar5_inline_recovery_picks_the_outermost_record() {
        // A stored archive nested inside this one has its own {RB} chunks, and
        // they sit earlier in the file than ours.
        let inner_prefix: Vec<u8> = (0..16_000).map(|index| (index * 7) as u8).collect();
        let mut inner = inner_prefix.clone();
        inner.extend_from_slice(&build_structural_inline_recovery_data(&inner_prefix, 20).unwrap());

        let mut prefix = b"outer archive header bytes".to_vec();
        prefix.extend_from_slice(&inner);
        prefix.extend_from_slice(&recovery_test_bytes(9_000, 5));
        let mut archive = prefix.clone();
        archive.extend_from_slice(b"service header bytes before chunks");
        let record_start = archive.len();
        archive.extend_from_slice(&build_structural_inline_recovery_data(&prefix, 20).unwrap());
        archive.extend_from_slice(b"end bytes");

        let mut damaged = archive.clone();
        damaged[record_start + 0x48] ^= 0xff;

        let repaired = repair_inline_recovery_archive(&damaged).unwrap();

        assert_eq!(repaired, archive);
    }

    #[test]
    fn rar5_inline_recovery_archive_accepts_healthy_archive() {
        let prefix: Vec<u8> = (0..32_000).map(|index| (index * 17) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut archive = prefix.clone();
        archive.extend_from_slice(b"service header bytes before chunks");
        archive.extend_from_slice(&recovery_data);
        archive.extend_from_slice(b"end bytes");

        let repaired = repair_inline_recovery_archive(&archive).unwrap();

        assert_eq!(repaired, archive);
    }

    #[test]
    fn rar5_archive_repair_rejects_impossible_protected_ranges() {
        let chunk = build_structural_inline_recovery_data(b"x", 10).unwrap();
        assert_eq!(
            repair_inline_recovery_archive(&chunk),
            Err(Error::BadRecoveryChunk)
        );

        let mut beyond_end = chunk.clone();
        let protected_size = beyond_end.len() as u64 + 1;
        beyond_end[0x22..0x2a].copy_from_slice(&protected_size.to_le_bytes());
        let crc = crc64_xz(&beyond_end[0x0c..]);
        beyond_end[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            repair_inline_recovery_archive(&beyond_end),
            Err(Error::BadRecoveryChunk)
        );
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn rar5_archive_repair_rejects_protected_size_above_native_range() {
        let mut chunk = build_structural_inline_recovery_data(b"x", 10).unwrap();
        chunk[0x22..0x2a].copy_from_slice(&(u32::MAX as u64 + 1).to_le_bytes());
        let crc = crc64_xz(&chunk[0x0c..]);
        chunk[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            repair_inline_recovery_archive(&chunk),
            Err(Error::PlanOverflow)
        );
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn rar5_archive_repair_rejects_native_payload_and_offset_overflows() {
        let mut chunk = build_structural_inline_recovery_data(b"x", 10).unwrap();
        let group_count = 65_536u64;
        let shard_size = 80 + group_count;
        chunk.resize(shard_size as usize, 0);
        chunk[0x0c..0x10].copy_from_slice(&(shard_size as u32).to_le_bytes());
        chunk[0x2a..0x32].copy_from_slice(&group_count.to_le_bytes());
        chunk[0x32..0x3a].copy_from_slice(&shard_size.to_le_bytes());
        chunk[0x3c..0x3e].copy_from_slice(&(u16::MAX - 1).to_le_bytes());
        let crc = crc64_xz(&chunk[0x0c..]);
        chunk[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());
        let mut archive = b"x".to_vec();
        archive.extend_from_slice(&chunk);
        assert_eq!(
            repair_inline_recovery_archive(&archive),
            Err(Error::PlanOverflow)
        );
        chunk[0x3e..0x40].copy_from_slice(&(u16::MAX - 2).to_le_bytes());
        let crc = crc64_xz(&chunk[0x0c..]);
        chunk[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());
        archive.truncate(1);
        archive.extend_from_slice(&chunk);
        assert_eq!(
            repair_inline_recovery_archive(&archive),
            Err(Error::BadRecoveryChunk)
        );

        let mut chunk = build_structural_inline_recovery_data(b"abcd", 10).unwrap();
        let group_count = 65_458u64;
        let shard_size = 80 + group_count;
        assert_eq!((u16::MAX as u64 - 1) * shard_size, u32::MAX as u64 - 3);
        chunk.resize(shard_size as usize, 0);
        chunk[0x0c..0x10].copy_from_slice(&(shard_size as u32).to_le_bytes());
        chunk[0x2a..0x32].copy_from_slice(&group_count.to_le_bytes());
        chunk[0x32..0x3a].copy_from_slice(&shard_size.to_le_bytes());
        chunk[0x3c..0x3e].copy_from_slice(&(u16::MAX - 1).to_le_bytes());
        let crc = crc64_xz(&chunk[0x0c..]);
        chunk[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());
        let mut archive = b"abcd".to_vec();
        archive.extend_from_slice(&chunk);
        assert_eq!(
            repair_inline_recovery_archive(&archive),
            Err(Error::PlanOverflow)
        );
    }

    #[test]
    fn rar5_archive_repair_rejects_missing_chunks_and_invalid_end_header_source() {
        assert_eq!(
            repair_inline_recovery_archive(b"no recovery chunks"),
            Err(Error::BadRecoveryChunk)
        );

        let prefix = b"not a RAR archive";
        let mut archive = prefix.to_vec();
        archive.extend_from_slice(&build_structural_inline_recovery_data(prefix, 10).unwrap());
        assert_eq!(
            repair_inline_recovery_archive(&archive),
            Err(Error::BadRecoveryChunk)
        );

        let options = super::InlineRepairOptions {
            record_range: Some(0..0),
            ..Default::default()
        };
        assert_eq!(
            super::repair_inline_recovery_archive_with_report(&archive, &options).unwrap_err(),
            Error::BadRecoveryChunk
        );
    }

    #[test]
    fn rar5_end_header_errors_preserve_cancellation() {
        assert_eq!(
            super::map_recovery_end_error(crate::Error::Cancelled),
            Error::Cancelled
        );
        assert_eq!(
            super::map_recovery_end_error(crate::Error::WrongPasswordOrCorruptData),
            Error::BadRecoveryChunk
        );
    }

    #[test]
    fn rar5_record_rebuild_checks_resource_and_record_length() {
        let control = crate::read_control::ReadControl::default();
        let impossible = InlineRecoveryPlan {
            data_shards: 1,
            recovery_shards: u64::MAX,
            group_count: 2,
            header_size: 80,
            shard_size: 82,
        };
        assert_eq!(
            super::rebuild_inline_recovery_record_with_control(
                &[],
                b"x",
                0..0,
                impossible,
                &control
            ),
            Err(Error::PlanOverflow)
        );
        let huge = InlineRecoveryPlan {
            data_shards: 1,
            recovery_shards: 1000,
            group_count: 2_000_000,
            header_size: 80,
            shard_size: 2_000_080,
        };
        assert_eq!(
            super::rebuild_inline_recovery_record_with_control(&[], b"x", 0..0, huge, &control),
            Err(Error::RebuildTooLarge)
        );

        let plan = plan_inline_recovery(1, 10).unwrap();
        assert_eq!(
            super::rebuild_inline_recovery_record_with_control(&[], b"x", 0..0, plan, &control),
            Err(Error::BadRecoveryChunk)
        );
    }

    #[test]
    fn rar5_archive_repair_keeps_prefix_when_record_rebuild_exceeds_limit() {
        let mut chunk = build_structural_inline_recovery_data(b"x", 10).unwrap();
        let group_count = 8192u64;
        let shard_size = 80 + group_count;
        let recovery_shards = u16::MAX - 1;
        chunk.resize(shard_size as usize, 0);
        chunk[0x0c..0x10].copy_from_slice(&(shard_size as u32).to_le_bytes());
        chunk[0x2a..0x32].copy_from_slice(&group_count.to_le_bytes());
        chunk[0x32..0x3a].copy_from_slice(&shard_size.to_le_bytes());
        chunk[0x3c..0x3e].copy_from_slice(&recovery_shards.to_le_bytes());
        let crc = crc64_xz(&chunk[0x0c..]);
        chunk[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());

        let mut archive = b"x".to_vec();
        archive.extend_from_slice(&chunk);
        let (repaired, report) = super::repair_inline_recovery_archive_with_report(
            &archive,
            &super::InlineRepairOptions::default(),
        )
        .unwrap();
        assert_eq!(repaired, archive);
        assert!(!report.changed);
        assert!(!report.recovery_record_rebuilt);
        assert_eq!(report.available_recovery_shards, Some(1));
        assert_eq!(
            report.expected_recovery_shards,
            Some(recovery_shards as u64)
        );
    }

    #[test]
    fn rar5_inline_recovery_rejects_unrepairable_damage_count() {
        let prefix = b"small prefix with only one parity shard".repeat(100);
        let recovery_data = build_structural_inline_recovery_data(&prefix, 1).unwrap();
        let mut damaged = prefix.clone();
        damaged[0] ^= 0xff;
        damaged[1024] ^= 0xff;

        assert_eq!(
            repair_inline_recovery_prefix(&damaged, &recovery_data),
            Err(Error::TooManyDamagedShards)
        );
    }

    #[test]
    fn rar5_reconstruct_data_shards_repairs_missing_shards_from_parity() {
        let first = b"abcdefgh".to_vec();
        let second = b"ijklmnop".to_vec();
        let third = b"qrstuvwx".to_vec();
        let refs = [first.as_slice(), second.as_slice(), third.as_slice()];
        let parity = encode_parity_shards(&refs, 2).unwrap();

        let reconstructed = reconstruct_data_shards(
            &[Some(&first), None, Some(&third)],
            &[(0, parity[0].as_slice())],
        )
        .unwrap();

        assert_eq!(reconstructed[0], first);
        assert_eq!(reconstructed[1], second);
        assert_eq!(reconstructed[2], third);
    }

    #[test]
    fn repair_restores_one_and_several_damaged_shards_byte_for_byte() {
        // Odd length, so the last shard is short and ends mid-word.
        let body = recovery_test_bytes(300_001, 7);
        let plan = plan_inline_recovery(body.len() as u64, 10).unwrap();
        let ranges = split_prefix_shard_ranges(body.len(), plan).unwrap();
        let last = ranges.iter().rposition(|range| !range.is_empty()).unwrap();
        assert_eq!(ranges[last].len() % 2, 1);
        let record = build_inline_recovery_data_for_plan(&body, plan).unwrap();
        let shards = split_prefix_shards(&body, plan).unwrap();
        let refs: Vec<_> = shards.iter().map(Vec::as_slice).collect();
        let parity = encode_parity_shards(&refs, plan.recovery_shards as usize).unwrap();

        for damaged in [vec![last], vec![0, last], vec![1, 4, 9, last]] {
            assert!(damaged.len() <= plan.recovery_shards as usize);
            let mut broken = body.clone();
            for &index in &damaged {
                for byte in &mut broken[ranges[index].clone()] {
                    *byte ^= 0x5a;
                }
            }
            assert_eq!(
                repair_inline_recovery_prefix(&broken, &record),
                Ok(body.clone()),
                "streamed repair of {damaged:?}"
            );

            let available: Vec<_> = refs
                .iter()
                .enumerate()
                .map(|(index, shard)| (!damaged.contains(&index)).then_some(*shard))
                .collect();
            let rows: Vec<_> = (0..damaged.len())
                .rev()
                .map(|row| (row, parity[row].as_slice()))
                .collect();
            assert_eq!(
                reconstruct_data_shards(&available, &rows),
                Ok(shards.clone()),
                "in-memory repair of {damaged:?}"
            );
        }
    }

    #[test]
    fn rar5_reconstruct_data_shards_validates_shapes_and_missing_count() {
        assert_eq!(reconstruct_data_shards(&[], &[]), Err(Error::TooManyShards));
        assert_eq!(
            reconstruct_data_shards(&[None], &[]),
            Err(Error::TooManyDamagedShards)
        );
        assert_eq!(
            reconstruct_data_shards(&[Some(&[1, 2, 3])], &[]),
            Err(Error::OddShardSize)
        );
        assert_eq!(
            reconstruct_data_shards(&[None], &[(0, &[1, 2]), (1, &[3, 4, 5, 6])]),
            Err(Error::ShardSizeMismatch)
        );
        assert_eq!(
            reconstruct_data_shards(&[Some(&[1, 2, 3, 4]), None], &[(0, &[5, 6])]),
            Err(Error::ShardSizeMismatch)
        );
        assert_eq!(
            reconstruct_data_shards(&[None, None], &[(0, &[1, 2])]),
            Err(Error::TooManyDamagedShards)
        );
        assert_eq!(
            reconstruct_data_shards(&[None], &[(usize::MAX, &[1, 2])]),
            Err(Error::TooManyShards)
        );
        let mut data_shards = vec![vec![0, 0]];
        assert_eq!(
            super::recover_damaged_shards(&mut data_shards, &[0], &[(usize::MAX, &[1, 2])]),
            Err(Error::TooManyShards)
        );
        assert_eq!(
            super::recover_damaged_shards(&mut data_shards, &[0], &[]),
            Err(Error::TooManyDamagedShards)
        );
        assert_eq!(
            reconstruct_data_shards(&[None], &[(super::FIELD_SIZE - 1, &[1, 2])]),
            Err(Error::TooManyShards)
        );
        assert_eq!(
            reconstruct_data_shards(&[Some(&[1, 2]), Some(&[3])], &[]),
            Ok(vec![vec![1, 2], vec![3, 0]])
        );
    }

    #[test]
    fn rar5_reconstruct_data_shards_repairs_multiple_missing_shards() {
        let first = b"abcdefgh".to_vec();
        let second = b"ijklmnop".to_vec();
        let third = b"qrstuvwx".to_vec();
        let refs = [first.as_slice(), second.as_slice(), third.as_slice()];
        let parity = encode_parity_shards(&refs, 2).unwrap();

        assert_eq!(
            reconstruct_data_shards(
                &[None, Some(&second), None],
                &[(0, parity[0].as_slice()), (0, parity[0].as_slice())]
            ),
            Err(Error::SingularElement)
        );

        let reconstructed = reconstruct_data_shards(
            &[None, Some(&second), None],
            &[(0, parity[0].as_slice()), (1, parity[1].as_slice())],
        )
        .unwrap();

        assert_eq!(reconstructed[0], first);
        assert_eq!(reconstructed[1], second);
        assert_eq!(reconstructed[2], third);
    }
}

fn check_repair(control: &crate::read_control::ReadControl) -> Result<()> {
    control.check().map_err(|_| Error::Cancelled)
}

fn repair_crc(
    data: &[u8],
    initial: u64,
    control: &crate::read_control::ReadControl,
) -> Result<u64> {
    let mut state = initial;
    for chunk in data.chunks(64 * 1024) {
        check_repair(control)?;
        state = crc64_update(chunk, state);
    }
    Ok(state)
}

#[cfg(test)]
mod repair_workspace_tests {
    use super::*;

    #[test]
    fn marker_search_finds_the_first_complete_marker() {
        for (input, expected) in [
            (&b""[..], None),
            (b"{RB", None),
            (b"{RB}", Some(0)),
            (b"{{RB}", Some(1)),
            (b"{RB{RB}", Some(3)),
            (b"{RX}{R}{", None),
            (b"ab{RA}{RB}{RB}", Some(6)),
            (b"data{RB", None),
            (b"data{RB}", Some(4)),
        ] {
            assert_eq!(find_recovery_marker(input), expected, "{input:?}");
        }
    }

    #[test]
    fn marker_search_finds_a_marker_across_scan_windows() {
        let control = crate::read_control::ReadControl::default();
        let window = MARKER_SCAN_WINDOW;
        for start in [window - 3, window - 1, window, 2 * window - 2] {
            let mut input = vec![b'{'; 3 * window];
            input[start..start + 4].copy_from_slice(b"{RB}");
            let read = |range: std::ops::Range<usize>| Ok(input[range].to_vec());
            assert_eq!(
                next_recovery_marker(&read, 0, input.len(), &control),
                Ok(Some(start))
            );
            assert_eq!(
                next_recovery_marker(&read, start + 1, input.len(), &control),
                Ok(None)
            );
        }
    }

    #[test]
    fn a_stray_marker_claiming_a_large_chunk_is_never_read_whole() {
        // Zeros fail every header check but the declared size, which fits.
        let mut input = vec![0u8; 4 << 20];
        input[1000..1004].copy_from_slice(b"{RB}");
        input[1000 + 0x0c..1000 + 0x10].copy_from_slice(&(3u32 << 20).to_le_bytes());
        input[1000 + 0x10..1000 + 0x14].copy_from_slice(&0x48u32.to_le_bytes());
        let largest = std::cell::Cell::new(0usize);
        let read = |range: std::ops::Range<usize>| {
            largest.set(largest.get().max(range.len()));
            Ok(input[range].to_vec())
        };
        let control = crate::read_control::ReadControl::default();
        assert!(matches!(
            find_inline_recovery_chunks_in(&read, input.len(), &control),
            Err(Error::BadRecoveryChunk)
        ));
        assert!(
            largest.get() < 1 << 20,
            "read {} bytes at once",
            largest.get()
        );
    }

    #[test]
    fn rar5_repair_admits_discovery_reads_before_calling_range_reader() {
        let prefix = b"data";
        let plan = InlineRecoveryPlan {
            data_shards: 1,
            recovery_shards: 1,
            group_count: 4,
            header_size: 80,
            shard_size: 84,
        };
        let chunk = build_inline_recovery_data_for_plan(prefix, plan).unwrap();
        let control = crate::read_control::ReadControl::default();
        let required = repair_solve_workspace_required(1, 0, 4, 0, 4).unwrap();
        let unexpected_read = |_| -> Result<Vec<u8>> {
            panic!("discovery must be refused before requesting range bytes")
        };
        assert_eq!(
            repair_inline_recovery_prefix_shards_with_workspace_limit(
                prefix.len(),
                &chunk,
                unexpected_read,
                &control,
                required - 1,
            ),
            Err(Error::RepairWorkspaceLimitExceeded {
                limit: required - 1,
                required,
            })
        );
        assert_eq!(
            repair_inline_recovery_prefix_shards_with_workspace_limit(
                prefix.len(),
                &chunk,
                |range| Ok(prefix[range].to_vec()),
                &control,
                required,
            ),
            Ok(Vec::new())
        );
        // Discovery fits, but the solve and repaired output do not. It must
        // stop after discovery rather than reread undamaged RHS shards.
        let mut reads = 0;
        let result = repair_inline_recovery_prefix_shards_with_workspace_limit(
            prefix.len(),
            &chunk,
            |range| {
                reads += 1;
                Ok(b"fail"[range].to_vec())
            },
            &control,
            required,
        );
        assert_eq!(reads, 1);
        assert!(matches!(result,
            Err(Error::RepairWorkspaceLimitExceeded { limit, required: solve })
                if limit == required && solve > required
        ));
        let token = crate::ReadCancellation::new();
        token.cancel();
        assert_eq!(
            repair_inline_recovery_prefix_shards_with_workspace_limit(
                prefix.len(),
                &chunk,
                unexpected_read,
                &crate::read_control::ReadControl::new(Some(&token)),
                0,
            ),
            Err(Error::Cancelled)
        );
    }

    #[test]
    fn rar5_repair_workspace_admission_is_checked_and_inclusive() {
        let limit = super::REPAIR_WORKSPACE_FLOOR_BYTES;
        assert_eq!(super::admit_repair_workspace(limit, 0), Ok(()));
        let refusal = Error::RepairWorkspaceLimitExceeded {
            limit,
            required: limit + 1,
        };
        assert_eq!(
            super::admit_repair_workspace(limit + 1, 0),
            Err(refusal.clone())
        );
        let typed = crate::Error::from(refusal.clone()).at_archive_offset(42);
        assert_eq!(typed.kind(), crate::ErrorKind::ResourceLimit);
        assert!(
            matches!(typed.root_cause(), crate::Error::Rar5Recovery(actual) if actual == &refusal)
        );
        assert!(typed.to_string().contains("repair workspace limit"));
        assert_eq!(
            super::repair_solve_workspace_required(1, 1, 0, u64::MAX, 0),
            Err(Error::PlanOverflow)
        );
        assert_eq!(
            super::repair_workspace_product(u64::MAX, 2),
            Err(Error::PlanOverflow)
        );
        // Ordinary generated geometry still fits even with all 200 shards
        // damaged, full output buffers and read scratch.
        let required =
            super::repair_solve_workspace_required(200, 200, 1024, 200 * 1024, 1024).unwrap();
        assert_eq!(super::admit_repair_workspace(required, 0), Ok(()));
    }

    #[test]
    fn rar5_repair_workspace_scales_with_genuine_input() {
        const MIB: u64 = 1024 * 1024;
        // A REV set of five 100 MiB volumes, one missing, with two REV files:
        // padded output alone exceeds the floor, yet master rebuilt it.
        let volume = 100 * MIB as usize;
        let required =
            super::repair_solve_workspace_required(5, 1, volume, 5 * volume as u64, 0).unwrap();
        assert!(required > super::REPAIR_WORKSPACE_FLOOR_BYTES);
        assert_eq!(
            super::admit_repair_workspace(required, 4 * 100 * MIB + 2 * 100 * MIB),
            Ok(())
        );

        // A 10 GiB archive with a 10% record has 51 MiB shards; repairing all
        // 20 recoverable shards must fit beside the archive and its record.
        let archive = 10 * 1024 * MIB;
        let shard = archive.div_ceil(200) as usize;
        let required =
            super::repair_solve_workspace_required(200, 20, shard, 20 * shard as u64, shard)
                .unwrap();
        assert!(required > super::REPAIR_WORKSPACE_FLOOR_BYTES);
        assert_eq!(
            super::admit_repair_workspace(required, archive + archive / 10),
            Ok(())
        );

        // The multiple still refuses records declaring far more than they hold.
        let input = super::REPAIR_WORKSPACE_FLOOR_BYTES;
        assert!(matches!(
            super::admit_repair_workspace(4 * input + 1, input),
            Err(Error::RepairWorkspaceLimitExceeded { .. })
        ));
    }

    #[test]
    fn rar5_tiny_incomplete_record_keeps_repaired_prefix_without_giant_rebuild() {
        // One 128 KiB chunk declares 16,000 recovery rows. Only 32 KiB of
        // parity would be rebuilt, but its full coefficient matrix is almost
        // 0.5 GiB and repeated headers would produce a 1.9 GiB recovery record.
        // Frame this one chunk directly, without generating the claimed rows.
        let data_count = 16_000usize;
        let recovery_count = 16_000usize;
        let header_size = 0x48 + data_count * 8;
        let shard_size = header_size + 2;
        let mut chunk = vec![0; shard_size];
        chunk[..4].copy_from_slice(b"{RB}");
        chunk[0x0c..0x10].copy_from_slice(&(shard_size as u32).to_le_bytes());
        chunk[0x10..0x14].copy_from_slice(&(header_size as u32).to_le_bytes());
        chunk[0x14] = 1;
        chunk[0x15] = 1;
        chunk[0x22..0x2a].copy_from_slice(&1u64.to_le_bytes());
        chunk[0x2a..0x32].copy_from_slice(&2u64.to_le_bytes());
        chunk[0x32..0x3a].copy_from_slice(&(shard_size as u64).to_le_bytes());
        chunk[0x3a..0x3c].copy_from_slice(&(data_count as u16).to_le_bytes());
        chunk[0x3c..0x3e].copy_from_slice(&(recovery_count as u16).to_le_bytes());
        chunk[0x40..0x48].copy_from_slice(&crc64_rar_state(b"a").to_le_bytes());
        let gf = shared_gf16();
        let parity = gf.mul(gf.inv(data_count as u16).unwrap(), b'a' as u16);
        chunk[header_size..].copy_from_slice(&parity.to_le_bytes());
        let crc = crc64_xz(&chunk[0x0c..]);
        chunk[4..0x0c].copy_from_slice(&crc.to_le_bytes());

        let mut archive = b"b".to_vec();
        archive.extend_from_slice(&chunk);
        let repaired = super::repair_inline_recovery_archive(&archive).unwrap();
        assert_eq!(repaired.len(), archive.len());
        assert_eq!(repaired[0], b'a');
        assert_eq!(&repaired[1..], &archive[1..]);
        let (reported, report) = super::repair_inline_recovery_archive_with_report(
            &archive,
            &super::InlineRepairOptions::default(),
        )
        .unwrap();
        assert_eq!(reported, repaired);
        assert!(report.changed);
        assert!(report.data_repaired);
        assert!(!report.recovery_record_rebuilt);
        assert!(!report.end_record_rebuilt);
        assert_eq!(report.available_recovery_shards, Some(1));
        assert_eq!(report.expected_recovery_shards, Some(recovery_count as u64));

        let plan = InlineRecoveryPlan {
            data_shards: data_count as u64,
            recovery_shards: recovery_count as u64,
            group_count: 2,
            header_size: header_size as u64,
            shard_size: shard_size as u64,
        };
        let end = 1 + plan.payload_size().unwrap() as usize;
        assert!(matches!(
            super::rebuild_inline_recovery_record_with_control(
                &archive,
                b"a",
                1..end,
                plan,
                &crate::read_control::ReadControl::default(),
            ),
            Err(Error::RepairWorkspaceLimitExceeded { limit, required })
                if limit == super::REPAIR_WORKSPACE_FLOOR_BYTES && required > limit
        ));
        let token = crate::ReadCancellation::new();
        token.cancel();
        let control = crate::read_control::ReadControl::new(Some(&token));
        assert_eq!(
            super::rebuild_inline_recovery_record_with_control(
                &archive,
                b"a",
                1..end,
                plan,
                &control
            ),
            Err(Error::Cancelled)
        );
    }

    #[test]
    fn rar5_reconstruction_admits_padded_output_and_all_solve_matrices() {
        // Less than 1 MiB of caller metadata and 8 KiB of parity must not
        // allocate 512 MiB of zero padding before the solve is considered.
        let empty = &[][..];
        let mut data = vec![Some(empty); super::FIELD_SIZE - 1];
        data[0] = None;
        let parity = vec![0; 8192];
        assert!(matches!(
            reconstruct_data_shards(&data, &[(0, &parity)]),
            Err(Error::RepairWorkspaceLimitExceeded { limit, required })
                if limit == super::REPAIR_WORKSPACE_FLOOR_BYTES && required > limit
        ));

        // Tiny two-byte shards can still ask for hundreds of MiB across
        // original equations, their working copy and the inverse together.
        let count = 7000;
        let data = vec![None; count];
        let recovery = (0..count).map(|row| (row, &[0, 0][..])).collect::<Vec<_>>();
        assert!(matches!(
            reconstruct_data_shards(&data, &recovery),
            Err(Error::RepairWorkspaceLimitExceeded { limit, required })
                if limit == super::REPAIR_WORKSPACE_FLOOR_BYTES && required > limit
        ));
    }

    #[test]
    fn rar5_reconstruction_validates_before_oversized_padding() {
        let parity = vec![0; 8192];
        let missing = vec![None; super::FIELD_SIZE - 1];
        assert_eq!(
            reconstruct_data_shards(&missing, &[(0, &parity)]),
            Err(Error::TooManyDamagedShards)
        );
        let mut data = vec![Some(&[][..]); super::FIELD_SIZE - 1];
        data[0] = None;
        assert_eq!(
            reconstruct_data_shards(&data, &[(usize::MAX, &parity)]),
            Err(Error::TooManyShards)
        );
        let long = vec![0; parity.len() + 1];
        *data.last_mut().unwrap() = Some(&long);
        assert_eq!(
            reconstruct_data_shards(&data, &[(0, &parity)]),
            Err(Error::ShardSizeMismatch)
        );
        assert_eq!(
            reconstruct_data_shards(&vec![Some(&[][..]); super::FIELD_SIZE + 1], &[]),
            Err(Error::TooManyShards)
        );
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    fn scheduled(checks: usize) -> crate::read_control::ReadControl {
        let token = crate::ReadCancellation::new();
        let control = crate::read_control::ReadControl::new(Some(&token));
        control.cancel_after_checks(checks);
        control
    }

    #[test]
    fn cancellation_stops_marker_search_and_chunk_checksums() {
        let noise = vec![0; 256 * 1024];
        assert_eq!(
            find_inline_recovery_chunks_with_control(&noise, &scheduled(2)).unwrap_err(),
            Error::Cancelled
        );
        let prefix = vec![42; 256 * 1024];
        let data = build_structural_inline_recovery_data(&prefix, 10).unwrap();
        assert_eq!(
            parse_inline_recovery_chunk_with_control(&data, &scheduled(1)).unwrap_err(),
            Error::Cancelled
        );
    }

    #[test]
    fn cancellation_stops_reconstruction_and_record_rebuilding() {
        let prefix = vec![42; 128 * 1024];
        let plan = plan_inline_recovery(prefix.len() as u64, 10).unwrap();
        let mut shards = split_prefix_shards(&prefix, plan).unwrap();
        let refs: Vec<_> = shards.iter().map(Vec::as_slice).collect();
        let parity = encode_parity_shards(&refs, plan.recovery_shards as usize).unwrap();
        shards[0].fill(0);
        assert_eq!(
            recover_damaged_shards_with_control(
                &mut shards,
                &[0],
                &[(0, &parity[0])],
                &scheduled(2)
            )
            .unwrap_err(),
            Error::Cancelled
        );
        assert_eq!(
            build_inline_recovery_data_for_plan_with_control(&prefix, plan, &scheduled(2))
                .unwrap_err(),
            Error::Cancelled
        );
    }

    #[test]
    fn cancellation_stops_selected_equation_generation_and_inverse_application() {
        let damaged: Vec<_> = (0..128).collect();
        let rows: Vec<_> = (0..128).map(|row| (row, &[][..])).collect();
        assert_eq!(
            recovery_equations(shared_gf16(), 128, &damaged, &rows, &scheduled(2)).unwrap_err(),
            Error::Cancelled
        );
        let inverse = vec![vec![1; 128]; 128];
        let rhs = vec![vec![1; 2]; 128];
        let mut outputs = vec![[0u8; 2]; 128];
        let mut repaired: Vec<_> = outputs.iter_mut().map(|output| &mut output[..]).collect();
        assert_eq!(
            fold_inverse(&inverse, &rhs, &mut repaired, &scheduled(2)).unwrap_err(),
            Error::Cancelled
        );
    }

    #[test]
    fn raw_repair_never_tolerates_cancellation_as_a_failed_record_rebuild() {
        let prefix = vec![42; 20_000];
        let recovery = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut archive = prefix;
        let record_start = archive.len();
        archive.extend_from_slice(&recovery);
        archive.extend_from_slice(b"end bytes");
        let expected = archive.clone();
        // Damage one recovery chunk; surviving chunks can rebuild the record.
        archive[record_start + 0x48] ^= 1;
        let mut cancelled = 0;
        let mut completed = 0;
        for checks in (0..256).chain([usize::MAX]) {
            let token = crate::ReadCancellation::new();
            let control = crate::read_control::ReadControl::new(Some(&token));
            control.cancel_after_checks(checks);
            let options = InlineRepairOptions {
                control: control.clone(),
                ..Default::default()
            };
            let result = repair_inline_recovery_archive_with_report(&archive, &options);
            match result {
                Err(Error::Cancelled) => cancelled += 1,
                Ok((data, report)) => {
                    assert!(!token.is_cancelled());
                    assert_eq!(data, expected);
                    assert!(report.recovery_record_rebuilt);
                    completed += 1;
                }
                other => panic!("unexpected repair result: {other:?}"),
            }
        }
        assert!(cancelled > 0 && completed > 0);
    }

    #[test]
    fn recovery_cancellation_has_the_public_cancelled_error_kind() {
        assert_eq!(
            crate::Error::from(Error::Cancelled),
            crate::Error::Cancelled
        );
        assert_eq!(
            crate::Error::Rar5Recovery(Error::Cancelled).kind(),
            crate::ErrorKind::Cancelled
        );
    }
}

#[cfg(all(test, feature = "write"))]
#[test]
fn missing_end_header_repair_preserves_an_active_cancellation_token() {
    let mut builder = crate::Builder::new(crate::ArchiveVersion::Rar50)
        .store(true)
        .recovery_percent(Some(20));
    builder
        .add_bytes(
            b"recoverable".to_vec(),
            b"protected payload".to_vec(),
            None,
            None,
        )
        .unwrap();
    let original = builder.to_bytes().unwrap();
    let archive = crate::rar50::Archive::parse(&original).unwrap();
    let end_start = archive
        .blocks
        .iter()
        .find_map(|block| match block {
            crate::rar50::Block::End(end) => Some(end.block.offset),
            _ => None,
        })
        .unwrap();
    let truncated = &original[..end_start];
    let token = crate::ReadCancellation::new();
    let options = InlineRepairOptions {
        control: crate::read_control::ReadControl::new(Some(&token)),
        ..Default::default()
    };
    let (repaired, report) =
        repair_inline_recovery_archive_with_report(truncated, &options).unwrap();
    assert!(!token.is_cancelled());
    assert!(report.end_record_rebuilt);
    assert_eq!(repaired, original);
    token.cancel();
    assert_eq!(
        repair_inline_recovery_archive_with_report(truncated, &options).unwrap_err(),
        Error::Cancelled
    );
}
