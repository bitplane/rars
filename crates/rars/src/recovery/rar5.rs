const CRC64_XZ_POLY: u64 = 0xc96c_5795_d787_0f42;
const CRC64_XZ_INIT: u64 = 0xffff_ffff_ffff_ffff;
const FIELD_SIZE: usize = 65_535;
const FIELD_MASK: u32 = 0xffff;
const PRIMITIVE_POLYNOMIAL: u32 = 0x1100b;
const ZERO_LOG_SENTINEL: u32 = (FIELD_SIZE * 2) as u32;
const MAX_WINRAR602_DATA_SHARDS: u64 = 200;
const KIB: u64 = 1024;
const RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE: u64 = 0x48;

use crate::write_progress::ProgressReporter;
use crate::{WriteOperation, WriteProgressEvent};

fn shared_gf16() -> &'static Gf16 {
    static GF16: std::sync::OnceLock<Gf16> = std::sync::OnceLock::new();
    GF16.get_or_init(Gf16::new)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    BadRecoveryChunk,
    OddShardSize,
    PlanOverflow,
    PrefixExceedsPlan,
    TooManyDamagedShards,
    ShardSizeMismatch,
    TooManyShards,
    SingularElement,
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRecoveryChunk => f.write_str("RAR 5 recovery chunk is invalid"),
            Self::OddShardSize => f.write_str("RAR 5 recovery shard size is odd"),
            Self::PlanOverflow => f.write_str("RAR 5 recovery plan overflows"),
            Self::PrefixExceedsPlan => {
                f.write_str("RAR 5 recovery prefix exceeds planned shard capacity")
            }
            Self::TooManyDamagedShards => {
                f.write_str("RAR 5 recovery data cannot repair this many damaged shards")
            }
            Self::ShardSizeMismatch => f.write_str("RAR 5 recovery shard sizes differ"),
            Self::TooManyShards => f.write_str("RAR 5 recovery shard count is invalid"),
            Self::SingularElement => f.write_str("RAR 5 recovery matrix is singular"),
            Self::Io(kind) => write!(f, "RAR 5 recovery I/O failed: {kind}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

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
    let header_size = data_shards
        .checked_mul(8)
        .and_then(|value| value.checked_add(RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE))
        .ok_or(Error::PlanOverflow)?;
    let shard_size = header_size
        .checked_add(group_count)
        .ok_or(Error::PlanOverflow)?;

    Ok(InlineRecoveryPlan {
        data_shards,
        recovery_shards,
        group_count,
        header_size,
        shard_size,
    })
}

pub fn crc64_xz(data: &[u8]) -> u64 {
    crc64_update(data, CRC64_XZ_INIT) ^ CRC64_XZ_INIT
}

fn crc64_update(data: &[u8], initial: u64) -> u64 {
    let mut crc = initial;
    for &byte in data {
        crc ^= byte as u64;
        for _ in 0..8 {
            let mask = 0u64.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC64_XZ_POLY & mask);
        }
    }
    crc
}

pub fn crc64_rar_state(data: &[u8]) -> u64 {
    crc64_update(data, 0)
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
        let start = shard_index
            .checked_mul(group_count)
            .ok_or(Error::PlanOverflow)?;
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
    encode_inline_recovery_parity_with_progress(archive_prefix, recovery_percent, None, 1)
}

fn encode_inline_recovery_parity_with_progress(
    archive_prefix: &[u8],
    recovery_percent: u64,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
) -> Result<(InlineRecoveryPlan, Vec<Vec<u8>>)> {
    let plan = plan_inline_recovery(archive_prefix.len() as u64, recovery_percent)?;
    let shards = split_prefix_shards(archive_prefix, plan)?;
    let shard_refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
    let total_bytes = plan.payload_size()?;
    if let Some(progress) = progress {
        progress.report(WriteProgressEvent::OperationStarted {
            operation: WriteOperation::Recovery,
            total_bytes: Some(total_bytes),
            total_entries: None,
            pass,
        });
    }
    let parity = encode_parity_shards_with_progress(
        &shard_refs,
        usize::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?,
        |completed| {
            if let Some(progress) = progress {
                progress.report(WriteProgressEvent::Advanced {
                    operation: WriteOperation::Recovery,
                    completed_bytes: completed,
                    total_bytes,
                    pass,
                });
            }
        },
    )?;
    if let Some(progress) = progress {
        progress.report(WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Recovery,
            total_bytes: Some(total_bytes),
            total_entries: None,
            pass,
        });
    }
    Ok((plan, parity))
}

pub fn build_structural_inline_recovery_data(
    archive_prefix: &[u8],
    recovery_percent: u64,
) -> Result<Vec<u8>> {
    build_structural_inline_recovery_data_with_progress(archive_prefix, recovery_percent, None, 1)
}

pub(crate) fn build_structural_inline_recovery_data_with_progress(
    archive_prefix: &[u8],
    recovery_percent: u64,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    build_streamed_inline_recovery(
        &mut std::io::Cursor::new(archive_prefix),
        archive_prefix.len() as u64,
        recovery_percent,
        RecoveryMemoryMode::Resident,
        None,
        &mut out,
        progress,
        pass,
    )?;
    Ok(out)
}

/// Read buffer size for streaming recovery passes. Even, so words never
/// straddle a chunk boundary.
pub(crate) const RECOVERY_IO_BLOCK: usize = 256 * 1024;
/// Striped mode never claims more than this, however large the budget is.
const STRIPE_BUDGET_CAP: u64 = 64 * 1024 * 1024;
/// Below this a stripe pass seeks far more than it reads, so rather than
/// thrash we report what striping would actually cost and let the caller
/// refuse the job.
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
    Striped { stripe_len: usize },
}

/// Picks a memory mode for `plan` under `memory_limit`, returning the mode and
/// the number of bytes the caller should reserve for it.
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
    let stripe_len_usize = usize::try_from(stripe_len).map_err(|_| Error::PlanOverflow)?;
    let required = rows.saturating_mul(stripe_len);
    Ok((
        RecoveryMemoryMode::Striped {
            stripe_len: stripe_len_usize,
        },
        required,
    ))
}

/// What a streaming recovery pass produced, so the caller can frame the
/// service block around the payload it just wrote.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamedRecoveryOutput {
    pub(crate) plan: InlineRecoveryPlan,
    pub(crate) payload_len: u64,
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
    let payload_len = plan.payload_size()?;

    // Fail on unrepresentable geometry before doing any work.
    let total_size = u32::try_from(plan.shard_size).map_err(|_| Error::PlanOverflow)?;
    let header_size_u32 = u32::try_from(plan.header_size).map_err(|_| Error::PlanOverflow)?;
    let data_shards_u16 = u16::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
    let recovery_shards_u16 =
        u16::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?;
    let data_shards = usize::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
    let recovery_shards = usize::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?;
    let group_count = usize::try_from(plan.group_count).map_err(|_| Error::PlanOverflow)?;
    let header_size = usize::try_from(plan.header_size).map_err(|_| Error::PlanOverflow)?;
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
    let encode_units = plan
        .recovery_shards
        .checked_mul(plan.group_count)
        .ok_or(Error::PlanOverflow)?;
    let report = |completed: u64| {
        if let Some(progress) = progress {
            progress.report(WriteProgressEvent::Advanced {
                operation: WriteOperation::Recovery,
                completed_bytes: completed.min(payload_len),
                total_bytes: payload_len,
                pass,
            });
        }
    };

    let matrix = make_encoder_matrix(data_shards, recovery_shards)?;
    let mut shard_states = vec![0u64; data_shards];

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
            )?;
            ParityRows::Spooled {
                scratch,
                group_count: plan.group_count,
            }
        }
    };

    // Every chunk repeats the CRC state of parity row 0, so it has to be
    // known before the first chunk can be framed.
    let mut buffer = vec![0u8; RECOVERY_IO_BLOCK.min(group_count.max(1))];
    let mut final_state = 0u64;
    if recovery_shards > 0 {
        rows.for_each_chunk(0, &mut buffer, |chunk| {
            final_state = crc64_update(chunk, final_state);
        })?;
    }

    let chunk_data_extent = body_len
        .saturating_sub(
            plan.group_count
                .saturating_mul(plan.data_shards.saturating_sub(1)),
        )
        .min(plan.group_count);
    let chunk_data_extent_u32 =
        u32::try_from(chunk_data_extent).map_err(|_| Error::PlanOverflow)?;

    let mut payload_crc32 = crate::crc32::Crc32::new();
    let mut written = 0u64;
    for shard_index in 0..recovery_shards {
        let mut header = Vec::with_capacity(header_size);
        header.extend_from_slice(b"{RB}");
        header.extend_from_slice(&0u64.to_le_bytes());
        header.extend_from_slice(&total_size.to_le_bytes());
        header.extend_from_slice(&header_size_u32.to_le_bytes());
        header.push(1);
        header.push(1);
        header.extend_from_slice(&0u64.to_le_bytes());
        header.extend_from_slice(&chunk_data_extent_u32.to_le_bytes());
        header.extend_from_slice(&body_len.to_le_bytes());
        header.extend_from_slice(&plan.group_count.to_le_bytes());
        header.extend_from_slice(&plan.shard_size.to_le_bytes());
        header.extend_from_slice(&data_shards_u16.to_le_bytes());
        header.extend_from_slice(&recovery_shards_u16.to_le_bytes());
        header.extend_from_slice(
            &u16::try_from(shard_index)
                .map_err(|_| Error::PlanOverflow)?
                .to_le_bytes(),
        );
        for &state in &shard_states {
            header.extend_from_slice(&state.to_le_bytes());
        }
        header.extend_from_slice(&final_state.to_le_bytes());
        if header.len() != header_size {
            return Err(Error::PlanOverflow);
        }

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

        let mut row_written = 0u64;
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
            row_written += chunk.len() as u64;
        })?;
        if let Some(error) = sink_error {
            return Err(error.into());
        }
        if row_written != plan.group_count {
            return Err(Error::PlanOverflow);
        }
        written += row_written;

        report(encode_units + (shard_index as u64 + 1) * plan.header_size);
    }

    if written != payload_len {
        return Err(Error::PlanOverflow);
    }
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

/// Parity rows, wherever they happen to live.
enum ParityRows<'a> {
    Resident(Vec<Vec<u8>>),
    Spooled {
        scratch: &'a mut dyn ReadWriteSeek,
        group_count: u64,
    },
}

impl ParityRows<'_> {
    /// Feeds row `index` to `visit` in buffer-sized pieces.
    fn for_each_chunk(
        &mut self,
        index: usize,
        buffer: &mut [u8],
        mut visit: impl FnMut(&[u8]),
    ) -> Result<()> {
        match self {
            Self::Resident(rows) => {
                let row = rows.get(index).ok_or(Error::PlanOverflow)?;
                if !row.is_empty() {
                    visit(row);
                }
                Ok(())
            }
            Self::Spooled {
                scratch,
                group_count,
            } => {
                if buffer.is_empty() {
                    return Ok(());
                }
                let start = (index as u64)
                    .checked_mul(*group_count)
                    .ok_or(Error::PlanOverflow)?;
                scratch.seek(std::io::SeekFrom::Start(start))?;
                let mut remaining = *group_count;
                while remaining != 0 {
                    let want = usize::try_from(remaining.min(buffer.len() as u64))
                        .map_err(|_| Error::PlanOverflow)?;
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
fn accumulate_scaled(destination: &mut [u8], source: &[u8], coefficient: u16, gf: &Gf16) {
    let words = source.len() / 2;
    for word in 0..words {
        let offset = word * 2;
        let value = u16::from_le_bytes([source[offset], source[offset + 1]]);
        let scaled = gf.mul(coefficient, value);
        if scaled == 0 {
            continue;
        }
        let current = u16::from_le_bytes([destination[offset], destination[offset + 1]]);
        destination[offset..offset + 2].copy_from_slice(&(current ^ scaled).to_le_bytes());
    }
    if !source.len().is_multiple_of(2) {
        let offset = words * 2;
        let value = u16::from_le_bytes([source[offset], 0]);
        let scaled = gf.mul(coefficient, value);
        if scaled != 0 {
            let current = u16::from_le_bytes([destination[offset], destination[offset + 1]]);
            destination[offset..offset + 2].copy_from_slice(&(current ^ scaled).to_le_bytes());
        }
    }
}

/// Single forward pass over the body, holding every parity row in memory.
fn encode_parity_resident(
    body: &mut dyn ReadSeek,
    body_len: u64,
    plan: &InlineRecoveryPlan,
    matrix: &[Vec<u16>],
    shard_states: &mut [u64],
    encode_units: u64,
    report: &dyn Fn(u64),
) -> Result<Vec<Vec<u8>>> {
    let group_count = usize::try_from(plan.group_count).map_err(|_| Error::PlanOverflow)?;
    let recovery_shards = usize::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?;
    let mut parity = vec![vec![0u8; group_count]; recovery_shards];
    if group_count == 0 || body_len == 0 {
        return Ok(parity);
    }

    let gf = shared_gf16();
    let mut buffer = vec![0u8; RECOVERY_IO_BLOCK.min(group_count)];
    body.seek(std::io::SeekFrom::Start(0))?;

    let mut consumed = 0u64;
    for (shard_index, state) in shard_states.iter_mut().enumerate() {
        let shard_start = (shard_index as u64)
            .checked_mul(plan.group_count)
            .ok_or(Error::PlanOverflow)?;
        if shard_start >= body_len {
            break;
        }
        let shard_bytes = plan.group_count.min(body_len - shard_start);

        let mut offset = 0u64;
        while offset < shard_bytes {
            let want = usize::try_from((shard_bytes - offset).min(buffer.len() as u64))
                .map_err(|_| Error::PlanOverflow)?;
            body.read_exact(&mut buffer[..want])?;
            *state = crc64_update(&buffer[..want], *state);

            let destination_offset = usize::try_from(offset).map_err(|_| Error::PlanOverflow)?;
            for (row, parity_row) in matrix.iter().zip(parity.iter_mut()) {
                accumulate_scaled(
                    &mut parity_row[destination_offset..],
                    &buffer[..want],
                    row[shard_index],
                    gf,
                );
            }

            offset += want as u64;
            consumed += want as u64;
            report(scaled_progress(consumed, body_len, encode_units));
        }
    }

    Ok(parity)
}

/// Column-stripe pass: bounded memory, one seek per data shard per stripe,
/// and the body still read exactly once in total.
#[allow(clippy::too_many_arguments)]
fn encode_parity_striped(
    body: &mut dyn ReadSeek,
    body_len: u64,
    plan: &InlineRecoveryPlan,
    matrix: &[Vec<u16>],
    shard_states: &mut [u64],
    stripe_len: usize,
    scratch: &mut dyn ReadWriteSeek,
    encode_units: u64,
    report: &dyn Fn(u64),
) -> Result<()> {
    let recovery_shards = usize::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?;
    if plan.group_count == 0 {
        return Ok(());
    }
    let stripe_len = stripe_len.max(2);
    let gf = shared_gf16();
    let mut stripe = vec![vec![0u8; stripe_len]; recovery_shards];
    let mut buffer = vec![0u8; stripe_len];
    let mut consumed = 0u64;

    let mut column = 0u64;
    while column < plan.group_count {
        let width = (plan.group_count - column).min(stripe_len as u64);
        let width_usize = usize::try_from(width).map_err(|_| Error::PlanOverflow)?;
        for row in stripe.iter_mut() {
            row[..width_usize].fill(0);
        }

        for (shard_index, state) in shard_states.iter_mut().enumerate() {
            let shard_start = (shard_index as u64)
                .checked_mul(plan.group_count)
                .ok_or(Error::PlanOverflow)?;
            let shard_bytes = plan.group_count.min(body_len.saturating_sub(shard_start));
            if column >= shard_bytes {
                continue;
            }
            let span = width.min(shard_bytes - column);
            let span_usize = usize::try_from(span).map_err(|_| Error::PlanOverflow)?;

            body.seek(std::io::SeekFrom::Start(shard_start + column))?;
            body.read_exact(&mut buffer[..span_usize])?;
            *state = crc64_update(&buffer[..span_usize], *state);

            for (row, stripe_row) in matrix.iter().zip(stripe.iter_mut()) {
                accumulate_scaled(stripe_row, &buffer[..span_usize], row[shard_index], gf);
            }

            consumed += span;
            report(scaled_progress(consumed, body_len, encode_units));
        }

        for (shard_index, stripe_row) in stripe.iter().enumerate() {
            let position = (shard_index as u64)
                .checked_mul(plan.group_count)
                .and_then(|start| start.checked_add(column))
                .ok_or(Error::PlanOverflow)?;
            scratch.seek(std::io::SeekFrom::Start(position))?;
            scratch.write_all(&stripe_row[..width_usize])?;
        }

        column += width;
    }

    Ok(())
}

fn scaled_progress(consumed: u64, total: u64, units: u64) -> u64 {
    if total == 0 {
        return units;
    }
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
    let chunks = parse_available_inline_recovery_chunks(recovery_data)?;
    let first = chunks.first().ok_or(Error::BadRecoveryChunk)?;
    let plan = first.plan;
    if first.protected_size != archive_prefix.len() as u64 {
        return Err(Error::BadRecoveryChunk);
    }
    if chunks.iter().any(|chunk| {
        chunk.plan != plan
            || chunk.protected_size != first.protected_size
            || chunk.data_shard_states != first.data_shard_states
    }) {
        return Err(Error::BadRecoveryChunk);
    }

    let mut data_shards = split_prefix_shards(archive_prefix, plan)?;
    let shard_ranges = split_prefix_shard_ranges(archive_prefix.len(), plan)?;
    let damaged: Vec<usize> = shard_ranges
        .iter()
        .enumerate()
        .filter_map(|(index, range)| {
            (crc64_rar_state(&archive_prefix[range.clone()]) != first.data_shard_states[index])
                .then_some(index)
        })
        .collect();
    if damaged.is_empty() {
        return Ok(archive_prefix.to_vec());
    }
    if damaged.len() > chunks.len() {
        return Err(Error::TooManyDamagedShards);
    }

    let recovery_rows: Vec<_> = chunks[..damaged.len()]
        .iter()
        .map(|chunk| (chunk.shard_index, chunk.parity.as_slice()))
        .collect();
    recover_damaged_shards(&mut data_shards, &damaged, &recovery_rows)?;

    let mut repaired = Vec::with_capacity(archive_prefix.len());
    for (shard, range) in data_shards.iter().zip(shard_ranges) {
        repaired.extend_from_slice(&shard[..range.len()]);
    }
    debug_assert_eq!(repaired.len(), archive_prefix.len());
    Ok(repaired)
}

/// Repair damaged RAR5 inline-recovery data shards without materializing the
/// whole protected prefix.
///
/// `read_range` receives byte ranges relative to the protected prefix and must
/// return the current bytes for each requested range. The returned pairs contain
/// only the damaged prefix ranges that need to be written back.
pub fn repair_inline_recovery_prefix_shards<F>(
    protected_size: usize,
    recovery_data: &[u8],
    mut read_range: F,
) -> Result<Vec<(std::ops::Range<usize>, Vec<u8>)>>
where
    F: FnMut(std::ops::Range<usize>) -> Result<Vec<u8>>,
{
    let chunks = parse_available_inline_recovery_chunks(recovery_data)?;
    let first = chunks.first().ok_or(Error::BadRecoveryChunk)?;
    if first.protected_size != protected_size as u64 {
        return Err(Error::BadRecoveryChunk);
    }
    if chunks
        .iter()
        .any(|chunk| chunk.plan != first.plan || chunk.protected_size != first.protected_size)
    {
        return Err(Error::BadRecoveryChunk);
    }

    let plan = first.plan;
    let shard_len = usize::try_from(plan.group_count).map_err(|_| Error::PlanOverflow)?;
    if !shard_len.is_multiple_of(2) {
        return Err(Error::OddShardSize);
    }
    let shard_ranges = split_prefix_shard_ranges(protected_size, plan)?;
    let mut damaged = Vec::new();
    for (index, range) in shard_ranges.iter().enumerate() {
        let shard = read_range(range.clone())?;
        if crc64_rar_state(&shard) != first.data_shard_states[index] {
            damaged.push(index);
        }
    }
    if damaged.is_empty() {
        return Ok(Vec::new());
    }
    if damaged.len() > chunks.len() {
        return Err(Error::TooManyDamagedShards);
    }

    let recovery_rows: Vec<_> = chunks[..damaged.len()]
        .iter()
        .map(|chunk| (chunk.shard_index, chunk.parity.as_slice()))
        .collect();
    if recovery_rows
        .iter()
        .any(|(_, shard)| shard.len() != shard_len)
    {
        return Err(Error::ShardSizeMismatch);
    }
    let matrix = make_encoder_matrix(shard_ranges.len(), plan.recovery_shards as usize)?;
    let equations: Vec<Vec<u16>> = recovery_rows
        .iter()
        .map(|&(row_index, _)| {
            damaged
                .iter()
                .map(|&data_index| matrix[row_index][data_index])
                .collect()
        })
        .collect();
    let gf = shared_gf16();
    let inverse = invert_linear_system_matrix(gf, &equations)?;
    let word_count = shard_len / 2;
    let mut rhs_by_row = recovery_rows
        .iter()
        .map(|(_, parity)| {
            parity
                .chunks_exact(2)
                .map(|word| u16::from_le_bytes([word[0], word[1]]))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let damaged_lookup = damaged_lookup(shard_ranges.len(), &damaged)?;

    for (data_index, range) in shard_ranges.iter().enumerate() {
        if damaged_lookup[data_index] {
            continue;
        }
        let shard = read_padded_prefix_shard(range.clone(), shard_len, &mut read_range)?;
        for (row_index, rhs) in rhs_by_row.iter_mut().enumerate() {
            let coeff = matrix[recovery_rows[row_index].0][data_index];
            if coeff == 0 {
                continue;
            }
            for (word_index, word) in shard.chunks_exact(2).enumerate() {
                let data_symbol = u16::from_le_bytes([word[0], word[1]]);
                rhs[word_index] ^= gf.mul(coeff, data_symbol);
            }
        }
    }

    let mut repaired = damaged
        .iter()
        .map(|&index| vec![0; shard_ranges[index].len()])
        .collect::<Vec<_>>();
    for word_index in 0..word_count {
        let rhs = rhs_by_row
            .iter()
            .map(|row| row[word_index])
            .collect::<Vec<_>>();
        let solved = apply_inverse_matrix(gf, &inverse, &rhs)?;
        for (output, &symbol) in repaired.iter_mut().zip(&solved) {
            let byte_offset = word_index * 2;
            if byte_offset < output.len() {
                let bytes = symbol.to_le_bytes();
                let take = (output.len() - byte_offset).min(2);
                output[byte_offset..byte_offset + take].copy_from_slice(&bytes[..take]);
            }
        }
    }

    Ok(damaged
        .into_iter()
        .zip(repaired)
        .map(|(index, data)| (shard_ranges[index].clone(), data))
        .collect())
}

fn damaged_lookup(data_count: usize, damaged: &[usize]) -> Result<Vec<bool>> {
    let mut lookup = vec![false; data_count];
    for &index in damaged {
        if index >= data_count {
            return Err(Error::TooManyDamagedShards);
        }
        lookup[index] = true;
    }
    Ok(lookup)
}

fn read_padded_prefix_shard<F>(
    range: std::ops::Range<usize>,
    shard_len: usize,
    read_range: &mut F,
) -> Result<Vec<u8>>
where
    F: FnMut(std::ops::Range<usize>) -> Result<Vec<u8>>,
{
    let mut shard = vec![0; shard_len];
    let bytes = read_range(range)?;
    if bytes.len() > shard_len {
        return Err(Error::ShardSizeMismatch);
    }
    shard[..bytes.len()].copy_from_slice(&bytes);
    Ok(shard)
}

pub fn repair_inline_recovery_archive(input: &[u8]) -> Result<Vec<u8>> {
    Ok(repair_inline_recovery_archive_with_report(input, None)?.0)
}

pub(crate) fn repair_inline_recovery_archive_with_report(
    input: &[u8],
    password: Option<&[u8]>,
) -> Result<(Vec<u8>, crate::RecoveryRepairReport)> {
    let chunks = find_inline_recovery_chunks(input)?;
    let first = chunks.first().ok_or(Error::BadRecoveryChunk)?;
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
        append_inline_recovery_chunk(input, found, &mut recovery_data)?;
    }
    let original_prefix = &input[..protected_size];
    let repaired_prefix = repair_inline_recovery_prefix(original_prefix, &recovery_data)?;
    let data_repaired = repaired_prefix != original_prefix;
    let plan = first.chunk.plan;
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
    let recovery_record_rebuilt = available != expected || record_end > input.len();
    let mut repaired = if recovery_record_rebuilt {
        let percent = (1..=100)
            .find(|&percent| plan_inline_recovery(protected_size as u64, percent) == Ok(plan))
            .ok_or(Error::BadRecoveryChunk)?;
        let rebuilt = build_structural_inline_recovery_data(&repaired_prefix, percent)?;
        let mut out = Vec::with_capacity(input.len().max(record_end));
        out.extend_from_slice(&repaired_prefix);
        out.extend_from_slice(
            input
                .get(protected_size..record_start)
                .ok_or(Error::BadRecoveryChunk)?,
        );
        out.extend_from_slice(&rebuilt);
        if record_end < input.len() {
            out.extend_from_slice(&input[record_end..]);
        }
        out
    } else {
        let mut out = input.to_vec();
        out[..protected_size].copy_from_slice(&repaired_prefix);
        out
    };
    let mut end_record_rebuilt = false;
    if record_end >= input.len() {
        let end = crate::rar50::recovery_end_header(input, password)
            .map_err(|_| Error::BadRecoveryChunk)?;
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
    Ok((repaired, report))
}

fn find_inline_recovery_chunks(input: &[u8]) -> Result<Vec<FoundInlineRecoveryChunk>> {
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = find_recovery_marker(&input[offset..]) {
        let start = offset + relative;
        if let Ok(chunk) = parse_inline_recovery_chunk(&input[start..]) {
            let shard_size =
                usize::try_from(chunk.plan.shard_size).map_err(|_| Error::PlanOverflow)?;
            if input.len().saturating_sub(start) >= shard_size {
                chunks.push(FoundInlineRecoveryChunk {
                    offset: start,
                    chunk,
                });
                offset = start + shard_size;
                continue;
            }
        }
        offset = start + 1;
    }
    if chunks.is_empty() {
        return Err(Error::BadRecoveryChunk);
    }
    Ok(chunks)
}

fn find_recovery_marker(input: &[u8]) -> Option<usize> {
    let mut offset = 0usize;
    while offset + 4 <= input.len() {
        let relative = input[offset..].iter().position(|&byte| byte == b'{')?;
        offset += relative;
        if input.get(offset..offset + 4) == Some(b"{RB}") {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

fn append_inline_recovery_chunk(
    input: &[u8],
    found: &FoundInlineRecoveryChunk,
    out: &mut Vec<u8>,
) -> Result<()> {
    let shard_size =
        usize::try_from(found.chunk.plan.shard_size).map_err(|_| Error::PlanOverflow)?;
    let start = found.offset;
    let end = start.checked_add(shard_size).ok_or(Error::PlanOverflow)?;
    out.extend_from_slice(input.get(start..end).ok_or(Error::BadRecoveryChunk)?);
    Ok(())
}

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

    let mut out = Vec::with_capacity(data_shards.len());
    let mut missing = Vec::new();
    for (index, shard) in data_shards.iter().enumerate() {
        let mut padded = vec![0; shard_len];
        if let Some(shard) = shard {
            if shard.len() > shard_len {
                return Err(Error::ShardSizeMismatch);
            }
            padded[..shard.len()].copy_from_slice(shard);
        } else {
            missing.push(index);
        }
        out.push(padded);
    }
    if missing.is_empty() {
        return Ok(out);
    }
    if missing.len() > recovery_shards.len() {
        return Err(Error::TooManyDamagedShards);
    }
    recover_damaged_shards(&mut out, &missing, &recovery_shards[..missing.len()])?;
    Ok(out)
}

fn parse_available_inline_recovery_chunks(
    recovery_data: &[u8],
) -> Result<Vec<InlineRecoveryChunk>> {
    Ok(find_inline_recovery_chunks(recovery_data)?
        .into_iter()
        .map(|found| found.chunk)
        .collect())
}

pub(crate) fn inline_recovery_chunk_counts(recovery_data: &[u8]) -> Result<(u64, u64)> {
    let chunks = parse_available_inline_recovery_chunks(recovery_data)?;
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

fn parse_inline_recovery_chunk(input: &[u8]) -> Result<InlineRecoveryChunk> {
    if input.len() < 0x48 || &input[..4] != b"{RB}" {
        return Err(Error::BadRecoveryChunk);
    }
    let total_size = read_u32(input, 0x0c)? as u64;
    let header_size = read_u32(input, 0x10)? as u64;
    if header_size < RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE || header_size > total_size {
        return Err(Error::BadRecoveryChunk);
    }
    let total_size_usize = usize::try_from(total_size).map_err(|_| Error::PlanOverflow)?;
    let header_size_usize = usize::try_from(header_size).map_err(|_| Error::PlanOverflow)?;
    if input.len() < total_size_usize {
        return Err(Error::BadRecoveryChunk);
    }
    let expected_crc = read_u64(input, 0x04)?;
    let actual_crc = crc64_xz(&input[0x0c..total_size_usize]);
    if actual_crc != expected_crc {
        return Err(Error::BadRecoveryChunk);
    }
    if input[0x14] != 1 || input[0x15] != 1 {
        return Err(Error::BadRecoveryChunk);
    }

    let protected_size = read_u64(input, 0x22)?;
    let group_count = read_u64(input, 0x2a)?;
    let shard_size = read_u64(input, 0x32)?;
    let data_shards = u16::from_le_bytes(input[0x3a..0x3c].try_into().unwrap()) as u64;
    let recovery_shards = u16::from_le_bytes(input[0x3c..0x3e].try_into().unwrap()) as u64;
    let shard_index = u16::from_le_bytes(input[0x3e..0x40].try_into().unwrap()) as usize;
    let plan = InlineRecoveryPlan {
        data_shards,
        recovery_shards,
        group_count,
        header_size,
        shard_size,
    };
    if plan.payload_size()?
        != recovery_shards
            .checked_mul(shard_size)
            .ok_or(Error::PlanOverflow)?
        || shard_size != total_size
        || shard_index >= recovery_shards as usize
        || header_size_usize != 0x48 + data_shards as usize * 8
        || total_size_usize < header_size_usize
    {
        return Err(Error::BadRecoveryChunk);
    }

    let mut data_shard_states = Vec::with_capacity(data_shards as usize);
    let mut pos = 0x40;
    for _ in 0..data_shards {
        data_shard_states.push(read_u64(input, pos)?);
        pos += 8;
    }
    let _final_state = read_u64(input, pos)?;
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
    let data_count = data_shards.len();
    let mut damaged_lookup = vec![false; data_count];
    for &data_index in damaged {
        if data_index >= data_count {
            return Err(Error::TooManyDamagedShards);
        }
        damaged_lookup[data_index] = true;
    }

    let recovery_count = recovery_shards
        .iter()
        .map(|(row, _)| row + 1)
        .max()
        .ok_or(Error::TooManyDamagedShards)?;
    let matrix = make_encoder_matrix(data_count, recovery_count)?;
    let gf = shared_gf16();
    let equations: Vec<Vec<u16>> = recovery_shards
        .iter()
        .map(|&(row_index, _)| {
            damaged
                .iter()
                .map(|&data_index| matrix[row_index][data_index])
                .collect()
        })
        .collect();
    let inverse = invert_linear_system_matrix(gf, &equations)?;

    let shard_len = data_shards.first().ok_or(Error::TooManyShards)?.len();
    for word_offset in (0..shard_len).step_by(2) {
        let mut rhs = Vec::with_capacity(recovery_shards.len());
        for &(row_index, parity) in recovery_shards {
            let mut value = u16::from_le_bytes([parity[word_offset], parity[word_offset + 1]]);
            for (data_index, shard) in data_shards.iter().enumerate() {
                if damaged_lookup[data_index] {
                    continue;
                }
                let data_symbol = u16::from_le_bytes([shard[word_offset], shard[word_offset + 1]]);
                value ^= gf.mul(matrix[row_index][data_index], data_symbol);
            }
            rhs.push(value);
        }
        let solved = apply_inverse_matrix(gf, &inverse, &rhs)?;
        for (&data_index, &symbol) in damaged.iter().zip(&solved) {
            data_shards[data_index][word_offset..word_offset + 2]
                .copy_from_slice(&symbol.to_le_bytes());
        }
    }
    Ok(())
}

fn invert_linear_system_matrix(gf: &Gf16, matrix: &[Vec<u16>]) -> Result<Vec<Vec<u16>>> {
    let n = matrix.len();
    if matrix.len() != n || matrix.iter().any(|row| row.len() != n) {
        return Err(Error::BadRecoveryChunk);
    }
    let mut matrix = matrix.to_vec();
    let mut inverse = vec![vec![0u16; n]; n];
    for (row, inverse_row) in inverse.iter_mut().enumerate() {
        inverse_row[row] = 1;
    }

    for col in 0..n {
        let pivot = (col..n)
            .find(|&row| matrix[row][col] != 0)
            .ok_or(Error::SingularElement)?;
        matrix.swap(col, pivot);
        inverse.swap(col, pivot);
        let inv = gf.inv(matrix[col][col])?;
        for value in &mut matrix[col] {
            *value = gf.mul(*value, inv);
        }
        for value in &mut inverse[col] {
            *value = gf.mul(*value, inv);
        }

        let pivot_matrix_row = matrix[col].clone();
        let pivot_inverse_row = inverse[col].clone();
        for row in 0..n {
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
                *value ^= gf.mul(factor, pivot);
            }
            for (value, pivot) in inverse[row]
                .iter_mut()
                .zip(pivot_inverse_row.iter().copied())
            {
                *value ^= gf.mul(factor, pivot);
            }
        }
    }
    Ok(inverse)
}

fn apply_inverse_matrix(gf: &Gf16, inverse: &[Vec<u16>], rhs: &[u16]) -> Result<Vec<u16>> {
    if inverse.len() != rhs.len() || inverse.iter().any(|row| row.len() != rhs.len()) {
        return Err(Error::BadRecoveryChunk);
    }
    Ok(inverse
        .iter()
        .map(|row| {
            row.iter()
                .zip(rhs)
                .fold(0u16, |sum, (&coefficient, &value)| {
                    sum ^ gf.mul(coefficient, value)
                })
        })
        .collect())
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32> {
    input
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(Error::BadRecoveryChunk)
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64> {
    input
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(Error::BadRecoveryChunk)
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
        let mut value = 1u32;
        for power in 0..FIELD_SIZE {
            log[value as usize] = power as u32;
            exp[power] = value as u16;
            exp[power + FIELD_SIZE] = value as u16;
            value <<= 1;
            if value > FIELD_MASK {
                value ^= PRIMITIVE_POLYNOMIAL;
            }
        }
        log[0] = ZERO_LOG_SENTINEL;
        Self {
            exp: exp.into_boxed_slice(),
            log: log.into_boxed_slice(),
        }
    }

    pub fn add(&self, left: u16, right: u16) -> u16 {
        left ^ right
    }

    pub fn mul(&self, left: u16, right: u16) -> u16 {
        if left == 0 || right == 0 {
            return 0;
        }
        let index = self.log[left as usize] + self.log[right as usize];
        self.exp[index as usize]
    }

    pub fn inv(&self, value: u16) -> Result<u16> {
        if value == 0 {
            return Err(Error::SingularElement);
        }
        let index = FIELD_SIZE as u32 - self.log[value as usize];
        Ok(self.exp[index as usize])
    }

    pub fn div(&self, numerator: u16, denominator: u16) -> Result<u16> {
        Ok(self.mul(numerator, self.inv(denominator)?))
    }
}

impl Default for Gf16 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn make_encoder_matrix(data_shards: usize, recovery_shards: usize) -> Result<Vec<Vec<u16>>> {
    if data_shards == 0 || recovery_shards == 0 || data_shards + recovery_shards > FIELD_SIZE {
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
    encode_parity_shards_with_progress(data, recovery_shards, |_| {})
}

fn encode_parity_shards_with_progress(
    data: &[&[u8]],
    recovery_shards: usize,
    mut progress: impl FnMut(u64),
) -> Result<Vec<Vec<u8>>> {
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
        progress(((recovery_index + 1) * first.len()) as u64);
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
        apply_inverse_matrix, build_structural_inline_recovery_data, crc64_rar_state, crc64_xz,
        encode_inline_recovery_parity, encode_parity_shards, invert_linear_system_matrix,
        make_encoder_matrix, plan_inline_recovery, reconstruct_data_shards,
        repair_inline_recovery_archive, repair_inline_recovery_prefix,
        repair_inline_recovery_prefix_shards, shared_gf16, split_prefix_shard_ranges,
        split_prefix_shards, Error, Gf16, InlineRecoveryPlan, MAX_WINRAR602_DATA_SHARDS,
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

        let inverse = invert_linear_system_matrix(gf, &equations).unwrap();
        let solved = apply_inverse_matrix(gf, &inverse, &rhs).unwrap();

        assert_eq!(solved, expected);
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
    fn rar5_reconstruct_data_shards_repairs_multiple_missing_shards() {
        let first = b"abcdefgh".to_vec();
        let second = b"ijklmnop".to_vec();
        let third = b"qrstuvwx".to_vec();
        let refs = [first.as_slice(), second.as_slice(), third.as_slice()];
        let parity = encode_parity_shards(&refs, 2).unwrap();

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
