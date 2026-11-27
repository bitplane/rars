use super::{Error, Result};
use crate::codec::workspace::Allowance;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(test, feature = "write"))]
pub(crate) enum FilterOp {
    #[cfg(test)]
    E8,
    #[cfg(test)]
    E8E9,
    Delta {
        channels: usize,
    },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DeltaErrorMessages {
    pub invalid_channels: &'static str,
    pub zero_channels: &'static str,
}

#[cfg(any(test, feature = "write"))]
pub(crate) fn encode_in_place(
    op: FilterOp,
    data: &mut [u8],
    file_offset: u32,
    messages: DeltaErrorMessages,
) -> Result<()> {
    let _ = file_offset;
    match op {
        #[cfg(test)]
        FilterOp::E8 => e8e9_encode(data, file_offset, false),
        #[cfg(test)]
        FilterOp::E8E9 => e8e9_encode(data, file_offset, true),
        FilterOp::Delta { channels } => {
            let encoded = delta_encode_with_allowance(
                data,
                channels,
                messages,
                &super::workspace::Allowance::default(),
            )?;
            data.copy_from_slice(&encoded);
        }
    }
    Ok(())
}

/// Channel ceiling on the decode side.
///
/// RAR 5 cannot exceed 32: its filter record stores `channels - 1` in five
/// bits. The RAR 2.9 VM takes the count from register R[0] instead, and the
/// reference decoder accepts up to 1024 there, so a decoder that stops at 32
/// refuses archives the official tools extract. The bound still has to exist,
/// because R[0] is a full 32-bit value from the archive.
pub(crate) const MAX_DELTA_CHANNELS: usize = 1024;

const GENERIC_DELTA_MESSAGES: DeltaErrorMessages = DeltaErrorMessages {
    invalid_channels: "DELTA filter channel count is invalid",
    zero_channels: "DELTA filter has zero channels",
};

#[cfg(test)]
pub(crate) fn decode_in_place(
    op: FilterOp,
    data: &mut Vec<u8>,
    file_offset: u32,
    messages: DeltaErrorMessages,
) -> Result<()> {
    decode_in_place_with_control(
        op,
        data,
        file_offset,
        messages,
        &crate::read_control::ReadControl::default(),
    )
}

#[cfg(test)]
pub(crate) fn decode_in_place_with_control(
    op: FilterOp,
    data: &mut Vec<u8>,
    file_offset: u32,
    messages: DeltaErrorMessages,
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    control.check_codec()?;

    match op {
        #[cfg(test)]
        FilterOp::E8 => e8e9_decode_with_control(data, file_offset, false, control)?,
        #[cfg(test)]
        FilterOp::E8E9 => e8e9_decode_with_control(data, file_offset, true, control)?,
        FilterOp::Delta { channels } => {
            *data = delta_decode_with_control(data, channels, messages, control)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn e8e9_decode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    e8e9_decode_with_control(
        data,
        file_offset,
        include_e9,
        &crate::read_control::ReadControl::default(),
    )
    .expect("uncancelled filter");
}

pub(crate) fn e8e9_decode_with_control(
    data: &mut [u8],
    file_offset: u32,
    include_e9: bool,
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    control.check_codec()?;
    let mut poller = control.poller();
    if data.len() <= 4 {
        return Ok(());
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while opcode_pos < opcode_limit {
        poller.check_codec(opcode_pos)?;
        let scan_end = if control.is_enabled() {
            opcode_limit.min(opcode_pos.saturating_add(64 * 1024))
        } else {
            opcode_limit
        };
        let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, scan_end, cmp_mask) else {
            opcode_pos = scan_end;
            continue;
        };
        let cur_pos = pos + 1;
        let offset = file_offset.wrapping_add(cur_pos as u32);
        let addr = u32::from_le_bytes([
            data[cur_pos],
            data[cur_pos + 1],
            data[cur_pos + 2],
            data[cur_pos + 3],
        ]);
        let new_addr = if addr < 0x0100_0000 {
            Some(addr.wrapping_sub(offset))
        } else if addr & 0x8000_0000 != 0 && addr.wrapping_add(offset) & 0x8000_0000 == 0 {
            Some(addr.wrapping_add(0x0100_0000))
        } else {
            None
        };
        if let Some(value) = new_addr {
            data[cur_pos..cur_pos + 4].copy_from_slice(&value.to_le_bytes());
        }
        opcode_pos = pos + 5;
    }

    Ok(())
}

#[cfg(any(test, feature = "write"))]
pub(crate) fn e8e9_encode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, opcode_limit, cmp_mask) {
        let cur_pos = pos + 1;
        let offset = file_offset.wrapping_add(cur_pos as u32);
        let addr = u32::from_le_bytes([
            data[cur_pos],
            data[cur_pos + 1],
            data[cur_pos + 2],
            data[cur_pos + 3],
        ]);
        let candidate = addr.wrapping_add(offset);
        if candidate < 0x0100_0000 {
            data[cur_pos..cur_pos + 4].copy_from_slice(&candidate.to_le_bytes());
        } else {
            let candidate = addr.wrapping_sub(0x0100_0000);
            if candidate & 0x8000_0000 != 0 && candidate.wrapping_add(offset) & 0x8000_0000 == 0 {
                data[cur_pos..cur_pos + 4].copy_from_slice(&candidate.to_le_bytes());
            }
        }
        opcode_pos = pos + 5;
    }
}

#[cfg(test)]
pub(crate) fn delta_decode_with_control(
    data: &[u8],
    channels: usize,
    messages: DeltaErrorMessages,
    control: &crate::read_control::ReadControl,
) -> Result<Vec<u8>> {
    delta_decode_with_allowance(
        data,
        channels,
        messages,
        control,
        &super::workspace::Allowance::default(),
    )
    .map(super::workspace::Buffer::into_vec)
}

pub(crate) fn delta_decode_with_allowance(
    data: &[u8],
    channels: usize,
    messages: DeltaErrorMessages,
    control: &crate::read_control::ReadControl,
    allowance: &Allowance,
) -> Result<super::workspace::Buffer<u8>> {
    control.check_codec()?;
    let mut poller = control.poller();
    if channels == 0 {
        return Err(Error::InvalidData(messages.zero_channels));
    }
    if channels > MAX_DELTA_CHANNELS {
        return Err(Error::InvalidData(messages.invalid_channels));
    }
    let mut out = super::workspace::Buffer::filled(data.len(), 0, allowance)?;
    match DELTA_DECODE_ROWS.get(channels - 1) {
        Some(decode_rows) => decode_rows(data, &mut out, &mut poller)?,
        None => delta_decode_strided(data, channels, &mut out, &mut poller)?,
    }
    Ok(out)
}

const DELTA_POLL_BYTES: usize = 64 * 1024;

type DeltaDecodeRows = fn(&[u8], &mut [u8], &mut crate::read_control::Poller) -> Result<()>;

// Row-major copies run every channel's sum side by side; past eight channels
// they stop beating one strided pass per channel.
const DELTA_DECODE_ROWS: [DeltaDecodeRows; 8] = [
    delta_decode_rows::<1>,
    delta_decode_rows::<2>,
    delta_decode_rows::<3>,
    delta_decode_rows::<4>,
    delta_decode_rows::<5>,
    delta_decode_rows::<6>,
    delta_decode_rows::<7>,
    delta_decode_rows::<8>,
];

fn delta_decode_rows<const N: usize>(
    data: &[u8],
    out: &mut [u8],
    poller: &mut crate::read_control::Poller,
) -> Result<()> {
    let planes = delta_planes::<N>(data);
    let (rows, ragged) = out.as_chunks_mut::<N>();
    let full_rows = rows.len();
    let mut prev = [0u8; N];
    for (block, dests) in rows.chunks_mut(DELTA_POLL_BYTES / N).enumerate() {
        let first = block * (DELTA_POLL_BYTES / N);
        poller.check_codec(first * N)?;
        let sources: [&[u8]; N] =
            std::array::from_fn(|channel| &planes[channel][first..first + dests.len()]);
        for (row, dest) in dests.iter_mut().enumerate() {
            for channel in 0..N {
                prev[channel] = prev[channel].wrapping_sub(sources[channel][row]);
            }
            *dest = prev;
        }
    }
    for (channel, dest) in ragged.iter_mut().enumerate() {
        *dest = prev[channel].wrapping_sub(planes[channel][full_rows]);
    }
    Ok(())
}

fn delta_decode_strided(
    data: &[u8],
    channels: usize,
    out: &mut [u8],
    poller: &mut crate::read_control::Poller,
) -> Result<()> {
    let mut planes = data;
    for channel in 0..channels.min(data.len()) {
        let plane_start = data.len() - planes.len();
        let (plane, rest) = planes.split_at(delta_plane_len(data.len(), channels, channel));
        planes = rest;
        let mut prev = 0u8;
        for (index, sources) in plane.chunks(DELTA_POLL_BYTES).enumerate() {
            poller.check_codec(plane_start + index * DELTA_POLL_BYTES)?;
            let start = channel + index * DELTA_POLL_BYTES * channels;
            for (dest, &byte) in out[start..].iter_mut().step_by(channels).zip(sources) {
                prev = prev.wrapping_sub(byte);
                *dest = prev;
            }
        }
    }
    Ok(())
}

fn delta_planes<const N: usize>(data: &[u8]) -> [&[u8]; N] {
    let mut rest = data;
    std::array::from_fn(|channel| {
        let (plane, tail) = rest.split_at(delta_plane_len(data.len(), N, channel));
        rest = tail;
        plane
    })
}

fn delta_plane_len(len: usize, channels: usize, channel: usize) -> usize {
    (len + channels - 1 - channel) / channels
}

/// Raw delta transform for benches; archive code passes format-specific messages.
pub fn delta_decode(data: &[u8], channels: usize) -> Result<Vec<u8>> {
    delta_decode_with_allowance(
        data,
        channels,
        GENERIC_DELTA_MESSAGES,
        &crate::read_control::ReadControl::default(),
        &super::workspace::Allowance::default(),
    )
    .map(super::workspace::Buffer::into_vec)
}

#[cfg(feature = "write")]
pub fn delta_encode(data: &[u8], channels: usize) -> Result<Vec<u8>> {
    delta_encode_with_allowance(
        data,
        channels,
        GENERIC_DELTA_MESSAGES,
        &super::workspace::Allowance::default(),
    )
    .map(super::workspace::Buffer::into_vec)
}

#[cfg(any(test, feature = "write"))]
pub(crate) fn delta_encode_with_allowance(
    data: &[u8],
    channels: usize,
    messages: DeltaErrorMessages,
    allowance: &Allowance,
) -> Result<super::workspace::Buffer<u8>> {
    if channels == 0 || channels > 32 {
        return Err(Error::InvalidData(messages.invalid_channels));
    }
    let mut out = super::workspace::Buffer::filled(data.len(), 0, allowance)?;
    let mut planes = &mut out[..];
    for channel in 0..channels.min(data.len()) {
        let (plane, rest) = std::mem::take(&mut planes).split_at_mut(delta_plane_len(
            data.len(),
            channels,
            channel,
        ));
        planes = rest;
        let mut prev = 0u8;
        for (dest, &byte) in plane
            .iter_mut()
            .zip(data[channel..].iter().step_by(channels))
        {
            *dest = prev.wrapping_sub(byte);
            prev = byte;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn short_x86_operands_are_unchanged_and_still_observe_cancellation() {
        for length in 0..=4 {
            for include_e9 in [false, true] {
                let original = vec![0xe8; length];
                let mut data = original.clone();
                super::e8e9_encode(&mut data, u32::MAX, include_e9);
                assert_eq!(data, original);
                super::e8e9_decode(&mut data, u32::MAX, include_e9);
                assert_eq!(data, original);
                let token = crate::ReadCancellation::new();
                token.cancel();
                let control = crate::read_control::ReadControl::new(Some(&token));
                assert_eq!(
                    super::e8e9_decode_with_control(&mut data, 0, include_e9, &control),
                    Err(super::Error::Cancelled)
                );
                assert_eq!(data, original);
            }
        }
    }

    #[test]
    fn configured_x86_scanning_matches_default_across_poll_boundaries() {
        let mut input = vec![0; 192 * 1024];
        for pos in [65530, 65535, 65541, 131070, 131080] {
            input[pos] = 0xe8;
            input[pos + 1..pos + 5].copy_from_slice(&123456u32.to_le_bytes());
        }
        let token = crate::ReadCancellation::new();
        let control = crate::read_control::ReadControl::new(Some(&token));
        let mut expected = input.clone();
        e8e9_decode(&mut expected, 4096, true);
        e8e9_decode_with_control(&mut input, 4096, true, &control).unwrap();
        assert_eq!(input, expected);
    }

    #[test]
    fn cancellation_interrupts_delta_and_opcode_free_x86_scans() {
        for x86 in [false, true] {
            let token = crate::ReadCancellation::new();
            let control = crate::read_control::ReadControl::new(Some(&token));
            control.cancel_after_checks(2);
            let mut bytes = vec![0; 384 * 1024];
            let result = if x86 {
                e8e9_decode_with_control(&mut bytes, 0, true, &control)
            } else {
                delta_decode_with_control(&bytes, 2, GENERIC_DELTA_MESSAGES, &control).map(|_| ())
            };
            assert_eq!(result.unwrap_err(), Error::Cancelled);
        }
    }
    use super::*;

    /// Filters a copy, going through the same dispatch the writers use.
    fn encode(op: FilterOp, data: &[u8], file_offset: u32) -> Result<Vec<u8>> {
        let mut out = data.to_vec();
        encode_in_place(op, &mut out, file_offset, GENERIC_DELTA_MESSAGES)?;
        Ok(out)
    }

    fn x86_sample() -> Vec<u8> {
        let mut data = b"prefix ".to_vec();
        data.extend_from_slice(&[0xe8, 0x10, 0x20, 0x00, 0x00]);
        data.extend_from_slice(b" middle ");
        data.extend_from_slice(&[0xe9, 0xf0, 0xff, 0xff, 0xff]);
        data.extend_from_slice(b" suffix");
        data
    }

    fn reference_e8e9_encode(data: &mut [u8], file_offset: u32, include_e9: bool) {
        if data.len() <= 4 {
            return;
        }
        let cmp_mask = if include_e9 { 0xfe } else { 0xff };
        let mut cur_pos = 0usize;
        while cur_pos < data.len() - 4 {
            cur_pos += 1;
            let opcode = data[cur_pos - 1];
            if opcode & cmp_mask == 0xe8 {
                let offset = file_offset.wrapping_add(cur_pos as u32);
                let addr = u32::from_le_bytes([
                    data[cur_pos],
                    data[cur_pos + 1],
                    data[cur_pos + 2],
                    data[cur_pos + 3],
                ]);
                let candidate = addr.wrapping_add(offset);
                if candidate < 0x0100_0000 {
                    data[cur_pos..cur_pos + 4].copy_from_slice(&candidate.to_le_bytes());
                } else {
                    let candidate = addr.wrapping_sub(0x0100_0000);
                    if candidate & 0x8000_0000 != 0
                        && candidate.wrapping_add(offset) & 0x8000_0000 == 0
                    {
                        data[cur_pos..cur_pos + 4].copy_from_slice(&candidate.to_le_bytes());
                    }
                }
                cur_pos += 4;
            }
        }
    }

    fn reference_e8e9_decode(data: &mut [u8], file_offset: u32, include_e9: bool) {
        if data.len() <= 4 {
            return;
        }
        let cmp_mask = if include_e9 { 0xfe } else { 0xff };
        let mut cur_pos = 0usize;
        while cur_pos < data.len() - 4 {
            cur_pos += 1;
            let opcode = data[cur_pos - 1];
            if opcode & cmp_mask == 0xe8 {
                let offset = file_offset.wrapping_add(cur_pos as u32);
                let addr = u32::from_le_bytes([
                    data[cur_pos],
                    data[cur_pos + 1],
                    data[cur_pos + 2],
                    data[cur_pos + 3],
                ]);
                let new_addr = if addr < 0x0100_0000 {
                    Some(addr.wrapping_sub(offset))
                } else if addr & 0x8000_0000 != 0 && addr.wrapping_add(offset) & 0x8000_0000 == 0 {
                    Some(addr.wrapping_add(0x0100_0000))
                } else {
                    None
                };
                if let Some(value) = new_addr {
                    data[cur_pos..cur_pos + 4].copy_from_slice(&value.to_le_bytes());
                }
                cur_pos += 4;
            }
        }
    }

    #[test]
    fn e8_transform_round_trips_representative_bytes() {
        let input = x86_sample();
        let mut filtered = encode(FilterOp::E8, &input, 4096).unwrap();

        decode_in_place(FilterOp::E8, &mut filtered, 4096, GENERIC_DELTA_MESSAGES).unwrap();

        assert_eq!(filtered, input);
    }

    #[test]
    fn e8e9_transform_round_trips_representative_bytes() {
        let input = x86_sample();
        let mut filtered = encode(FilterOp::E8E9, &input, 8192).unwrap();

        decode_in_place(FilterOp::E8E9, &mut filtered, 8192, GENERIC_DELTA_MESSAGES).unwrap();

        assert_eq!(filtered, input);
    }

    #[test]
    fn e8e9_transform_matches_reference_at_chunk_boundaries_and_skips_payloads() {
        let mut input = vec![0x41u8; 104];
        for (pos, address) in [
            (0usize, 0x0000_00e8u32),
            (31, 0x0000_0100),
            (36, 0x0000_0200),
            (64, 0x0000_0300),
            (96, 0xffff_ff00),
        ] {
            input[pos] = if pos == 36 { 0xe9 } else { 0xe8 };
            input[pos + 1..pos + 5].copy_from_slice(&address.to_le_bytes());
        }
        input[32] = 0xe8;
        input[65] = 0xe9;

        for &include_e9 in &[false, true] {
            let mut expected = input.clone();
            let mut actual = input.clone();
            reference_e8e9_encode(&mut expected, 0x1000, include_e9);
            e8e9_encode(&mut actual, 0x1000, include_e9);
            assert_eq!(actual, expected);

            reference_e8e9_decode(&mut expected, 0x1000, include_e9);
            e8e9_decode(&mut actual, 0x1000, include_e9);
            assert_eq!(actual, expected);
            assert_eq!(actual, input);
        }
    }

    #[test]
    fn delta_transform_round_trips_interleaved_channels() {
        let input = b"abcdefghijklmnopqrstuvwxyz0123456789".repeat(3);
        let mut filtered = encode(FilterOp::Delta { channels: 3 }, &input, 0).unwrap();

        decode_in_place(
            FilterOp::Delta { channels: 3 },
            &mut filtered,
            0,
            GENERIC_DELTA_MESSAGES,
        )
        .unwrap();

        assert_eq!(filtered, input);
    }

    #[test]
    fn delta_decode_accepts_channel_counts_the_rar29_vm_can_ask_for() {
        // 33 is past what RAR 5 can encode and well inside what the RAR 2.9
        // VM can put in R[0]. Refusing it here refused whole archives.
        let mut filtered = vec![0; 64];

        assert_eq!(
            decode_in_place(
                FilterOp::Delta { channels: 33 },
                &mut filtered,
                0,
                GENERIC_DELTA_MESSAGES,
            ),
            Ok(())
        );
    }

    #[test]
    fn delta_decode_rejects_channel_counts_above_the_vm_limit() {
        let mut filtered = vec![0; 64];

        assert_eq!(
            decode_in_place(
                FilterOp::Delta {
                    channels: MAX_DELTA_CHANNELS + 1,
                },
                &mut filtered,
                0,
                GENERIC_DELTA_MESSAGES,
            ),
            Err(Error::InvalidData("DELTA filter channel count is invalid"))
        );
    }

    fn per_byte_delta_decode(data: &[u8], channels: usize) -> Vec<u8> {
        let mut out = vec![0; data.len()];
        let mut src = 0;
        for channel in 0..channels {
            let mut prev = 0u8;
            for dest in (channel..out.len()).step_by(channels) {
                prev = prev.wrapping_sub(data[src]);
                out[dest] = prev;
                src += 1;
            }
        }
        out
    }

    fn per_byte_delta_encode(data: &[u8], channels: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for channel in 0..channels {
            let mut prev = 0u8;
            for &byte in data.iter().skip(channel).step_by(channels) {
                out.push(prev.wrapping_sub(byte));
                prev = byte;
            }
        }
        out
    }

    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 7) as u8
            })
            .collect()
    }

    #[test]
    fn cancellation_interrupts_delta_decode_past_the_row_major_channel_counts() {
        let token = crate::ReadCancellation::new();
        let control = crate::read_control::ReadControl::new(Some(&token));
        control.cancel_after_checks(2);
        let bytes = vec![0; 384 * 1024];

        let result = delta_decode_with_control(&bytes, 64, GENERIC_DELTA_MESSAGES, &control);

        assert_eq!(result.unwrap_err(), Error::Cancelled);
    }

    #[test]
    fn delta_decode_runs_each_planar_channel_into_interleaved_output() {
        let decoded = super::delta_decode(&[1, 2, 3, 4, 5], 2).unwrap();

        assert_eq!(decoded, [255, 252, 253, 247, 250]);
    }

    #[test]
    fn delta_matches_per_byte_model_for_every_channel_count_and_ragged_length() {
        let control = crate::read_control::ReadControl::default();
        let allowance = super::super::workspace::Allowance::default();
        let input = noise(300);
        for channels in (1..=33).chain([64, 255, 1024]) {
            for len in (0..=2 * channels + 3).chain([97, 300]) {
                let data = &input[..len.min(input.len())];
                let decoded = delta_decode_with_allowance(
                    data,
                    channels,
                    GENERIC_DELTA_MESSAGES,
                    &control,
                    &allowance,
                )
                .unwrap();
                assert_eq!(
                    decoded,
                    per_byte_delta_decode(data, channels),
                    "decode channels={channels} len={len}"
                );
                if channels <= 32 {
                    let encoded = delta_encode_with_allowance(
                        data,
                        channels,
                        GENERIC_DELTA_MESSAGES,
                        &allowance,
                    )
                    .unwrap();
                    assert_eq!(
                        encoded,
                        per_byte_delta_encode(data, channels),
                        "encode channels={channels} len={len}"
                    );
                }
            }
        }
    }

    #[test]
    fn controlled_delta_decode_matches_model_across_poll_boundaries() {
        let token = crate::ReadCancellation::new();
        let control = crate::read_control::ReadControl::new(Some(&token));
        let data = noise(3 * 64 * 1024 + 7);
        for channels in [1, 3, 8, 9] {
            let decoded = delta_decode_with_allowance(
                &data,
                channels,
                GENERIC_DELTA_MESSAGES,
                &control,
                &super::super::workspace::Allowance::default(),
            )
            .unwrap();
            assert_eq!(decoded, per_byte_delta_decode(&data, channels));
        }
    }

    #[test]
    fn encode_in_place_matches_allocating_encode() {
        let input = x86_sample();
        let expected = encode(FilterOp::E8E9, &input, 1234).unwrap();
        let mut actual = input;

        encode_in_place(FilterOp::E8E9, &mut actual, 1234, GENERIC_DELTA_MESSAGES).unwrap();

        assert_eq!(actual, expected);
    }
}
