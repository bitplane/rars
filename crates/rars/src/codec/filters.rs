use super::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterOp {
    E8,
    E8E9,
    Delta { channels: usize },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DeltaErrorMessages {
    pub invalid_channels: &'static str,
    pub zero_channels: &'static str,
    pub truncated_source: &'static str,
}

pub(crate) fn encode_in_place(
    op: FilterOp,
    data: &mut [u8],
    file_offset: u32,
    messages: DeltaErrorMessages,
) -> Result<()> {
    match op {
        FilterOp::E8 => e8e9_encode(data, file_offset, false),
        FilterOp::E8E9 => e8e9_encode(data, file_offset, true),
        FilterOp::Delta { channels } => {
            let encoded = delta_encode(data, channels, messages)?;
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
/// because R[0] is a full 32-bit value from the archive and the deinterleave
/// loop runs once per channel whether or not the channel has any bytes.
pub(crate) const MAX_DELTA_CHANNELS: usize = 1024;

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

pub(crate) fn decode_in_place_with_control(
    op: FilterOp,
    data: &mut Vec<u8>,
    file_offset: u32,
    messages: DeltaErrorMessages,
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    control.check_codec()?;

    match op {
        FilterOp::E8 => e8e9_decode_with_control(data, file_offset, false, control)?,
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

pub(crate) fn delta_decode_with_control(
    data: &[u8],
    channels: usize,
    messages: DeltaErrorMessages,
    control: &crate::read_control::ReadControl,
) -> Result<Vec<u8>> {
    control.check_codec()?;
    let mut poller = control.poller();
    if channels == 0 {
        return Err(Error::InvalidData(messages.zero_channels));
    }
    if channels > MAX_DELTA_CHANNELS {
        return Err(Error::InvalidData(messages.invalid_channels));
    }
    let mut out = vec![0u8; data.len()];
    let mut src = 0usize;
    for channel in 0..channels {
        let mut prev = 0u8;
        let mut dest = channel;
        while dest < out.len() {
            poller.check_codec(src)?;
            let byte = *data
                .get(src)
                .ok_or(Error::InvalidData(messages.truncated_source))?;
            prev = prev.wrapping_sub(byte);
            out[dest] = prev;
            src += 1;
            dest += channels;
        }
    }
    Ok(out)
}

pub(crate) fn delta_encode(
    data: &[u8],
    channels: usize,
    messages: DeltaErrorMessages,
) -> Result<Vec<u8>> {
    if channels == 0 || channels > 32 {
        return Err(Error::InvalidData(messages.invalid_channels));
    }
    let mut out = Vec::with_capacity(data.len());
    for channel in 0..channels {
        let mut prev = 0u8;
        let mut src = channel;
        while src < data.len() {
            let byte = data[src];
            out.push(prev.wrapping_sub(byte));
            prev = byte;
            src += channels;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
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
                delta_decode_with_control(&bytes, 2, generic_messages(), &control).map(|_| ())
            };
            assert_eq!(result.unwrap_err(), Error::Cancelled);
        }
    }
    use super::*;

    fn generic_messages() -> DeltaErrorMessages {
        DeltaErrorMessages {
            invalid_channels: "DELTA filter channel count is invalid",
            zero_channels: "DELTA filter has zero channels",
            truncated_source: "DELTA filter source is truncated",
        }
    }

    /// Filters a copy, going through the same dispatch the writers use.
    fn encode(op: FilterOp, data: &[u8], file_offset: u32) -> Result<Vec<u8>> {
        let mut out = data.to_vec();
        encode_in_place(op, &mut out, file_offset, generic_messages())?;
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

        decode_in_place(FilterOp::E8, &mut filtered, 4096, generic_messages()).unwrap();

        assert_eq!(filtered, input);
    }

    #[test]
    fn e8e9_transform_round_trips_representative_bytes() {
        let input = x86_sample();
        let mut filtered = encode(FilterOp::E8E9, &input, 8192).unwrap();

        decode_in_place(FilterOp::E8E9, &mut filtered, 8192, generic_messages()).unwrap();

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
            generic_messages(),
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
                generic_messages(),
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
                generic_messages(),
            ),
            Err(Error::InvalidData("DELTA filter channel count is invalid"))
        );
    }

    #[test]
    fn encode_in_place_matches_allocating_encode() {
        let input = x86_sample();
        let expected = encode(FilterOp::E8E9, &input, 1234).unwrap();
        let mut actual = input;

        encode_in_place(FilterOp::E8E9, &mut actual, 1234, generic_messages()).unwrap();

        assert_eq!(actual, expected);
    }
}
