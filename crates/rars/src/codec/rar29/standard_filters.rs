//! RAR29 standard VM filter recognition and execution.
use super::super::filters;
#[cfg(all(test, feature = "write"))]
use super::Allowance;
use super::{
    rar29_delta_messages, Budget, Buffer, Error, Result, StandardFilter, MAX_AUDIO_CHANNELS,
};
use crate::crc32::crc32;

pub(super) fn identify_standard_filter(code: &[u8]) -> Option<StandardFilter> {
    if code.iter().fold(0u8, |acc, &byte| acc ^ byte) != 0 {
        return None;
    }
    match (code.len(), crc32(code)) {
        (53, 0xad57_6887) => Some(StandardFilter::E8),
        (57, 0x3cd7_e57e) => Some(StandardFilter::E8E9),
        (120, 0x3769_893f) => Some(StandardFilter::Itanium),
        (29, 0x0e06_077d) => Some(StandardFilter::Delta),
        (149, 0x1c2c_5dc8) => Some(StandardFilter::Rgb),
        (216, 0xbc85_e701) => Some(StandardFilter::Audio),
        _ => None,
    }
}

#[cfg(all(test, feature = "write"))]
pub(super) fn apply_standard_filter_with_control(
    filter: StandardFilter,
    data: &mut Vec<u8>,
    file_offset: u32,
    regs: &[u32; 7],
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    let mut owned = Buffer::from_vec(std::mem::take(data));
    let result =
        apply_standard_filter_with_allowance(filter, &mut owned, file_offset, regs, control);
    *data = owned.into_vec();
    result
}
#[cfg(all(test, feature = "write"))]
pub(super) fn apply_standard_filter(
    filter: StandardFilter,
    data: &mut Vec<u8>,
    file_offset: u32,
    regs: &[u32; 7],
) -> Result<()> {
    apply_standard_filter_with_control(
        filter,
        data,
        file_offset,
        regs,
        &crate::read_control::ReadControl::default(),
    )
}

pub(super) fn apply_standard_filter_with_allowance<B: Budget>(
    filter: StandardFilter,
    data: &mut Buffer<u8, B>,
    file_offset: u32,
    regs: &[u32; 7],
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    control.check_codec()?;

    match filter {
        StandardFilter::E8 => filters::e8e9_decode_with_control(data, file_offset, false, control)?,
        StandardFilter::E8E9 => {
            filters::e8e9_decode_with_control(data, file_offset, true, control)?
        }
        StandardFilter::Itanium => itanium_decode_with_control(data, file_offset, control)?,
        StandardFilter::Delta => {
            let channels = regs[0] as usize;
            // Validate once in the shared decoder, retaining the register
            // diagnostic for zero as well as excessive channel counts.
            let mut messages = rar29_delta_messages();
            messages.zero_channels = messages.invalid_channels;
            *data = filters::delta_decode_with_allowance(
                data,
                channels,
                messages,
                control,
                &data.allowance(),
            )?;
        }
        StandardFilter::Rgb => {
            if regs[0] < 3 || regs[1] > 2 {
                return Err(Error::InvalidData(
                    "RAR 2.9 RGB filter parameters are invalid",
                ));
            }
            let width = regs[0] as usize - 3;
            let pos_r = regs[1] as usize;
            *data = rgb_decode_with_allowance(data, width, pos_r, control, &data.allowance())?;
        }
        StandardFilter::Audio => {
            let channels = regs[0] as usize;
            if channels == 0 || channels > MAX_AUDIO_CHANNELS {
                return Err(Error::InvalidData(
                    "RAR 2.9 AUDIO filter channel count is invalid",
                ));
            }
            *data = audio_decode_with_allowance(data, channels, control, &data.allowance())?;
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "write"))]
pub(super) fn itanium_decode(data: &mut [u8], file_offset: u32) {
    itanium_decode_with_control(
        data,
        file_offset,
        &crate::read_control::ReadControl::default(),
    )
    .expect("uncancelled filter");
}

pub(super) fn itanium_decode_with_control(
    data: &mut [u8],
    file_offset: u32,
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    control.check_codec()?;
    let mut poller = control.poller();
    if data.len() <= 21 {
        return Ok(());
    }
    let base_offset = file_offset >> 4;
    // Each 16-byte Itanium bundle can inspect a 4-byte instruction field that
    // starts up to 13 bytes into the bundle. Keeping a 21-byte tail prevents
    // decoding a partial final bundle.
    let block_count = (data.len() - 21).div_ceil(16);
    for block in 0..block_count {
        let pos = block * 16;
        poller.check_codec(pos)?;
        let file_offset = base_offset.wrapping_add(block as u32);
        let mut mask = (0x334b_0000u32 >> (data[pos] & 0x1e)) & 3;
        if mask != 0 {
            mask += 1;
            while mask <= 4 {
                let p = pos + (mask as usize * 5 - 8);
                if ((data[p + 3] >> mask) & 15) == 5 {
                    let raw = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
                    let mut value = raw >> mask;
                    value = value.wrapping_sub(file_offset) & 0x000f_ffff;
                    let raw = (raw & !(0x000f_ffff << mask)) | (value << mask);
                    data[p..p + 4].copy_from_slice(&raw.to_le_bytes());
                }
                mask += 1;
            }
        }
    }

    Ok(())
}

#[cfg(all(test, feature = "write"))]
pub(super) fn rgb_decode_with_control(
    data: &[u8],
    width: usize,
    pos_r: usize,
    control: &crate::read_control::ReadControl,
) -> Result<Vec<u8>> {
    rgb_decode_with_allowance(data, width, pos_r, control, &Allowance::default())
        .map(Buffer::into_vec)
}
fn rgb_decode_with_allowance<B: Budget>(
    data: &[u8],
    width: usize,
    pos_r: usize,
    control: &crate::read_control::ReadControl,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    control.check_codec()?;
    let mut poller = control.poller();
    if data.len() < 3 || width == 0 || !width.is_multiple_of(3) || width > data.len() || pos_r > 2 {
        return Err(Error::InvalidData(
            "RAR 2.9 RGB filter parameters are invalid",
        ));
    }
    let mut out = Buffer::filled(data.len(), 0, allowance)?;
    let mut src = 0usize;
    for channel in 0..3 {
        let mut prev = 0u8;
        let mut i = channel;
        while i < data.len() {
            poller.check_codec(src)?;
            let predicted = if i >= width + 3 {
                rgb_predict(prev, out[i - width], out[i - width - 3])
            } else {
                prev
            };
            let encoded = *data
                .get(src)
                .ok_or(Error::InvalidData("RAR 2.9 RGB filter source is truncated"))?;
            prev = predicted.wrapping_sub(encoded);
            out[i] = prev;
            src += 1;
            i += 3;
        }
    }
    for i in (pos_r..data.len().saturating_sub(2)).step_by(3) {
        poller.check_codec(i)?;
        let green = out[i + 1];
        out[i] = out[i].wrapping_add(green);
        out[i + 2] = out[i + 2].wrapping_add(green);
    }
    Ok(out)
}

pub(super) fn rgb_predict(prev: u8, upper: u8, upper_left: u8) -> u8 {
    let predicted = i32::from(prev) + i32::from(upper) - i32::from(upper_left);
    let pa = (predicted - i32::from(prev)).abs();
    let pb = (predicted - i32::from(upper)).abs();
    let pc = (predicted - i32::from(upper_left)).abs();
    if pa <= pb && pa <= pc {
        prev
    } else if pb <= pc {
        upper
    } else {
        upper_left
    }
}

#[cfg(all(test, feature = "write"))]
pub(super) fn audio_decode_with_control(
    data: &[u8],
    channels: usize,
    control: &crate::read_control::ReadControl,
) -> Result<Vec<u8>> {
    audio_decode_with_allowance(data, channels, control, &Allowance::default())
        .map(Buffer::into_vec)
}
fn audio_decode_with_allowance<B: Budget>(
    data: &[u8],
    channels: usize,
    control: &crate::read_control::ReadControl,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    control.check_codec()?;
    let mut poller = control.poller();
    let mut out = Buffer::filled(data.len(), 0, allowance)?;
    let mut src = 0usize;
    for channel in 0..channels {
        let mut prev_byte = 0u32;
        let mut prev_delta = 0i32;
        let mut d1 = 0i32;
        let mut d2 = 0i32;
        let mut k1 = 0i32;
        let mut k2 = 0i32;
        let mut k3 = 0i32;
        let mut dif = [0u32; 7];
        let mut byte_count = 0usize;
        let mut i = channel;
        while i < data.len() {
            poller.check_codec(src)?;
            let d3 = d2;
            d2 = prev_delta - d1;
            d1 = prev_delta;
            let predicted = ((8 * prev_byte as i32 + k1 * d1 + k2 * d2 + k3 * d3) >> 3) & 0xff;
            let encoded = *data.get(src).ok_or(Error::InvalidData(
                "RAR 2.9 AUDIO filter source is truncated",
            ))?;
            src += 1;
            let decoded = (predicted as u8).wrapping_sub(encoded);
            out[i] = decoded;
            prev_delta = decoded.wrapping_sub(prev_byte as u8) as i8 as i32;
            prev_byte = decoded as u32;
            let d = (encoded as i8 as i32) << 3;
            dif[0] += d.unsigned_abs();
            dif[1] += (d - d1).unsigned_abs();
            dif[2] += (d + d1).unsigned_abs();
            dif[3] += (d - d2).unsigned_abs();
            dif[4] += (d + d2).unsigned_abs();
            dif[5] += (d - d3).unsigned_abs();
            dif[6] += (d + d3).unsigned_abs();
            if byte_count & 0x1f == 0 {
                let mut min = dif[0];
                let mut min_index = 0usize;
                dif[0] = 0;
                for (index, value) in dif.iter_mut().enumerate().skip(1) {
                    if *value < min {
                        min = *value;
                        min_index = index;
                    }
                    *value = 0;
                }
                match min_index {
                    1 if k1 >= -16 => k1 -= 1,
                    2 if k1 < 16 => k1 += 1,
                    3 if k2 >= -16 => k2 -= 1,
                    4 if k2 < 16 => k2 += 1,
                    5 if k3 >= -16 => k3 -= 1,
                    6 if k3 < 16 => k3 += 1,
                    _ => {}
                }
            }
            byte_count += 1;
            i += channels;
        }
    }
    Ok(out)
}
