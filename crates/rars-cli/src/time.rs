use rars::{ArchiveFamily, TimeRefinement};
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) fn current_filetime() -> u64 {
    const FILETIME_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;
    const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration
        .as_secs()
        .saturating_add(FILETIME_UNIX_EPOCH_SECONDS)
        .saturating_mul(FILETIME_TICKS_PER_SECOND);
    seconds.saturating_add(u64::from(duration.subsec_nanos() / 100))
}

pub(crate) fn format_filetime_utc(filetime: u64) -> String {
    filetime_to_system_time(filetime)
        .and_then(format_system_time_utc)
        .unwrap_or_else(|| format!("{filetime:#018x}"))
}

pub(crate) fn source_unix_mtime(metadata: &fs::Metadata) -> Option<u32> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u32::try_from(duration.as_secs()).ok())
}

pub(crate) fn source_dos_mtime(metadata: &fs::Metadata) -> u32 {
    metadata
        .modified()
        .ok()
        .and_then(system_time_to_dos_time)
        .unwrap_or(0)
}

pub(crate) fn extracted_system_time(
    family: ArchiveFamily,
    file_time: u32,
    refinement: Option<TimeRefinement>,
) -> Option<SystemTime> {
    let base = match family {
        ArchiveFamily::Rar13 | ArchiveFamily::Rar15To40 => dos_time_to_system_time(file_time),
        ArchiveFamily::Rar50Plus => unix_seconds_to_system_time(file_time),
        _ => None,
    }?;
    // A DOS timestamp counts in two-second steps, so an odd second and any
    // sub-second detail arrive separately and have to be added back on.
    let Some(refinement) = refinement else {
        return Some(base);
    };
    let extra = Duration::from_secs(u64::from(refinement.add_second))
        + Duration::from_nanos(u64::from(refinement.nanoseconds));
    base.checked_add(extra).or(Some(base))
}

fn system_time_to_dos_time(time: SystemTime) -> Option<u32> {
    let seconds = time.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let days = i64::try_from(seconds / 86_400).ok()?;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    if !(1980..=2107).contains(&year) {
        return None;
    }
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Some(
        ((u32::try_from(year - 1980).ok()?) << 25)
            | (month << 21)
            | (day << 16)
            | ((hour as u32) << 11)
            | ((minute as u32) << 5)
            | ((second as u32) / 2),
    )
}

fn dos_time_to_system_time(time: u32) -> Option<SystemTime> {
    if time == 0 {
        return None;
    }
    let second = (time & 0x1f) * 2;
    let minute = (time >> 5) & 0x3f;
    let hour = (time >> 11) & 0x1f;
    let day = (time >> 16) & 0x1f;
    let month = (time >> 21) & 0x0f;
    let year = 1980 + i32::try_from((time >> 25) & 0x7f).ok()?;
    if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = u64::try_from(days)
        .ok()?
        .checked_mul(86_400)?
        .checked_add(u64::from(hour) * 3_600 + u64::from(minute) * 60 + u64::from(second))?;
    Some(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn unix_seconds_to_system_time(seconds: u32) -> Option<SystemTime> {
    (seconds != 0).then_some(UNIX_EPOCH + Duration::from_secs(u64::from(seconds)))
}

fn filetime_to_system_time(filetime: u64) -> Option<SystemTime> {
    const FILETIME_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;
    const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;

    let seconds = filetime / FILETIME_TICKS_PER_SECOND;
    let ticks = filetime % FILETIME_TICKS_PER_SECOND;
    let unix_seconds = seconds.checked_sub(FILETIME_UNIX_EPOCH_SECONDS)?;
    Some(UNIX_EPOCH + Duration::from_secs(unix_seconds) + Duration::from_nanos(ticks * 100))
}

fn format_system_time_utc(time: SystemTime) -> Option<String> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    let days = i64::try_from(duration.as_secs() / 86_400).ok()?;
    let seconds_of_day = duration.as_secs() % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(month <= 2);
    (year as i32, month as u32, day as u32)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
