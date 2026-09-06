//! Timestamp conversions shared by archive consumers.
//! Legacy DOS values follow the established extracting-machine local-zone policy.

use crate::tzif::TimeZone;
use crate::{ArchiveFamily, TimeRefinement};
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A stored timestamp with its interpretation attached, before refinements.
///
/// This is a view of archive metadata, not necessarily a valid instant.
/// Presence is represented separately by `Option<StoredTimestamp>`:
/// `DosLocal(0)` is an invalid stored date, while `UnixSeconds(0)` is the Unix
/// epoch. Odd-second and subsecond refinements remain separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoredTimestamp {
    /// Packed DOS date/time fields with no stored timezone and two-second
    /// resolution. Obtaining an instant requires a timezone policy.
    DosLocal(u32),
    /// Absolute whole seconds since the Unix epoch.
    UnixSeconds(u32),
}

impl StoredTimestamp {
    pub(crate) fn from_family(family: ArchiveFamily, raw: u32) -> Self {
        match family {
            ArchiveFamily::Rar13 | ArchiveFamily::Rar15To40 => Self::DosLocal(raw),
            ArchiveFamily::Rar50Plus => Self::UnixSeconds(raw),
        }
    }

    /// Calendar fields `(year, month, day, hour, minute, second)` for display.
    ///
    /// DOS values expose the stored wall-clock fields without timezone
    /// conversion; Unix values use UTC. Refinements are not applied. For
    /// compatibility with Python date tuples, a zero DOS month or day returns
    /// `None`; other field values are exposed without validation.
    /// Use [`crate::ArchiveMemberMeta::modification_time`] to obtain an instant
    /// under the existing local-zone and refinement policy instead.
    pub fn calendar_fields(self) -> Option<(u16, u8, u8, u8, u8, u8)> {
        match self {
            Self::UnixSeconds(seconds) => Some(unix_datetime(seconds)),
            Self::DosLocal(raw) => {
                let year = 1980 + ((raw >> 25) & 0x7f) as u16;
                let month = ((raw >> 21) & 0x0f) as u8;
                let day = ((raw >> 16) & 0x1f) as u8;
                let hour = ((raw >> 11) & 0x1f) as u8;
                let minute = ((raw >> 5) & 0x3f) as u8;
                let second = ((raw & 0x1f) * 2) as u8;
                (month != 0 && day != 0).then_some((year, month, day, hour, minute, second))
            }
        }
    }
}

pub fn current_filetime() -> u64 {
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

pub fn format_filetime_utc(filetime: u64) -> String {
    filetime_to_system_time(filetime)
        .and_then(format_system_time_utc)
        .unwrap_or_else(|| format!("{filetime:#018x}"))
}

pub fn source_unix_mtime(metadata: &fs::Metadata) -> Option<u32> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u32::try_from(duration.as_secs()).ok())
}

/// UTC calendar fields for a RAR5 whole-second timestamp, including Unix epoch.
pub fn unix_datetime(seconds: u32) -> (u16, u8, u8, u8, u8, u8) {
    let (year, month, day) = civil_from_days(i64::from(seconds / 86_400));
    let within_day = seconds % 86_400;
    (
        year as u16,
        month as u8,
        day as u8,
        (within_day / 3600) as u8,
        ((within_day % 3600) / 60) as u8,
        (within_day % 60) as u8,
    )
}

pub fn source_dos_mtime(metadata: &fs::Metadata) -> u32 {
    metadata
        .modified()
        .ok()
        .and_then(system_time_to_dos_time)
        .unwrap_or(0)
}

/// Converts a present stored timestamp without treating Unix epoch as missing.
/// Legacy DOS zero remains invalid under the existing local-zone conversion.
pub fn extracted_system_time(
    family: ArchiveFamily,
    file_time: Option<u32>,
    refinement: Option<TimeRefinement>,
) -> Option<SystemTime> {
    let file_time = file_time?;
    let base = match family {
        ArchiveFamily::Rar13 | ArchiveFamily::Rar15To40 => dos_time_to_system_time(file_time),
        ArchiveFamily::Rar50Plus => Some(UNIX_EPOCH + Duration::from_secs(u64::from(file_time))),
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

/// A DOS timestamp is a wall-clock reading with no zone, so both directions go
/// through the local zone rather than UTC. See [`crate::tzif`] for why, and for
/// what that costs.
fn system_time_to_dos_time(time: SystemTime) -> Option<u32> {
    let instant = i64::try_from(time.duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()?;
    let local = instant.checked_add(i64::from(TimeZone::local().offset_at(instant)))?;
    let seconds = u64::try_from(local).ok()?;
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
    let local = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))?;
    let zone = TimeZone::local();
    let instant = local.checked_sub(i64::from(zone.offset_for_local(local)))?;
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(instant).ok()?))
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

#[cfg(test)]
mod tests {
    use super::StoredTimestamp;

    #[test]
    fn stored_calendar_fields_keep_wall_clock_separate_from_utc() {
        assert_eq!(StoredTimestamp::DosLocal(0).calendar_fields(), None);
        assert_eq!(
            StoredTimestamp::UnixSeconds(0).calendar_fields(),
            Some((1970, 1, 1, 0, 0, 0))
        );
        assert_eq!(
            StoredTimestamp::DosLocal(0x5022_1882).calendar_fields(),
            Some((2020, 1, 2, 3, 4, 4))
        );
        assert_eq!(
            StoredTimestamp::UnixSeconds(1_582_934_400).calendar_fields(),
            Some((2020, 2, 29, 0, 0, 0))
        );
        // The display accessor retains historically exposed raw DOS fields,
        // rather than silently normalizing malformed dates into another date.
        assert_eq!(
            StoredTimestamp::DosLocal(u32::MAX).calendar_fields(),
            Some((2107, 15, 31, 31, 63, 62))
        );
    }
}
