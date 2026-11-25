//! The machine's local time zone, which legacy RAR timestamps are read and
//! written in.
//!
//! RAR 1.3 through 4.x store a wall-clock reading with no zone; see
//! [`crate::tzif`] for why that reading is resolved against the local zone and
//! not UTC. Everywhere but Windows the zone comes from the system's TZif
//! database.
//!
//! Windows has no zone database to read. There the offsets come from the
//! system's own time zone settings, through chrono's `Local`: the standard and
//! daylight offsets and the rule for switching between them, for each year, as
//! Windows reports them. That is the zone Python's `time.localtime` uses there
//! too. Only the instant-to-offset direction is asked of Windows; the reverse
//! is worked out here by [`offset_for_local_from`], so it is the same code on
//! every platform's tests.

#[cfg(not(windows))]
use crate::tzif::TimeZone;

/// The machine's local zone, in whichever form the platform provides it.
pub(crate) enum LocalZone {
    /// A TZif file, read once.
    #[cfg(not(windows))]
    Tzif(&'static TimeZone),
    /// The zone Windows is set to, asked at each conversion.
    #[cfg(windows)]
    System,
}

impl LocalZone {
    pub(crate) fn current() -> Self {
        #[cfg(not(windows))]
        return Self::Tzif(TimeZone::local());
        #[cfg(windows)]
        return Self::System;
    }

    /// The offset in force at an instant, in seconds east of UTC.
    pub(crate) fn offset_at(&self, unix_seconds: i64) -> i32 {
        match self {
            #[cfg(not(windows))]
            Self::Tzif(zone) => zone.offset_at(unix_seconds),
            #[cfg(windows)]
            Self::System => system::offset_at(unix_seconds),
        }
    }

    /// The offset that turns a wall-clock reading back into an instant. A
    /// reading in the hour a zone repeats or skips resolves to standard time.
    pub(crate) fn offset_for_local(&self, local_seconds: i64) -> i32 {
        match self {
            #[cfg(not(windows))]
            Self::Tzif(zone) => zone.offset_for_local(local_seconds),
            #[cfg(windows)]
            Self::System => offset_for_local_from(local_seconds, system::offset_at),
        }
    }
}

/// `TimeZone::offset_for_local` for a zone that can only be asked for the
/// offset at an instant, with no daylight-saving flag to go by.
///
/// The candidates are the offsets in force at the reading and a day either
/// side of it, and one is accepted when applying it lands on an instant whose
/// own offset is the same. Where two qualify, or none do because the reading is
/// in a skipped hour, the smaller offset wins. Windows describes every zone as
/// a standard offset and a daylight one ahead of it, so the smaller is standard
/// time, which is what a TZif zone resolves these readings to as well.
#[cfg(any(windows, test))]
fn offset_for_local_from(local_seconds: i64, offset_at: impl Fn(i64) -> i32) -> i32 {
    const DAY: i64 = 86_400;
    let mut candidates: Vec<i32> = Vec::with_capacity(3);
    for probe in [local_seconds - DAY, local_seconds, local_seconds + DAY] {
        let offset = offset_at(probe);
        if !candidates.contains(&offset) {
            candidates.push(offset);
        }
    }
    let reachable = candidates
        .iter()
        .copied()
        .filter(|&offset| offset_at(local_seconds - i64::from(offset)) == offset)
        .min();
    // `candidates` is never empty: it holds the offset at the reading itself.
    reachable.unwrap_or_else(|| candidates.iter().copied().min().unwrap_or(0))
}

#[cfg(windows)]
mod system {
    use chrono::{DateTime, Offset, TimeZone};

    /// The offset Windows gives for an instant, in seconds east of UTC.
    ///
    /// Every instant a DOS timestamp can name, 1980 to 2107, is inside
    /// chrono's range, so the zero fallback is never reached from one.
    pub(super) fn offset_at(unix_seconds: i64) -> i32 {
        DateTime::from_timestamp(unix_seconds, 0).map_or(0, |utc| {
            chrono::Local
                .offset_from_utc_datetime(&utc.naive_utc())
                .fix()
                .local_minus_utc()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::offset_for_local_from;
    use crate::tzif::TimeZone;

    fn zone(bytes: &[u8]) -> TimeZone {
        TimeZone::parse(bytes).expect("fixture parses")
    }

    fn fixtures() -> [(&'static str, TimeZone); 5] {
        [
            (
                "Europe/London",
                zone(include_bytes!("../tests/fixtures/tz/Europe_London")),
            ),
            (
                "America/New_York",
                zone(include_bytes!("../tests/fixtures/tz/America_New_York")),
            ),
            (
                "Asia/Kolkata",
                zone(include_bytes!("../tests/fixtures/tz/Asia_Kolkata")),
            ),
            (
                "Australia/Lord_Howe",
                zone(include_bytes!("../tests/fixtures/tz/Australia_Lord_Howe")),
            ),
            (
                "Etc/GMT+5",
                zone(include_bytes!("../tests/fixtures/tz/Etc_GMT_5")),
            ),
        ]
    }

    /// The offset-only resolution has no daylight flag, so it is checked
    /// against the TZif resolution, which has one, on every half hour of 2026,
    /// the repeated and skipped hours included.
    #[test]
    fn offset_only_resolution_agrees_with_the_zone_database() {
        for (name, zone) in fixtures() {
            let mut reading = 1_767_225_600; // 2026-01-01
            while reading < 1_798_761_600 {
                assert_eq!(
                    offset_for_local_from(reading, |instant| zone.offset_at(instant)),
                    zone.offset_for_local(reading),
                    "{name} reading {reading}"
                );
                reading += 1_800;
            }
        }
    }

    #[test]
    fn repeated_and_skipped_readings_resolve_to_standard_time() {
        let new_york = zone(include_bytes!("../tests/fixtures/tz/America_New_York"));
        let offset_at = |instant| new_york.offset_at(instant);
        // 2026-11-01 01:30 happens twice, as EDT then as EST.
        assert_eq!(offset_for_local_from(1_793_496_600, offset_at), -18_000);
        // 2026-03-08 02:30 never happens; EST carries it forward to 03:30 EDT.
        assert_eq!(offset_for_local_from(1_772_937_000, offset_at), -18_000);
        // Away from those hours the answer is the one offset in force.
        assert_eq!(offset_for_local_from(1_784_109_600, offset_at), -14_400);
        assert_eq!(offset_for_local_from(1_768_478_400, offset_at), -18_000);
        assert_eq!(offset_for_local_from(0, |_| 19_800), 19_800);
    }

    /// Writing then reading a legacy time on one machine has to land on the
    /// same wall-clock reading. The instant itself need not come back, since
    /// a repeated hour gives two instants one reading.
    #[test]
    fn offset_only_resolution_round_trips() {
        for (name, zone) in fixtures() {
            let offset_at = |instant| zone.offset_at(instant);
            let mut instant = 1_767_225_600;
            while instant < 1_798_761_600 {
                let reading = instant + i64::from(offset_at(instant));
                let back = reading - i64::from(offset_for_local_from(reading, offset_at));
                assert_eq!(
                    back + i64::from(offset_at(back)),
                    reading,
                    "{name} at {instant}"
                );
                instant += 900;
            }
        }
    }

    /// Whatever the platform's zone, a legacy time written and read back keeps
    /// its wall-clock reading.
    #[test]
    fn the_current_zone_round_trips() {
        let zone = super::LocalZone::current();
        let mut instant = 1_767_225_600;
        while instant < 1_798_761_600 {
            let reading = instant + i64::from(zone.offset_at(instant));
            let back = reading - i64::from(zone.offset_for_local(reading));
            assert_eq!(
                back + i64::from(zone.offset_at(back)),
                reading,
                "at {instant}"
            );
            instant += 3_600;
        }
    }
}
