//! The local time zone, read from the system's TZif database.
//!
//! RAR 1.3 through 4.x store a modification time as MS-DOS fields: a wall-clock
//! reading with no zone and no offset. Every reader in the wild resolves that
//! against the *extracting* machine's local zone, so a file archived at 15:00
//! shows 15:00 wherever it is unpacked. Reading those fields as UTC instead is
//! self-consistent and round-trips, which is how the mistake survives, but it
//! disagrees with every other tool by the local offset.
//!
//! Doing better needs the zone's offset *for the timestamp in question*, since
//! a summer archive extracted in winter still needs summer's rules. That means
//! the zone database. The C library would answer it in two calls, but both are
//! `unsafe`, and this workspace forbids that; a TZif file is a binary format,
//! and parsing those is what the rest of this project does anyway.
//!
//! Only what a timestamp conversion needs is read: transition instants, the
//! offset in force after each, and whether that offset is daylight saving.
//! Designations, leap seconds and the standard/wall indicators are skipped.
//!
//! The trailing POSIX rule string is skipped too, which is the one deliberate
//! gap. It governs dates after the final transition, and the tables run to
//! 2037. Before then the transitions answer everything, including for zones
//! that have none at all: a fixed-offset zone still records its offset in the
//! type table, so `Etc/GMT+5` resolves correctly with an empty transition list.
//! After 2037 a daylight-saving zone freezes at its final offset, which needs a
//! file stamped past 2038 *and* stored in a pre-RAR-5 archive to notice.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// One local time type: an offset from UTC and whether it is daylight saving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalType {
    offset: i32,
    is_dst: bool,
}

/// A time zone's transitions, enough to convert in both directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TimeZone {
    /// Transition instants in Unix seconds, ascending.
    transitions: Vec<i64>,
    /// The local type in force from the matching transition onward.
    types: Vec<LocalType>,
    /// Which entry of `types` each transition selects.
    indices: Vec<u8>,
}

impl TimeZone {
    /// The zone where every offset is zero, used when nothing else resolves.
    pub(crate) fn utc() -> Self {
        Self {
            transitions: Vec::new(),
            types: vec![LocalType {
                offset: 0,
                is_dst: false,
            }],
            indices: Vec::new(),
        }
    }

    /// The machine's zone, parsed once and reused.
    ///
    /// Anything unreadable or unparsable falls back to UTC, which is what this
    /// did before the database was consulted at all. A timestamp is not worth
    /// failing an extraction over.
    pub(crate) fn local() -> &'static Self {
        static LOCAL: OnceLock<TimeZone> = OnceLock::new();
        LOCAL.get_or_init(|| {
            local_zone_path()
                .and_then(|path| std::fs::read(path).ok())
                .and_then(|bytes| Self::parse(&bytes))
                .unwrap_or_else(Self::utc)
        })
    }

    /// Reads a TZif file, preferring its 64-bit block when there is one.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        let header = Header::parse(bytes, 0)?;
        // A version 2 or later file repeats everything in a second block with
        // 64-bit transition times. That block is the authoritative one; the
        // first exists only for readers that predate it.
        if header.version >= b'2' {
            let second = header.data_end(TimeWidth::Bits32)?;
            let header = Header::parse(bytes, second)?;
            Self::parse_block(bytes, &header, second + Header::LEN, TimeWidth::Bits64)
        } else {
            Self::parse_block(bytes, &header, Header::LEN, TimeWidth::Bits32)
        }
    }

    fn parse_block(bytes: &[u8], header: &Header, start: usize, width: TimeWidth) -> Option<Self> {
        // Check every declared field, including skipped data, before reserving
        // arrays from the header's counts.
        bytes.get(start..start.checked_add(header.data_len(width)?)?)?;
        let stride = width.bytes();
        let mut pos = start;

        let mut transitions = Vec::with_capacity(header.timecnt);
        for _ in 0..header.timecnt {
            let raw = bytes.get(pos..pos.checked_add(stride)?)?;
            transitions.push(match width {
                TimeWidth::Bits32 => i64::from(i32::from_be_bytes(raw.try_into().ok()?)),
                TimeWidth::Bits64 => i64::from_be_bytes(raw.try_into().ok()?),
            });
            pos += stride;
        }

        let indices = bytes.get(pos..pos.checked_add(header.timecnt)?)?.to_vec();
        pos += header.timecnt;

        let mut types = Vec::with_capacity(header.typecnt);
        for _ in 0..header.typecnt {
            let record = bytes.get(pos..pos.checked_add(6)?)?;
            types.push(LocalType {
                offset: i32::from_be_bytes(record[..4].try_into().ok()?),
                is_dst: record[4] != 0,
            });
            pos += 6;
        }

        if types.is_empty() || indices.iter().any(|&i| usize::from(i) >= types.len()) {
            return None;
        }
        if transitions.windows(2).any(|pair| pair[0] >= pair[1]) {
            return None;
        }
        Some(Self {
            transitions,
            types,
            indices,
        })
    }

    /// The offset in force at an instant.
    fn type_at(&self, unix_seconds: i64) -> LocalType {
        let after = self
            .transitions
            .partition_point(|&transition| transition <= unix_seconds);
        match after.checked_sub(1) {
            Some(index) => self.types[usize::from(self.indices[index])],
            // RFC 8536 section 3.2 specifies type 0 before the first transition.
            None => self.types[0],
        }
    }

    /// The offset in force at an instant, in seconds east of UTC.
    pub(crate) fn offset_at(&self, unix_seconds: i64) -> i32 {
        self.type_at(unix_seconds).offset
    }

    /// The offset that turns a wall-clock reading back into an instant.
    ///
    /// A reading is not always one instant. In the hour a zone repeats when
    /// daylight saving ends it names two, and in the hour it skips when
    /// daylight saving starts it names none. An offset is accepted here when
    /// applying it lands on an instant whose own offset is the same one, so
    /// only genuinely reachable readings are accepted; where two qualify the
    /// standard-time one wins, and where none do the search still returns the
    /// standard-time candidate rather than failing.
    ///
    /// The reference readers disagree with each other in exactly these hours,
    /// so there is nothing to match: RAR 7.12 resolves the repeated hour to
    /// standard time under `Europe/London` and to daylight saving under
    /// `America/New_York`. Everything outside those two hours a year is
    /// unambiguous and agrees.
    pub(crate) fn offset_for_local(&self, local_seconds: i64) -> i32 {
        let mut best: Option<LocalType> = None;
        for candidate in self.candidates(local_seconds) {
            if self.type_at(local_seconds - i64::from(candidate.offset)) != candidate {
                continue;
            }
            let better = match best {
                None => true,
                Some(current) => current.is_dst && !candidate.is_dst,
            };
            if better {
                best = Some(candidate);
            }
        }
        best.or_else(|| {
            // A reading in the skipped hour matches nothing. Resolve it with
            // the standard-time offset, which moves it forward into the hour
            // that does exist rather than backward into the one that does not.
            self.candidates(local_seconds)
                .into_iter()
                .find(|local| !local.is_dst)
        })
        .unwrap_or_else(|| self.type_at(local_seconds))
        .offset
    }

    /// The types plausibly in force around a wall-clock reading.
    ///
    /// A day either side covers every real transition, which never move a
    /// clock by anything close to that.
    fn candidates(&self, local_seconds: i64) -> Vec<LocalType> {
        const DAY: i64 = 86_400;
        let mut found: Vec<LocalType> = Vec::new();
        for probe in [local_seconds - DAY, local_seconds, local_seconds + DAY] {
            let local = self.type_at(probe);
            if !found.contains(&local) {
                found.push(local);
            }
        }
        found
    }
}

/// Which file holds the machine's zone.
///
/// `TZ` names a zone under the database directory; unset, the symlink at
/// `/etc/localtime` is the answer. A `TZ` holding a POSIX rule string rather
/// than a name has no file, and resolves to nothing here.
fn local_zone_path() -> Option<PathBuf> {
    zone_path(
        std::env::var_os("TZ").as_deref(),
        std::env::var_os("TZDIR").as_deref(),
    )
}

fn zone_path(
    name: Option<&std::ffi::OsStr>,
    directory: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    const DEFAULT_DIR: &str = "/usr/share/zoneinfo";

    let Some(name) = name else {
        return Some(PathBuf::from("/etc/localtime"));
    };
    let name = name.to_str()?;
    // A leading colon is allowed and means the rest is a file name.
    let name = name.strip_prefix(':').unwrap_or(name);
    if name.is_empty() {
        return None;
    }
    if Path::new(name).is_absolute() {
        return Some(PathBuf::from(name));
    }
    // TZ comes from the environment, so refuse anything that could walk out of
    // the database directory.
    if name
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    let dir = directory.map_or_else(|| PathBuf::from(DEFAULT_DIR), PathBuf::from);
    Some(dir.join(name))
}

#[derive(Clone, Copy)]
enum TimeWidth {
    Bits32,
    Bits64,
}

impl TimeWidth {
    fn bytes(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }
}

struct Header {
    version: u8,
    isutcnt: usize,
    isstdcnt: usize,
    leapcnt: usize,
    timecnt: usize,
    typecnt: usize,
    charcnt: usize,
}

impl Header {
    const LEN: usize = 44;

    fn parse(bytes: &[u8], at: usize) -> Option<Self> {
        let header = bytes.get(at..at.checked_add(Self::LEN)?)?;
        if &header[..4] != b"TZif" {
            return None;
        }
        let counts: Vec<usize> = header[20..44]
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as usize)
            .collect();
        Some(Self {
            version: header[4],
            isutcnt: counts[0],
            isstdcnt: counts[1],
            leapcnt: counts[2],
            timecnt: counts[3],
            typecnt: counts[4],
            charcnt: counts[5],
        })
    }

    /// Where this block's data ends, which is where the next header begins.
    fn data_end(&self, width: TimeWidth) -> Option<usize> {
        Self::LEN.checked_add(self.data_len(width)?)
    }

    fn data_len(&self, width: TimeWidth) -> Option<usize> {
        self.timecnt
            .checked_mul(width.bytes() + 1)?
            .checked_add(self.typecnt.checked_mul(6)?)?
            .checked_add(self.charcnt)?
            .checked_add(self.leapcnt.checked_mul(width.bytes() + 4)?)?
            .checked_add(self.isstdcnt)?
            .checked_add(self.isutcnt)
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalType, TimeZone};

    /// Zone files are shipped rather than read from the machine, so these test
    /// the parser and not whatever the build box is set to.
    const LONDON: &[u8] = include_bytes!("../tests/fixtures/tz/Europe_London");
    const NEW_YORK: &[u8] = include_bytes!("../tests/fixtures/tz/America_New_York");
    const KOLKATA: &[u8] = include_bytes!("../tests/fixtures/tz/Asia_Kolkata");
    const LORD_HOWE: &[u8] = include_bytes!("../tests/fixtures/tz/Australia_Lord_Howe");
    const GMT_MINUS_5: &[u8] = include_bytes!("../tests/fixtures/tz/Etc_GMT_5");

    fn zone(name: &str) -> TimeZone {
        let bytes = match name {
            "Europe/London" => LONDON,
            "America/New_York" => NEW_YORK,
            "Asia/Kolkata" => KOLKATA,
            "Australia/Lord_Howe" => LORD_HOWE,
            "Etc/GMT+5" => GMT_MINUS_5,
            other => panic!("no fixture for {other}"),
        };
        TimeZone::parse(bytes).expect("fixture parses")
    }

    /// Expected offsets come from Python's `zoneinfo`, so the arithmetic here
    /// is checked against another implementation rather than against itself.
    #[test]
    fn offset_at_matches_the_zone_database() {
        let cases = [
            ("Europe/London", 1_768_478_400, 0),            // 2026-01-15 GMT
            ("Europe/London", 1_784_116_800, 3_600),        // 2026-07-15 BST
            ("America/New_York", 1_768_478_400, -18_000),   // EST
            ("America/New_York", 1_784_116_800, -14_400),   // EDT
            ("Asia/Kolkata", 1_784_116_800, 19_800),        // +05:30, no DST
            ("Australia/Lord_Howe", 1_768_478_400, 39_600), // +11 in their summer
            ("Australia/Lord_Howe", 1_784_116_800, 37_800), // +10:30, a 30-minute step
            ("Etc/GMT+5", 1_784_116_800, -18_000),          // no transitions at all
            ("Europe/London", 486_475_200, 3_600),          // 1985, well before the tables end
            ("America/New_York", 946_681_200, -18_000),     // 1999
        ];
        for (name, instant, expected) in cases {
            assert_eq!(
                zone(name).offset_at(instant),
                expected,
                "{name} at {instant}"
            );
        }
    }

    /// The reverse direction, on readings that name exactly one instant.
    #[test]
    fn offset_for_local_matches_the_zone_database() {
        let cases = [
            ("Europe/London", 1_768_478_400, 0),            // 12:00 GMT
            ("Europe/London", 1_784_127_600, 3_600),        // 15:00 BST
            ("America/New_York", 1_784_109_600, -14_400),   // 10:00 EDT
            ("Asia/Kolkata", 1_784_143_800, 19_800),        // 19:30 IST
            ("Australia/Lord_Howe", 1_784_154_600, 37_800), // 22:30 +10:30
            ("Etc/GMT+5", 1_784_098_800, -18_000),          // 07:00 -05
            ("Europe/London", 2_131_272_000, 3_600),        // 2037, the last year the tables cover
        ];
        for (name, reading, expected) in cases {
            assert_eq!(
                zone(name).offset_for_local(reading),
                expected,
                "{name} reading {reading}"
            );
        }
    }

    /// Both directions have to agree, or a timestamp written and read back on
    /// one machine would drift.
    #[test]
    fn the_two_directions_round_trip() {
        for name in [
            "Europe/London",
            "America/New_York",
            "Asia/Kolkata",
            "Australia/Lord_Howe",
            "Etc/GMT+5",
        ] {
            let zone = zone(name);
            // Every six hours across 2026, skipping nothing.
            let mut instant = 1_767_225_600; // 2026-01-01
            while instant < 1_798_761_600 {
                let reading = instant + i64::from(zone.offset_at(instant));
                let back = reading - i64::from(zone.offset_for_local(reading));
                // The instant itself need not come back. In the hour a zone
                // repeats, two instants share one reading and either is a
                // correct answer. What must hold is that the answer still
                // reads the same on the clock, which is the whole point of
                // storing a reading.
                let back_reading = back + i64::from(zone.offset_at(back));
                assert_eq!(back_reading, reading, "{name} at {instant}");
                instant += 21_600;
            }
        }
    }

    /// The hour a zone repeats names two instants and the hour it skips names
    /// none. Both resolve to standard time here, deterministically.
    ///
    /// The reference readers are not consistent in these hours, so there is
    /// nothing to match: RAR 7.12 resolves London's repeated hour to standard
    /// time and New York's to daylight saving. This pins our own choice.
    #[test]
    fn ambiguous_and_skipped_readings_resolve_to_standard_time() {
        // 2026-10-25 01:30 in London happens twice, as BST then as GMT.
        assert_eq!(zone("Europe/London").offset_for_local(1_792_891_800), 0);
        // 2026-03-29 01:30 in London never happens; the clock jumps 01:00→02:00.
        assert_eq!(zone("Europe/London").offset_for_local(1_774_747_800), 0);
        // 2026-11-01 01:30 in New York happens twice, as EDT then as EST.
        assert_eq!(
            zone("America/New_York").offset_for_local(1_793_496_600),
            -18_000
        );
    }

    #[test]
    fn a_zone_with_no_transitions_still_has_its_offset() {
        let zone = zone("Etc/GMT+5");
        assert!(zone.transitions.is_empty());
        assert_eq!(zone.offset_at(0), -18_000);
        assert_eq!(zone.offset_at(i64::MAX / 2), -18_000);
    }

    #[test]
    fn utc_is_the_fallback_and_has_no_offset() {
        let zone = TimeZone::utc();
        assert_eq!(zone.offset_at(1_784_116_800), 0);
        assert_eq!(zone.offset_for_local(1_784_116_800), 0);
        assert_eq!(
            zone.types,
            vec![LocalType {
                offset: 0,
                is_dst: false
            }]
        );
    }

    // RFC 8536 sections 3.1 and 3.2: a version-1 header, signed 32-bit
    // transition instants, type indices, six-byte type records and designations.
    fn version_one(transitions: &[(i32, u8)], types: &[(i32, bool)]) -> Vec<u8> {
        let mut bytes = b"TZif\0".to_vec();
        bytes.resize(20, 0);
        for count in [0, 0, 0, transitions.len() as u32, types.len() as u32, 4] {
            bytes.extend(count.to_be_bytes());
        }
        for &(instant, _) in transitions {
            bytes.extend(instant.to_be_bytes());
        }
        bytes.extend(transitions.iter().map(|&(_, index)| index));
        for &(offset, daylight) in types {
            bytes.extend(offset.to_be_bytes());
            bytes.extend([u8::from(daylight), 0]);
        }
        bytes.extend(b"STD\0");
        bytes
    }

    #[test]
    fn version_one_signed_transitions_apply_at_the_exact_instant() {
        let bytes = version_one(&[(-3600, 1), (3600, 0)], &[(1800, false), (3600, true)]);
        let zone = TimeZone::parse(&bytes).unwrap();
        for (instant, offset) in [(-3601, 1800), (-3600, 3600), (3599, 3600), (3600, 1800)] {
            assert_eq!(zone.offset_at(instant), offset);
        }
    }

    #[test]
    fn before_first_transition_uses_type_zero_even_when_it_is_daylight_time() {
        let bytes = version_one(&[(2_000_000_000, 1)], &[(3600, true), (0, false)]);
        let zone = TimeZone::parse(&bytes).unwrap();
        assert_eq!(zone.offset_at(1_000_000_000), 3600);
        assert_eq!(zone.offset_at(1_999_999_999), 3600);
        assert_eq!(zone.offset_at(2_000_000_000), 0);
        assert_eq!(zone.offset_for_local(1_000_000_000), 3600);
    }

    #[test]
    fn rejects_empty_types_invalid_indices_and_nonascending_transitions() {
        for bytes in [
            version_one(&[], &[]),
            version_one(&[(0, 1)], &[(0, false)]),
            version_one(&[(3600, 0), (0, 0)], &[(0, false)]),
            version_one(&[(0, 0), (0, 0)], &[(0, false)]),
        ] {
            assert!(TimeZone::parse(&bytes).is_none());
        }
        let bytes = version_one(&[(0, 0)], &[(0, false)]);
        // Every prefix missing transition/type data is incomplete.
        for cut in 0..bytes.len() - 4 {
            assert!(TimeZone::parse(&bytes[..cut]).is_none(), "cut {cut}");
        }
        let mut foreign = bytes;
        foreign[..4].copy_from_slice(b"NOPE");
        assert!(TimeZone::parse(&foreign).is_none());
    }

    #[test]
    fn rejects_truncated_designations_and_other_declared_block_data() {
        let bytes = version_one(&[(0, 0)], &[(0, false)]);
        for cut in bytes.len() - 4..bytes.len() {
            assert!(TimeZone::parse(&bytes[..cut]).is_none(), "cut {cut}");
        }
        // Counts for leap records and standard/UT indicators also contribute
        // to the block extent, even though conversion does not interpret them.
        for count_at in [20, 24, 28] {
            let mut incomplete = bytes.clone();
            incomplete[count_at..count_at + 4].copy_from_slice(&1u32.to_be_bytes());
            assert!(
                TimeZone::parse(&incomplete).is_none(),
                "count at {count_at}"
            );
        }
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn declared_block_sizes_reject_overflow_on_native_32_bit_hosts() {
        use super::{Header, TimeWidth};
        let empty = Header {
            version: 0,
            isutcnt: 0,
            isstdcnt: 0,
            leapcnt: 0,
            timecnt: 0,
            typecnt: 0,
            charcnt: 0,
        };
        let wire_maximum = u32::MAX as usize;
        for header in [
            Header {
                timecnt: wire_maximum,
                ..empty
            },
            Header {
                typecnt: wire_maximum,
                ..empty
            },
            Header {
                leapcnt: wire_maximum,
                ..empty
            },
            Header {
                isstdcnt: wire_maximum,
                isutcnt: 1,
                ..empty
            },
        ] {
            assert!(header.data_len(TimeWidth::Bits32).is_none());
            assert!(header.data_len(TimeWidth::Bits64).is_none());
        }
        let header = Header {
            charcnt: wire_maximum,
            ..empty
        };
        assert_eq!(header.data_len(TimeWidth::Bits32), Some(wire_maximum));
        assert!(header.data_end(TimeWidth::Bits32).is_none());
    }

    #[test]
    fn zone_paths_honor_colons_and_directories_without_parent_traversal() {
        use std::ffi::OsStr;
        use std::path::PathBuf;
        assert_eq!(
            super::zone_path(None, None),
            Some(PathBuf::from("/etc/localtime"))
        );
        for name in [
            "",
            ":",
            "Europe//London",
            "Europe/../London",
            "./Europe/London",
            "Europe/./London",
            "Europe/",
        ] {
            assert!(
                super::zone_path(Some(OsStr::new(name)), None).is_none(),
                "{name}"
            );
        }
        for name in ["Europe/London", ":Europe/London"] {
            assert_eq!(
                super::zone_path(Some(OsStr::new(name)), None),
                Some(PathBuf::from("/usr/share/zoneinfo/Europe/London")),
            );
            assert_eq!(
                super::zone_path(Some(OsStr::new(name)), Some(OsStr::new("custom-zones"))),
                Some(PathBuf::from("custom-zones/Europe/London")),
            );
        }
        let absolute = std::env::current_dir().unwrap().join("chosen-zone");
        for name in [
            absolute.as_os_str().to_owned(),
            format!(":{}", absolute.display()).into(),
        ] {
            assert_eq!(super::zone_path(Some(&name), None), Some(absolute.clone()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert!(super::zone_path(Some(OsStr::from_bytes(&[0xff])), None).is_none());
        }
    }

    #[test]
    fn daylight_only_gap_uses_the_offset_at_the_reading_when_no_standard_type_exists() {
        let bytes = version_one(&[(1_000_000_000, 1)], &[(3600, true), (7200, true)]);
        let zone = TimeZone::parse(&bytes).unwrap();
        assert_eq!(zone.offset_for_local(1_000_005_000), 7200);
    }

    #[test]
    fn repeated_reading_retains_first_candidate_when_daylight_status_is_equal() {
        // A political offset change can repeat a reading without changing
        // daylight status. Both instants are valid; preserve the first match.
        for daylight in [false, true] {
            let bytes = version_one(&[(1_000_000_000, 1)], &[(7200, daylight), (3600, daylight)]);
            let zone = TimeZone::parse(&bytes).unwrap();
            let reading = 1_000_005_000;
            assert_eq!(zone.offset_at(reading - 7200), 7200);
            assert_eq!(zone.offset_at(reading - 3600), 3600);
            assert_eq!(zone.offset_for_local(reading), 7200);
        }
    }

    /// A damaged or foreign file must not panic or be believed.
    #[test]
    fn rejects_files_that_are_not_a_usable_zone() {
        assert!(TimeZone::parse(b"").is_none());
        assert!(TimeZone::parse(b"not a tzif file at all").is_none());
        assert!(TimeZone::parse(&LONDON[..20]).is_none(), "truncated header");
        assert!(TimeZone::parse(&LONDON[..200]).is_none(), "truncated body");
    }
}
