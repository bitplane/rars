//! Lossless RAR5 file timestamps and conversion of legacy extended times.

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTimestamp {
    Unix { seconds: u32, nanoseconds: u32 },
    WindowsFiletime(u64),
}

impl FileTimestamp {
    pub fn unix_nanoseconds(self) -> i128 {
        match self {
            Self::Unix {
                seconds,
                nanoseconds,
            } => i128::from(seconds) * 1_000_000_000 + i128::from(nanoseconds),
            Self::WindowsFiletime(ticks) => (i128::from(ticks) - 116_444_736_000_000_000) * 100,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileTimes {
    pub modified: Option<FileTimestamp>,
    pub created: Option<FileTimestamp>,
    pub accessed: Option<FileTimestamp>,
}

impl FileTimes {
    /// Build a record from exact Unix nanoseconds, using FILETIME when needed.
    /// FILETIME requires 100-nanosecond precision for every present timestamp.
    pub fn from_unix_nanoseconds(
        modified: Option<i128>,
        created: Option<i128>,
        accessed: Option<i128>,
    ) -> Result<Self> {
        let values = [modified, created, accessed];
        let unix = values
            .iter()
            .flatten()
            .all(|value| *value >= 0 && *value / 1_000_000_000 <= i128::from(u32::MAX));
        let mut result = [None; 3];
        for (slot, value) in result.iter_mut().zip(values) {
            if let Some(value) = value {
                *slot = Some(if unix {
                    FileTimestamp::Unix {
                        seconds: (value / 1_000_000_000) as u32,
                        nanoseconds: (value % 1_000_000_000) as u32,
                    }
                } else {
                    if value % 100 != 0 {
                        return Err(Error::InvalidArgument(
                            "FILETIME range requires 100-nanosecond precision",
                        ));
                    }
                    let ticks = (value / 100)
                        .checked_add(116_444_736_000_000_000)
                        .and_then(|ticks| u64::try_from(ticks).ok())
                        .ok_or(Error::InvalidArgument("timestamp exceeds FILETIME range"))?;
                    FileTimestamp::WindowsFiletime(ticks)
                });
            }
        }
        Ok(Self {
            modified: result[0],
            created: result[1],
            accessed: result[2],
        })
    }

    pub(crate) fn encode(self) -> Result<Vec<u8>> {
        let times = [self.modified, self.created, self.accessed];
        let first = times
            .iter()
            .flatten()
            .next()
            .ok_or(Error::InvalidArgument("file time record is empty"))?;
        let unix = matches!(first, FileTimestamp::Unix { .. });
        let mut flags = u8::from(unix);
        let mut seconds = Vec::new();
        let mut fractions = Vec::new();
        for (index, time) in times.into_iter().enumerate() {
            if let Some(time) = time {
                flags |= 2 << index;
                match time {
                    FileTimestamp::Unix {
                        seconds: value,
                        nanoseconds,
                    } if unix && nanoseconds < 1_000_000_000 => {
                        flags |= 0x10;
                        seconds.extend_from_slice(&value.to_le_bytes());
                        fractions.extend_from_slice(&nanoseconds.to_le_bytes());
                    }
                    FileTimestamp::WindowsFiletime(ticks) if !unix => {
                        seconds.extend_from_slice(&ticks.to_le_bytes())
                    }
                    _ => {
                        return Err(Error::InvalidArgument(
                            "file times require one encoding and fractions below one second",
                        ))
                    }
                }
            }
        }
        let mut record = vec![flags];
        record.extend(seconds);
        record.extend(fractions);
        Ok(record)
    }

    pub(crate) fn parse(flags: u64, data: &[u8]) -> Option<Self> {
        if flags & !0x1f != 0 || flags & 0x0e == 0 || flags & 0x11 == 0x10 {
            return None;
        }
        let unix = flags & 1 != 0;
        let count = (flags & 0x0e).count_ones() as usize;
        let width = if unix { 4 } else { 8 };
        let fractions = unix && flags & 0x10 != 0;
        if data.len() != count * (width + if fractions { 4 } else { 0 }) {
            return None;
        }
        let mut times = [None; 3];
        let mut at = 0;
        for (index, slot) in times.iter_mut().enumerate() {
            if flags & (2 << index) == 0 {
                continue;
            }
            *slot = Some(if unix {
                let seconds = u32::from_le_bytes(data[at * width..at * width + 4].try_into().ok()?);
                let nanoseconds = if fractions {
                    let offset = count * width + at * 4;
                    u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?)
                } else {
                    0
                };
                if nanoseconds >= 1_000_000_000 {
                    return None;
                }
                FileTimestamp::Unix {
                    seconds,
                    nanoseconds,
                }
            } else {
                FileTimestamp::WindowsFiletime(u64::from_le_bytes(
                    data[at * width..at * width + 8].try_into().ok()?,
                ))
            });
            at += 1;
        }
        Some(Self {
            modified: times[0],
            created: times[1],
            accessed: times[2],
        })
    }

    pub(crate) fn legacy(raw: &[u8], mtime: Option<u32>) -> Result<Option<Self>> {
        if raw.is_empty() {
            return Ok(None);
        }
        let invalid =
            || Error::InvalidArgument("legacy extended timestamps are incomplete or invalid");
        let flags = u16::from_le_bytes(raw.get(..2).ok_or_else(invalid)?.try_into().unwrap());
        let mut at = 2;
        let mut times = [None; 3];
        // Fourth legacy slot is archival time. It has no RAR5 counterpart.
        if flags & 8 != 0 {
            return Err(Error::InvalidArgument(
                "legacy archival time has no supported RAR5 representation",
            ));
        }
        for (index, slot) in times.iter_mut().enumerate() {
            let mode = (flags >> (12 - index * 4)) & 15;
            if mode & 8 == 0 {
                continue;
            }
            let seconds = if index == 0 {
                mtime.ok_or_else(invalid)?
            } else {
                let value = u32::from_le_bytes(
                    raw.get(at..at + 4).ok_or_else(invalid)?.try_into().unwrap(),
                );
                at += 4;
                value
            };
            let mut ticks = 0u32;
            for _ in 0..mode & 3 {
                ticks = (u32::from(*raw.get(at).ok_or_else(invalid)?) << 16) | (ticks >> 8);
                at += 1;
            }
            if ticks >= 10_000_000 {
                return Err(invalid());
            }
            let time = crate::timestamp::extracted_system_time(
                crate::ArchiveFamily::Rar15To40,
                Some(seconds),
                Some(crate::TimeRefinement {
                    add_second: mode & 4 != 0,
                    nanoseconds: ticks * 100,
                }),
            )
            .ok_or_else(invalid)?;
            let duration = time
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| invalid())?;
            *slot = Some(FileTimestamp::Unix {
                seconds: u32::try_from(duration.as_secs()).map_err(|_| invalid())?,
                nanoseconds: duration.subsec_nanos(),
            });
        }
        if at != raw.len() {
            return Err(invalid());
        }
        let times = Self {
            modified: times[0],
            created: times[1],
            accessed: times[2],
        };
        Ok((times != Self::default()).then_some(times))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_rar5_time_combinations_retain_full_precision() {
        for unix in [true, false] {
            for mask in 1..8 {
                let stamp = |index: u64| {
                    if unix {
                        FileTimestamp::Unix {
                            seconds: if index == 0 { 0 } else { u32::MAX },
                            nanoseconds: (index as u32 + 1) * 123,
                        }
                    } else {
                        FileTimestamp::WindowsFiletime(if index == 0 {
                            0
                        } else {
                            u64::MAX - index
                        })
                    }
                };
                let times = FileTimes {
                    modified: (mask & 1 != 0).then(|| stamp(0)),
                    created: (mask & 2 != 0).then(|| stamp(1)),
                    accessed: (mask & 4 != 0).then(|| stamp(2)),
                };
                let bytes = times.encode().unwrap();
                assert_eq!(
                    FileTimes::parse(u64::from(bytes[0]), &bytes[1..]),
                    Some(times)
                );
            }
        }
        assert_eq!(
            FileTimestamp::WindowsFiletime(0).unix_nanoseconds(),
            -11_644_473_600_000_000_000
        );
    }

    #[test]
    fn malformed_or_mixed_time_records_are_rejected() {
        assert!(FileTimes::parse(0x23, &[0; 4]).is_none());
        assert!(FileTimes::parse(0x13, &[0; 4]).is_none());
        let mut data = vec![0; 4];
        data.extend(1_000_000_000u32.to_le_bytes());
        assert!(FileTimes::parse(0x13, &data).is_none());
        let mixed = FileTimes {
            modified: Some(FileTimestamp::WindowsFiletime(0)),
            created: Some(FileTimestamp::Unix {
                seconds: 0,
                nanoseconds: 0,
            }),
            accessed: None,
        };
        assert!(mixed.encode().is_err());
    }

    #[test]
    fn legacy_creation_and_access_times_keep_odd_seconds_and_fractions() {
        let dos = 0x5022_1882u32;
        let mut raw = 0xfb90u16.to_le_bytes().to_vec();
        raw.extend([1, 2, 3]);
        raw.extend(dos.to_le_bytes());
        raw.extend([4, 5, 6]);
        raw.extend(dos.to_le_bytes());
        raw.push(7);
        let times = FileTimes::legacy(&raw, Some(dos)).unwrap().unwrap();
        let base = crate::timestamp::extracted_system_time(
            crate::ArchiveFamily::Rar15To40,
            Some(dos),
            None,
        )
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i128
            * 1_000_000_000;
        assert_eq!(
            times.modified.unwrap().unix_nanoseconds(),
            base + 1_000_000_000 + 0x030201 * 100
        );
        assert_eq!(
            times.created.unwrap().unix_nanoseconds(),
            base + 0x060504 * 100
        );
        assert_eq!(
            times.accessed.unwrap().unix_nanoseconds(),
            base + 0x070000 * 100
        );
        raw.pop();
        assert!(FileTimes::legacy(&raw, Some(dos)).is_err());
    }
}
