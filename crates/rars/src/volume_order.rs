use crate::{Archive, Error, Result};

/// Checks a set's volumes in turn against the numbers their headers record.
pub struct VolumeOrder {
    index: u64,
    /// RAR 5's number for the first volume given, so a run starting later in a set still reads.
    start: u64,
    previous: Option<u16>,
}

impl VolumeOrder {
    pub fn after(first: &Archive) -> Self {
        let start = match first {
            Archive::Rar50Plus(archive) => archive.main.volume_number.unwrap_or(0),
            _ => 0,
        };
        Self {
            index: 0,
            start,
            previous: legacy_number(first),
        }
    }

    /// RAR 5 numbers each volume from the set's start; RAR 1.5-4 counts on from the one before, wrapping at 16 bits.
    pub fn next(&mut self, volume: &Archive) -> Result<()> {
        self.index += 1;
        let number = legacy_number(volume);
        let previous = std::mem::replace(&mut self.previous, number);
        let follows = match volume {
            Archive::Rar50Plus(archive) => archive
                .main
                .volume_number
                .is_none_or(|number| number == self.start.wrapping_add(self.index)),
            _ => !matches!((previous, number), (Some(previous), Some(number))
                if number != previous.wrapping_add(1)),
        };
        if follows {
            Ok(())
        } else {
            Err(Error::VolumeOutOfOrder)
        }
    }
}

/// RAR 1.3 and 2.0 volumes, and later ones without a numbered end block, record nothing to check.
fn legacy_number(archive: &Archive) -> Option<u16> {
    match archive {
        Archive::Rar15To40(archive) => archive.end_volume_number(),
        _ => None,
    }
}

pub(crate) fn check_set(archives: &[Archive]) -> Result<()> {
    let Some((first, later)) = archives.split_first() else {
        return Ok(());
    };
    let mut order = VolumeOrder::after(first);
    later.iter().enumerate().try_for_each(|(index, volume)| {
        order.next(volume).map_err(|error| Error::InVolume {
            index: index + 1,
            source: Box::new(error),
        })
    })
}
