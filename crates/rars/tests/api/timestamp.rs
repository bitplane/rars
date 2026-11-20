use rars::timestamp::StoredTimestamp;

#[test]
fn filetime_format_boundaries_keep_epoch_and_far_future_dates() {
    let epoch = 116_444_736_000_000_000;
    assert_eq!(
        rars::timestamp::format_filetime_utc(epoch - 1),
        "0x019db1ded53e7fff"
    );
    assert_eq!(
        rars::timestamp::format_filetime_utc(epoch),
        "1970-01-01T00:00:00Z"
    );
    assert_eq!(
        rars::timestamp::format_filetime_utc(u64::MAX),
        "60056-05-28T05:36:10Z"
    );
}

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
