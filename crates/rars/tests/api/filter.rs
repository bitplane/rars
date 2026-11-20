use rars::filter::*;

/// Exhaustive by construction: a new filter has to be added here, and the
/// two conversions below then have to say what each format does with it.
const ALL: [FilterKind; 7] = [
    FilterKind::Delta { channels: 1 },
    FilterKind::E8,
    FilterKind::E8E9,
    FilterKind::Arm,
    FilterKind::Itanium,
    FilterKind::Rgb { width: 3, pos_r: 0 },
    FilterKind::Audio { channels: 1 },
];

#[test]
fn kind_conversion_selects_the_whole_member_without_changing_parameters() {
    for kind in ALL {
        let spec = FilterSpec::from(kind);
        assert_eq!(spec.kind, kind);
        assert_eq!(spec.range, None);
    }
}

#[test]
fn each_filter_names_the_formats_that_can_write_it() {
    use rars::ArchiveVersion;
    assert_eq!(
        formats_supporting_filter(FilterKind::Arm),
        vec![ArchiveVersion::Rar50, ArchiveVersion::Rar70]
    );
    assert_eq!(
        formats_supporting_filter(FilterKind::Itanium),
        vec![
            ArchiveVersion::Rar29,
            ArchiveVersion::Rar30,
            ArchiveVersion::Rar40
        ]
    );
    // Delta is the one every filtering format has.
    assert_eq!(
        formats_supporting_filter(FilterKind::Delta { channels: 2 }),
        vec![
            ArchiveVersion::Rar29,
            ArchiveVersion::Rar30,
            ArchiveVersion::Rar40,
            ArchiveVersion::Rar50,
            ArchiveVersion::Rar70
        ]
    );
    for kind in ALL {
        assert!(!formats_supporting_filter(kind).is_empty(), "{kind:?}");
    }
}

#[test]
fn a_policy_defaults_to_leaving_the_data_alone() {
    assert_eq!(FilterPolicy::default(), FilterPolicy::None);
    assert_eq!(
        FilterPolicy::explicit(FilterKind::E8),
        FilterPolicy::Explicit(FilterSpec::whole(FilterKind::E8))
    );
}
