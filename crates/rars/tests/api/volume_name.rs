use rars::volume_name::*;

use std::path::Path;

#[test]
fn old_style_names_roll_from_r99_to_s00_as_rar_4_does() {
    let first = Path::new("dir/set.rar");
    for (index, expected) in [
        (0, "dir/set.rar"),
        (1, "dir/set.r00"),
        (100, "dir/set.r99"),
        (101, "dir/set.s00"),
        (200, "dir/set.s99"),
        (201, "dir/set.t00"),
        (900, "dir/set.z99"),
    ] {
        assert_eq!(
            old_style(first, index).as_deref(),
            Some(Path::new(expected))
        );
    }
    assert_eq!(old_style(first, 901), None);
    assert_eq!(
        old_style(Path::new("SET.RAR"), 101).as_deref(),
        Some(Path::new("SET.S00"))
    );
    for (input, expected) in [
        ("set.RAR", "set.R00"),
        ("set.Rar", "set.R00"),
        ("set.rAR", "set.r00"),
        ("set", "set.r00"),
        ("set.sfx", "set.r00"),
        ("SET.sfx", "SET.r00"),
        ("SET.EXE", "SET.R00"),
    ] {
        assert_eq!(
            old_style(Path::new(input), 1).as_deref(),
            Some(Path::new(expected))
        );
    }
}

#[test]
fn part_style_names_replace_the_first_part_number() {
    for (input, index, width, expected) in [
        ("set.part01.rar", 1, 2, "set.part02.rar"),
        ("set.part01.rar", 99, 2, "set.part100.rar"),
        ("set.part001.rar", 1, 3, "set.part002.rar"),
        ("set.RAR", 0, 2, "set.part01.RAR"),
        ("set.PART009.RAR", 0, 2, "set.part01.RAR"),
        ("set.part.rar", 0, 2, "set.part.part01.rar"),
        ("set", 0, 2, "set.part01.rar"),
        ("set.bin", 0, 2, "set.bin.part01.rar"),
        ("set.part2.part3.rar", 0, 2, "set.part2.part01.rar"),
        ("dir/set.rar", 9, 3, "dir/set.part010.rar"),
        ("set.part1.sfx", 1, 1, "set.part2.rar"),
        ("set.part01.exe", 12, 2, "set.part13.rar"),
        ("SET.part1.sfx", 1, 1, "SET.part2.rar"),
        ("SET.PART1.EXE", 1, 1, "SET.part2.RAR"),
        ("set.part1.tar.gz", 0, 2, "set.part1.tar.gz.part01.rar"),
        ("set.part1.bin", 0, 2, "set.part1.bin.part01.rar"),
    ] {
        assert_eq!(
            part_style(Path::new(input), index, width).as_deref(),
            Some(Path::new(expected)),
            "{input}"
        );
    }
    assert_eq!(part_style(Path::new("/"), 0, 2), None);
}

#[test]
fn part_width_counts_the_first_part_digits() {
    for (input, expected) in [
        ("set.part1.rar", Some(1)),
        ("set.part01.RAR", Some(2)),
        ("set.part001.rar", Some(3)),
        ("set.rar", None),
        ("set.part.rar", None),
        ("set.partx.rar", None),
        ("set.part01", None),
        ("set.part1.sfx", Some(1)),
        ("set.part01.EXE", Some(2)),
        ("set.part1.", None),
        ("set.part1.bin", None),
        ("set.exe", None),
    ] {
        assert_eq!(part_width(Path::new(input)), expected, "{input}");
    }
}
