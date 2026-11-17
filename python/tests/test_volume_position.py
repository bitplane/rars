from pathlib import Path
import random

import pytest
import rars


FIXTURES = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures"


def write_set(tmp_path, format, first):
    builder = rars.RarBuilder(version=format, level=0, volume_size=4096)
    builder.add_bytes(random.Random(22).randbytes(40_000), "large.bin")
    paths = builder.write_volumes(tmp_path / first)
    assert len(paths) > 3
    return paths


def numbers_of(paths):
    numbers = []
    for path in paths:
        with rars.RarFile(path, first_volume_only=True) as archive:
            numbers.append(archive.volume_number)
    return numbers


@pytest.mark.parametrize(
    "format, first, naming", [("rar50", "set.part01.rar", "part"), ("rar29", "set.rar", "old")]
)
def test_each_volume_of_a_built_set_knows_its_place(tmp_path, format, first, naming):
    paths = write_set(tmp_path, format, first)
    places = []
    for path in paths:
        with rars.RarFile(path, first_volume_only=True) as archive:
            places.append((archive.volume_number, archive.is_first_volume, archive.volume_naming))
    expected = [(number, number == 1, naming) for number in range(1, len(paths) + 1)]
    assert places == expected


def test_winrar_5_volumes_know_their_numbers():
    paths = [FIXTURES / f"rar50/multivol.part{n}.rar" for n in (1, 2, 3)]
    assert numbers_of(paths) == [1, 2, 3]


# WinRAR 3.00 records no number in its end blocks, so only the first volume knows its place.
@pytest.mark.parametrize(
    "names",
    [
        [f"stored_multivol_rar300.{ext}" for ext in ("rar", "r00", "r01", "r02")],
        [f"multivol_newnaming_rar300.part0{n}.rar" for n in (1, 2)],
    ],
)
def test_a_winrar_3_00_set_numbers_only_its_first_volume(names):
    paths = [FIXTURES / "rar15_40/rar300" / name for name in names]
    assert numbers_of(paths) == [1] + [None] * (len(names) - 1)


def test_a_built_rar2_set_numbers_only_its_first_volume(tmp_path):
    paths = write_set(tmp_path, "rar20", "set.rar")
    assert numbers_of(paths) == [1] + [None] * (len(paths) - 1)


def test_a_rar_1_54_set_records_no_numbers():
    paths = [FIXTURES / f"rar15_40/rar154/random.{ext}" for ext in ("rar", "r00", "r01")]
    assert numbers_of(paths) == [None, None, None]


@pytest.mark.parametrize(
    "name", ["rar50/stored.rar", "rar15_40/rar154/readme_154_normal.rar", "rar13/README.RAR"]
)
def test_a_single_archive_is_volume_one_of_one(name):
    with rars.RarFile(FIXTURES / name) as archive:
        assert archive.is_volume is False
        assert archive.volume_number == 1
        assert archive.is_first_volume is True


def test_a_rar_1_3_volume_records_no_number():
    paths = [FIXTURES / f"rar13/MULTIVOL.{ext}" for ext in ("RAR", "R00", "R01", "R02")]
    for path in paths:
        with rars.RarFile(path, first_volume_only=True) as archive:
            assert archive.is_volume is True
            assert archive.volume_number is None


def firsts_of(paths):
    firsts = []
    for path in paths:
        with rars.RarFile(path, first_volume_only=True) as archive:
            firsts.append(archive.is_first_volume)
    return firsts


@pytest.mark.parametrize(
    "names, firsts",
    [
        (["rar50/multivol.part1.rar", "rar50/multivol.part2.rar"], [True, False]),
        (
            [f"rar15_40/rar300/stored_multivol_rar300.{ext}" for ext in ("rar", "r00", "r01")],
            [True, False, False],
        ),
        (
            [f"rar15_40/rar300/multivol_newnaming_rar300.part0{n}.rar" for n in (1, 2)],
            [True, False],
        ),
        # Nothing records the first: only a continued member rules a volume out.
        ([f"rar15_40/rar154/random.{ext}" for ext in ("rar", "r00")], [None, False]),
        ([f"rar13/MULTIVOL.{ext}" for ext in ("RAR", "R00")], [None, False]),
        (["rar50/stored.rar"], [True]),
    ],
)
def test_a_volume_says_whether_it_is_first_where_it_can_tell(names, firsts):
    assert firsts_of([FIXTURES / name for name in names]) == firsts


@pytest.mark.parametrize(
    "name, naming",
    [
        ("rar50/multivol.part2.rar", "part"),
        ("rar15_40/rar300/multivol_newnaming_rar300.part01.rar", "part"),
        ("rar15_40/rar300/multivol_newnaming_rar300.part02.rar", "part"),
        ("rar15_40/rar300/stored_multivol_rar300.rar", "old"),
        ("rar15_40/rar300/stored_multivol_rar300.r00", "old"),
        ("rar15_40/rar154/random.r00", "old"),
        ("rar13/MULTIVOL.R00", "old"),
    ],
)
def test_a_volume_knows_how_its_set_is_named(name, naming):
    with rars.RarFile(FIXTURES / name, first_volume_only=True) as archive:
        assert archive.volume_naming == naming


@pytest.mark.parametrize("format, first", [("rar50", "set.part01.rar"), ("rar29", "set.rar")])
def test_a_middle_volume_lists_the_member_it_continues(tmp_path, format, first):
    paths = write_set(tmp_path, format, first)
    with rars.RarFile(paths[2]) as archive:
        [member] = archive.infolist()
        assert member.filename == "large.bin"
        assert member.is_split_before and member.is_split_after
        assert archive.volume_number == 3
        assert archive.is_first_volume is False
