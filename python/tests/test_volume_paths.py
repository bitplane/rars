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


@pytest.mark.parametrize(
    "format, first",
    [
        ("rar50", "set.part01.rar"),
        ("rar29", "set.rar"),
    ],
)
def test_a_complete_set_lists_every_volume_in_order(tmp_path, format, first):
    paths = write_set(tmp_path, format, first)
    with rars.RarFile(paths[0]) as archive:
        assert archive.volume_paths() == paths


@pytest.mark.parametrize(
    "first, count",
    [
        ("rar15_40/rar300/multivol_oldnaming_rar300.rar", 2),
        ("rar15_40/rar300/multivol_newnaming_rar300.part01.rar", 2),
        ("rar15_40/rar300/stored_multivol_rar300.rar", 4),
        ("rar50/multivol.part1.rar", 3),
    ],
)
def test_winrar_sets_list_every_volume(first, count):
    with rars.RarFile(FIXTURES / first) as archive:
        paths = archive.volume_paths()
    assert paths[0] == FIXTURES / first
    assert len(paths) == count
    assert all(path.is_file() and path.parent == paths[0].parent for path in paths)
    assert len(set(paths)) == count


@pytest.mark.parametrize("format", ["rar50", "rar29"])
def test_a_set_with_its_third_volume_deleted_lists_the_first_two(tmp_path, format):
    paths = write_set(tmp_path, format, "set.part01.rar")
    paths[2].unlink()
    with rars.RarFile(paths[0]) as archive:
        assert archive.volume_paths() == paths[:2]


@pytest.mark.parametrize(
    "format, first, spare",
    [
        ("rar50", "set.part01.rar", lambda number: f"set.part{number:02}.rar"),
        ("rar29", "set.rar", lambda number: f"set.r{number - 2:02}"),
    ],
)
def test_a_spare_file_named_after_the_last_volume_is_left_out(
    tmp_path, format, first, spare
):
    paths = write_set(tmp_path, format, first)
    spare = tmp_path / spare(len(paths) + 1)
    assert not spare.exists()
    spare.write_bytes(paths[1].read_bytes())
    with rars.RarFile(paths[0]) as archive:
        assert archive.volume_paths() == paths


def test_a_single_archive_lists_its_own_path():
    path = FIXTURES / "rar50/stored.rar"
    with rars.RarFile(path) as archive:
        assert archive.volume_paths() == [path]


def test_an_archive_opened_from_bytes_has_no_volume_paths():
    with rars.RarFile((FIXTURES / "rar50/stored.rar").read_bytes()) as archive:
        with pytest.raises(ValueError, match="bytes"):
            archive.volume_paths()


def test_a_later_volume_cannot_list_the_set(tmp_path):
    paths = write_set(tmp_path, "rar50", "set.part01.rar")
    with rars.RarFile(paths[1]) as archive:
        with pytest.raises(ValueError, match="first volume"):
            archive.volume_paths()


@pytest.mark.parametrize("format", ["rar13", "rar20"])
def test_a_set_without_an_end_record_stops_at_the_first_gap(tmp_path, format):
    paths = write_set(tmp_path, format, "set.rar")
    paths[3].unlink()
    with rars.RarFile(paths[0]) as archive:
        assert archive.volume_paths() == paths[:3]


@pytest.mark.parametrize("format", ["rar50", "rar29"])
def test_a_volume_whose_headers_cannot_be_read_ends_the_list(tmp_path, format):
    paths = write_set(tmp_path, format, "set.rar")
    paths[2].write_bytes(paths[2].read_bytes()[:10])
    with rars.RarFile(paths[0]) as archive:
        assert archive.volume_paths() == paths[:2]
