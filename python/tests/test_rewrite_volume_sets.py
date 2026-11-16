from pathlib import Path
import random

import pytest
import rars

FIXTURES = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures"
PAYLOAD = random.Random(31).randbytes(30_000)


def write_set(tmp_path, format):
    builder = rars.RarBuilder(format=format, volume_size=8192)
    if format == "rar50":
        builder.add_bytes(b"head", "head.txt")
        builder.add_directory("dir")
    builder.add_bytes(PAYLOAD, "large.bin")
    if format == "rar50":
        builder.add_bytes(b"tail", "tail.txt")
    first = "set.part01.rar" if format == "rar50" else "set.rar"
    (tmp_path / "made").mkdir()
    paths = builder.write_volumes(tmp_path / "made" / first)
    assert len(paths) > 2
    return paths


def extracted(archive, out):
    archive.extractall(out)
    return {
        path.relative_to(out).as_posix(): path.read_bytes() if path.is_file() else None
        for path in sorted(out.rglob("*"))
    }


def assert_rewrites_whole(tmp_path, first, **kwargs):
    with rars.RarFile(first) as archive:
        expected = extracted(archive, tmp_path / "expected")
    rewrite = rars.RarBuilder.from_archive(first, preserve=False, **kwargs)
    rewritten = rars.RarFile(rewrite.to_bytes())
    assert not rewritten.is_volume
    assert extracted(rewritten, tmp_path / "rewritten") == expected


@pytest.mark.parametrize("format", ["rar50", "rar29"])
def test_a_set_found_by_name_rewrites_into_one_archive(tmp_path, format):
    paths = write_set(tmp_path, format)
    assert_rewrites_whole(tmp_path, paths[0])


@pytest.mark.parametrize("first", [
    "rar15_40/rar300/multivol_oldnaming_rar300.rar",
    "rar15_40/rar300/multivol_newnaming_rar300.part01.rar",
    "rar50/solid_multivol.part01.rar",
])
def test_winrar_sets_rewrite_into_one_archive(tmp_path, first):
    assert_rewrites_whole(tmp_path, FIXTURES / first)


def test_volumes_supplies_the_later_volumes(tmp_path):
    paths = write_set(tmp_path, "rar50")
    data = paths[0].read_bytes()
    rewrite = rars.RarBuilder.from_archive(
        data, preserve=False, volumes=(path.read_bytes() for path in paths[1:])
    )
    rewritten = rars.RarFile(rewrite.to_bytes())
    assert rewritten.read("large.bin") == PAYLOAD
    assert rewritten.namelist() == ["head.txt", "dir", "large.bin", "tail.txt"]


def test_a_set_from_bytes_without_volumes_points_at_volumes(tmp_path):
    paths = write_set(tmp_path, "rar50")
    with pytest.raises(rars.Error, match="volumes="):
        rars.RarBuilder.from_archive(paths[0].read_bytes(), preserve=False)


def test_a_rarfile_set_rewrites_with_the_volumes_it_was_opened_with(tmp_path):
    paths = write_set(tmp_path, "rar50")
    archive = rars.RarFile(paths[0].read_bytes(), volumes=paths[1:])
    rewritten = rars.RarFile(
        rars.RarBuilder.from_archive(archive, preserve=False).to_bytes()
    )
    assert rewritten.read("large.bin") == PAYLOAD


def test_preserving_a_set_points_at_preserve_false(tmp_path):
    paths = write_set(tmp_path, "rar50")
    with pytest.raises(rars.UnsupportedRarFeature, match="preserve=False"):
        rars.RarBuilder.from_archive(paths[0])


def test_a_set_opened_first_volume_only_is_refused(tmp_path):
    paths = write_set(tmp_path, "rar50")
    archive = rars.RarFile(paths[0], first_volume_only=True)
    with pytest.raises(ValueError, match="first_volume_only"):
        rars.RarBuilder.from_archive(archive, preserve=False)
