import os
import warnings
import zlib

import pytest
import rars
from test_extract_guards import _headers, _read_vint

HARD_LINK = 4
FILE_COPY = 5
pytestmark = pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")


def archive(links, format="rar50", target=True):
    builder = rars.RarBuilder(format=format, store=True)
    if target:
        builder.add_bytes(b"target", "c/target.txt")
    for name, link_target in links:
        builder.add_unix_symlink(name, link_target)
    return builder.to_bytes()


def redirect(data, kind):
    data = bytearray(data)
    for crc_at, body_at, body_end in _headers(data):
        _, cursor = _read_vint(data, body_at)
        header, cursor = _read_vint(data, cursor)
        flags, cursor = _read_vint(data, cursor)
        if header != 2 or not flags & 1:
            continue
        extra_size, cursor = _read_vint(data, cursor)
        cursor = body_end - extra_size
        while cursor < body_end:
            size, record_start = _read_vint(data, cursor)
            tag, payload_start = _read_vint(data, record_start)
            if tag == 5:
                data[payload_start] = kind
                crc = zlib.crc32(data[body_at:body_end]).to_bytes(4, "little")
                data[crc_at:crc_at + 4] = crc
            cursor = record_start + size
    return bytes(data)


@pytest.mark.parametrize("in_place", [False, True])
def test_hard_link_extracts_as_a_hard_link(tmp_path, in_place):
    data = redirect(archive([("b/hard.txt", "c/target.txt")]), HARD_LINK)
    written = rars.RarFile.from_bytes(data).extractall(tmp_path, in_place=in_place)
    assert tmp_path / "b/hard.txt" in written
    assert (tmp_path / "b/hard.txt").read_bytes() == b"target"
    assert os.stat(tmp_path / "b/hard.txt").st_nlink == 2
    assert os.path.samefile(tmp_path / "b/hard.txt", tmp_path / "c/target.txt")


@pytest.mark.parametrize("in_place", [False, True])
def test_file_copy_extracts_as_a_separate_file(tmp_path, in_place):
    data = redirect(archive([("b/copy.txt", "c/target.txt")]), FILE_COPY)
    written = rars.RarFile.from_bytes(data).extractall(tmp_path, in_place=in_place)
    assert tmp_path / "b/copy.txt" in written
    assert (tmp_path / "b/copy.txt").read_bytes() == b"target"
    assert not os.path.samefile(tmp_path / "b/copy.txt", tmp_path / "c/target.txt")


@pytest.mark.parametrize("kind", [HARD_LINK, FILE_COPY])
def test_link_whose_target_was_not_extracted_fails_as_in_the_cli(tmp_path, kind):
    data = redirect(archive([("b/link.txt", "c/target.txt")]), kind)
    rar = rars.RarFile.from_bytes(data)
    with pytest.raises(rars.Error, match="not extracted earlier"):
        rar.extractall(tmp_path / "selected", members=["b/link.txt"])
    data = redirect(archive([("b/link.txt", "c/target.txt")], target=False), kind)
    with pytest.raises(rars.Error, match="not extracted earlier"):
        rars.RarFile.from_bytes(data).extractall(tmp_path / "all")


@pytest.mark.parametrize("format", ["rar50", "rar29"])
def test_symlinks_that_stay_inside_are_created(tmp_path, format):
    data = archive(
        [("a/sym.txt", "../c/target.txt"), ("a/near.txt", "local.txt")], format
    )
    written = rars.RarFile.from_bytes(data).extractall(tmp_path)
    assert {tmp_path / "a/sym.txt", tmp_path / "a/near.txt"} <= set(written)
    assert os.readlink(tmp_path / "a/sym.txt") == "../c/target.txt"
    assert (tmp_path / "a/sym.txt").read_bytes() == b"target"
    assert os.readlink(tmp_path / "a/near.txt") == "local.txt"


@pytest.mark.parametrize("format", ["rar50", "rar29"])
@pytest.mark.parametrize("target", ["../../outside", "/etc/passwd"])
def test_symlinks_that_leave_are_skipped_with_a_warning(tmp_path, format, target):
    builder = rars.RarBuilder(format=format, store=True)
    builder.add_unix_symlink("a/escape", target)
    builder.add_bytes(b"after", "after.txt")
    rar = rars.RarFile.from_bytes(builder.to_bytes())
    with pytest.warns(rars.UnsafeLinkWarning, match="a/escape") as caught:
        written = rar.extractall(tmp_path)
    assert target in str(caught[0].message)
    assert written == [tmp_path / "after.txt"]
    assert not os.path.lexists(tmp_path / "a/escape")
    with warnings.catch_warnings():
        warnings.simplefilter("error", rars.UnsafeLinkWarning)
        with pytest.raises(rars.UnsafeLinkWarning):
            rar.extractall(tmp_path / "strict")


def test_a_chain_through_an_earlier_link_cannot_climb_out(tmp_path):
    data = archive([("a/up", ".."), ("x", "a/up/..")])
    with pytest.warns(rars.UnsafeLinkWarning, match="'x'"):
        rars.RarFile.from_bytes(data).extractall(tmp_path)
    assert os.readlink(tmp_path / "a/up") == ".."
    assert not os.path.lexists(tmp_path / "x")


def test_selected_extraction_creates_only_selected_links(tmp_path):
    data = archive([("unselected", "c/target.txt"), ("selected", "c/target.txt")])
    rar = rars.RarFile.from_bytes(data)
    written = rar.extractall(tmp_path, members=["c/target.txt", "selected"])
    assert written == [tmp_path / "c/target.txt", tmp_path / "selected"]
    assert not os.path.lexists(tmp_path / "unselected")
    assert os.readlink(tmp_path / "selected") == "c/target.txt"
    assert rar.extract("selected", tmp_path / "one") == tmp_path / "one/selected"
    assert os.readlink(tmp_path / "one/selected") == "c/target.txt"


def test_selected_legacy_symlink_is_a_link_not_a_file(tmp_path):
    data = archive([("link", "c/target.txt")], format="rar29")
    rars.RarFile.from_bytes(data).extractall(tmp_path, members=["link"])
    assert os.readlink(tmp_path / "link") == "c/target.txt"


@pytest.mark.parametrize("format", ["rar50", "rar29"])
def test_volume_path_creates_links(tmp_path, format):
    data = archive([("link", "c/target.txt"), ("escape", "../outside")], format)
    with pytest.warns(rars.UnsafeLinkWarning, match="escape"):
        written = rars.RarFile.from_bytes(data).extractall(tmp_path, volumes=[])
    assert tmp_path / "link" in written
    assert os.readlink(tmp_path / "link") == "c/target.txt"
    assert not os.path.lexists(tmp_path / "escape")
