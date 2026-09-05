"""Conversion keeps DOS flags as flags, including through reference extraction."""

import os
import shutil
import subprocess
import sys
import zlib
from pathlib import Path

import pytest
import rars

from test_extract_guards import _headers, _read_vint, _rewrite_name

ROOT = Path(__file__).resolve().parents[2]


def test_rewrite_rejects_duplicate_source_names_explicitly():
    source = rars.RarBuilder(store=True)
    source.add_bytes(b"first", "one.txt")
    source.add_bytes(b"second", "two.txt")
    archive = rars.RarFile.from_bytes(_rewrite_name(source.to_bytes(), b"two.txt", b"one.txt"))
    assert archive.namelist() == ["one.txt", "one.txt"]
    with pytest.raises(ValueError, match="duplicate member name.*one.txt"):
        rars.RarBuilder.from_archive(archive)


def test_rewrite_source_indices_survive_directory_and_file_edits():
    source = rars.RarBuilder(solid=True)
    source.add_directory("empty")
    source.add_bytes(b"first payload", "first")
    source.add_directory("other")
    source.add_bytes(b"last payload", "last")
    rewritten = rars.RarBuilder.from_archive(rars.RarFile.from_bytes(source.to_bytes()))
    rewritten.remove("empty")
    rewritten.remove("first")
    rewritten.rename("last", "first")
    rewritten.add_bytes(b"new payload", "last")
    output = rars.RarFile.from_bytes(rewritten.to_bytes())
    assert output.namelist() == ["other", "first", "last"]
    assert output.read("first") == b"last payload"
    assert output.read("last") == b"new payload"


@pytest.mark.parametrize("format", ["rar50", "rar70"])
@pytest.mark.parametrize("mode", [None, 0o750])
def test_rewrite_retains_empty_directories_and_metadata(format, mode):
    source = rars.RarBuilder(format=format, solid=True)
    source.add_directory("empty", mtime=1_700_000_002, mode=mode)
    source.add_directory("nested", mode=mode)
    source.add_bytes(b"payload", "nested/file")
    rewritten = rars.RarBuilder.from_archive(rars.RarFile.from_bytes(source.to_bytes()))
    rewritten.rename("empty", "renamed")
    result = rars.RarFile.from_bytes(rewritten.to_bytes())
    assert result.namelist() == ["renamed", "nested", "nested/file"]
    for name in ("renamed", "nested"):
        info = result.getinfo(name)
        assert info.is_dir()
        assert info.file_attr == (0x10 if mode is None else 0o040000 | mode)
    assert result.read("nested/file") == b"payload"


@pytest.mark.skipif(os.name != "posix" or not shutil.which("unrar"), reason="requires POSIX and unrar")
def test_rewritten_directories_extract_with_unrar(tmp_path):
    source = rars.RarBuilder(solid=True)
    source.add_directory("empty", mtime=1_700_000_002, mode=0o750)
    source.add_directory("nested", mode=0o750)
    source.add_bytes(b"payload", "nested/file")
    rewritten = tmp_path / "rewritten.rar"
    rars.RarBuilder.from_archive(rars.RarFile.from_bytes(source.to_bytes())).write(rewritten)
    output = tmp_path / "out"
    output.mkdir()
    subprocess.run(["unrar", "x", "-idq", "-o+", str(rewritten), str(output) + "/"],
                   check=True, capture_output=True)
    assert (output / "empty").is_dir()
    assert list((output / "empty").iterdir()) == []
    assert (output / "empty").stat().st_mode & 0o777 == 0o750
    assert (output / "empty").stat().st_mtime_ns == 1_700_000_002_000_000_000
    assert (output / "nested/file").read_bytes() == b"payload"


@pytest.mark.parametrize("fixture", ["symlink.rar", "hardlink.rar", "rarfile_hlink.rar"])
def test_rewrite_rejects_redirections_before_writing(fixture):
    source = ROOT / "crates/rars/tests/fixtures/rar50/wild" / fixture
    with pytest.raises(rars.UnsupportedRarFeature, match="cannot rewrite special entry"):
        rars.RarBuilder.from_archive(source)


@pytest.mark.parametrize("kind", [0o010000, 0o020000, 0o060000, 0o120000, 0o140000])
def test_rewrite_rejects_unix_special_file_modes(kind):
    source = rars.RarBuilder(format="rar29", store=True)
    source.add_bytes(b"special payload", "special", mode=kind | 0o644)
    archive = rars.RarFile.from_bytes(source.to_bytes())
    assert archive.read("special") == b"special payload"
    with pytest.raises(rars.UnsupportedRarFeature, match="special"):
        rars.RarBuilder.from_archive(archive)


@pytest.mark.skipif(os.name != "posix" or not shutil.which("unrar"), reason="requires POSIX and unrar")
@pytest.mark.parametrize("zone", ["Asia_Kolkata", "Europe_London", "Etc_GMT_5"])
def test_legacy_rewrite_uses_extractions_local_zone_and_odd_second(tmp_path, zone):
    source = ROOT / "crates/rars/tests/fixtures/rar15_40/rar420/ext_time_rar420.rar"
    rewritten = tmp_path / "rewritten.rar"
    env = dict(os.environ, TZDIR=str(ROOT / "crates/rars/tests/fixtures/tz"), TZ=zone)
    # Zone state is cached once per process, just as in CLI extraction.
    subprocess.run(
        [sys.executable, "-c", "import rars,sys; rars.RarBuilder.from_archive(sys.argv[1]).write(sys.argv[2])",
         str(source), str(rewritten)], env=env, check=True, capture_output=True,
    )
    times = []
    for index, archive in enumerate((source, rewritten)):
        output = tmp_path / str(index)
        output.mkdir()
        subprocess.run(
            ["unrar", "x", "-idq", "-o+", str(archive), str(output) + "/"],
            env=env, check=True, capture_output=True,
        )
        times.append((output / "hello.txt").stat().st_mtime_ns)
    assert times[0] == times[1]


def archive_with_dos_flags(flags):
    builder = rars.RarBuilder(store=True)
    builder.add_bytes(b"DOS payload", "file.txt")
    data = bytearray(builder.to_bytes())
    for crc_at, body_at, body_end in _headers(data):
        _, cursor = _read_vint(data, body_at)
        kind, cursor = _read_vint(data, cursor)
        block_flags, cursor = _read_vint(data, cursor)
        if kind != 2:
            continue
        if block_flags & 1:
            _, cursor = _read_vint(data, cursor)
        if block_flags & 2:
            _, cursor = _read_vint(data, cursor)
        _, cursor = _read_vint(data, cursor)  # file flags
        _, cursor = _read_vint(data, cursor)  # unpacked size
        assert data[cursor] == 0x20 and 0 <= flags < 128
        data[cursor] = flags
        data[crc_at:crc_at + 4] = zlib.crc32(data[body_at:body_end]).to_bytes(4, "little")
        return bytes(data)
    raise AssertionError("no file header")


@pytest.mark.parametrize("flags", [0, 1, 2, 4, 0x20, 0x27])
def test_rewrite_retains_dos_flags(flags):
    source = rars.RarFile.from_bytes(archive_with_dos_flags(flags))
    # Validate the crafted input, so a broken fixture cannot pass as a rewrite fix.
    assert source.getinfo("file.txt").file_attr == flags
    assert source.getinfo("file.txt").host_os == 0
    assert source.read("file.txt") == b"DOS payload"
    rewritten = rars.RarBuilder.from_archive(source)
    rewritten.rename("file.txt", "renamed.txt")
    output = rars.RarFile.from_bytes(rewritten.to_bytes())
    assert output.getinfo("renamed.txt").file_attr == flags
    assert output.getinfo("renamed.txt").host_os == 0
    assert output.read("renamed.txt") == b"DOS payload"


@pytest.mark.skipif(os.name != "posix" or not shutil.which("unrar"), reason="requires POSIX and unrar")
def test_rewrite_readonly_flag_matches_unrar(tmp_path):
    source = tmp_path / "source.rar"
    source.write_bytes(archive_with_dos_flags(0x21))
    rewritten = tmp_path / "rewritten.rar"
    rars.RarBuilder.from_archive(source).write(rewritten)
    modes = []
    for index, archive in enumerate((source, rewritten)):
        output = tmp_path / str(index)
        output.mkdir()
        subprocess.run(
            ["unrar", "x", "-idq", "-o+", str(archive), str(output) + "/"],
            check=True, capture_output=True,
        )
        file = output / "file.txt"
        modes.append(file.stat().st_mode & 0o777)
        assert file.read_bytes() == b"DOS payload"
    assert modes[0] & 0o222 == 0
    assert modes[0] == modes[1]
