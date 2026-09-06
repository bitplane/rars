import shutil
import struct
import subprocess
import zlib

import pytest
import rars

from test_rewrite_legacy import ROOT, DOS_TIME, headers, file_metadata


def check_unrar(tmp_path, data, password="password"):
    if shutil.which("unrar"):
        path = tmp_path / "rewritten.rar"
        path.write_bytes(data)
        result = subprocess.run(["unrar", "t", "-idq", "-p" + password, str(path)], capture_output=True)
        assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("fixture", ["readme_154_normal.rar", "readme_154_password.rar",
    "readme_154_store_solid.rar", "doc_154_best.rar", "audio_win_names_unpack15.rar", "audio_dos_names_unpack15.rar"])
def test_vintage_rar15_preservation(tmp_path, fixture):
    path = ROOT / "crates/rars/tests/fixtures/rar15_40/rar154" / fixture
    source = rars.RarFile(path, password="password")
    editor = rars.RarBuilder.from_archive(source)
    editor.rename(source.namelist()[0], "renamed")
    data = editor.to_bytes()
    output = rars.RarFile.from_bytes(data, password="password")
    assert output.rewrite_preservation_issues() == []
    for before, after in zip(source.namelist(), output.namelist(), strict=True):
        assert source.read(before) == output.read(after)
        assert source.gettimes(before) == output.gettimes(after)
        assert source.getinfo(before).file_attr == output.getinfo(after).file_attr
        assert source.getinfo(before).is_encrypted == output.getinfo(after).is_encrypted
    assert all(meta[3] == 15 for meta in file_metadata(data))
    check_unrar(tmp_path, data)


@pytest.mark.parametrize("version", [15, 26])
@pytest.mark.parametrize("solid", [False, True])
@pytest.mark.parametrize("password", [None, "password"])
def test_older_formats_keep_version_and_solid_directory_state(tmp_path, version, solid, password):
    builder = rars.RarBuilder(format="rar15" if version == 15 else "rar20", solid=solid, password=password)
    builder.add_bytes(b"first " * 300, b"raw-\xff", mtime=DOS_TIME)
    builder.add_directory("empty", mtime=DOS_TIME)
    builder.add_bytes(b"first " * 300 + b"end", "last", mtime=DOS_TIME)
    original = bytearray(builder.to_bytes())
    if version == 26:
        for offset, kind, _, size in headers(original):
            if kind == 0x74:
                original[offset + 24] = 26
                struct.pack_into("<H", original, offset, zlib.crc32(original[offset + 2:offset + size]) & 0xffff)
    source = rars.RarFile.from_bytes(bytes(original), password=password)
    editor = rars.RarBuilder.from_archive(source)
    editor.rename(b"raw-\xff", "renamed")
    data = editor.to_bytes()
    output = rars.RarFile.from_bytes(data, password=password)
    assert output.read("renamed") == b"first " * 300
    assert output.read("last") == b"first " * 300 + b"end"
    assert output.getinfo("empty").is_dir()
    assert output.gettimes("empty") == source.gettimes("empty")
    assert all(meta[3] == version for meta in file_metadata(data))
    check_unrar(tmp_path, data)
    editor.remove("renamed")
    data = editor.to_bytes()
    assert rars.RarFile.from_bytes(data, password=password).read("last") == b"first " * 300 + b"end"
    check_unrar(tmp_path, data)
