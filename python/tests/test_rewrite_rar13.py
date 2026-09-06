import struct
from pathlib import Path

import pytest
import rars

from test_rewrite_legacy import ROOT, DOS_TIME
from test_rewrite_older import check_unrar


@pytest.mark.parametrize("fixture", ["README.RAR", "README_password=password.rar", "STOREPWD.RAR",
    "WITHDIR.RAR", "SOLID.RAR", "FCOMM.RAR", "COMMENT.RAR", "MULTIFIL.RAR"])
def test_vintage_rar13_metadata_payloads_and_comments(tmp_path, fixture):
    source = rars.RarFile(ROOT / "crates/rars/tests/fixtures/rar13" / fixture, password="password")
    editor = rars.RarBuilder.from_archive(source)
    editor.rename(source.namelist()[0], "renamed")
    data = editor.to_bytes()
    output = rars.RarFile.from_bytes(data, password="password")
    assert output.family == source.family == "rar13"
    assert output.rewrite_preservation_issues() == []
    assert output.comment == source.comment
    for before, after in zip(source.namelist(), output.namelist(), strict=True):
        assert output.getinfo(after).is_dir() == source.getinfo(before).is_dir()
        assert output.getinfo(after).file_attr == source.getinfo(before).file_attr
        assert output.getinfo(after).is_encrypted == source.getinfo(before).is_encrypted
        assert output.gettimes(after) == source.gettimes(before)
        assert output.getcomment(after) == source.getcomment(before)
        if not source.getinfo(before).is_dir():
            assert output.read(after) == source.read(before)
    check_unrar(tmp_path, data)


@pytest.mark.parametrize("solid", [False, True])
def test_rar13_directories_between_solid_members_and_after_removal(tmp_path, solid):
    builder = rars.RarBuilder(format="rar13", solid=solid, password="password")
    builder.add_bytes(b"data " * 500, b"raw-\xff", mtime=DOS_TIME)
    builder.add_directory("empty", mtime=DOS_TIME)
    builder.add_bytes(b"data " * 500 + b"end", "last", mtime=DOS_TIME)
    source = rars.RarFile.from_bytes(builder.to_bytes(), password="password")
    editor = rars.RarBuilder.from_archive(source)
    data = editor.to_bytes()
    check_unrar(tmp_path, data)
    editor.remove(b"raw-\xff")
    data = editor.to_bytes()
    assert rars.RarFile.from_bytes(data, password="password").read("last") == b"data " * 500 + b"end"
    check_unrar(tmp_path, data)


@pytest.mark.parametrize("damage", ["main_flags", "file_flags", "extra", "version"])
def test_rar13_unknown_metadata_preserves_destination(tmp_path, damage):
    builder = rars.RarBuilder(format="rar13", store=True)
    builder.add_bytes(b"data", "file")
    data = bytearray(builder.to_bytes())
    offset = struct.unpack_from("<H", data, 4)[0]
    if damage == "main_flags":
        data[6] |= 0x40
    elif damage == "file_flags":
        data[offset + 17] |= 0x80
    elif damage == "version":
        data[offset + 18] = 7
    else:
        size = struct.unpack_from("<H", data, offset + 10)[0]
        data[offset + size:offset + size] = b"unknown"
        struct.pack_into("<H", data, offset + 10, size + 7)
    source = rars.RarFile.from_bytes(bytes(data))
    path = tmp_path / "existing.rar"
    path.write_bytes(b"keep")
    with pytest.raises(rars.UnsupportedRarFeature):
        rars.RarBuilder.from_archive(source).write(path)
    assert path.read_bytes() == b"keep"


def test_rar13_mixed_encryption_keeps_plain_members_plain(tmp_path):
    plain = rars.RarBuilder(format="rar13", store=True)
    plain.add_bytes(b"public", "plain")
    encrypted = rars.RarBuilder(format="rar13", password="password")
    encrypted.add_bytes(b"private", "secret")
    data = encrypted.to_bytes()
    source = rars.RarFile.from_bytes(plain.to_bytes() + data[struct.unpack_from("<H", data, 4)[0]:], password="password")
    editor = rars.RarBuilder.from_archive(source)
    rewritten = editor.to_bytes()
    output = rars.RarFile.from_bytes(rewritten, password="password")
    assert not output.getinfo("plain").is_encrypted
    assert output.getinfo("secret").is_encrypted
    assert output.read("plain") == b"public"
    assert output.read("secret") == b"private"
    check_unrar(tmp_path, rewritten)
    editor.remove("secret")
    assert rars.RarFile.from_bytes(editor.to_bytes()).read("plain") == b"public"
