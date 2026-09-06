import shutil
import struct
import subprocess
import zlib

import pytest
import rars

from test_rewrite_legacy import ROOT, headers, source_bytes
from test_rewrite_older import check_unrar


def unicode_wire(name):
    units = name.encode("utf-16le")
    encoded = b"".join(b"\xaa" + units[i:i + 8] for i in range(0, len(units), 8))
    return b"fallback.txt\0\0" + encoded


def replace_first_name(data, raw):
    data = bytearray(data)
    offset, _, flags, size = next(h for h in headers(data) if h[1] == 0x74)
    length = struct.unpack_from("<H", data, offset + 26)[0]
    data[offset + 32:offset + 32 + length] = raw
    size += len(raw) - length
    struct.pack_into("<H", data, offset + 26, len(raw))
    struct.pack_into("<H", data, offset + 5, size)
    struct.pack_into("<H", data, offset + 3, flags | 0x200)
    struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + size]) & 0xffff)
    return bytes(data)


def raw_names(data):
    return [(flags & 0x200, data[offset + 32:offset + 32 + struct.unpack_from("<H", data, offset + 26)[0]])
            for offset, kind, flags, _ in headers(data) if kind == 0x74]


@pytest.mark.parametrize("format", ["rar20", "rar40"])
@pytest.mark.parametrize("name", ["日本語.txt", "cafe\u0301-😀.txt"])
def test_unicode_wire_bytes_survive_and_rename_keeps_unicode(tmp_path, format, name):
    raw = unicode_wire(name)
    source = rars.RarFile.from_bytes(replace_first_name(source_bytes(format, solid=True), raw))
    editor = rars.RarBuilder.from_archive(source)
    assert raw_names(editor.to_bytes())[0] == (0x200, raw)
    editor.rename(name, name)
    assert raw_names(editor.to_bytes())[0] == (0x200, raw)
    with pytest.raises(ValueError, match="UTF-8"):
        editor.rename(name, b"invalid-\xff")
    assert raw_names(editor.to_bytes())[0] == (0x200, raw)
    renamed = "renamed-日本語.txt"
    editor.rename(name, renamed)
    data = editor.to_bytes()
    output = rars.RarFile.from_bytes(data)
    assert output.read(renamed) == b"payload" * 50
    assert output.read("second") == b"second"
    assert raw_names(data)[0][0] == 0x200
    check_unrar(tmp_path, data)
    if shutil.which("unrar"):
        out = tmp_path / "out"
        out.mkdir()
        subprocess.run(["unrar", "x", "-idq", str(tmp_path / "rewritten.rar"), str(out) + "/"], check=True, capture_output=True)
        assert (out / renamed).read_bytes() == b"payload" * 50


@pytest.mark.parametrize("fixture", ["rar4_sharpcompress_files_only.rar", "rar4_junrar_file_content_encrypted_unicode.rar"])
def test_reference_encrypted_unicode_archives_retain_exact_names(tmp_path, fixture):
    path = ROOT / "crates/rars/tests/fixtures/rar15_40/encrypted" / fixture
    source = rars.RarFile(path, password="test")
    data = rars.RarBuilder.from_archive(source).to_bytes()
    assert raw_names(data) == raw_names(path.read_bytes())
    output = rars.RarFile.from_bytes(data, password="test")
    assert output.namelist() == source.namelist()
    for name in source.namelist():
        if not source.getinfo(name).is_dir():
            assert output.read(name) == source.read(name)
    check_unrar(tmp_path, data, password="test")


@pytest.mark.parametrize("raw", [b"fallback\0\0\x80\0\xd8", b"fallback\0\0\xc0\x7f", b"invalid-\xff"])
def test_malformed_unicode_names_are_refused(tmp_path, raw):
    source = rars.RarFile.from_bytes(replace_first_name(source_bytes(store=True), raw))
    path = tmp_path / "existing.rar"
    path.write_bytes(b"keep")
    with pytest.raises(rars.UnsupportedRarFeature):
        rars.RarBuilder.from_archive(source).write(path)
    assert path.read_bytes() == b"keep"


def test_unicode_rename_retains_non_bmp_characters():
    source = rars.RarFile.from_bytes(replace_first_name(source_bytes(store=True), unicode_wire("name.txt")))
    editor = rars.RarBuilder.from_archive(source)
    editor.rename("name.txt", "emoji-😀.txt")
    output = rars.RarFile.from_bytes(editor.to_bytes())
    assert output.read("emoji-😀.txt") == b"payload" * 50
