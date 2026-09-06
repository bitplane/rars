import shutil
import struct
import subprocess
import zlib

import pytest
import rars

from test_rewrite_legacy import ROOT, headers


@pytest.mark.parametrize("format", ["rar20", "rar29", "rar30", "rar40"])
@pytest.mark.parametrize("comment", [b"", b"archive comment\xff"])
@pytest.mark.parametrize("password", [None, "secret"])
def test_native_archive_comments_survive_rewrites(format, comment, password):
    builder = rars.RarBuilder(format=format, comment=comment, password=password)
    builder.add_bytes(b"payload", "file")
    source = rars.RarFile.from_bytes(builder.to_bytes(), password=password)
    assert source.rewrite_preservation_issues() == []
    editor = rars.RarBuilder.from_archive(source)
    editor.rename("file", "renamed")
    data = editor.to_bytes()
    output = rars.RarFile.from_bytes(data, password=password)
    assert output.family == "rar15_40"
    assert output.comment == comment
    assert output.read("renamed") == b"payload"
    assert output.rewrite_preservation_issues() == []
    assert rars.RarFile.from_bytes(rars.RarBuilder.from_archive(output).to_bytes(), password=password).comment == comment


@pytest.mark.parametrize("password", [None, "secret"])
@pytest.mark.parametrize("format", ["rar20", "rar29"])
def test_embedded_file_comments_follow_edits_and_keep_empty_distinct(password, format):
    builder = rars.RarBuilder(format=format, comment=b"archive", password=password)
    for name in ["file", "empty", "absent", "remove"]:
        builder.add_bytes(name.encode(), name)
    builder.set_file_comment("file", b"comment\xff")
    builder.set_file_comment("empty", b"")
    builder.set_file_comment("remove", b"discard")
    source = rars.RarFile.from_bytes(builder.to_bytes(), password=password)
    editor = rars.RarBuilder.from_archive(source)
    editor.rename("file", "renamed")
    editor.remove("remove")
    output = rars.RarFile.from_bytes(editor.to_bytes(), password=password)
    assert output.comment == b"archive"
    assert output.getcomment("renamed") == b"comment\xff"
    assert output.getcomment("empty") == b""
    assert output.getcomment("absent") is None
    assert output.read("renamed") == b"file"
    editor.set_file_comment("renamed", b"changed")
    assert rars.RarFile.from_bytes(editor.to_bytes(), password=password).getcomment("renamed") == b"changed"
    editor.set_file_comment("renamed", None)
    assert rars.RarFile.from_bytes(editor.to_bytes(), password=password).getcomment("renamed") is None


def old_comment_archive():
    builder = rars.RarBuilder(format="rar29", store=True, comment=b"comment")
    builder.add_bytes(b"payload", "file")
    return builder.to_bytes()


def test_nested_archive_comment_is_retained():
    data = bytearray(old_comment_archive())
    offset, _, _, size = next(h for h in headers(data) if h[1] == 0x75)
    assert offset == 20
    struct.pack_into("<H", data, 12, 13 + size)
    struct.pack_into("<H", data, 7, zlib.crc32(data[9:20]) & 0xffff)
    source = rars.RarFile.from_bytes(bytes(data))
    assert source.comment == b"comment"
    output = rars.RarFile.from_bytes(rars.RarBuilder.from_archive(source).to_bytes())
    assert output.comment == b"comment"
    assert output.read("file") == b"payload"


@pytest.mark.parametrize("damage", ["duplicate", "unknown_flags", "nested_trailing", "corrupt_payload"])
def test_bad_archive_comments_leave_destination_untouched(tmp_path, damage):
    data = bytearray(old_comment_archive())
    offset, _, _, size = next(h for h in headers(data) if h[1] == 0x75)
    if damage == "duplicate":
        data[offset:offset] = data[offset:offset + size]
    elif damage == "unknown_flags":
        struct.pack_into("<H", data, offset + 3, 1)
        struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + 13]) & 0xffff)
    elif damage == "nested_trailing":
        data[offset + size:offset + size] = b"?"
        struct.pack_into("<H", data, 12, 13 + size + 1)
        struct.pack_into("<H", data, 7, zlib.crc32(data[9:20]) & 0xffff)
    else:
        data[offset + 13] ^= 1
    source = rars.RarFile.from_bytes(bytes(data))
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep")
    with pytest.raises((rars.UnsupportedRarFeature, rars.BadRarFile)):
        rars.RarBuilder.from_archive(source).write(destination)
    assert destination.read_bytes() == b"keep"


def test_corrupt_file_comment_fails_before_destination_write(tmp_path):
    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"payload", "file")
    builder.set_file_comment("file", b"comment")
    data = bytearray(builder.to_bytes())
    offset, _, _, _ = next(h for h in headers(data) if h[1] == 0x74)
    name_size = struct.unpack_from("<H", data, offset + 26)[0]
    data[offset + 32 + name_size + 13] ^= 1
    source = rars.RarFile.from_bytes(bytes(data))
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep")
    with pytest.raises(rars.BadRarFile):
        rars.RarBuilder.from_archive(source).write(destination)
    assert destination.read_bytes() == b"keep"


def test_reference_rar300_comment_survives_native_rewrite(tmp_path):
    source = rars.RarFile(ROOT / "crates/rars/tests/fixtures/rar15_40/rar300/with_comment_rar300.rar")
    editor = rars.RarBuilder.from_archive(source)
    destination = tmp_path / "rewritten.rar"
    editor.write(destination)
    output = rars.RarFile(destination)
    assert output.family == source.family
    assert output.comment == source.comment
    original = (ROOT / "crates/rars/tests/fixtures/rar15_40/rar300/with_comment_rar300.rar").read_bytes()
    rewritten = destination.read_bytes()
    before = next(offset for offset, kind, _, _ in headers(original) if kind == 0x7a)
    after = next(offset for offset, kind, _, _ in headers(rewritten) if kind == 0x7a)
    assert rewritten[after + 20:after + 24] == original[before + 20:before + 24]
    assert rewritten[after + 15] == original[before + 15]
    for name in source.namelist():
        assert output.read(name) == source.read(name)
    if shutil.which("unrar"):
        result = subprocess.run(["unrar", "l", str(destination)], check=True, capture_output=True)
        assert output.comment.strip() in result.stdout


@pytest.mark.parametrize("damage", ["duplicate", "after_file", "unknown_flags"])
def test_unsupported_cmt_service_layout_is_rejected(damage):
    builder = rars.RarBuilder(format="rar30", comment=b"comment")
    builder.add_bytes(b"payload", "file")
    data = bytearray(builder.to_bytes())
    offset, _, flags, size = next(h for h in headers(data) if h[1] == 0x7a)
    packed = struct.unpack_from("<I", data, offset + 7)[0]
    block = data[offset:offset + size + packed]
    if damage == "duplicate":
        data[offset:offset] = block
    elif damage == "after_file":
        del data[offset:offset + len(block)]
        data += block
    else:
        struct.pack_into("<H", data, offset + 3, flags | 0x1000)
        struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + size]) & 0xffff)
    source = rars.RarFile.from_bytes(bytes(data))
    with pytest.raises(rars.UnsupportedRarFeature):
        rars.RarBuilder.from_archive(source)
