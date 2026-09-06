"""The first native legacy rewrite subset: regular, unencrypted RAR 2.9–4 files."""
import shutil
import struct
import subprocess
import zlib
from pathlib import Path

import pytest
import rars

ROOT = Path(__file__).resolve().parents[2]
DOS_TIME = ((2024 - 1980) << 25) | (3 << 21) | (10 << 16) | (2 << 11) | (30 << 5) | 7


def headers(data):
    offset = 7
    while offset + 7 <= len(data):
        _, kind, flags, size = struct.unpack_from("<HBHH", data, offset)
        yield offset, kind, flags, size
        packed = struct.unpack_from("<I", data, offset + 7)[0] if flags & 0x8000 else 0
        offset += size + packed


def file_metadata(data):
    result = []
    for offset, kind, _, _ in headers(data):
        if kind == 0x74:
            length = struct.unpack_from("<H", data, offset + 26)[0]
            result.append((data[offset + 32:offset + 32 + length], data[offset + 15],
                           struct.unpack_from("<I", data, offset + 20)[0],
                           data[offset + 24], struct.unpack_from("<I", data, offset + 28)[0]))
    return result


def source_bytes(format="rar40", **options):
    builder = rars.RarBuilder(format=format, **options)
    builder.add_bytes(b"payload" * 50, b"raw-\xff", mtime=DOS_TIME, mode=0o100640)
    builder.add_bytes(b"second", "second", mtime=0)
    return builder.to_bytes()


@pytest.mark.parametrize("format", ["rar29", "rar30", "rar40"])
@pytest.mark.parametrize("options", [{"store": True}, {}, {"solid": True}])
@pytest.mark.parametrize("on_disk", [False, True])
def test_native_legacy_preservation_keeps_names_times_attributes_and_format(tmp_path, format, options, on_disk):
    original = source_bytes(format, **options)
    if on_disk:
        source = tmp_path / "source.rar"
        source.write_bytes(original)
    else:
        source = rars.RarFile.from_bytes(original)
    builder = rars.RarBuilder.from_archive(source)
    builder.rename(b"raw-\xff", b"renamed-\xfe")
    builder.remove("second")
    data = builder.to_bytes()
    output = rars.RarFile.from_bytes(data)
    assert output.family == "rar15_40"
    assert output.read(b"renamed-\xfe") == b"payload" * 50
    assert output.rewrite_preservation_issues() == []
    expected = file_metadata(original)[0]
    assert file_metadata(data) == [(b"renamed-\xfe", *expected[1:])]
    assert bool(next(headers(data))[2] & 8) == options.get("solid", False)
    assert rars.RarBuilder.from_archive(output).to_bytes()


@pytest.mark.parametrize("damage, message", [
    ("trailing", "trailing bytes"), ("partial_header", "trailing bytes"),
    ("main_reserved", "main header"), ("unknown_file_flag", "file flags"),
    ("unicode", "Unicode"), ("extended", "extended timestamps"),
    ("comment", "file comments"),
])
def test_unsupported_legacy_metadata_is_rejected_before_destination_write(tmp_path, damage, message):
    data = bytearray(source_bytes(store=True))
    if damage == "trailing":
        data += b"extra"
    elif damage == "partial_header":
        data += b"xyz"
    else:
        offset, _, flags, size = next(h for h in headers(data) if h[1] == (0x73 if damage == "main_reserved" else 0x74))
        if damage == "main_reserved":
            data[offset + 7] = 1
        else:
            flags |= {"unknown_file_flag": 0x2000, "unicode": 0x200, "extended": 0x1000, "comment": 8}[damage]
            struct.pack_into("<H", data, offset + 3, flags)
        struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + size]) & 0xffff)
    source = rars.RarFile.from_bytes(bytes(data))
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep")
    with pytest.raises(rars.UnsupportedRarFeature, match=message):
        rars.RarBuilder.from_archive(source).write(destination)
    assert destination.read_bytes() == b"keep"


def test_legacy_encryption_is_still_rejected_with_a_specific_reason():
    source = rars.RarFile.from_bytes(source_bytes(password="secret"), password="secret")
    with pytest.raises(rars.UnsupportedRarFeature, match="legacy data encryption"):
        rars.RarBuilder.from_archive(source)


@pytest.mark.skipif(not shutil.which("unrar"), reason="requires unrar")
def test_unrar_extracts_native_legacy_rewrite(tmp_path):
    source = rars.RarBuilder(format="rar40", solid=True)
    source.add_bytes(b"first" * 100, "first", mtime=DOS_TIME)
    source.add_bytes(b"second" * 100, "second", mtime=DOS_TIME)
    builder = rars.RarBuilder.from_archive(rars.RarFile.from_bytes(source.to_bytes()))
    builder.rename("first", "renamed")
    archive = tmp_path / "rewritten.rar"
    builder.write(archive)
    output = tmp_path / "output"
    output.mkdir()
    subprocess.run(["unrar", "x", "-idq", str(archive), str(output) + "/"], check=True, capture_output=True)
    assert (output / "renamed").read_bytes() == b"first" * 100
    assert (output / "second").read_bytes() == b"second" * 100


@pytest.mark.parametrize("fixture", ["ppmd_lorem_rar300.rar", "ppmd_solid_rar300.rar"])
def test_native_legacy_rewrites_reference_rar300_archives(fixture):
    path = ROOT / "crates/rars/tests/fixtures/rar15_40/ppmd" / fixture
    source = rars.RarFile(path)
    builder = rars.RarBuilder.from_archive(source)
    original_name = source.namelist()[0]
    builder.rename(original_name, "renamed")
    output_bytes = builder.to_bytes()
    output = rars.RarFile.from_bytes(output_bytes)
    assert output.family == source.family
    assert output.read("renamed") == source.read(original_name)
    original_metadata = file_metadata(path.read_bytes())
    emitted_metadata = file_metadata(output_bytes)
    for before, after in zip(original_metadata, emitted_metadata, strict=True):
        # The Windows host uses the same DOS attributes as emitted host zero.
        assert after[2:] == before[2:]
    assert bool(next(headers(output_bytes))[2] & 8) == bool(next(headers(path.read_bytes()))[2] & 8)


def test_removing_last_legacy_member_keeps_existing_destination(tmp_path):
    source = rars.RarFile.from_bytes(source_bytes())
    builder = rars.RarBuilder.from_archive(source)
    builder.remove(b"raw-\xff")
    builder.remove("second")
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep")
    with pytest.raises(ValueError, match="no entries"):
        builder.write(destination)
    assert destination.read_bytes() == b"keep"


def test_native_legacy_rewrite_can_replace_its_source(tmp_path):
    path = tmp_path / "source.rar"
    path.write_bytes(source_bytes(solid=True))
    builder = rars.RarBuilder.from_archive(path)
    builder.rename(b"raw-\xff", b"renamed-\xff")
    builder.write(path)
    output = rars.RarFile(path)
    assert output.read(b"renamed-\xff") == b"payload" * 50
    assert output.read("second") == b"second"
    assert file_metadata(path.read_bytes())[1][2] == 0
