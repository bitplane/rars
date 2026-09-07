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


@pytest.mark.parametrize("format", ["rar20", "rar29", "rar30", "rar40"])
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


# Insert a native time record into otherwise ordinary legacy file headers.
def with_extended_times(data, raw):
    data = bytearray(data)
    offset, _, flags, size = next(h for h in headers(data) if h[1] == 0x74)
    data[offset + size:offset + size] = raw
    struct.pack_into("<H", data, offset + 3, flags | 0x1000)
    struct.pack_into("<H", data, offset + 5, size + len(raw))
    struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + size + len(raw)]) & 0xffff)
    return bytes(data)


def extended_time_records(data):
    result = []
    for offset, kind, flags, size in headers(data):
        if kind == 0x74:
            name_size = struct.unpack_from("<H", data, offset + 26)[0]
            result.append(data[offset + 32 + name_size:offset + size] if flags & 0x1000 else None)
    return result


@pytest.mark.parametrize("width", range(4))
@pytest.mark.parametrize("solid", [False, True])
def test_native_extended_times_retain_all_four_slots_and_precision(width, solid):
    mode = 12 | width  # Present, plus the odd-second bit.
    raw = struct.pack("<H", mode * 0x1111)
    for index in range(4):
        if index:
            raw += struct.pack("<I", DOS_TIME + index)
        raw += b"\x01" * width
    source = rars.RarFile.from_bytes(with_extended_times(source_bytes(solid=solid), raw))
    assert source.rewrite_preservation_issues() == []
    builder = rars.RarBuilder.from_archive(source)
    builder.rename(b"raw-\xff", "renamed")
    builder.remove("second")
    output = builder.to_bytes()
    assert extended_time_records(output) == [raw]
    assert rars.RarFile.from_bytes(output).read("renamed") == b"payload" * 50
    assert extended_time_records(rars.RarBuilder.from_archive(rars.RarFile.from_bytes(output)).to_bytes()) == [raw]


@pytest.mark.parametrize("raw", [b"\0\0", b"\0\x80"])
def test_explicit_empty_or_whole_second_time_records_remain_present(raw):
    source = rars.RarFile.from_bytes(with_extended_times(source_bytes(), raw))
    output = rars.RarBuilder.from_archive(source).to_bytes()
    assert extended_time_records(output) == [raw, None]


@pytest.mark.parametrize("raw", [b"", b"\x00", b"\0\xb0", b"\0\x08", b"\0\0extra", b"\0\xb0\xff\xff\xff", b"\0\x10"])
def test_malformed_extended_times_fail_before_destination_write(tmp_path, raw):
    source = rars.RarFile.from_bytes(with_extended_times(source_bytes(), raw))
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep")
    with pytest.raises(rars.UnsupportedRarFeature, match="extended timestamps"):
        rars.RarBuilder.from_archive(source).write(destination)
    assert destination.read_bytes() == b"keep"


def test_reference_rar420_extended_times_survive_native_rewrite(tmp_path):
    path = ROOT / "crates/rars/tests/fixtures/rar15_40/rar420/ext_time_rar420.rar"
    source = rars.RarFile(path)
    builder = rars.RarBuilder.from_archive(source)
    output_bytes = builder.to_bytes()
    assert extended_time_records(output_bytes) == extended_time_records(path.read_bytes())
    output = rars.RarFile.from_bytes(output_bytes)
    assert output.family == "rar15_40"
    for name in source.namelist():
        assert output.gettimes(name) == source.gettimes(name)
        assert output.read(name) == source.read(name)
    if shutil.which("unrar"):
        rewritten = tmp_path / "rewritten.rar"
        rewritten.write_bytes(output_bytes)
        extracted_times = []
        for index, archive in enumerate([path, rewritten]):
            directory = tmp_path / str(index)
            directory.mkdir()
            subprocess.run(["unrar", "x", "-idq", str(archive), str(directory) + "/"], check=True, capture_output=True)
            extracted_times.append({file.relative_to(directory): file.stat().st_mtime_ns
                                    for file in directory.rglob("*") if file.is_file()})
        assert extracted_times[0] == extracted_times[1]


@pytest.mark.parametrize("header_encryption", [False, True])
@pytest.mark.parametrize("solid", [False, True])
def test_legacy_encryption_survives_edits(tmp_path, header_encryption, solid):
    original = source_bytes(password="secret", encrypt_headers=header_encryption, solid=solid)
    source = rars.RarFile.from_bytes(original, password="secret")
    assert source.rewrite_preservation_issues() == []
    builder = rars.RarBuilder.from_archive(source)
    builder.rename(b"raw-\xff", "renamed")
    output_bytes = builder.to_bytes()
    if header_encryption:
        with pytest.raises(rars.PasswordRequired):
            rars.RarFile.from_bytes(output_bytes)
    output = rars.RarFile.from_bytes(output_bytes, password="secret")
    assert output.rewrite_preservation_issues() == []
    for name in output.namelist():
        assert output.getinfo(name).is_encrypted
    assert output.read("renamed") == b"payload" * 50
    assert output.read("second") == b"second"
    assert rars.RarBuilder.from_archive(output).to_bytes()
    if shutil.which("unrar"):
        path = tmp_path / "encrypted.rar"
        path.write_bytes(output_bytes)
        subprocess.run(["unrar", "t", "-psecret", "-idq", str(path)], check=True, capture_output=True)


@pytest.mark.parametrize("format", ["rar20", "rar40"])
@pytest.mark.parametrize("encrypted_first", [False, True])
def test_mixed_legacy_encryption_keeps_plaintext_members_plain(tmp_path, format, encrypted_first):
    plain = rars.RarBuilder(format=format, store=True)
    plain.add_bytes(b"public", "plain")
    encrypted = rars.RarBuilder(format=format, password="secret")
    encrypted.add_bytes(b"private", "encrypted")
    first, second = (encrypted, plain) if encrypted_first else (plain, encrypted)
    second_bytes = second.to_bytes()
    member_offset = next(offset for offset, kind, _, _ in headers(second_bytes) if kind == 0x74)
    source = rars.RarFile.from_bytes(first.to_bytes() + second_bytes[member_offset:], password="secret")
    rewritten = rars.RarBuilder.from_archive(source).to_bytes()
    output = rars.RarFile.from_bytes(rewritten)
    assert not output.getinfo("plain").is_encrypted
    assert output.read("plain") == b"public"
    assert output.open("plain").read() == b"public"
    assert output.read("plain", pwd="wrong") == b"public"
    extracted = output.extract("plain", tmp_path / "single")
    assert extracted.read_bytes() == b"public"
    paths = output.extractall(tmp_path / "filtered", members=["plain"], pwd="wrong")
    assert [path.read_bytes() for path in paths] == [b"public"]
    with pytest.raises(KeyError):
        output.extract("missing", tmp_path / "missing")
    assert output.extractall(tmp_path / "none", members=[]) == []
    assert not (tmp_path / "missing").exists()
    assert not (tmp_path / "none").exists()
    assert output.getinfo("encrypted").is_encrypted
    with pytest.raises(rars.PasswordRequired):
        output.read("encrypted")
    with pytest.raises(rars.PasswordRequired):
        output.testrar()
    with pytest.raises(rars.PasswordRequired):
        output.extractall(tmp_path / "all")
    assert rars.RarFile.from_bytes(rewritten, password="secret").read("encrypted") == b"private"
    if shutil.which("unrar"):
        path = tmp_path / "mixed.rar"
        path.write_bytes(rewritten)
        result = subprocess.run(["unrar", "p", "-p-", "-inul", str(path), "plain"], check=True, capture_output=True)
        assert result.stdout == b"public"
    builder = rars.RarBuilder.from_archive(source)
    builder.remove("encrypted")
    assert rars.RarFile.from_bytes(builder.to_bytes()).read("plain") == b"public"



@pytest.mark.parametrize("password", [None, "wrong"])
@pytest.mark.parametrize("header_encryption", [False, True])
def test_legacy_password_failure_keeps_destination(tmp_path, password, header_encryption):
    data = source_bytes(password="secret", encrypt_headers=header_encryption)
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep")
    with pytest.raises((rars.PasswordRequired, rars.BadPassword, rars.BadRarFile)):
        source = rars.RarFile.from_bytes(data, password=password)
        rars.RarBuilder.from_archive(source).write(destination)
    assert destination.read_bytes() == b"keep"
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("fixture", ["per_file_rar300_password.rar", "header_rar300_password.rar", "header_rar420_password.rar"])
def test_reference_legacy_encryption_is_preserved(fixture):
    source = rars.RarFile(ROOT / "crates/rars/tests/fixtures/rar15_40/encrypted" / fixture, password="password")
    builder = rars.RarBuilder.from_archive(source)
    output = rars.RarFile.from_bytes(builder.to_bytes(), password="password")
    assert output.family == source.family
    for name in source.namelist():
        assert output.getinfo(name).is_encrypted == source.getinfo(name).is_encrypted
        assert output.read(name) == source.read(name)
        assert output.gettimes(name) == source.gettimes(name)
