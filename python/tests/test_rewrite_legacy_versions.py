import struct
import zlib

import pytest
import rars

from test_rewrite_legacy import DOS_TIME, headers, file_metadata
from test_rewrite_older import check_unrar


def versioned_file(version, name, password=None):
    builder = rars.RarBuilder(format={15: "rar15", 20: "rar20", 26: "rar20", 29: "rar29"}[version], password=password)
    builder.add_bytes(name.encode() * 100, name, mtime=DOS_TIME)
    data = bytearray(builder.to_bytes())
    if version == 26:
        offset, _, _, size = next(h for h in headers(data) if h[1] == 0x74)
        data[offset + 24] = version
        struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + size]) & 0xffff)
    return bytes(data)


@pytest.mark.parametrize("versions", [(15, 20), (20, 15), (20, 26), (26, 15), (15, 29), (29, 20)])
@pytest.mark.parametrize("password", [None, "password"])
def test_mixed_unpackers_keep_archive_requirement_even_after_removing_newer_member(tmp_path, versions, password):
    first = versioned_file(versions[0], "first", password)
    second = versioned_file(versions[1], "second")
    start = next(offset for offset, kind, _, _ in headers(second) if kind == 0x74)
    source = rars.RarFile.from_bytes(first + second[start:], password=password)
    editor = rars.RarBuilder.from_archive(source)
    data = editor.to_bytes()
    output = rars.RarFile.from_bytes(data, password=password)
    assert output.read("first") == b"first" * 100
    assert output.read("second") == b"second" * 100
    assert output.getinfo("first").is_encrypted == (password is not None)
    assert not output.getinfo("second").is_encrypted
    assert all(meta[3] == max(versions) for meta in file_metadata(data))
    check_unrar(tmp_path, data)
    editor.remove("first" if versions[0] > versions[1] else "second")
    data = editor.to_bytes()
    assert file_metadata(data)[0][3] == max(versions)
    check_unrar(tmp_path, data)


def test_rar15_dos_directory_without_later_directory_marker(tmp_path):
    builder = rars.RarBuilder(format="rar15")
    builder.add_bytes(b"first" * 100, "first", mtime=DOS_TIME)
    builder.add_directory("directory", mtime=DOS_TIME)
    builder.add_bytes(b"last" * 100, "last", mtime=DOS_TIME)
    data = bytearray(builder.to_bytes())
    offset, _, flags, size = [h for h in headers(data) if h[1] == 0x74][1]
    struct.pack_into("<H", data, offset + 3, flags & ~0xe0)
    data[offset + 25] = 0x33  # Vintage directory method marker; there is no payload.
    struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + size]) & 0xffff)
    source = rars.RarFile.from_bytes(bytes(data))
    assert source.getinfo("directory").is_dir()
    editor = rars.RarBuilder.from_archive(source)
    editor.rename("directory", "renamed")
    data = editor.to_bytes()
    output = rars.RarFile.from_bytes(data)
    assert output.getinfo("renamed").is_dir()
    assert output.gettimes("renamed") == source.gettimes("directory")
    assert output.read("last") == b"last" * 100
    check_unrar(tmp_path, data)
