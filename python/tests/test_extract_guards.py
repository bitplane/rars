"""The extract path guards, exercised through archives the builder will not make.

`RarBuilder` validates member names on the way in, so there is no way to ask it
for an archive that carries `../escape.txt`. These tests build a valid archive
with a placeholder name of the right length and then rewrite that name inside
the RAR 5 file header, fixing the header CRC32 so what comes out is a perfectly
well-formed archive that simply names a member somewhere it has no business
being.

That rewriting is the part worth distrusting: an archive broken by a clumsy
patch would be rejected too, and the guard would look like it worked when
nothing had exercised it. `test_the_rewriter_produces_an_archive_that_still_reads`
covers that by rewriting one safe name to another and checking the reader
agrees.
"""

from __future__ import annotations

import os
import zlib
from pathlib import Path

import pytest
import rars


RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
END_OF_ARCHIVE = 5


def _read_vint(data: bytes, pos: int) -> tuple[int, int]:
    """One RAR 5 variable-length integer: seven bits a byte, high bit continues."""
    value = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def _headers(data: bytes) -> list[tuple[int, int, int]]:
    """Every block header as (crc offset, body start, body end).

    The header CRC32 covers the body: everything from the size field to the end
    of the header, which is what `validate_block_header_crc` checks.
    """
    assert data.startswith(RAR5_SIGNATURE), "not a RAR 5 archive"
    found = []
    pos = len(RAR5_SIGNATURE)
    while pos + 4 < len(data):
        crc_at = pos
        body_at = pos + 4
        header_size, after_size = _read_vint(data, body_at)
        body_end = after_size + header_size
        found.append((crc_at, body_at, body_end))

        header_type, cursor = _read_vint(data, after_size)
        flags, cursor = _read_vint(data, cursor)
        if flags & 0x0001:  # extra area, counted inside header_size
            _, cursor = _read_vint(data, cursor)
        data_size = 0
        if flags & 0x0002:  # data area, follows the header
            data_size, cursor = _read_vint(data, cursor)

        if header_type == END_OF_ARCHIVE:
            break
        pos = body_end + data_size
    return found


def _rewrite_name(archive: bytes, placeholder: bytes, replacement: bytes) -> bytes:
    """Swap a member name for one of the same length and repair the header CRC."""
    assert len(placeholder) == len(replacement), "the name length vint must not move"
    assert archive.count(placeholder) == 1, "placeholder is not unique in the archive"

    patched = bytearray(archive)
    for crc_at, body_at, body_end in _headers(archive):
        found = patched.find(placeholder, body_at, body_end)
        if found < 0:
            continue
        patched[found : found + len(placeholder)] = replacement
        crc = zlib.crc32(bytes(patched[body_at:body_end])) & 0xFFFFFFFF
        patched[crc_at : crc_at + 4] = crc.to_bytes(4, "little")
        return bytes(patched)
    raise AssertionError("placeholder is not inside any block header")


def hostile_archive(name: bytes, payload: bytes = b"owned\n") -> bytes:
    """A valid archive whose single member is called `name`."""
    placeholder = b"p" * len(name)
    builder = rars.RarBuilder(format="rar50", store=True)
    builder.add_bytes(payload, placeholder.decode())
    return _rewrite_name(builder.to_bytes(), placeholder, name)


def tree(root: Path) -> set[Path]:
    return {path.relative_to(root) for path in root.rglob("*")}


def test_the_rewriter_produces_an_archive_that_still_reads():
    archive = rars.RarFile.from_bytes(hostile_archive(b"harmless.txt"))

    assert archive.namelist() == ["harmless.txt"]
    assert archive.read("harmless.txt") == b"owned\n"
    archive.testrar()


@pytest.mark.parametrize(
    ("name", "label"),
    [
        (b"../escape.txt", "parent traversal"),
        (b"a/../../escape.txt", "traversal below a safe first component"),
        (b"..\\escape.txt", "backslash traversal, since backslashes become slashes"),
        (b"/etc/passwd", "absolute path"),
        (b"C:\\windows\\x", "windows drive letter"),
        (b"with\x00nul.txt", "NUL byte"),
    ],
)
def test_extractall_refuses_a_hostile_member_name(tmp_path, name, label):
    out = tmp_path / "out"
    out.mkdir()
    archive = rars.RarFile.from_bytes(hostile_archive(name))

    with pytest.raises(rars.Error) as raised:
        archive.extractall(out)

    assert isinstance(raised.value, rars.UnsafeArchivePath), (
        f"{label} raised {type(raised.value).__name__}, which callers catching "
        f"UnsafeArchivePath would miss: {raised.value}"
    )
    # A guard that raises after writing the file is still a hole, so check the
    # disk rather than trusting the exception.
    assert tree(out) == set(), f"{label} left {tree(out)} behind"
    assert tree(tmp_path) == {Path("out")}, f"{label} wrote outside the output directory"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_extractall_refuses_to_follow_a_symlinked_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    guarded = outside / "file.txt"
    guarded.write_bytes(b"do not overwrite\n")

    out = tmp_path / "out"
    out.mkdir()
    (out / "sub").symlink_to(outside, target_is_directory=True)

    archive = rars.RarFile.from_bytes(hostile_archive(b"sub/file.txt"))

    with pytest.raises(rars.UnsafeArchivePath):
        archive.extractall(out)

    assert guarded.read_bytes() == b"do not overwrite\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_extractall_refuses_to_write_through_a_symlinked_file(tmp_path):
    guarded = tmp_path / "guarded.txt"
    guarded.write_bytes(b"do not overwrite\n")

    out = tmp_path / "out"
    out.mkdir()
    (out / "member.txt").symlink_to(guarded)

    archive = rars.RarFile.from_bytes(hostile_archive(b"member.txt"))

    with pytest.raises(rars.UnsafeArchivePath):
        archive.extractall(out, overwrite=True)

    assert guarded.read_bytes() == b"do not overwrite\n"
