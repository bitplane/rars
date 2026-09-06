import shutil
import struct
import subprocess
import zlib

import pytest
import rars

from test_rewrite_legacy import headers
from test_rewrite_older import check_unrar


@pytest.mark.parametrize("encrypted_headers,file_comments", [(False, False), (True, False), (False, True)])
def test_comments_survive_encrypted_headers_and_cmt_combinations(tmp_path, encrypted_headers, file_comments):
    builder = rars.RarBuilder(format="rar40", password="password", encrypt_headers=encrypted_headers, comment=b"archive comment", solid=True)
    builder.add_bytes(b"data " * 100, "file")
    builder.add_directory("directory")
    builder.add_bytes(b"data " * 100 + b"end", "last")
    if file_comments:
        builder.set_file_comment("file", b"first comment")
        builder.set_file_comment("directory", b"")
    original = builder.to_bytes()
    source = rars.RarFile.from_bytes(original, password="password")
    assert source.comment == b"archive comment"
    editor = rars.RarBuilder.from_archive(source)
    editor.rename("file", "renamed")
    data = editor.to_bytes()
    output = rars.RarFile.from_bytes(data, password="password")
    assert output.rewrite_preservation_issues() == []
    assert output.comment == source.comment
    assert output.read("renamed") == b"data " * 100
    assert output.read("last") == b"data " * 100 + b"end"
    if file_comments:
        assert output.getcomment("renamed") == b"first comment"
        assert output.getcomment("directory") == b""
    if encrypted_headers:
        with pytest.raises(rars.PasswordRequired):
            rars.RarFile.from_bytes(data)
    if not file_comments:
        check_unrar(tmp_path, data)
    elif shutil.which("unrar"):
        # Embedded old comments have the same second-CRC issue as vintage
        # fixtures. Pin identical diagnostics and successful payload checks.
        results = []
        for index, value in enumerate([original, data]):
            path = tmp_path / f"{index}.rar"
            path.write_bytes(value)
            results.append(subprocess.run(["unrar", "t", "-ppassword", str(path)], capture_output=True))
        assert results[0].returncode == results[1].returncode
        assert results[0].stderr == results[1].stderr
        assert results[0].stdout.count(b" OK") == results[1].stdout.count(b" OK") == 3


def encrypted_comment_source():
    comment = rars.RarBuilder(format="rar40", password="password")
    comment.add_bytes(b"secret archive comment", "CMT")
    data = bytearray(comment.to_bytes())
    offset, _, _, size = next(h for h in headers(data) if h[1] == 0x74)
    data[offset + 2] = 0x7a
    struct.pack_into("<I", data, offset + 28, 0)
    struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + size]) & 0xffff)
    plain = rars.RarBuilder(format="rar40", store=True)
    plain.add_bytes(b"public", "plain")
    plain_data = plain.to_bytes()
    member = next(offset for offset, kind, _, _ in headers(plain_data) if kind == 0x74)
    return bytes(data) + plain_data[member:]


def test_encrypted_archive_comment_retains_password_with_plain_members(tmp_path):
    source = rars.RarFile.from_bytes(encrypted_comment_source(), password="password")
    assert source.comment == b"secret archive comment"
    data = rars.RarBuilder.from_archive(source).to_bytes()
    output = rars.RarFile.from_bytes(data, password="password")
    assert output.comment == source.comment
    assert not output.getinfo("plain").is_encrypted
    assert output.read("plain") == b"public"
    assert next(flags for _, kind, flags, _ in headers(data) if kind == 0x7a) & 0x404 == 0x404
    with pytest.raises(rars.PasswordRequired):
        rars.RarFile.from_bytes(data).comment
    check_unrar(tmp_path, data)
    if shutil.which("unrar"):
        result = subprocess.run(["unrar", "l", "-ppassword", str(tmp_path / "rewritten.rar")], capture_output=True, check=True)
        assert b"secret archive comment" in result.stdout


@pytest.mark.parametrize("password", [None, "wrong"])
def test_encrypted_comment_failure_leaves_destination_intact(tmp_path, password):
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep")
    with pytest.raises((rars.PasswordRequired, rars.BadPassword, rars.BadRarFile)):
        source = rars.RarFile.from_bytes(encrypted_comment_source(), password=password)
        rars.RarBuilder.from_archive(source).write(destination)
    assert destination.read_bytes() == b"keep"


def test_embedded_file_comments_with_encrypted_headers_fail_before_writing(tmp_path):
    builder = rars.RarBuilder(format="rar40", password="password", encrypt_headers=True)
    builder.add_bytes(b"data", "file")
    builder.set_file_comment("file", b"comment")
    path = tmp_path / "existing.rar"
    path.write_bytes(b"keep")
    with pytest.raises((ValueError, rars.UnsupportedRarFeature), match="embedded legacy file comments"):
        builder.write(path)
    assert path.read_bytes() == b"keep"
