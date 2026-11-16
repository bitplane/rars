import io
import os
import pathlib

import pytest
import rars


def archive_bytes():
    builder = rars.RarBuilder()
    builder.add_bytes(b"payload", "file")
    return builder.to_bytes()


STUB = b"MZ" + b"\x90" * 70_000


class Unseekable(io.RawIOBase):
    def __init__(self, data):
        self.inner = io.BytesIO(data)

    def readable(self):
        return True

    def seekable(self):
        return False

    def readinto(self, buffer):
        return self.inner.readinto(buffer)


def test_plain_archive_is_rar_both_ways(tmp_path):
    data = archive_bytes()
    path = tmp_path / "plain.rar"
    path.write_bytes(data)
    for source in (data, path, str(path), io.BytesIO(data)):
        assert rars.is_rarfile(source)
        assert rars.is_rarfile_sfx(source)


def test_sfx_archive_is_only_found_by_the_sfx_check(tmp_path):
    data = STUB + archive_bytes()
    path = tmp_path / "setup.exe"
    path.write_bytes(data)
    assert not rars.is_rarfile(path)
    assert rars.is_rarfile_sfx(path)
    assert rars.RarFile(path).read("file") == b"payload"


def test_neither_check_reads_headers():
    assert rars.is_rarfile(b"Rar!\x1a\x07\x01\x00")
    assert rars.is_rarfile_sfx(b"MZ Rar!\x1a\x07\x01\x00")


def test_sfx_check_stops_at_the_scan_limit():
    assert not rars.is_rarfile_sfx(bytes(8 * 1024 * 1024 + 1) + archive_bytes())


def test_other_data_is_not_rar():
    assert not rars.is_rarfile(b"")
    assert not rars.is_rarfile(b"PK\x03\x04")
    assert not rars.is_rarfile_sfx(b"ordinary bytes" * 1000)


def test_seekable_file_object_is_put_back():
    data = b"xx" + STUB + archive_bytes()
    file = io.BytesIO(data)
    file.seek(2)
    assert not rars.is_rarfile(file)
    assert file.tell() == 2
    assert rars.is_rarfile_sfx(file)
    assert file.tell() == 2


def test_unseekable_stream_is_not_rar_as_with_zipfile():
    for check in (rars.is_rarfile, rars.is_rarfile_sfx):
        stream = Unseekable(archive_bytes())
        assert not check(stream)
        assert stream.inner.tell() == 0


def test_nul_in_path_raises_as_with_zipfile():
    for check in (rars.is_rarfile, rars.is_rarfile_sfx):
        for path in ("a\0b.rar", pathlib.PurePosixPath("a\0b.rar")):
            with pytest.raises(ValueError):
                check(path)


def test_unreadable_path_is_not_rar(tmp_path):
    for check in (rars.is_rarfile, rars.is_rarfile_sfx):
        assert not check(tmp_path / "missing.rar")
        assert not check(str(tmp_path / "missing.rar"))
        assert not check(tmp_path)


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs file permissions")
def test_unreadable_permissions_are_not_rar(tmp_path):
    path = tmp_path / "locked.rar"
    path.write_bytes(archive_bytes())
    path.chmod(0)
    for check in (rars.is_rarfile, rars.is_rarfile_sfx):
        assert not check(path)


class FailingRead(io.RawIOBase):
    def __init__(self, error):
        self.error = error

    def readable(self):
        return True

    def tell(self):
        return 0

    def seek(self, offset, whence=0):
        return 0

    def readinto(self, buffer):
        raise self.error


class FailingSeek(io.BytesIO):
    def seek(self, offset, whence=0):
        raise OSError("device gone")


def test_file_object_os_error_is_not_rar():
    for check in (rars.is_rarfile, rars.is_rarfile_sfx):
        assert not check(FailingRead(OSError("device gone")))
        assert not check(FailingSeek(archive_bytes()))


def test_other_errors_still_raise():
    for check in (rars.is_rarfile, rars.is_rarfile_sfx):
        with pytest.raises(ValueError):
            check(FailingRead(ValueError("closed")))
        with pytest.raises(TypeError):
            check(42)


def test_text_mode_file_is_refused(tmp_path):
    path = tmp_path / "a.txt"
    path.write_text("hello")
    with open(path) as file, pytest.raises(TypeError):
        rars.is_rarfile(file)
