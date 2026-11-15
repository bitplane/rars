import io

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


def test_unseekable_stream_keeps_what_was_read():
    stream = Unseekable(STUB + archive_bytes())
    assert rars.is_rarfile_sfx(stream)
    assert stream.inner.tell() > 0


def test_missing_file_raises(tmp_path):
    for check in (rars.is_rarfile, rars.is_rarfile_sfx):
        with pytest.raises(FileNotFoundError):
            check(tmp_path / "missing.rar")


def test_text_mode_file_is_refused(tmp_path):
    path = tmp_path / "a.txt"
    path.write_text("hello")
    with open(path) as file, pytest.raises(TypeError):
        rars.is_rarfile(file)
