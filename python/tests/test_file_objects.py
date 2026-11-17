import io
from contextlib import ExitStack
from pathlib import Path

import pytest
import rars


def archive_bytes(format="rar50"):
    builder = rars.RarBuilder(format=format)
    builder.add_bytes(b"payload" * 1000, "file")
    builder.add_bytes(b"other", "dir/other")
    return builder.to_bytes()


@pytest.mark.parametrize("format", ["rar14", "rar29", "rar50"])
def test_rarfile_reads_bytesio_and_open_files_like_bytes(tmp_path, format):
    data = archive_bytes(format)
    path = tmp_path / "archive.rar"
    path.write_bytes(data)
    expected = rars.RarFile(data)
    with path.open("rb") as file:
        for source in (io.BytesIO(data), file):
            archive = rars.RarFile(source)
            assert archive.namelist() == expected.namelist()
            assert archive.read("file") == b"payload" * 1000
            assert archive.read_many(["dir/other", "file"]) == [b"other", b"payload" * 1000]
            archive.testrar()
            archive.extractall(tmp_path / f"out-{id(source)}")
            assert (tmp_path / f"out-{id(source)}/dir/other").read_bytes() == b"other"


class Stream(io.RawIOBase):
    def __init__(self, data):
        self.inner = io.BytesIO(data)

    def readable(self):
        return True

    def readinto(self, buffer):
        return self.inner.readinto(buffer)


def volume_set(tmp_path, format="rar50"):
    builder = rars.RarBuilder(format=format, level=0, volume_size=4096)
    builder.add_bytes(bytes(range(256)) * 80, "large.bin")
    return [Path(path) for path in builder.write_volumes(tmp_path / "set.part01.rar")]


@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_volumes_take_file_objects(tmp_path, format):
    paths = volume_set(tmp_path, format)
    with ExitStack() as stack:
        opened = [stack.enter_context(path.open("rb")) for path in paths]
        later = [opened[1], io.BytesIO(paths[2].read_bytes()), *map(Stream, (p.read_bytes() for p in paths[3:]))]
        archive = rars.RarFile(opened[0], volumes=later)
        assert archive.namelist() == ["large.bin"]
        assert archive.read("large.bin") == bytes(range(256)) * 80
        archive.extractall(tmp_path / "out")
    assert (tmp_path / "out/large.bin").read_bytes() == bytes(range(256)) * 80

    with paths[0].open("rb") as first:
        archive = rars.RarFile(first)
        rest = [Stream(path.read_bytes()) for path in paths[1:]]
        assert archive.read("large.bin", volumes=rest) == bytes(range(256)) * 80


def test_unseekable_source_is_read_whole():
    archive = rars.RarFile(Stream(archive_bytes()))
    assert archive.read("file") == b"payload" * 1000
    assert archive.read("dir/other") == b"other"


def test_text_mode_file_is_refused(tmp_path):
    path = tmp_path / "archive.rar"
    path.write_bytes(archive_bytes())
    with path.open("r", encoding="latin-1") as text:
        with pytest.raises(TypeError, match="text mode"):
            rars.RarFile(text)
        with pytest.raises(TypeError, match="text mode"):
            rars.RarFile(archive_bytes(), volumes=[text])
        with pytest.raises(TypeError, match="text mode"):
            rars.repair(text)


@pytest.mark.parametrize("value", [7, None, [b"Rar!"]])
def test_unsupported_value_names_the_accepted_kinds(value):
    message = "bytes-like.*str or os.PathLike.*binary file object"
    with pytest.raises(TypeError, match=message):
        rars.RarFile(value)
    with pytest.raises(TypeError, match=message):
        rars.repair(value)
    with pytest.raises(TypeError, match=message):
        rars.RarBuilder.from_archive(value)


def test_bytes_naming_a_file_say_to_pass_a_path(tmp_path):
    path = tmp_path / "archive.rar"
    path.write_bytes(archive_bytes())
    with pytest.raises(TypeError, match="pass it as str or os.PathLike"):
        rars.RarFile(bytes(path))
    with pytest.raises(TypeError, match="pass it as str or os.PathLike"):
        rars.repair(bytes(path))
    with pytest.raises(rars.NotRarFile):
        rars.RarFile(bytes(tmp_path / "missing.rar"))


def damaged_archive():
    builder = rars.RarBuilder(format="rar50", level=0, recovery_percent=10)
    builder.add_bytes(b"recoverable payload " * 1000, "file")
    data = bytearray(builder.to_bytes())
    data[len(data) // 3] ^= 0xFF
    return bytes(data)


def test_repair_takes_file_objects(tmp_path):
    data = damaged_archive()
    expected = rars.repair(data).data
    path = tmp_path / "damaged.rar"
    path.write_bytes(data)
    with path.open("rb") as file:
        file.read(10)
        assert rars.repair(file).data == expected
        assert rars.repair(io.BytesIO(data)).data == expected
        assert rars.repair(Stream(data), output=tmp_path / "repaired.rar").data is None
    assert (tmp_path / "repaired.rar").read_bytes() == expected
    assert rars.RarFile(expected).read("file") == b"recoverable payload " * 1000


def test_from_archive_takes_file_objects(tmp_path):
    data = archive_bytes()
    path = tmp_path / "archive.rar"
    path.write_bytes(data)
    with path.open("rb") as file:
        builder = rars.RarBuilder.from_archive(file)
        builder.add_bytes(b"new", "new")
        rewritten = rars.RarFile(builder.to_bytes())
    assert rewritten.namelist() == ["file", "dir/other", "new"]
    assert rewritten.read("file") == b"payload" * 1000
    streamed = rars.RarFile(rars.RarBuilder.from_archive(Stream(data)).to_bytes())
    assert streamed.read("dir/other") == b"other"


class Flaky(io.BytesIO):
    def __init__(self, data, fail_after):
        super().__init__(data)
        self.reads = 0
        self.fail_after = fail_after

    def read(self, size=-1):
        self.reads += 1
        if self.reads > self.fail_after:
            raise RuntimeError("source went away")
        return bytearray(super().read(size))


def test_reader_exceptions_reach_the_caller_unchanged():
    data = archive_bytes()
    archive = rars.RarFile(Flaky(data, fail_after=10**6))
    assert archive.read("file") == b"payload" * 1000
    archive = rars.RarFile(Flaky(data, fail_after=archive_reads(data)))
    with pytest.raises(RuntimeError, match="source went away"):
        archive.read("file")
    with pytest.raises(RuntimeError):
        rars.RarFile(Flaky(data, fail_after=1))


def archive_reads(data):
    source = Flaky(data, fail_after=10**6)
    rars.RarFile(source)
    return source.reads
