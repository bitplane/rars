import array
import mmap
from pathlib import Path

import pytest
import rars


def archive_bytes():
    builder = rars.RarBuilder()
    builder.add_bytes(b"payload", "file")
    return builder.to_bytes()


BYTES_LIKE = {
    "bytes": bytes,
    "bytearray": bytearray,
    "memoryview": memoryview,
    "array": lambda data: array.array("B", data),
    "strided memoryview": lambda data: memoryview(bytes(b for byte in data for b in (byte, 0)))[::2],
}


@pytest.mark.parametrize("kind", BYTES_LIKE)
def test_bytes_like_objects_are_archive_data(kind):
    data = BYTES_LIKE[kind](archive_bytes())
    assert rars.RarFile(data).read("file") == b"payload"
    assert rars.RarFile.from_bytes(data).read("file") == b"payload"


def test_mmap_is_archive_data(tmp_path):
    path = tmp_path / "archive.rar"
    path.write_bytes(archive_bytes())
    with path.open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as view:
        assert rars.RarFile(view).read("file") == b"payload"


@pytest.mark.parametrize("kind", [str, Path])
def test_str_and_pathlike_are_paths(tmp_path, kind):
    path = tmp_path / "archive.rar"
    path.write_bytes(archive_bytes())
    assert rars.RarFile(kind(path)).read("file") == b"payload"


@pytest.mark.parametrize("value", [list(b"Rar!"), (82, 97), 7])
def test_other_values_are_neither(value):
    with pytest.raises(TypeError):
        rars.RarFile(value)
    with pytest.raises(TypeError, match="bytes-like"):
        rars.RarFile.from_bytes(value)
    with pytest.raises(TypeError, match="bytes-like"):
        rars.RarBuilder().add_bytes(value, "file")


def test_volumes_take_bytes_like_objects_and_paths(tmp_path):
    builder = rars.RarBuilder(store=True, volume_size=4096)
    builder.add_bytes(bytes(range(256)) * 80, "large.bin")
    paths = builder.write_volumes(tmp_path / "set.part01.rar")
    rest = [Path(path) for path in paths[1:]]
    sources = [memoryview(rest[0].read_bytes()), *map(str, rest[1:])]
    with rars.RarFile(paths[0]) as archive:
        archive.extractall(tmp_path / "out", volumes=sources)
    assert (tmp_path / "out/large.bin").read_bytes() == bytes(range(256)) * 80
    with rars.RarFile(paths[0]) as archive, pytest.raises(TypeError):
        archive.extractall(tmp_path / "bad", volumes=[list(rest[0].read_bytes())])
