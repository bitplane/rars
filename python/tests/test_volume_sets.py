from pathlib import Path
import random
import shutil
import threading
import time

import pytest
import rars


PAYLOAD = random.Random(22).randbytes(40_000)


def write_set(tmp_path, compressed, format="rar50"):
    builder = rars.RarBuilder(format=format, store=not compressed, volume_size=4096)
    builder.add_bytes(PAYLOAD, "large.bin")
    if format == "rar50":
        builder.add_bytes(b"small", "small.txt")
    (tmp_path / "made").mkdir()
    paths = builder.write_volumes(tmp_path / "made" / "set.part01.rar")
    assert len(paths) > 3
    return paths


@pytest.mark.parametrize("compressed", [False, True])
def test_extracts_while_a_thread_delivers_volumes(tmp_path, compressed):
    paths = write_set(tmp_path, compressed)
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    arrived = [threading.Event() for _ in paths]

    def deliver():
        for index, path in enumerate(paths):
            time.sleep(0.02)
            # An obfuscated name: no naming rule could find it.
            shutil.copy(path, incoming / f"{index:03}.bin")
            arrived[index].set()

    def volumes():
        for index in range(1, len(paths)):
            assert arrived[index].wait(10)
            yield incoming / f"{index:03}.bin"

    feeder = threading.Thread(target=deliver)
    feeder.start()
    try:
        assert arrived[0].wait(10)
        with rars.RarFile(incoming / "000.bin") as archive:
            written = archive.extractall(tmp_path / "out", volumes=volumes())
    finally:
        feeder.join()

    assert (tmp_path / "out" / "large.bin").read_bytes() == PAYLOAD
    assert (tmp_path / "out" / "small.txt").read_bytes() == b"small"
    assert sorted(Path(p).name for p in written) == ["large.bin", "small.txt"]


@pytest.mark.parametrize("format", ["rar50", "rar29"])
def test_volumes_are_not_pulled_past_a_marked_last_volume(tmp_path, format):
    paths = write_set(tmp_path, compressed=True, format=format)

    def volumes():
        yield from paths[1:]
        raise AssertionError("pulled past the last volume")

    with rars.RarFile(paths[0]) as archive:
        archive.testrar(volumes=volumes())
        archive.extractall(tmp_path / "out", volumes=volumes())
    assert (tmp_path / "out" / "large.bin").read_bytes() == PAYLOAD


def test_volumes_may_be_bytes(tmp_path):
    paths = write_set(tmp_path, compressed=False)
    with rars.RarFile(paths[0]) as archive:
        archive.extractall(tmp_path / "out", volumes=(path.read_bytes() for path in paths[1:]))
    assert (tmp_path / "out" / "large.bin").read_bytes() == PAYLOAD


def test_an_exception_from_volumes_aborts_and_is_raised(tmp_path):
    paths = write_set(tmp_path, compressed=False)

    class Gone(Exception):
        pass

    def volumes():
        yield paths[1]
        raise Gone("volume 3 never arrived")

    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(Gone, match="never arrived"):
            archive.extractall(tmp_path / "out", volumes=volumes())


def test_volumes_ending_before_the_last_aborts(tmp_path):
    paths = write_set(tmp_path, compressed=False)
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.Error, match="volume is missing"):
            archive.extractall(tmp_path / "out", volumes=paths[1:2])


def test_volumes_cannot_be_combined_with_members(tmp_path):
    paths = write_set(tmp_path, compressed=False)
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(ValueError):
            archive.extractall(tmp_path / "out", members=["small.txt"], volumes=paths[1:])
