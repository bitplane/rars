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


def test_extractall_members_follow_the_volume_set(tmp_path):
    paths = write_set(tmp_path, compressed=False)
    with rars.RarFile(paths[0]) as archive:
        assert archive.read("large.bin", volumes=paths[1:]) == PAYLOAD
        assert archive.read(0, volumes=paths[1:]) == PAYLOAD
        assert archive.open("small.txt", volumes=paths[1:]).read() == b"small"
        written = archive.extractall(tmp_path / "out", members=["large.bin"], volumes=paths[1:])
        extracted = archive.extract("small.txt", tmp_path / "one", volumes=paths[1:])
    assert (tmp_path / "out" / "large.bin").read_bytes() == PAYLOAD
    assert not (tmp_path / "out" / "small.txt").exists()
    assert Path(extracted).read_bytes() == b"small"
    assert [Path(path).name for path in written] == ["large.bin"]


FIXTURES = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures"


def write_named_set(tmp_path, format):
    builder = rars.RarBuilder(format=format, store=True, volume_size=4096)
    builder.add_bytes(PAYLOAD, "large.bin")
    first = "set.part01.rar" if format == "rar50" else "set.rar"
    (tmp_path / "made").mkdir()
    paths = builder.write_volumes(tmp_path / "made" / first)
    assert len(paths) > 3
    return paths


@pytest.mark.parametrize("format", ["rar13", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50"])
def test_extractall_finds_later_volumes_by_name(tmp_path, format):
    paths = write_named_set(tmp_path, format)
    with rars.RarFile(paths[0]) as archive:
        archive.testrar()
        written = archive.extractall(tmp_path / "out")
    assert (tmp_path / "out" / "large.bin").read_bytes() == PAYLOAD
    assert [Path(p).name for p in written] == ["large.bin"]


@pytest.mark.parametrize(
    "first",
    [
        "rar15_40/rar300/multivol_oldnaming_rar300.rar",
        "rar15_40/rar300/multivol_newnaming_rar300.part01.rar",
        "rar15_40/rar154/random.rar",
        "rar13/MULTIVOL.RAR",
        "rar50/multivol.part1.rar",
        "rar50/solid_multivol.part01.rar",
    ],
)
def test_extractall_names_volumes_as_the_archive_does(tmp_path, first):
    first = FIXTURES / first
    later = sorted(
        p
        for p in first.parent.iterdir()
        if p != first and p.name.lower().startswith(first.name.lower().split(".")[0] + ".")
        and p.suffix.lower() != ".rev"
    )
    with rars.RarFile(first) as archive:
        expected = archive.extractall(tmp_path / "given", volumes=later)
        archive.testrar()
        found = archive.extractall(tmp_path / "found")
    assert len(expected) > 0
    for given, guessed in zip(expected, found):
        assert Path(given).read_bytes() == Path(guessed).read_bytes()
    assert len(found) == len(expected)


@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_a_missing_middle_volume_is_named(tmp_path, format):
    paths = write_named_set(tmp_path, format)
    paths[2].unlink()
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.Error, match=f"volume is missing.*{paths[2].name}"):
            archive.extractall(tmp_path / "out")
        with pytest.raises(rars.Error, match="volume is missing"):
            archive.testrar()


@pytest.mark.parametrize("format", ["rar13", "rar15", "rar20"])
def test_a_set_without_end_blocks_ends_at_its_last_volume(tmp_path, format):
    paths = write_named_set(tmp_path, format)
    with rars.RarFile(paths[0]) as archive:
        archive.testrar()
        archive.extractall(tmp_path / "out")
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["large.bin"]


def test_volumes_overrides_the_guessed_names(tmp_path):
    paths = write_named_set(tmp_path, "rar29")
    renamed = []
    for index, path in enumerate(paths[1:]):
        renamed.append(path.rename(path.with_name(f"{index:03}.bin")))
    # A decoy where the guess would look.
    shutil.copy(paths[0], paths[1])
    asked = []

    def volumes():
        for path in renamed:
            asked.append(path)
            yield path

    with rars.RarFile(paths[0]) as archive:
        archive.extractall(tmp_path / "out", volumes=volumes())
    assert asked == renamed
    assert (tmp_path / "out" / "large.bin").read_bytes() == PAYLOAD


@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_a_set_opened_from_bytes_points_at_volumes(tmp_path, format):
    paths = write_named_set(tmp_path, format)
    with rars.RarFile(paths[0].read_bytes()) as archive:
        with pytest.raises(rars.Error, match="volumes="):
            archive.extractall(tmp_path / "out")
        with pytest.raises(rars.Error, match="volumes="):
            archive.testrar()
