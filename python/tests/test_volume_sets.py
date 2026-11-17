from pathlib import Path
import random
import shutil
import threading
import time

import pytest
import rars


PAYLOAD = random.Random(22).randbytes(40_000)


def write_set(tmp_path, compressed, format="rar50"):
    builder = rars.RarBuilder(version=format, level=3 if compressed else 0, volume_size=4096)
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


FIXTURES = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures"


def write_named_set(tmp_path, format):
    builder = rars.RarBuilder(version=format, level=0, volume_size=4096)
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


def write_mixed_set(tmp_path, format="rar50", compressed=False, solid=False):
    builder = rars.RarBuilder(
        version=format, level=3 if compressed else 0, solid=solid, volume_size=4096
    )
    if format == "rar50":
        builder.add_bytes(b"head", "head.txt")
    builder.add_bytes(PAYLOAD, "large.bin")
    if format == "rar50":
        builder.add_bytes(random.Random(23).randbytes(12_000), "after.bin")
    first = "set.part01.rar" if format == "rar50" else "set.rar"
    (tmp_path / "made").mkdir()
    paths = builder.write_volumes(tmp_path / "made" / first)
    assert len(paths) > 3
    return paths


@pytest.mark.parametrize("format", ["rar15", "rar20", "rar29", "rar50"])
@pytest.mark.parametrize("compressed", [False, True])
def test_reads_follow_a_split_member_into_later_volumes(tmp_path, format, compressed):
    paths = write_mixed_set(tmp_path, format, compressed)
    with rars.RarFile(paths[0]) as archive:
        assert archive.read("large.bin") == PAYLOAD
        assert archive.open("large.bin").read() == PAYLOAD
        assert archive.read_many(["large.bin", "large.bin"]) == [PAYLOAD, PAYLOAD]


def test_read_many_mixes_split_and_whole_members(tmp_path):
    paths = write_mixed_set(tmp_path)
    with rars.RarFile(paths[0]) as archive:
        assert archive.read_many(["large.bin", "head.txt", "large.bin"]) == [
            PAYLOAD,
            b"head",
            PAYLOAD,
        ]


@pytest.mark.parametrize(
    "first",
    [
        "rar15_40/rar300/multivol_oldnaming_rar300.rar",
        "rar15_40/rar300/multivol_newnaming_rar300.part01.rar",
        "rar50/multivol.part1.rar",
        "rar50/solid_multivol.part01.rar",
    ],
)
def test_reads_follow_split_members_of_winrar_sets(tmp_path, first):
    with rars.RarFile(FIXTURES / first) as archive:
        archive.extractall(tmp_path / "all")
        split = [info for info in archive.infolist() if info.is_split_after]
        assert split
        for info in split:
            expected = (tmp_path / "all" / info.filename).read_bytes()
            assert archive.read(info) == expected
            assert archive.open(info).read() == expected
            assert archive.read_many([info]) == [expected]
            written = archive.extract(info, tmp_path / "one")
            assert Path(written).read_bytes() == expected


@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_extract_follows_a_split_member_into_later_volumes(tmp_path, format):
    paths = write_mixed_set(tmp_path, format)
    with rars.RarFile(paths[0]) as archive:
        written = archive.extract("large.bin", tmp_path / "out")
    assert Path(written) == tmp_path / "out" / "large.bin"
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["large.bin"]
    assert (tmp_path / "out" / "large.bin").read_bytes() == PAYLOAD


@pytest.mark.parametrize("given", [False, True])
def test_extractall_members_takes_just_those_from_a_set(tmp_path, given):
    paths = write_mixed_set(tmp_path)
    volumes = {"volumes": paths[1:]} if given else {}
    with rars.RarFile(paths[0]) as archive:
        written = archive.extractall(
            tmp_path / "out", members=["head.txt", "large.bin"], **volumes
        )
    assert sorted(Path(p).name for p in written) == ["head.txt", "large.bin"]
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["head.txt", "large.bin"]
    assert (tmp_path / "out" / "large.bin").read_bytes() == PAYLOAD
    assert (tmp_path / "out" / "head.txt").read_bytes() == b"head"


def volume_ending(paths, name):
    for index, path in enumerate(paths):
        with rars.RarFile(path) as volume:
            info = volume.infolist()[0]
            if info.filename == name and info.is_split_before and not info.is_split_after:
                return index
    raise AssertionError(f"{name} never ends")


@pytest.mark.parametrize("compressed, solid", [(False, False), (True, False), (True, True)])
def test_volumes_are_not_pulled_past_the_last_selected_member(tmp_path, compressed, solid):
    paths = write_mixed_set(tmp_path, compressed=compressed, solid=solid)
    end = volume_ending(paths, "large.bin")
    assert end < len(paths) - 1

    def volumes():
        yield from paths[1 : end + 1]
        raise AssertionError("pulled past the last selected member")

    with rars.RarFile(paths[0]) as archive:
        assert archive.read("large.bin", volumes=volumes()) == PAYLOAD
        assert archive.read_many(["head.txt", "large.bin"], volumes=volumes())[1] == PAYLOAD
        archive.extract("large.bin", tmp_path / "one", volumes=volumes())
        archive.extractall(tmp_path / "some", members=["large.bin"], volumes=volumes())


def test_members_in_the_first_volume_never_pull_volumes(tmp_path):
    paths = write_mixed_set(tmp_path)

    def volumes():
        raise AssertionError("pulled a volume")
        yield

    with rars.RarFile(paths[0]) as archive:
        assert archive.read("head.txt", volumes=volumes()) == b"head"
        archive.extractall(tmp_path / "out", members=["head.txt"], volumes=volumes())
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["head.txt"]


@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_a_missing_middle_volume_is_named_when_reading(tmp_path, format):
    paths = write_mixed_set(tmp_path, format)
    paths[2].unlink()
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.Error, match=f"volume is missing.*{paths[2].name}"):
            archive.read("large.bin")
        with pytest.raises(rars.Error, match=f"volume is missing.*{paths[2].name}"):
            archive.extractall(tmp_path / "out", members=["large.bin"])


@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_reading_a_split_member_opened_from_bytes_points_at_volumes(tmp_path, format):
    paths = write_mixed_set(tmp_path, format)
    with rars.RarFile(paths[0].read_bytes()) as archive:
        with pytest.raises(rars.Error, match="volumes="):
            archive.read("large.bin")
        with pytest.raises(rars.Error, match="volumes="):
            archive.extract("large.bin", tmp_path / "out")
        assert archive.read("large.bin", volumes=[p.read_bytes() for p in paths[1:]]) == PAYLOAD


def test_a_later_member_over_a_limit_does_not_fail_a_finished_read(tmp_path):
    paths = write_mixed_set(tmp_path)
    options = rars.ReadOptions(max_total_output_bytes=45_000)
    with rars.RarFile(paths[0]) as archive:
        assert archive.read("large.bin", options=options) == PAYLOAD


@pytest.mark.parametrize("format", ["rar15", "rar20"])
def test_a_set_without_end_blocks_is_not_pulled_past_the_selected_member(tmp_path, format):
    paths = write_mixed_set(tmp_path, format)

    def volumes():
        yield from paths[1:]
        raise AssertionError("pulled past the last selected member")

    with rars.RarFile(paths[0]) as archive:
        assert archive.read("large.bin", volumes=volumes()) == PAYLOAD
