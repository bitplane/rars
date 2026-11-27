"""A RAR 5 member that fails, or whose output fails, leaves the same files at any thread count."""

import random
import threading

import pytest
import rars


MEMBERS = {f"m{index}.bin": random.Random(42 + index).randbytes(40_000) for index in range(5)}
THREADS = [1, 2, 8]


def build(solid):
    builder = rars.RarBuilder(version="rar50", level=0, solid=solid)
    builder.add_directory("dir")
    for name, data in MEMBERS.items():
        builder.add_bytes(data, name)
    builder.add_unix_symlink("link", "m0.bin")
    return builder.to_bytes()


def flipped(archive, name):
    data = bytearray(archive)
    data[archive.index(MEMBERS[name]) + 1000] ^= 0xFF
    return bytes(data)


def tree(directory):
    return {
        str(path.relative_to(directory)): (
            "link -> " + str(path.readlink())
            if path.is_symlink()
            else "dir"
            if path.is_dir()
            else path.read_bytes()
        )
        for path in directory.rglob("*")
    }


@pytest.mark.parametrize("solid", [False, True])
@pytest.mark.parametrize("threads", THREADS)
def test_a_member_that_fails_verification_is_dropped_and_the_rest_extract(tmp_path, solid, threads):
    archive = rars.RarFile(flipped(build(solid), "m2.bin"))
    failed = []
    written = archive.extractall(
        tmp_path,
        options=rars.ReadOptions(threads=threads),
        on_member_error=failed.append,
    )
    assert [error.member for error in failed] == ["m2.bin"]
    assert isinstance(failed[0], rars.BadRarFile)
    kept = ["m0.bin", "m1.bin", "m3.bin", "m4.bin"]
    assert [path.name for path in written] == ["dir", *kept, "link"]
    assert tree(tmp_path) == {
        "dir": "dir",
        **{name: MEMBERS[name] for name in kept},
        "link": "link -> m0.bin",
    }


@pytest.mark.parametrize("solid", [False, True])
@pytest.mark.parametrize("threads", THREADS)
def test_a_member_whose_output_fails_stops_after_the_members_before_it(tmp_path, solid, threads):
    archive = rars.RarFile(build(solid))
    (tmp_path / "m2.bin").write_bytes(b"already here")
    failed = []
    with pytest.raises(FileExistsError, match="m2.bin already exists"):
        archive.extractall(
            tmp_path,
            options=rars.ReadOptions(threads=threads),
            on_member_error=failed.append,
        )
    assert failed == []
    assert tree(tmp_path) == {
        "dir": "dir",
        "m0.bin": MEMBERS["m0.bin"],
        "m1.bin": MEMBERS["m1.bin"],
        "m2.bin": b"already here",
    }



@pytest.mark.parametrize("solid", [False, True])
def test_progress_is_reported_on_the_calling_thread(tmp_path, solid):
    archive = rars.RarFile(build(solid))
    threads = set()
    events = []

    def progress(event):
        threads.add(threading.get_ident())
        events.append(event)

    archive.extractall(tmp_path, options=rars.ReadOptions(threads=8), progress=progress)
    assert threads == {threading.get_ident()}
    assert events[-1].completed == sum(map(len, MEMBERS.values()))
