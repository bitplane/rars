"""Entries planted in the output directory while an extraction runs are never written through.

A volume set's `volumes` iterator is asked for the next volume while a member
spanning volumes is being written, which is the hook used to change the output
directory between members.
"""
import os

import pytest
import rars

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks and hard links")

POLICIES = [False, True, "rename"]
BIG = bytes(range(256)) * 80


def write_set(tmp_path, names):
    """A stored set whose member `big` spans volumes, between the members `names` splits it into."""
    before, after = names
    builder = rars.RarBuilder(level=0, volume_size=4096)
    for name in before:
        builder.add_bytes(name.encode(), name)
    builder.add_bytes(BIG, f"{before[0].rsplit('/', 1)[0]}/big")
    for name in after:
        builder.add_bytes(name.encode(), name)
    (tmp_path / "set").mkdir()
    return builder.write(tmp_path / "set" / "set.part01.rar")


def extract_planting(paths, out, plant, **kwargs):
    """Extracts the set, calling `plant` once, while the spanning member is being written."""
    def volumes():
        plant()
        yield from paths[1:]

    with rars.RarFile(paths[0]) as archive:
        return archive.extractall(out, volumes=volumes(), **kwargs)


def listing(path):
    return sorted(entry.name for entry in path.iterdir())


@pytest.mark.parametrize("in_place", [False, True])
@pytest.mark.parametrize("overwrite", POLICIES)
@pytest.mark.parametrize("planted", ["a", "a/b"])
def test_a_directory_swapped_for_a_symlink_mid_extraction_is_never_written_through(
        tmp_path, in_place, overwrite, planted):
    paths = write_set(tmp_path, (["a/b/one"], ["a/b/three", "a/b/c/four"]))
    out = tmp_path / "out"
    outside = tmp_path / "outside"
    outside.mkdir()
    moved = out / "moved"

    def swap():
        assert (out / "a/b/one").read_bytes() == b"a/b/one"
        os.rename(out / planted, moved)
        os.symlink(outside, out / planted, target_is_directory=True)

    try:
        extract_planting(paths, out, swap, overwrite=overwrite, in_place=in_place)
        finished = True
    except (OSError, rars.Error):
        finished = False

    assert listing(outside) == []
    # Members after the swap land in the directory the extraction opened, wherever it went.
    assert finished or not in_place
    if finished:
        landed = moved / "b" if planted == "a" else moved
        for name in ["one", "three", "c/four"]:
            assert (landed / name).read_bytes() == f"a/b/{name}".encode()
        assert (landed / "big").read_bytes() == BIG


@pytest.mark.parametrize("in_place", [False, True])
@pytest.mark.parametrize("overwrite", POLICIES)
@pytest.mark.parametrize("made_by_the_run", [False, True])
def test_a_symlink_planted_at_a_later_members_destination_is_refused(
        tmp_path, in_place, overwrite, made_by_the_run):
    paths = write_set(tmp_path, (["d/one"], ["d/two"]))
    out = tmp_path / "out"
    if not made_by_the_run:
        (out / "d").mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_bytes(b"victim\n")

    with pytest.raises(rars.UnsafeArchivePath) as raised:
        extract_planting(paths, out, lambda: os.symlink(victim, out / "d/two"),
                         overwrite=overwrite, in_place=in_place)

    assert str(raised.value).endswith("while extracting entry 'd/two': unsafe archive path crosses symlink")
    assert victim.read_bytes() == b"victim\n"
    assert os.readlink(out / "d/two") == str(victim)
    assert (out / "d/one").read_bytes() == b"d/one"
    assert (out / "d/big").read_bytes() == BIG
    assert listing(tmp_path) == ["out", "set", "victim"]


@pytest.mark.parametrize("in_place", [False, True])
@pytest.mark.parametrize("overwrite", POLICIES)
@pytest.mark.parametrize("made_by_the_run", [False, True])
def test_a_hard_link_planted_at_a_later_members_destination_is_never_written_through(
        tmp_path, in_place, overwrite, made_by_the_run):
    paths = write_set(tmp_path, (["d/one"], ["d/two"]))
    out = tmp_path / "out"
    if not made_by_the_run:
        (out / "d").mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_bytes(b"victim\n")

    def extract():
        return extract_planting(paths, out, lambda: os.link(victim, out / "d/two"),
                                overwrite=overwrite, in_place=in_place)

    if overwrite is False:
        with pytest.raises(FileExistsError, match="overwrite=True"):
            extract()
        assert os.stat(out / "d/two").st_ino == os.stat(victim).st_ino
    elif overwrite is True and in_place:
        with pytest.raises(OSError, match="refusing to write in place through a link"):
            extract()
        assert os.stat(out / "d/two").st_ino == os.stat(victim).st_ino
    elif overwrite is True:
        # Replaced by a new file, which leaves the one it linked to alone.
        assert out / "d/two" in extract()
        assert (out / "d/two").read_bytes() == b"d/two"
        assert os.stat(victim).st_nlink == 1
    else:
        assert out / "d/two(1)" in extract()
        assert (out / "d/two(1)").read_bytes() == b"d/two"
        assert os.stat(out / "d/two").st_ino == os.stat(victim).st_ino
    assert victim.read_bytes() == b"victim\n"
    assert (out / "d/big").read_bytes() == BIG
    assert listing(tmp_path) == ["out", "set", "victim"]


@pytest.mark.parametrize("in_place", [False, True])
def test_files_and_directories_keep_their_times_staged_or_in_place(tmp_path, in_place):
    builder = rars.RarBuilder(level=0)
    builder.add_directory("d", mtime=1_500_000_000)
    builder.add_bytes(b"one", "d/one", mtime=1_600_000_000)
    builder.add_bytes(b"two", "d/e/two", mtime=1_700_000_000)
    out = tmp_path / "out"
    rars.RarFile(builder.to_bytes()).extractall(out, in_place=in_place)

    mtime = lambda name: os.stat(out / name).st_mtime
    assert mtime("d") == 1_500_000_000
    assert mtime("d/one") == 1_600_000_000
    assert mtime("d/e/two") == 1_700_000_000
