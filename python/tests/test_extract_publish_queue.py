import os

import pytest

import rars

THREADS = [2, 8]
FAMILIES = ["rar29", "rar50"]
POLICIES = [False, True, "rename"]


def files(count):
    return [(f"d{index % 3}/f{index}.txt", f"member {index} ".encode() * (index + 1)) for index in range(count)]


def archive(tmp_path, version, members, split, solid=False, links=()):
    builder = rars.RarBuilder(version, level=0 if split else 3, solid=solid, volume_size=4096 if split else None)
    for name, data in members:
        builder.add_bytes(data, name)
    for name, target in links:
        builder.add_unix_symlink(name, target)
    directory = tmp_path / "archive"
    directory.mkdir()
    return builder.write(directory / ("set.part01.rar" if split else "one.rar"))[0]


def tree(directory):
    if not directory.exists():
        return {}
    return {
        path.relative_to(directory).as_posix(): (
            "link -> " + str(path.readlink())
            if path.is_symlink()
            else "dir"
            if path.is_dir()
            else path.read_bytes()
        )
        for path in directory.rglob("*")
    }


def run(path, out, threads, prepare, **kwargs):
    prepare(out)
    try:
        written = rars.RarFile(path).extractall(out, options=rars.ReadOptions(threads=threads), **kwargs)
        outcome = sorted(p.relative_to(out).as_posix() for p in written)
    except Exception as error:  # noqa: BLE001 - compared across thread counts
        outcome = (type(error).__name__, str(error).replace(str(out), "<out>"))
    return outcome, tree(out)


def alike(tmp_path, path, prepare=lambda out: None, **kwargs):
    one = run(path, tmp_path / "out-1", 1, prepare, **kwargs)
    for threads in THREADS:
        assert run(path, tmp_path / f"out-{threads}", threads, prepare, **kwargs) == one, f"threads={threads}"
    return one


def existing(name, data=b"already here"):
    def prepare(out):
        (out / name).parent.mkdir(parents=True, exist_ok=True)
        (out / name).write_bytes(data)
    return prepare


@pytest.mark.parametrize("version, solid", [("rar29", False), ("rar50", False), ("rar50", True)])
@pytest.mark.parametrize("split", [False, True])
def test_a_refused_output_ends_the_run_where_one_thread_does(tmp_path, version, split, solid):
    members = files(30)
    path = archive(tmp_path, version, members, split, solid)
    outcome, left = alike(tmp_path, path, existing(members[17][0]))
    assert outcome[0] == "FileExistsError"
    assert left[members[17][0]] == b"already here"
    assert members[16][0] in left and members[18][0] not in left


@pytest.mark.parametrize("version", FAMILIES)
@pytest.mark.parametrize("split", [False, True])
@pytest.mark.parametrize("overwrite", POLICIES)
def test_every_member_publishes_over_what_was_there_as_at_one_thread(tmp_path, version, split, overwrite):
    members = files(30)
    path = archive(tmp_path, version, members, split)
    outcome, _left = alike(tmp_path, path, existing(members[5][0]), overwrite=overwrite)
    assert (outcome[0] == "FileExistsError") == (overwrite is False)


@pytest.mark.parametrize("version", FAMILIES)
@pytest.mark.parametrize("split", [False, True])
@pytest.mark.parametrize("overwrite", POLICIES)
def test_a_file_landing_on_an_earlier_members_directory_matches_one_thread(tmp_path, version, split, overwrite):
    members = [*files(10), ("a/b/c", b"inner"), ("a/b", b"outer"), ("z.txt", b"after")]
    path = archive(tmp_path, version, members, split)
    _outcome, left = alike(tmp_path, path, overwrite=overwrite)
    assert left["a/b/c"] == b"inner"
    assert "z.txt" not in left or overwrite == "rename"


@pytest.mark.parametrize("version", FAMILIES)
@pytest.mark.parametrize("overwrite", POLICIES)
def test_members_flattened_onto_one_name_match_one_thread(tmp_path, version, overwrite):
    members = [("a/x.txt", b"first"), *files(10), ("b/x.txt", b"second"), ("c/y.txt", b"tail")]
    path = archive(tmp_path, version, members, False)
    alike(tmp_path, path, overwrite=overwrite, flatten=True)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
@pytest.mark.parametrize("version", FAMILIES)
@pytest.mark.parametrize("overwrite", POLICIES)
def test_links_find_every_earlier_member_in_place(tmp_path, version, overwrite):
    members = files(20)
    links = [("d0/link", "f0.txt"), ("d1/up", "../d2/f2.txt"), ("dangling", "nowhere")]
    path = archive(tmp_path, version, members, False, links=links)
    _outcome, left = alike(tmp_path, path, overwrite=overwrite)
    assert left["d0/link"] == "link -> f0.txt"
    assert (tmp_path / "out-8" / "d1/up").read_bytes() == dict(members)["d2/f2.txt"]
