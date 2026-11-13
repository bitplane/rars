import os
from pathlib import Path

import pytest
import rars
from test_extract_guards import _rewrite_name, hostile_archive, tree
from test_extract_links import FILE_COPY, HARD_LINK, redirect

FORMATS = ["rar14", "rar29", "rar50"]
FIXTURES = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures/rar50"
symlinks = pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")


def archive(files, format="rar50", **kwargs):
    builder = rars.RarBuilder(format=format, **kwargs)
    builder.add_directory("a")
    for name, contents in files:
        builder.add_bytes(contents.encode(), name)
    return rars.RarFile.from_bytes(builder.to_bytes())


def listing(out):
    return sorted(
        (path.name, path.read_text())
        for path in out.iterdir()
        if not path.name.startswith(".rars-extract")
    )


COLLIDING = [("a/readme.txt", "first"), ("b/readme.txt", "second")]


@pytest.mark.parametrize("format", FORMATS)
def test_flatten_writes_every_file_into_the_output_directory(tmp_path, format):
    rar = archive([("a/one.txt", "1"), ("a/b/two.txt", "2"), ("top.txt", "3")], format)
    written = rar.extractall(tmp_path / "out", flatten=True)
    assert listing(tmp_path / "out") == [("one.txt", "1"), ("top.txt", "3"), ("two.txt", "2")]
    assert sorted(written) == sorted((tmp_path / "out").iterdir())
    rar.extractall(tmp_path / "nested")
    assert (tmp_path / "nested/a/b/two.txt").read_text() == "2"


@pytest.mark.parametrize("format", FORMATS)
def test_flat_collisions_follow_the_overwrite_setting(tmp_path, format):
    rar = archive(COLLIDING, format)
    with pytest.raises(OSError, match="a/readme.txt.*b/readme.txt"):
        rar.extractall(tmp_path / "never", flatten=True)
    assert listing(tmp_path / "never") == [("readme.txt", "first")]

    written = rar.extractall(tmp_path / "always", flatten=True, overwrite=True)
    assert listing(tmp_path / "always") == [("readme.txt", "second")]
    assert written == [tmp_path / "always/readme.txt"]

    written = rar.extractall(tmp_path / "rename", flatten=True, overwrite="rename")
    assert listing(tmp_path / "rename") == [("readme(1).txt", "second"), ("readme.txt", "first")]
    assert written == [tmp_path / "rename/readme.txt", tmp_path / "rename/readme(1).txt"]


@pytest.mark.parametrize("format", FORMATS)
@pytest.mark.parametrize("in_place", [False, True])
def test_rename_numbers_past_a_file_already_on_disk(tmp_path, format, in_place):
    out = tmp_path / "out"
    out.mkdir()
    (out / "readme.txt").write_text("old")
    archive(COLLIDING, format).extractall(
        out, flatten=True, overwrite="rename", in_place=in_place
    )
    assert listing(out) == [
        ("readme(1).txt", "first"),
        ("readme(2).txt", "second"),
        ("readme.txt", "old"),
    ]


@pytest.mark.parametrize("format", FORMATS)
def test_rename_without_flatten_renames_only_against_files_on_disk(tmp_path, format):
    (tmp_path / "a").mkdir()
    (tmp_path / "a/readme.txt").write_text("old")
    written = archive(COLLIDING, format).extractall(tmp_path, overwrite="rename")
    assert tmp_path / "a/readme(1).txt" in written
    assert listing(tmp_path / "a") == [("readme(1).txt", "first"), ("readme.txt", "old")]
    assert listing(tmp_path / "b") == [("readme.txt", "second")]


def test_extract_flattens_and_renames_one_member(tmp_path):
    rar = archive(COLLIDING)
    (tmp_path / "readme.txt").write_text("old")
    assert rar.extract("b/readme.txt", tmp_path, overwrite="rename", flatten=True) == (
        tmp_path / "readme(1).txt"
    )
    assert (tmp_path / "readme(1).txt").read_text() == "second"
    assert rar.extractall(tmp_path / "some", members=["b/readme.txt"], flatten=True) == [
        tmp_path / "some/readme.txt"
    ]


@pytest.mark.parametrize("value, error", [("replace", ValueError), (1, TypeError), (None, TypeError)])
def test_an_invalid_overwrite_value_raises(tmp_path, value, error):
    rar = archive(COLLIDING)
    with pytest.raises(error):
        rar.extractall(tmp_path, overwrite=value)
    with pytest.raises(error):
        rar.extract("a/readme.txt", tmp_path, overwrite=value)
    assert not (tmp_path / "a").exists()


@pytest.mark.parametrize(
    "name", [b"../evil.txt", b"a/../../evil.txt", b"..\\evil.txt", b"/etc/evil", b"C:\\evil", b".."]
)
@pytest.mark.parametrize("overwrite", [False, True, "rename"])
def test_flatten_cannot_escape_the_output_directory(tmp_path, name, overwrite):
    out = tmp_path / "out"
    out.mkdir()
    rar = rars.RarFile.from_bytes(hostile_archive(name))
    with pytest.raises(rars.UnsafeArchivePath):
        rar.extractall(out, flatten=True, overwrite=overwrite)
    assert tree(tmp_path) == {Path("out")}


@symlinks
@pytest.mark.parametrize("in_place", [False, True])
def test_flat_links_resolve_to_flattened_targets_and_skip_any_with_a_path(tmp_path, in_place):
    rar = rars.RarFile(FIXTURES / "flat_links.rar")
    with pytest.warns(rars.UnsafeLinkWarning) as caught:
        written = rar.extractall(tmp_path, flatten=True, in_place=in_place)
    messages = " ".join(str(warning.message) for warning in caught)
    assert "a/sym.txt" in messages and "a/abs.txt" in messages
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "copy.txt", "hard.txt", "local.txt", "near.txt", "target.txt"
    ]
    assert sorted(p.name for p in written) == sorted(p.name for p in tmp_path.iterdir())
    assert os.readlink(tmp_path / "near.txt") == "local.txt"
    assert os.stat(tmp_path / "hard.txt").st_nlink == 2
    assert os.path.samefile(tmp_path / "hard.txt", tmp_path / "target.txt")
    assert (tmp_path / "copy.txt").read_text() == "target\n"
    assert not os.path.samefile(tmp_path / "copy.txt", tmp_path / "target.txt")


@symlinks
def test_flat_links_take_the_renamed_target_name(tmp_path):
    (tmp_path / "target.txt").write_text("old")
    with pytest.warns(rars.UnsafeLinkWarning):
        rars.RarFile(FIXTURES / "flat_links.rar").extractall(
            tmp_path, flatten=True, overwrite="rename"
        )
    assert os.path.samefile(tmp_path / "hard.txt", tmp_path / "target(1).txt")
    assert (tmp_path / "target.txt").read_text() == "old"


@symlinks
@pytest.mark.parametrize("kind", [HARD_LINK, FILE_COPY])
def test_flat_redirections_built_by_rars_resolve_too(tmp_path, kind):
    builder = rars.RarBuilder(format="rar50", store=True)
    builder.add_bytes(b"target", "c/target.txt")
    builder.add_unix_symlink("b/link.txt", "c/target.txt")
    data = redirect(builder.to_bytes(), kind)
    rars.RarFile.from_bytes(data).extractall(tmp_path, flatten=True)
    assert (tmp_path / "link.txt").read_bytes() == b"target"
    assert os.path.samefile(tmp_path / "link.txt", tmp_path / "target.txt") == (kind == HARD_LINK)


@symlinks
@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_flat_legacy_symlinks_keep_only_bare_targets(tmp_path, format):
    builder = rars.RarBuilder(format=format, store=True)
    builder.add_bytes(b"local", "a/local.txt")
    builder.add_unix_symlink("a/near.txt", "local.txt")
    builder.add_unix_symlink("a/up.txt", "../x/local.txt")
    with pytest.warns(rars.UnsafeLinkWarning, match="a/up.txt"):
        rars.RarFile.from_bytes(builder.to_bytes()).extractall(tmp_path, flatten=True)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["local.txt", "near.txt"]
    assert os.readlink(tmp_path / "near.txt") == "local.txt"


@pytest.mark.parametrize("given", [False, True])
def test_volume_sets_flatten_the_same_way(tmp_path, given):
    builder = rars.RarBuilder(format="rar50", store=True, volume_size=4096)
    builder.add_bytes(b"\1" * 3000, "a/one.bin")
    builder.add_bytes(b"\2" * 3000, "b/c/two.bin")
    (tmp_path / "made").mkdir()
    paths = builder.write_volumes(tmp_path / "made" / "set.part01.rar")
    assert len(paths) > 1
    with rars.RarFile(paths[0]) as rar:
        volumes = iter(paths[1:]) if given else None
        written = rar.extractall(tmp_path / "out", flatten=True, volumes=volumes)
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["one.bin", "two.bin"]
    assert sorted(p.name for p in written) == ["one.bin", "two.bin"]


@pytest.mark.parametrize("format", FORMATS)
def test_member_times_are_restored_on_flattened_and_renamed_files(tmp_path, format):
    # Legacy formats take DOS-packed times.
    times = [1_600_000_000, 1_700_000_000] if format == "rar50" else [0x5A21_6000, 0x5E21_6000]
    builder = rars.RarBuilder(format=format)
    builder.add_bytes(b"x", "a/readme.txt", mtime=times[0])
    builder.add_bytes(b"x", "b/readme.txt", mtime=times[1])
    rar = rars.RarFile.from_bytes(builder.to_bytes())
    rar.extractall(tmp_path / "flat", flatten=True, overwrite="rename")
    rar.extractall(tmp_path / "nested")
    mtime = lambda path: os.stat(tmp_path / path).st_mtime_ns
    assert mtime("nested/a/readme.txt") != mtime("nested/b/readme.txt")
    for flat, stored in [("readme.txt", "a/readme.txt"), ("readme(1).txt", "b/readme.txt")]:
        assert mtime(f"flat/{flat}") == mtime(f"nested/{stored}")


def test_rename_without_flatten_refuses_a_repeated_stored_path_as_the_cli_does(tmp_path):
    builder = rars.RarBuilder(format="rar50", store=True)
    builder.add_bytes(b"first", "a/readme.txt")
    builder.add_bytes(b"second", "pppppppppppp")
    data = _rewrite_name(builder.to_bytes(), b"pppppppppppp", b"a/readme.txt")
    with pytest.raises(rars.Error, match="same output path"):
        rars.RarFile.from_bytes(data).extractall(tmp_path, overwrite="rename")
    assert listing(tmp_path / "a") == [("readme.txt", "first")]
