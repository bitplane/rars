import os
import stat
import warnings

import pytest
import rars
from test_extract_links import FILE_COPY, HARD_LINK, redirect

pytestmark = pytest.mark.skipif(os.name == "nt", reason="modes and symlinks are Unix only")


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def modes_archive():
    builder = rars.RarBuilder(level=0)
    builder.add_bytes(b"run", "run.sh", mode=0o100750)
    builder.add_bytes(b"secret", "secret.txt", mode=0o100400)
    builder.add_directory("private", mode=0o040700)
    builder.add_bytes(b"inner", "private/inner.txt", mode=0o100604)
    return rars.RarFile(builder.to_bytes())


@pytest.mark.parametrize("in_place", [False, True])
def test_unix_modes_are_restored(tmp_path, in_place):
    archive = modes_archive()

    archive.extractall(tmp_path / "all", in_place=in_place)
    archive.extract("run.sh", tmp_path / "one", in_place=in_place)

    assert mode_of(tmp_path / "all/run.sh") == 0o750
    assert mode_of(tmp_path / "all/secret.txt") == 0o400
    assert mode_of(tmp_path / "all/private") == 0o700
    assert mode_of(tmp_path / "all/private/inner.txt") == 0o604
    assert mode_of(tmp_path / "one/run.sh") == 0o750


def test_restore_modes_false_keeps_the_umask_defaults(tmp_path):
    umask = os.umask(0o022)
    try:
        archive = modes_archive()
        archive.extractall(tmp_path / "all", restore_modes=False)
        archive.extract("secret.txt", tmp_path / "one", restore_modes=False)
    finally:
        os.umask(umask)

    for name in ["all/run.sh", "all/secret.txt", "all/private/inner.txt", "one/secret.txt"]:
        assert mode_of(tmp_path / name) == 0o644
    assert mode_of(tmp_path / "all/private") == 0o755


@pytest.mark.parametrize("kind, nlink, mode", [(HARD_LINK, 2, 0o200), (FILE_COPY, 1, 0o640)])
def test_a_hard_link_and_a_copy_of_an_unreadable_file_keep_their_modes(tmp_path, kind, nlink, mode):
    builder = rars.RarBuilder(level=0)
    builder.add_bytes(b"source", "source.txt", mode=0o100200)
    builder.add_unix_symlink("linked.txt", "source.txt", mode=0o100640)
    data = redirect(builder.to_bytes(), kind, only="linked.txt")

    rars.RarFile(data).extractall(tmp_path)

    assert mode_of(tmp_path / "source.txt") == 0o200
    assert mode_of(tmp_path / "linked.txt") == mode
    assert os.lstat(tmp_path / "linked.txt").st_nlink == nlink


def test_skip_symlinks_leaves_symlinks_out_and_keeps_hard_links(tmp_path):
    builder = rars.RarBuilder(level=0)
    builder.add_bytes(b"target", "c/target.txt")
    builder.add_unix_symlink("a/inside.txt", "../c/target.txt")
    builder.add_unix_symlink("a/outside.txt", "../../outside.txt")
    builder.add_unix_symlink("b/hard.txt", "c/target.txt")
    data = redirect(builder.to_bytes(), HARD_LINK, only="b/hard.txt")

    with warnings.catch_warnings():
        warnings.simplefilter("error", rars.UnsafeLinkWarning)
        written = rars.RarFile(data).extractall(tmp_path, skip_symlinks=True)

    assert not os.path.lexists(tmp_path / "a/inside.txt")
    assert not os.path.lexists(tmp_path / "a/outside.txt")
    assert tmp_path / "a/inside.txt" not in written
    assert os.path.samefile(tmp_path / "b/hard.txt", tmp_path / "c/target.txt")


@pytest.mark.parametrize("format", ["rar50", "rar29"])
def test_skip_symlinks_on_extract_and_with_flatten(tmp_path, format):
    builder = rars.RarBuilder(version=format, level=0)
    builder.add_bytes(b"target", "target.txt")
    builder.add_unix_symlink("near.txt", "target.txt")
    archive = rars.RarFile(builder.to_bytes())

    with pytest.raises(KeyError, match="no extractable payload"):
        archive.extract("near.txt", tmp_path / "one", skip_symlinks=True)
    archive.extractall(tmp_path / "flat", flatten=True, skip_symlinks=True)

    assert not os.path.lexists(tmp_path / "one/near.txt")
    assert not os.path.lexists(tmp_path / "flat/near.txt")
    assert (tmp_path / "flat/target.txt").read_bytes() == b"target"


@pytest.mark.parametrize("volumes", [None, []])
def test_a_hard_link_to_a_skipped_symlink_fails_as_its_own_member(tmp_path, volumes):
    builder = rars.RarBuilder(level=0)
    builder.add_bytes(b"target", "target.txt")
    builder.add_unix_symlink("sym", "target.txt")
    builder.add_unix_symlink("hard", "sym")
    builder.add_bytes(b"after", "after.txt")
    data = redirect(builder.to_bytes(), HARD_LINK, only="hard")

    failed = []
    written = rars.RarFile(data).extractall(
        tmp_path, skip_symlinks=True, on_member_error=failed.append, volumes=volumes
    )

    assert [error.member for error in failed] == ["hard"]
    assert "symbolic link left out" in str(failed[0])
    assert not os.path.lexists(tmp_path / "hard")
    assert (tmp_path / "after.txt").read_bytes() == b"after"
    assert tmp_path / "after.txt" in written
