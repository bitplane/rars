import os
import stat
import subprocess
import sys
import threading

import pytest
import rars


def archive_of(**members):
    builder = rars.RarBuilder(store=True)
    for name, payload in members.items():
        builder.add_bytes(payload, name)
    return rars.RarFile.from_bytes(builder.to_bytes())


@pytest.mark.skipif(os.name == "nt", reason="POSIX hard links")
def test_overwrite_replaces_a_hard_link_instead_of_writing_through_it(tmp_path):
    victim = tmp_path / "outside" / "victim"
    victim.parent.mkdir()
    victim.write_bytes(b"victim\n")
    out = tmp_path / "out"
    out.mkdir()
    os.link(victim, out / "file.txt")

    archive_of(**{"file.txt": b"archive bytes"}).extractall(out, overwrite=True)

    assert victim.read_bytes() == b"victim\n"
    assert (out / "file.txt").read_bytes() == b"archive bytes"
    assert os.stat(out / "file.txt").st_nlink == 1


def extract_in_thread(call):
    outcome = {}

    def run():
        try:
            outcome["value"] = call()
        except BaseException as error:
            outcome["error"] = error

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=10)
    return thread.is_alive(), outcome


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs")
@pytest.mark.parametrize("overwrite", [True, False])
def test_a_fifo_at_the_output_path_never_blocks_extraction(tmp_path, overwrite):
    fifo = tmp_path / "file.txt"
    os.mkfifo(fifo)
    archive = archive_of(**{"file.txt": b"archive bytes"})

    blocked, outcome = extract_in_thread(lambda: archive.extractall(tmp_path, overwrite=overwrite))
    if blocked:
        # Release the stuck open so the daemon thread can end.
        os.close(os.open(fifo, os.O_RDONLY | os.O_NONBLOCK))
    assert not blocked

    if overwrite:
        assert "error" not in outcome
        assert (tmp_path / "file.txt").read_bytes() == b"archive bytes"
    else:
        assert isinstance(outcome["error"], OSError)
        assert stat.S_ISFIFO(os.lstat(fifo).st_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_without_overwrite_an_existing_symlink_is_refused(tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"victim\n")
    out = tmp_path / "out"
    out.mkdir()
    (out / "file.txt").symlink_to(victim)

    with pytest.raises(rars.Error):
        archive_of(**{"file.txt": b"archive bytes"}).extractall(out)

    assert victim.read_bytes() == b"victim\n"
    assert os.readlink(out / "file.txt") == str(victim)


def corrupt_last(builder):
    data = bytearray(builder.to_bytes())
    data[data.rindex(b"bad payload")] ^= 0xFF
    return rars.RarFile.from_bytes(bytes(data))


def staging_left(out):
    return [path.name for path in out.iterdir() if path.name.startswith(".rars-extract-")]


@pytest.mark.parametrize("members", [None, ["good.txt", "bad.txt"]])
@pytest.mark.parametrize("old", [None, b"old contents"])
def test_a_member_that_fails_its_checksum_leaves_its_destination_alone(tmp_path, members, old):
    builder = rars.RarBuilder(store=True)
    builder.add_bytes(b"good payload", "good.txt")
    builder.add_bytes(b"bad payload", "bad.txt")
    archive = corrupt_last(builder)
    if old is not None:
        (tmp_path / "bad.txt").write_bytes(old)

    with pytest.raises(rars.BadRarFile):
        archive.extractall(tmp_path, members=members, overwrite=True)

    assert (tmp_path / "good.txt").read_bytes() == b"good payload"
    if old is None:
        assert not (tmp_path / "bad.txt").exists()
    else:
        assert (tmp_path / "bad.txt").read_bytes() == old
    assert staging_left(tmp_path) == []


def write_set(tmp_path):
    builder = rars.RarBuilder(store=True, volume_size=4096)
    builder.add_bytes(b"small payload", "small.txt")
    builder.add_bytes(bytes(range(256)) * 80, "large.bin")
    (tmp_path / "made").mkdir()
    return builder.write_volumes(tmp_path / "made" / "set.part01.rar")


@pytest.mark.parametrize("old", [None, b"old contents"])
def test_a_volume_set_member_that_fails_its_checksum_is_not_published(tmp_path, old):
    paths = write_set(tmp_path)
    last = bytearray(paths[-1].read_bytes())
    last[len(last) // 2] ^= 0xFF
    paths[-1].write_bytes(bytes(last))
    out = tmp_path / "out"
    if old is not None:
        out.mkdir()
        (out / "large.bin").write_bytes(old)

    with rars.RarFile(paths[0]) as archive, pytest.raises(rars.BadRarFile):
        archive.extractall(out, overwrite=True)

    assert (out / "small.txt").read_bytes() == b"small payload"
    if old is None:
        assert not (out / "large.bin").exists()
    else:
        assert (out / "large.bin").read_bytes() == old
    assert staging_left(out) == []


def test_no_staging_remains_after_success_cancellation_or_a_raising_volumes_iterable(tmp_path):
    paths = write_set(tmp_path)
    with rars.RarFile(paths[0]) as archive:
        archive.extractall(tmp_path / "ok")

        token = rars.CancellationToken()

        def cancelling():
            token.cancel()
            yield from paths[1:]

        with pytest.raises(InterruptedError):
            archive.extractall(tmp_path / "cancelled", volumes=cancelling(),
                               options=rars.ReadOptions(cancellation=token))

        def raising():
            yield paths[1]
            raise LookupError("volume never arrived")

        with pytest.raises(LookupError):
            archive.extractall(tmp_path / "raised", volumes=raising())

    for name in ["ok", "cancelled", "raised"]:
        assert staging_left(tmp_path / name) == [], name
    assert not (tmp_path / "cancelled/large.bin").exists()
    assert not (tmp_path / "raised/large.bin").exists()


# Linux keeps the parent's ru_maxrss across exec, so read this process's own peak there.
PEAK_RSS = """
import resource, sys, rars
rars.RarFile(sys.argv[1]).extractall(sys.argv[2])
try:
    with open("/proc/self/status") as status:
        print(next(int(line.split()[1]) * 1024 for line in status if line.startswith("VmHWM:")))
except FileNotFoundError:
    print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
"""


@pytest.mark.skipif(os.name == "nt", reason="resource module")
def test_staging_streams_to_disk_instead_of_buffering_a_member(tmp_path):
    def peak(size):
        archive = tmp_path / f"{size}.rar"
        builder = rars.RarBuilder(store=True)
        builder.add_bytes(os.urandom(size), "member.bin")
        builder.write(archive)
        out = tmp_path / f"out-{size}"
        result = subprocess.run([sys.executable, "-c", PEAK_RSS, archive, out],
                                check=True, capture_output=True, text=True)
        assert (out / "member.bin").stat().st_size == size
        return int(result.stdout)

    small, large = peak(1 << 20), peak(128 << 20)
    assert large - small < 32 << 20


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
@pytest.mark.parametrize("members", [None, ["sub/file.txt"]])
def test_a_refused_member_is_named_in_the_error(tmp_path, members):
    (tmp_path / "outside").mkdir()
    out = tmp_path / "out"
    out.mkdir()
    (out / "sub").symlink_to("../outside", target_is_directory=True)

    with pytest.raises(rars.UnsafeArchivePath) as raised:
        archive_of(**{"sub/file.txt": b"payload"}).extractall(out, members=members)

    assert str(raised.value) == "while extracting entry 'sub/file.txt': unsafe archive path crosses symlink"
    assert not (tmp_path / "outside/file.txt").exists()
