import os

import pytest
import rars


MTIME_NS = 1_700_000_000_123_456_700


def test_extractall_restores_rar5_times_with_sub_second_precision(tmp_path):
    builder = rars.RarBuilder()
    builder.add_bytes(b"payload", "file.txt")
    builder.set_times("file.txt", modified_ns=MTIME_NS)
    archive = rars.RarFile.from_bytes(builder.to_bytes())

    archive.extractall(tmp_path)

    assert os.stat(tmp_path / "file.txt").st_mtime_ns == MTIME_NS


@pytest.mark.parametrize("format", ["rar13", "rar15", "rar20", "rar29", "rar40", "rar50"])
def test_extractall_restores_file_and_directory_times(tmp_path, format):
    builder = rars.RarBuilder(format=format)
    builder.add_directory("dir", mtime=1_600_000_000)
    builder.add_bytes(b"payload", "dir/file.txt", mtime=1_650_000_000)
    archive = rars.RarFile.from_bytes(builder.to_bytes())

    archive.extractall(tmp_path)

    assert os.stat(tmp_path / "dir").st_mtime_ns == archive.gettimes("dir")["modified"]
    assert os.stat(tmp_path / "dir/file.txt").st_mtime_ns == archive.gettimes("dir/file.txt")["modified"]


def test_restore_times_false_keeps_written_times(tmp_path):
    builder = rars.RarBuilder()
    builder.add_bytes(b"payload", "file.txt", mtime=1_600_000_000)
    archive = rars.RarFile.from_bytes(builder.to_bytes())

    archive.extractall(tmp_path / "all", restore_times=False)
    archive.extract("file.txt", tmp_path / "one", restore_times=False)

    assert os.stat(tmp_path / "all/file.txt").st_mtime > 1_600_000_000
    assert os.stat(tmp_path / "one/file.txt").st_mtime > 1_600_000_000


def test_extract_and_selected_members_restore_times(tmp_path):
    builder = rars.RarBuilder()
    builder.add_bytes(b"one", "one.txt", mtime=1_600_000_000)
    builder.add_bytes(b"two", "two.txt", mtime=1_600_000_002)
    archive = rars.RarFile.from_bytes(builder.to_bytes())

    archive.extract("one.txt", tmp_path / "single")
    archive.extractall(tmp_path / "selected", members=["one.txt", "two.txt"])

    assert os.stat(tmp_path / "single/one.txt").st_mtime == 1_600_000_000
    assert os.stat(tmp_path / "selected/one.txt").st_mtime == 1_600_000_000
    assert os.stat(tmp_path / "selected/two.txt").st_mtime == 1_600_000_002


@pytest.mark.parametrize("format", ["rar50", "rar29"])
def test_volume_sets_restore_times(tmp_path, format):
    builder = rars.RarBuilder(format=format, store=True, volume_size=4096)
    builder.add_bytes(bytes(20_000), "large.bin", mtime=1_600_000_000)
    (tmp_path / "made").mkdir()
    paths = builder.write_volumes(tmp_path / "made" / "set.part01.rar")
    assert len(paths) > 2

    with rars.RarFile(paths[0]) as archive:
        archive.extractall(tmp_path / "found")
        archive.extractall(tmp_path / "given", volumes=paths[1:])
        expected = archive.gettimes("large.bin")["modified"]

    assert os.stat(tmp_path / "found/large.bin").st_mtime_ns == expected
    assert os.stat(tmp_path / "given/large.bin").st_mtime_ns == expected


@pytest.mark.parametrize("members", [None, ["good.txt", "bad.txt"]])
def test_failed_extraction_restores_completed_outputs_only(tmp_path, members):
    builder = rars.RarBuilder(store=True)
    builder.add_bytes(b"good payload", "good.txt", mtime=1_600_000_000)
    builder.add_bytes(b"spacer", "spacer.txt", mtime=1_600_000_000)
    builder.add_bytes(b"bad payload", "bad.txt", mtime=1_600_000_000)
    data = bytearray(builder.to_bytes())
    data[data.rindex(b"bad payload")] ^= 0xFF
    archive = rars.RarFile.from_bytes(bytes(data))

    with pytest.raises(rars.Error):
        archive.extractall(tmp_path, members=members)

    assert os.stat(tmp_path / "good.txt").st_mtime == 1_600_000_000
    assert not (tmp_path / "bad.txt").exists()


def test_cancelled_volume_set_restores_completed_outputs_and_drops_the_rest(tmp_path):
    builder = rars.RarBuilder(store=True, volume_size=4096)
    builder.add_bytes(b"small", "small.txt", mtime=1_600_000_000)
    builder.add_bytes(bytes(20_000), "large.bin", mtime=1_600_000_000)
    (tmp_path / "made").mkdir()
    paths = builder.write_volumes(tmp_path / "made" / "set.part01.rar")
    token = rars.CancellationToken()

    def volumes():
        token.cancel()
        yield from paths[1:]

    with rars.RarFile(paths[0]) as archive, pytest.raises(InterruptedError):
        archive.extractall(tmp_path / "out", volumes=volumes(), options=rars.ReadOptions(cancellation=token))

    assert os.stat(tmp_path / "out/small.txt").st_mtime == 1_600_000_000
    assert not (tmp_path / "out/large.bin").exists()
