from pathlib import Path

import pytest
import rars


ROOT = Path(__file__).resolve().parents[2]
RAR50_STORED = ROOT / "crates/rars/tests/fixtures/rar50/stored.rar"
RAR50_PASSWORD = ROOT / "crates/rars/tests/fixtures/rar50/password_crc32.rar"


def test_rarfile_lists_and_reads_fixture():
    archive = rars.RarFile(RAR50_STORED)
    names = archive.namelist()

    assert names
    info = archive.getinfo(names[0])
    assert isinstance(info.filename, str)
    assert archive.read(info) == archive.read(names[0].encode())


def test_extractall_rejects_existing_without_overwrite(tmp_path):
    builder = rars.RarBuilder(store=True)
    builder.add_bytes(b"payload", "hello.txt")
    archive = rars.RarFile.from_bytes(builder.to_bytes())

    archive.extractall(tmp_path)
    with pytest.raises(OSError):
        archive.extractall(tmp_path)
    archive.extractall(tmp_path, overwrite=True)
    assert (tmp_path / "hello.txt").read_bytes() == b"payload"


def test_builder_creates_archive_and_rewrite_model():
    builder = rars.RarBuilder(format="rar50", store=True)
    builder.add_bytes(b"one", "one.txt")
    builder.add_bytes(b"two", "two.txt")

    archive = rars.RarFile.from_bytes(builder.to_bytes())
    rewritten = rars.RarBuilder.from_archive(archive)
    rewritten.remove("one.txt")
    rewritten.rename("two.txt", "renamed.txt")
    rewritten.add_bytes(b"three", "three.txt")

    output = rars.RarFile.from_bytes(rewritten.to_bytes())
    assert output.namelist() == ["renamed.txt", "three.txt"]
    assert output.read("renamed.txt") == b"two"


def test_builder_reports_compression_progress():
    builder = rars.RarBuilder(format="rar70", compression=3, solid=True)
    builder.add_bytes(b"progress payload " * 8192, "payload.txt")
    events = []

    data = builder.to_bytes(progress=events.append)

    assert data
    assert events
    compression = [event for event in events if event.phase == "compression"]
    assert compression
    assert compression[-1].completed == compression[-1].total
    assert compression[-1].percentage == 100.0
    assert all(left.completed <= right.completed for left, right in zip(compression, compression[1:]))


def test_builder_progress_exception_cancels_and_is_reraised():
    builder = rars.RarBuilder(format="rar50", compression=3)
    builder.add_bytes(b"cancel me " * 8192, "payload.txt")

    class StopCompression(Exception):
        pass

    def stop(_event):
        raise StopCompression("stop now")

    with pytest.raises(StopCompression, match="stop now"):
        builder.to_bytes(progress=stop)


def test_builder_writes_and_extracts_volumes(tmp_path):
    builder = rars.RarBuilder(format="rar50", store=True, volume_size=64)
    builder.add_bytes(b"0123456789" * 20, "large.txt")
    paths = builder.write_volumes(tmp_path / "archive.part01.rar")

    assert len(paths) > 1
    rars.test_volumes(paths)
    out_dir = tmp_path / "out"
    rars.extract_volumes(paths, out_dir)
    assert (out_dir / "large.txt").read_bytes() == b"0123456789" * 20


def test_builder_writes_volumes_from_added_paths(tmp_path):
    source = tmp_path / "large.txt"
    source.write_bytes(b"0123456789" * 20)

    builder = rars.RarBuilder(format="rar50", store=True, volume_size=64)
    builder.add(source)
    paths = builder.write_volumes(tmp_path / "archive.part01.rar")

    assert len(paths) > 1
    rars.test_volumes(paths)
    out_dir = tmp_path / "out"
    rars.extract_volumes(paths, out_dir)
    assert (out_dir / "large.txt").read_bytes() == b"0123456789" * 20


def test_password_errors_are_typed():
    with pytest.raises(rars.PasswordRequired):
        rars.RarFile(RAR50_PASSWORD).testrar()

    archive = rars.RarFile(RAR50_PASSWORD, password="password")
    archive.testrar()


def test_repair_detailed_reports_repaired_data(tmp_path):
    payload = bytes((index * 7 + (index >> 5)) & 0xFF for index in range(200_000))
    builder = rars.RarBuilder(format="rar50", store=True, recovery_percent=10)
    builder.add_bytes(payload, "payload.bin")
    archive_path = tmp_path / "recovery.rar"
    builder.write(archive_path)
    damaged = bytearray(archive_path.read_bytes())
    midpoint = len(damaged) // 2
    for index in range(midpoint, midpoint + 64):
        damaged[index] ^= 0xFF

    result = rars.repair_detailed(damaged)

    assert result.report.changed
    assert result.report.data_repaired
    assert result.report.expected_recovery_shards >= 1
    assert rars.RarFile(result.data).read("payload.bin") == payload


@pytest.mark.parametrize(
    "kwargs",
    [
        {"solid": True},
        {"comment": "a streamed comment"},
        {"recovery_percent": 5},
        {"password": "secret", "encrypt_headers": True},
        {"solid": True, "password": "secret", "encrypt_headers": True, "recovery_percent": 5},
    ],
)
def test_builder_writes_every_supported_feature_combination(tmp_path, kwargs):
    archive_path = tmp_path / "archive.rar"
    builder = rars.RarBuilder(format="rar50", **kwargs)
    builder.add_bytes(b"streamed payload\n" * 500, "a.txt")
    builder.add_bytes(b"second payload\n" * 500, "b.txt")
    builder.write(archive_path)

    password = kwargs.get("password")
    archive = rars.RarFile(archive_path, password=password)
    archive.testrar()
    assert sorted(info.filename for info in archive.infolist()) == ["a.txt", "b.txt"]
    assert archive.read("a.txt") == b"streamed payload\n" * 500
