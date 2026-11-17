import random
import pytest
import rars


@pytest.mark.parametrize("format", ["rar50", "rar70"])
@pytest.mark.parametrize("store,solid,recovery", [(True, False, None), (False, False, None), (False, True, 10)])
def test_writer_memory_preserves_output(format, store, solid, recovery):
    options = dict(version=format, level=0 if store else 3, solid=solid, recovery_percent=recovery)
    plain = rars.RarBuilder(**options)
    limited = rars.RarBuilder(**options, resources=rars.WriterResources(max_memory_bytes=256 << 20))
    for builder in (plain, limited):
        builder.add_bytes(b"payload" * 1024, "member")
    expected = plain.to_bytes()
    for _ in range(2):
        actual = limited.to_bytes()
        assert actual == expected
        assert rars.RarFile(actual).read("member") == b"payload" * 1024


def test_writer_memory_failure_preserves_destination(tmp_path):
    builder = rars.RarBuilder(version="rar50", level=0, resources=rars.WriterResources(max_memory_bytes=1024))
    builder.add_bytes(b"payload" * 1024, "member")
    destination = tmp_path / "archive.rar"
    destination.write_bytes(b"original")
    for _ in range(3):
        with pytest.raises(rars.LimitExceeded):
            builder.to_bytes()
        with pytest.raises(rars.LimitExceeded):
            builder.write(destination, overwrite=True)
        assert destination.read_bytes() == b"original"
        assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40"])
def test_legacy_writer_refuses_memory_policy(format):
    with pytest.raises(ValueError, match="memory limit"):
        rars.RarBuilder(version=format, level=0, resources=rars.WriterResources(max_memory_bytes=0))


@pytest.mark.parametrize("encrypt_headers", [False, True])
def test_encrypted_recovery_and_volume_output_obey_memory_policy(tmp_path, encrypt_headers):
    options = dict(version="rar50", level=0, password="secret",
                   encrypt_headers=encrypt_headers, recovery_percent=10,
                   resources=rars.WriterResources(max_memory_bytes=32 << 20))
    builder = rars.RarBuilder(**options)
    builder.add_bytes(b"payload" * 1024, "member")
    archive = rars.RarFile(builder.to_bytes(), password="secret")
    assert archive.read("member") == b"payload" * 1024
    builder = rars.RarBuilder(**options, volume_size=2048)
    builder.add_bytes(b"payload" * 1024, "member")
    parts = builder.write(tmp_path / "set.part1.rar")
    assert len(parts) > 1
    output = tmp_path / "extracted"
    with rars.RarFile(parts[0], password="secret") as archive:
        archive.testrar(volumes=parts[1:])
        archive.extractall(output, volumes=parts[1:])
    assert (output / "member").read_bytes() == b"payload" * 1024


ALL_VERSIONS = ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70"]


def _members(builder):
    # Text and noise, so compressed members take real work.
    builder.add_bytes(b"workspace budget " * 40000, "text.txt")
    builder.add_bytes(random.Random(1).randbytes(300000), "noise.bin")
    return builder


@pytest.mark.parametrize("format", ALL_VERSIONS)
def test_a_workspace_budget_changes_no_bytes(tmp_path, format):
    level = 0 if format == "rar13" else 3
    expected = _members(rars.RarBuilder(version=format, level=level)).to_bytes()
    for budget in (256 << 20, 4 << 30):
        resources = rars.WriterResources(max_workspace_bytes=budget)
        builder = _members(rars.RarBuilder(version=format, level=level, resources=resources))
        assert builder.to_bytes() == expected
        [path] = builder.write(tmp_path / f"{format}-{budget}.rar")
        assert path.read_bytes() == expected


@pytest.mark.parametrize("format", ["rar20", "rar29", "rar50"])
def test_a_small_workspace_budget_still_writes_readable_volumes(tmp_path, format):
    # Below the 256 MiB a job plans within, though above what one RAR 5 job needs.
    payload = random.Random(1).randbytes(300000)
    resources = rars.WriterResources(max_workspace_bytes=128 << 20)
    builder = rars.RarBuilder(version=format, level=3, volume_size=200000, resources=resources)
    plain = rars.RarBuilder(version=format, level=3, volume_size=200000)
    for each in (builder, plain):
        each.add_bytes(payload, "text.txt")
    parts = builder.write(tmp_path / f"{format}.rar")
    assert len(parts) > 1
    if format != "rar50":
        # Legacy writers plan nothing by workspace, so the bytes match too.
        expected = plain.write(tmp_path / f"{format}-plain.rar")
        assert [part.read_bytes() for part in parts] == [part.read_bytes() for part in expected]
    with rars.RarFile(parts[0]) as archive:
        archive.testrar(volumes=parts[1:])
        assert archive.read("text.txt", volumes=parts[1:]) == payload


def test_a_workspace_budget_too_small_for_one_job_is_refused():
    resources = rars.WriterResources(max_workspace_bytes=16 << 20)
    builder = rars.RarBuilder(version="rar50", level=3, resources=resources)
    builder.add_bytes(b"x" * 300000, "a")
    with pytest.raises(rars.LimitExceeded, match="working memory"):
        builder.to_bytes()


def test_workspace_budget_reads_back_and_refuses_zero():
    assert rars.WriterResources().max_workspace_bytes is None
    resources = rars.WriterResources(max_workspace_bytes=1 << 30, max_memory_bytes=1 << 31)
    assert (resources.max_workspace_bytes, resources.max_memory_bytes) == (1 << 30, 1 << 31)
    with pytest.raises(ValueError, match="max_workspace_bytes"):
        rars.WriterResources(max_workspace_bytes=0)
