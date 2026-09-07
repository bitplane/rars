import pytest
import rars


def source_archive(format="rar50", solid=False):
    builder = rars.RarBuilder(
        format=format, solid=solid, store=not solid or format in ("rar50", "rar70")
    )
    builder.add_directory("empty", mtime=123)
    builder.add_bytes(b"first payload", "first", mtime=456)
    builder.add_bytes(b"second payload", "second", mtime=789)
    return builder.to_bytes()


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70"])
@pytest.mark.parametrize("preserve", [False, True])
def test_staging_tracks_identity_through_edits_and_repeated_writes(tmp_path, format, preserve):
    staging = tmp_path / "staging"
    staging.mkdir()
    builder = rars.RarBuilder.from_archive(
        rars.RarFile.from_bytes(source_archive(format, solid=True)),
        preserve=preserve, staging_dir=staging, max_staged_bytes=14,
    )
    builder.remove("first")
    builder.rename("second", "first")
    builder.rename("first", "renamed")
    # Failed edits must leave the identity mapping intact.
    with pytest.raises(ValueError):
        builder.rename("renamed", "empty")
    with pytest.raises(KeyError):
        builder.remove("missing")
    builder.add_bytes(b"replacement", "second")
    for _ in range(2):
        output = rars.RarFile.from_bytes(builder.to_bytes())
        assert output.namelist() == ["empty", "renamed", "second"]
        assert output.getinfo("empty").is_dir()
        assert output.read("renamed") == b"second payload"
        assert output.read("second") == b"replacement"
        assert list(staging.iterdir()) == []
    builder.remove("renamed")
    builder.add_bytes(b"fresh", "renamed")
    assert rars.RarFile.from_bytes(builder.to_bytes()).read("renamed") == b"fresh"
    assert list(staging.iterdir()) == []


def test_limit_is_lazy_per_write_and_counts_only_retained_payloads(tmp_path):
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep")
    builder = rars.RarBuilder.from_archive(
        rars.RarFile.from_bytes(source_archive()), max_staged_bytes=14,
    )
    with pytest.raises(MemoryError, match="rewrite staging limit"):
        builder.write(destination)
    assert destination.read_bytes() == b"keep"
    assert list(tmp_path.iterdir()) == [destination]
    builder.remove("first")
    builder.write(destination)
    assert rars.RarFile(destination).read("second") == b"second payload"
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("method", ["to_bytes", "write"])
def test_default_directory_and_cleanup_after_writer_callback_failure(tmp_path, monkeypatch, method):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    monkeypatch.chdir(cwd)
    builder = rars.RarBuilder.from_archive(rars.RarFile.from_bytes(source_archive()))
    destination = output_dir / "archive.rar"
    destination.write_bytes(b"keep")
    expected = cwd if method == "to_bytes" else output_dir

    def stop(event):
        if event.phase == "staging":
            return
        # Writer callbacks run with verified sources alive for this write.
        assert len(list(expected.glob(".rars-spool-*"))) >= 2
        raise RuntimeError("stop after staging")

    with pytest.raises(RuntimeError, match="stop after staging"):
        if method == "to_bytes":
            builder.to_bytes(progress=stop)
        else:
            builder.write(destination, progress=stop)
    assert destination.read_bytes() == b"keep"
    assert list(cwd.iterdir()) == []
    assert list(output_dir.iterdir()) == [destination]
    # A failed write must not poison or retain that session's sources.
    builder.write(destination)
    assert rars.RarFile(destination).read("first") == b"first payload"
    assert list(output_dir.iterdir()) == [destination]


@pytest.mark.parametrize("solid", [False, True])
def test_removed_corrupt_member_only_decoded_when_required_by_solid_history(tmp_path, solid):
    data = bytearray(source_archive(solid=solid))
    data[data.index(b"first payload")] ^= 1
    builder = rars.RarBuilder.from_archive(rars.RarFile.from_bytes(bytes(data)), staging_dir=tmp_path)
    builder.remove("first")
    if solid:
        with pytest.raises(rars.BadRarFile):
            builder.to_bytes()
    else:
        output = rars.RarFile.from_bytes(builder.to_bytes())
        assert output.read("second") == b"second payload"
    assert list(tmp_path.iterdir()) == []


def test_no_retained_payloads_need_no_staging_directory(tmp_path):
    builder = rars.RarBuilder.from_archive(
        rars.RarFile.from_bytes(source_archive()),
        staging_dir=tmp_path / "missing", max_staged_bytes=0,
    )
    with pytest.raises(MemoryError):
        builder.to_bytes()
    builder.remove("first")
    builder.remove("second")
    assert rars.RarFile.from_bytes(builder.to_bytes()).namelist() == ["empty"]
    assert list(tmp_path.iterdir()) == []


def test_staging_directory_error_does_not_publish(tmp_path):
    destination = tmp_path / "archive.rar"
    destination.write_bytes(b"keep")
    builder = rars.RarBuilder.from_archive(
        rars.RarFile.from_bytes(source_archive()), staging_dir=tmp_path / "missing",
    )
    with pytest.raises(OSError):
        builder.write(destination)
    assert destination.read_bytes() == b"keep"
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("solid", [False, True])
def test_staging_progress_counts_decoded_dependencies_before_compression(tmp_path, solid):
    builder = rars.RarBuilder.from_archive(
        rars.RarFile.from_bytes(source_archive(solid=solid)), staging_dir=tmp_path,
    )
    builder.remove("first")
    events = []
    builder.to_bytes(progress=events.append)
    staging = [event for event in events if event.phase == "staging"]
    assert staging
    assert events[0].phase == "staging"
    assert staging[0].completed == 0
    expected = 27 if solid else 14
    assert all(event.total == expected for event in staging)
    assert all(event.total_entries == (2 if solid else 1) for event in staging)
    assert staging[-1].completed == expected
    assert [event.completed for event in staging] == sorted(event.completed for event in staging)
    names = {event.entry_name for event in staging if event.entry_name is not None}
    assert names == ({b"first", b"second"} if solid else {b"second"})
    first_encoding = next(index for index, event in enumerate(events) if event.phase != "staging")
    assert all(event.phase != "staging" for event in events[first_encoding:])
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70"])
@pytest.mark.parametrize("when", ["start", "bytes"])
def test_staging_callback_cancels_and_preserves_destination(tmp_path, format, when):
    original = rars.RarBuilder(format=format, store=True)
    original.add_bytes(b"payload" * 20000, "file")
    builder = rars.RarBuilder.from_archive(rars.RarFile.from_bytes(original.to_bytes()))
    destination = tmp_path / "archive.rar"
    destination.write_bytes(b"keep")
    failure = RuntimeError("cancel staging")
    seen = []

    def stop(event):
        seen.append(event)
        assert event.phase == "staging"
        if when == "start" or event.completed > 0:
            if when == "start":
                assert list(tmp_path.iterdir()) == [destination]
            else:
                assert event.completed <= 64 * 1024
                assert list(tmp_path.glob(".rars-spool-*"))
            raise failure

    with pytest.raises(RuntimeError) as caught:
        builder.write(destination, progress=stop)
    assert caught.value is failure
    assert seen
    assert destination.read_bytes() == b"keep"
    assert list(tmp_path.iterdir()) == [destination]
    builder.write(destination)
    assert rars.RarFile(destination).read("file") == b"payload" * 20000
    assert list(tmp_path.iterdir()) == [destination]


def test_staging_can_cancel_while_discarding_solid_predecessor(tmp_path):
    builder = rars.RarBuilder.from_archive(
        rars.RarFile.from_bytes(source_archive(solid=True)), staging_dir=tmp_path,
    )
    builder.remove("first")

    def stop(event):
        if event.phase == "staging" and event.completed:
            assert event.entry_name == b"first"
            # The selected payload has not started, so there is no staged file yet.
            assert list(tmp_path.iterdir()) == []
            raise RuntimeError("cancel dependency")

    with pytest.raises(RuntimeError, match="cancel dependency"):
        builder.to_bytes(progress=stop)
    assert list(tmp_path.iterdir()) == []
