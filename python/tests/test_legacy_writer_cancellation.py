import pytest
import rars


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40"])
@pytest.mark.parametrize("store", [False, True])
def test_legacy_encoding_callback_exception_preserves_destination(tmp_path, format, store):
    builder = rars.RarBuilder(format=format, store=store)
    payload = b"legacy cancellation\n" * 8000
    builder.add_bytes(payload, "file")
    destination = tmp_path / "archive.rar"
    destination.write_bytes(b"keep")
    failure = RuntimeError("cancel encoding")

    def stop(event):
        if event.phase == "compression" and event.completed > 0:
            raise failure

    with pytest.raises(RuntimeError) as caught:
        builder.write(destination, progress=stop)
    assert caught.value is failure
    assert destination.read_bytes() == b"keep"
    assert list(tmp_path.iterdir()) == [destination]
    builder.write(destination)
    assert rars.RarFile(destination).read("file") == payload


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40"])
def test_chunked_legacy_encryption_round_trip(format):
    builder = rars.RarBuilder(format=format, store=True, password="secret")
    payload = bytes(range(256)) * 601
    builder.add_bytes(payload, "file")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    assert archive.read("file", pwd="secret") == payload


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40"])
def test_legacy_streaming_progress_has_unknown_total_until_completion(format):
    builder = rars.RarBuilder(format=format, store=True)
    payload = b"streamed payload\n" * 8000
    builder.add_bytes(payload, "file")
    events = []
    data = builder.to_bytes(progress=events.append)
    writing = [event for event in events if event.phase == "writing"]
    assert writing[0].completed == 0
    assert writing[0].percentage is None
    assert any(event.completed > 0 and event.percentage is None for event in writing)
    assert all(event.percentage is None for event in writing[:-1])
    assert writing[-1].completed == writing[-1].total == len(data)
    assert writing[-1].percentage == 100
    assert [event.completed for event in writing] == sorted(event.completed for event in writing)
    assert rars.RarFile.from_bytes(data).read("file") == payload
