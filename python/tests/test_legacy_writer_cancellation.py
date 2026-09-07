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
