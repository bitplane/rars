import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
import rars


FORMATS = ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70"]


@pytest.mark.parametrize("format", FORMATS)
@pytest.mark.parametrize("method", ["to_bytes", "write", "write_volumes"])
def test_pre_cancelled_token_refuses_without_callback_or_publication(tmp_path, format, method):
    builder = rars.RarBuilder(format=format, store=True,
                              volume_size=1000 if method == "write_volumes" else None)
    builder.add_bytes(b"payload" * 1000, "file")
    token = rars.CancellationToken()
    assert not token.is_cancelled()
    token.cancel()
    token.cancel()
    assert token.is_cancelled()
    destination = tmp_path / "archive.rar"
    destination.write_bytes(b"keep")
    with pytest.raises(InterruptedError):
        if method == "to_bytes":
            builder.to_bytes(cancellation=token)
        else:
            getattr(builder, method)(destination, cancellation=token)
    assert destination.read_bytes() == b"keep"
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("phase", ["compression", "staging"])
def test_another_python_thread_can_cancel_a_write(tmp_path, phase):
    builder = rars.RarBuilder(store=True)
    payload = b"thread cancellation\n" * 10000
    builder.add_bytes(payload, "file")
    if phase == "staging":
        builder = rars.RarBuilder.from_archive(rars.RarFile.from_bytes(builder.to_bytes()),
                                              staging_dir=tmp_path)
    token = rars.CancellationToken()
    reached = threading.Event()
    resume = threading.Event()
    destination = tmp_path / "archive.rar"
    destination.write_bytes(b"keep")

    def report(event):
        if event.phase == phase and not reached.is_set():
            reached.set()
            assert resume.wait(10), "test did not release callback"

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(builder.write, destination, progress=report, cancellation=token)
        try:
            assert reached.wait(10), "writer did not reach requested phase"
            token.cancel()
        finally:
            resume.set()
        with pytest.raises(InterruptedError):
            future.result(timeout=10)
    assert destination.read_bytes() == b"keep"
    assert list(tmp_path.iterdir()) == [destination]
    with pytest.raises(InterruptedError):
        builder.write(destination, cancellation=token)
    fresh = rars.CancellationToken()
    builder.write(destination, cancellation=fresh)
    assert not fresh.is_cancelled()
    assert rars.RarFile(destination).read("file") == payload


@pytest.mark.parametrize("rewrite", [False, True])
def test_callback_failure_does_not_cancel_the_callers_token(tmp_path, rewrite):
    builder = rars.RarBuilder(store=True)
    builder.add_bytes(b"payload", "file")
    if rewrite:
        builder = rars.RarBuilder.from_archive(rars.RarFile.from_bytes(builder.to_bytes()),
                                              staging_dir=tmp_path)
    token = rars.CancellationToken()
    failure = RuntimeError("callback failed")

    def stop(event):
        raise failure

    with pytest.raises(RuntimeError) as caught:
        builder.to_bytes(progress=stop, cancellation=token)
    assert caught.value is failure
    assert not token.is_cancelled()
    assert list(tmp_path.iterdir()) == []
    output = rars.RarFile.from_bytes(builder.to_bytes(cancellation=token))
    assert output.read("file") == b"payload"
    assert not token.is_cancelled()
