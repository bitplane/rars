from pathlib import Path

import pytest
import rars


@pytest.mark.parametrize("method", ["repair", "repair_detailed", "repair_to_path"])
@pytest.mark.parametrize("source", [b"invalid archive", Path("missing-archive.rar")])
def test_cancelled_repair_does_not_read_input_or_touch_output(tmp_path, method, source):
    token = rars.CancellationToken()
    token.cancel()
    output = tmp_path / "existing.rar"
    output.write_bytes(b"keep")
    args = (source, output) if method == "repair_to_path" else (source,)
    with pytest.raises(InterruptedError):
        getattr(rars, method)(*args, cancellation=token)
    assert output.read_bytes() == b"keep"
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.parametrize("format", ["rar20", "rar40", "rar50", "rar70"])
def test_repair_token_is_reusable_and_path_publication_cleans_up(tmp_path, format):
    builder = rars.RarBuilder(format=format, store=True, recovery_percent=10)
    payload = b"recoverable payload " * 1000
    builder.add_bytes(payload, "file")
    original = builder.to_bytes()
    fixtures = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures/rar15_40"
    if format in ("rar20", "rar40"):
        fixture = "rar250_protect_head_rr5.rar" if format == "rar20" else "rar300/with_compressed_recovery_rar300.rar"
        original = (fixtures / fixture).read_bytes()
    source = tmp_path / "input.rar"
    source.write_bytes(original)
    output = tmp_path / "output.rar"
    output.write_bytes(b"keep")
    token = rars.CancellationToken()
    repaired = rars.repair(source, cancellation=token)
    detailed = rars.repair_detailed(original, cancellation=token)
    assert repaired == detailed.data == rars.repair(original)
    rars.RarFile.from_bytes(repaired).testrar()
    rars.repair_to_path(source, output, cancellation=token)
    assert output.read_bytes() == repaired
    assert not token.is_cancelled()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["input.rar", "output.rar"]
    token.cancel()
    with pytest.raises(InterruptedError):
        rars.repair_to_path(source, output, cancellation=token)
    assert output.read_bytes() == repaired
    rars.repair_to_path(source, source)
    assert source.read_bytes() == repaired


@pytest.mark.parametrize("method", ["repair", "repair_detailed", "repair_to_path"])
def test_repair_token_keeps_damaged_header_fallback_working(tmp_path, method):
    builder = rars.RarBuilder(format="rar50", store=True, recovery_percent=10)
    payload = b"recoverable payload " * 1000
    builder.add_bytes(payload, "file")
    damaged = bytearray(builder.to_bytes())
    damaged[8] ^= 1  # Main-header CRC: repair must use the raw recovery fallback.
    token = rars.CancellationToken()
    if method == "repair_to_path":
        output = tmp_path / "fixed.rar"
        rars.repair_to_path(damaged, output, cancellation=token)
        result = output.read_bytes()
    else:
        result = getattr(rars, method)(damaged, cancellation=token)
        if method == "repair_detailed":
            assert result.report.data_repaired
            result = result.data
    assert rars.RarFile.from_bytes(result).read("file") == payload
    assert not token.is_cancelled()
