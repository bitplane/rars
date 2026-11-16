from pathlib import Path

import pytest
import rars


@pytest.mark.parametrize("to_file", [False, True])
@pytest.mark.parametrize("source", [b"invalid archive", Path("missing-archive.rar")])
def test_cancelled_repair_does_not_read_input_or_touch_output(tmp_path, to_file, source):
    token = rars.CancellationToken()
    token.cancel()
    output = tmp_path / "existing.rar"
    output.write_bytes(b"keep")
    with pytest.raises(InterruptedError):
        rars.repair(source, output=output if to_file else None, cancellation=token)
    assert output.read_bytes() == b"keep"
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.parametrize("format", ["rar20", "rar40", "rar50", "rar70"])
def test_repair_token_is_reusable_and_path_publication_cleans_up(tmp_path, format):
    builder = rars.RarBuilder(format=format, store=True, recovery_percent=10 if format in ("rar50", "rar70") else None)
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
    repaired = rars.repair(source, cancellation=token).data
    assert repaired == rars.repair(original, cancellation=token).data == rars.repair(original).data
    rars.RarFile.from_bytes(repaired).testrar()
    written = rars.repair(source, output=output, cancellation=token)
    assert written.data is None
    assert output.read_bytes() == repaired
    assert not token.is_cancelled()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["input.rar", "output.rar"]
    token.cancel()
    with pytest.raises(InterruptedError):
        rars.repair(source, output=output, cancellation=token)
    assert output.read_bytes() == repaired
    rars.repair(source, output=source)
    assert source.read_bytes() == repaired


@pytest.mark.parametrize("to_file", [False, True])
def test_repair_token_keeps_damaged_header_fallback_working(tmp_path, to_file):
    builder = rars.RarBuilder(format="rar50", store=True, recovery_percent=10)
    payload = b"recoverable payload " * 1000
    builder.add_bytes(payload, "file")
    damaged = bytearray(builder.to_bytes())
    damaged[8] ^= 1  # Main-header CRC: repair must use the raw recovery fallback.
    token = rars.CancellationToken()
    output = tmp_path / "fixed.rar"
    result = rars.repair(damaged, output=output if to_file else None, cancellation=token)
    assert result.report.data_repaired
    repaired = output.read_bytes() if to_file else result.data
    assert rars.RarFile.from_bytes(repaired).read("file") == payload
    assert not token.is_cancelled()


def test_repair_reads_with_the_options_given():
    builder = rars.RarBuilder(format="rar50", store=True, recovery_percent=10)
    builder.add_bytes(b"recoverable payload " * 1000, "file")
    with pytest.raises(MemoryError):
        rars.repair(builder.to_bytes(), options=rars.ReadOptions(max_header_count=0))
