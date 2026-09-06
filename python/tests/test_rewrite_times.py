from pathlib import Path

import pytest
import rars


@pytest.mark.parametrize("times", [
    dict(modified=0, created=123, accessed=4_294_967_295_999_999_999),
    dict(modified=-11_644_473_600_000_000_000, created=1_728_229_934_970_955_161_500, accessed=100),
    dict(created=0, accessed=123_456_789),
])
def test_rewrite_preserves_all_file_times_without_narrowing(times):
    builder = rars.RarBuilder()
    builder.add_bytes(b"payload", "file")
    builder.set_times("file", **{kind + "_ns": value for kind, value in times.items()})
    source = rars.RarFile.from_bytes(builder.to_bytes())
    assert source.gettimes("file") == times
    assert source.rewrite_preservation_issues() == []
    rewritten = rars.RarBuilder.from_archive(source, preserve=True)
    rewritten.rename("file", "renamed")
    output = rars.RarFile.from_bytes(rewritten.to_bytes())
    assert output.gettimes("renamed") == times
    assert output.read("renamed") == b"payload"


def test_legacy_extended_times_survive_conversion():
    source = rars.RarFile(Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures/rar15_40/rar420/ext_time_rar420.rar")
    output = rars.RarFile.from_bytes(rars.RarBuilder.from_archive(source).to_bytes())
    for name in source.namelist():
        assert output.gettimes(name) == source.gettimes(name)


def test_unrepresentable_mixed_precision_leaves_queued_times_unchanged():
    builder = rars.RarBuilder()
    builder.add_bytes(b"payload", "file", mtime=123)
    with pytest.raises(ValueError, match="100-nanosecond"):
        builder.set_times("file", modified_ns=-100, created_ns=1)
    assert rars.RarFile.from_bytes(builder.to_bytes()).gettimes("file") == {"modified": 123_000_000_000}
