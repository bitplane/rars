from pathlib import Path

import pytest
import rars


def times(info):
    return info.mtime_ns, info.birthtime_ns, info.atime_ns


@pytest.mark.parametrize("given", [
    dict(mtime_ns=0, birthtime_ns=123, atime_ns=4_294_967_295_999_999_999),
    dict(mtime_ns=-11_644_473_600_000_000_000, birthtime_ns=1_728_229_934_970_955_161_500, atime_ns=100),
    dict(birthtime_ns=0, atime_ns=123_456_789),
])
def test_rewrite_preserves_all_file_times_without_narrowing(given):
    builder = rars.RarBuilder()
    builder.add_bytes(b"payload", "file")
    builder.set_times("file", **given)
    expected = (given.get("mtime_ns"), given.get("birthtime_ns"), given.get("atime_ns"))
    source = rars.RarFile(builder.to_bytes())
    assert times(source.getinfo("file")) == expected
    assert source.rewrite_preservation_issues() == []
    rewritten = rars.RarBuilder.from_archive(source, preserve=True)
    rewritten.rename("file", "renamed")
    output = rars.RarFile(rewritten.to_bytes())
    assert times(output.getinfo("renamed")) == expected
    assert output.read("renamed") == b"payload"


def test_legacy_extended_times_survive_conversion():
    source = rars.RarFile(Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures/rar15_40/rar420/ext_time_rar420.rar")
    output = rars.RarFile(rars.RarBuilder.from_archive(source, preserve=False).to_bytes())
    for name in source.namelist():
        assert times(output.getinfo(name)) == times(source.getinfo(name))


def test_unrepresentable_mixed_precision_leaves_queued_times_unchanged():
    builder = rars.RarBuilder()
    builder.add_bytes(b"payload", "file", mtime=123)
    with pytest.raises(ValueError, match="100-nanosecond"):
        builder.set_times("file", mtime_ns=-100, birthtime_ns=1)
    assert times(rars.RarFile(builder.to_bytes()).getinfo("file")) == (123_000_000_000, None, None)
