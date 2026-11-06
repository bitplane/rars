import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest
import rars

MEMBER_BYTES = 2 << 20
MEMBERS = 64
ARCHIVE_BYTES = MEMBER_BYTES * MEMBERS

PEAK_RSS = textwrap.dedent("""
    import resource, sys
    import rars

    def peak():
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return rss if sys.platform == "darwin" else rss * 1024

    before = peak()
    archive = rars.RarFile(sys.argv[1])
    opened = peak()
    archive.extractall(sys.argv[2])
    print(opened - before, peak() - opened)
""")


@pytest.mark.skipif(sys.platform == "win32", reason="resource module is POSIX-only")
@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_path_open_and_extract_do_not_hold_the_archive_in_memory(tmp_path, format):
    builder = rars.RarBuilder(format=format, store=True)
    for index in range(MEMBERS):
        builder.add_bytes(os.urandom(MEMBER_BYTES), f"member{index}")
    archive = tmp_path / "archive.rar"
    builder.write(archive)
    del builder
    output = tmp_path / "out"
    opening, extracting = map(int, subprocess.run(
        [sys.executable, "-c", PEAK_RSS, str(archive), str(output)],
        check=True, capture_output=True, text=True,
    ).stdout.split())
    assert sum(path.stat().st_size for path in output.iterdir()) == ARCHIVE_BYTES
    assert opening < ARCHIVE_BYTES // 16
    assert extracting < ARCHIVE_BYTES


def test_path_open_parses_cancellably(tmp_path):
    builder = rars.RarBuilder(format="rar50", store=True)
    builder.add_bytes(b"payload", "member")
    archive = tmp_path / "archive.rar"
    builder.write(archive)
    token = rars.CancellationToken()
    token.cancel()
    with pytest.raises(InterruptedError):
        rars.RarFile(archive, options=rars.ReadOptions(cancellation=token))
    assert rars.RarFile(archive).read("member") == b"payload"


@pytest.mark.parametrize("format", ["rar14", "rar29", "rar50"])
@pytest.mark.parametrize("as_path", [False, True])
def test_relative_path_survives_working_directory_change(tmp_path, monkeypatch, format, as_path):
    builder = rars.RarBuilder(format=format, store=True)
    builder.add_bytes(b"payload", "member")
    builder.write(tmp_path / "archive.rar")
    monkeypatch.chdir(tmp_path)
    source = Path("archive.rar") if as_path else "archive.rar"
    archive = rars.RarFile(source)
    rewrite = rars.RarBuilder.from_archive(source)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    assert archive.read("member") == b"payload"
    archive.extractall("out")
    assert (elsewhere / "out" / "member").read_bytes() == b"payload"
    rewritten = rars.RarFile.from_bytes(rewrite.to_bytes())
    assert rewritten.read("member") == b"payload"
