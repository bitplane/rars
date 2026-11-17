import time
from datetime import datetime

import pytest
import rars


@pytest.mark.parametrize("seconds, expected", [
    (None, None),
    (0, (1970, 1, 1, 0, 0, 0)),
    (951_827_696, (2000, 2, 29, 12, 34, 56)),
    (1_700_000_002, (2023, 11, 14, 22, 13, 22)),
    (0xFFFFFFFF, (2106, 2, 7, 6, 28, 15)),
])
def test_rar5_times_are_unix_and_date_time_is_local(seconds, expected):
    builder = rars.RarBuilder(level=0)
    builder.add_bytes(b"time", "file", mtime=seconds)
    info = rars.RarFile(builder.to_bytes()).getinfo("file")
    if seconds is None:
        assert info.date_time is info.mtime is info.mtime_ns is None
        return
    assert info.mtime_ns == seconds * 10**9
    assert info.mtime == seconds
    assert info.date_time == time.localtime(seconds)[:6]
    assert time.gmtime(seconds)[:6] == expected


def test_legacy_date_time_keeps_stored_wall_clock_fields():
    # RAR 1.3-4.x store local wall-clock fields; date_time shows them as stored.
    seconds = int(datetime(2026, 7, 15, 15, 23, 42).timestamp())
    builder = rars.RarBuilder(version="rar29", level=0)
    builder.add_bytes(b"time", "file", mtime=seconds)
    archive = rars.RarFile(builder.to_bytes())
    assert archive.getinfo("file").date_time == (2026, 7, 15, 15, 23, 42)


@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_mtime_takes_a_float_as_stat_gives_it(format):
    builder = rars.RarBuilder(version=format, level=0)
    builder.add_bytes(b"time", "file", mtime=1_700_000_000.25)
    info = rars.RarFile(builder.to_bytes()).getinfo("file")
    if format == "rar50":
        assert info.mtime_ns == 1_700_000_000_250_000_000
    else:
        assert info.mtime == pytest.approx(1_700_000_000.25, abs=2)
    with pytest.raises(ValueError):
        builder.add_bytes(b"x", "nan", mtime=float("nan"))
