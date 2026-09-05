import pytest
import rars


@pytest.mark.parametrize("seconds, expected", [
    (None, None),
    (0, (1970, 1, 1, 0, 0, 0)),
    (951_827_696, (2000, 2, 29, 12, 34, 56)),
    (1_700_000_002, (2023, 11, 14, 22, 13, 22)),
    (0xFFFFFFFF, (2106, 2, 7, 6, 28, 15)),
])
def test_rar5_date_time_is_utc(seconds, expected):
    builder = rars.RarBuilder(store=True)
    builder.add_bytes(b"time", "file", mtime=seconds)
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    assert archive.getinfo("file").date_time == expected


def test_legacy_date_time_keeps_stored_wall_clock_fields():
    raw = ((2026 - 1980) << 25) | (7 << 21) | (15 << 16) | (15 << 11) | (23 << 5) | 21
    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"time", "file", mtime=raw)
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    assert archive.getinfo("file").date_time == (2026, 7, 15, 15, 23, 42)
