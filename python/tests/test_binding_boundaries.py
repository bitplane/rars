"""Small public API regressions for binding-only behavior."""
from pathlib import Path

import pytest
import rars

ROOT = Path(__file__).resolve().parents[2]
STORED = ROOT / "crates/rars/tests/fixtures/rar50/stored.rar"


def test_legacy_volume_name_refusal_preserves_existing_parts(tmp_path):
    builder = rars.RarBuilder(format="rar14", store=True, volume_size=1)
    builder.add_bytes(bytes(range(128)), "payload.bin")
    first = tmp_path / "archive.rar"
    second = tmp_path / "archive.r00"
    first.write_bytes(b"original first")
    second.write_bytes(b"original second")
    with pytest.raises(ValueError, match=r"\.r00 through \.r99"):
        builder.write_volumes(first)
    assert first.read_bytes() == b"original first"
    assert second.read_bytes() == b"original second"
    assert set(tmp_path.iterdir()) == {first, second}


def test_reader_context_iteration_and_info_aliases():
    with rars.RarFile(STORED) as archive:
        assert archive.sfx_offset == 0
        assert archive.family == "rar50_plus"
        infos = list(archive)
        assert [info.filename for info in infos] == archive.namelist()
        for info in infos:
            assert info.CRC == info.crc
            assert "RarInfo(" in repr(info)
            assert isinstance(info.is_dir(), bool)
            with archive.open(info) as stream:
                assert stream.read() == archive.read(info)
    with pytest.raises(RuntimeError, match="context exception"):
        with rars.RarFile(STORED):
            raise RuntimeError("context exception")


def test_reader_modes_and_noncallable_progress_are_rejected():
    with pytest.raises(NotImplementedError, match="reading"):
        rars.RarFile(STORED, mode="w")
    builder = rars.RarBuilder(store=True)
    builder.add_bytes(b"payload", "file.txt")
    with pytest.raises(ValueError, match="progress must be callable"):
        builder.to_bytes(progress=123)
    with pytest.raises(NotImplementedError, match="filter selection"):
        rars.RarBuilder(filters=[])
