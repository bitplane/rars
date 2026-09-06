"""Archive identity and native Unix paths must not pass through display text."""
import os
from pathlib import Path

import pytest
import rars


@pytest.mark.skipif(os.name != "posix", reason="native Unix byte names")
@pytest.mark.parametrize("format", ["rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70"])
def test_native_filename_round_trip(tmp_path, format):
    root = tmp_path / os.fsdecode(b"tree-\xfe")
    root.mkdir()
    names = [b"name-\xff", b"name-\xfe", "name-\ufffd".encode()]
    for name in names:
        (root / os.fsdecode(name)).write_bytes(name)
    builder = rars.RarBuilder(format=format, store=True)
    builder.add(root)
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    # Lookups continue to use exact archive identity, including RAR5 mapping.
    for info in archive.infolist():
        assert archive.read(info) in names
    output = tmp_path / "out"
    archive.extractall(output)
    for name in names:
        assert (output / root.name / os.fsdecode(name)).read_bytes() == name


@pytest.mark.skipif(os.name != "posix", reason="native Unix byte names")
def test_legacy_byte_member_can_be_added_and_selected(tmp_path):
    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"payload", b"legacy-\xff")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    assert archive.read(b"legacy-\xff") == b"payload"
    written = archive.extract(b"legacy-\xff", tmp_path)
    assert Path(written).read_bytes() == b"payload"
    assert os.fsencode(Path(written).name) == b"legacy-\xff"
