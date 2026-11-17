"""Archive identity and native Unix paths must not pass through display text."""
import errno
import os
from pathlib import Path

import pytest
import rars


@pytest.fixture
def raw_native_names_supported(tmp_path):
    """Probe the mounted filesystem, which may reject non-UTF-8 Unix names."""
    probe = os.fsencode(tmp_path) + b"/raw-byte-probe-\xff"
    try:
        descriptor = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as error:
        if error.errno == errno.EILSEQ:
            return False
        raise
    os.close(descriptor)
    os.unlink(probe)
    return True


@pytest.mark.skipif(os.name != "posix", reason="native Unix byte names")
@pytest.mark.parametrize("format", ["rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70"])
@pytest.mark.parametrize("raw_names", [False, True], ids=["unicode", "non_utf8"])
def test_native_filename_round_trip(tmp_path, format, raw_names, request):
    if raw_names and not request.getfixturevalue("raw_native_names_supported"):
        pytest.skip("filesystem rejects non-UTF-8 filenames with EILSEQ")
    root_name = b"tree-\xfe" if raw_names else "tree-\u2603".encode()
    names = (
        [b"name-\xff", b"name-\xfe", "name-\ufffd".encode()]
        if raw_names
        else ["name-\u03bb".encode(), "name-\u96ea".encode(), "name-\ufffd".encode()]
    )
    root = tmp_path / os.fsdecode(root_name)
    root.mkdir()
    for name in names:
        (root / os.fsdecode(name)).write_bytes(name)
    builder = rars.RarBuilder(format=format, level=0)
    builder.add(root)
    archive = rars.RarFile(builder.to_bytes())
    # Lookups continue to use exact archive identity, including RAR5 mapping.
    for info in archive.infolist():
        assert archive.read(info) in names
    output = tmp_path / "out"
    archive.extractall(output)
    for name in names:
        assert (output / root.name / os.fsdecode(name)).read_bytes() == name


@pytest.fixture
def legacy_byte_archive():
    builder = rars.RarBuilder(format="rar29", level=0)
    builder.add_bytes(b"payload", b"legacy-\xff")
    return rars.RarFile(builder.to_bytes())


def test_legacy_byte_member_can_be_added_and_selected(legacy_byte_archive):
    assert legacy_byte_archive.read(b"legacy-\xff") == b"payload"


@pytest.mark.skipif(os.name != "posix", reason="native Unix byte names")
def test_legacy_byte_member_extraction(tmp_path, legacy_byte_archive, raw_native_names_supported):
    if not raw_native_names_supported:
        with pytest.raises(OSError) as raised:
            legacy_byte_archive.extract(b"legacy-\xff", tmp_path)
        # The binding currently retains the OS code in its message rather
        # than OSError.errno. Accept only the probed EILSEQ, never other I/O.
        assert raised.value.errno == errno.EILSEQ or f"(os error {errno.EILSEQ})" in str(raised.value)
        assert list(tmp_path.iterdir()) == []
        return
    written = legacy_byte_archive.extract(b"legacy-\xff", tmp_path)
    assert Path(written).read_bytes() == b"payload"
    assert os.fsencode(Path(written).name) == b"legacy-\xff"
