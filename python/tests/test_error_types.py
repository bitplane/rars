import random

import pytest
import rars


def rar_bytes():
    builder = rars.RarBuilder(format="rar50", store=True)
    builder.add_bytes(b"payload", "file.txt")
    return builder.to_bytes()


@pytest.mark.parametrize(
    "data",
    [
        b"PK\x03\x04" + bytes(100),
        b"",
        random.Random(5).randbytes(4096),
    ],
    ids=["zip", "empty", "random"],
)
def test_input_without_a_rar_signature_is_not_a_rar_file(tmp_path, data):
    path = tmp_path / "input.bin"
    path.write_bytes(data)
    with pytest.raises(rars.NotRarFile) as raised:
        rars.RarFile(path)
    assert isinstance(raised.value, rars.Error)
    assert not isinstance(raised.value, (rars.BadRarFile, rars.UnsupportedRarFeature))
    with pytest.raises(rars.NotRarFile):
        rars.RarFile(data)


def test_an_sfx_stub_inside_the_scan_limit_still_opens():
    stub = b"MZ" + random.Random(6).randbytes(64 * 1024)
    with rars.RarFile(stub + rar_bytes()) as archive:
        assert archive.read("file.txt") == b"payload"
        assert archive.sfx_offset == len(stub)
