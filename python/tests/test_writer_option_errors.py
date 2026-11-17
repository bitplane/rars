import pytest
import rars


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40"])
def test_legacy_name_limit_is_an_option_error(format):
    builder = rars.RarBuilder(format=format, level=0)
    name = "a" * (256 if format in ("rar13", "rar14") else 65536)
    builder.add_bytes(b"payload", name)
    with pytest.raises(ValueError, match="file name"):
        builder.to_bytes()


@pytest.mark.parametrize("format", ["rar15", "rar29", "rar50"])
def test_level_zero_stores(format):
    payload = b"compressible " * 1000
    builder = rars.RarBuilder(format=format, level=0)
    builder.add_bytes(payload, "file")
    info = rars.RarFile(builder.to_bytes()).getinfo("file")
    assert info.compress_size == len(payload)
    with pytest.raises(TypeError):
        rars.RarBuilder(format=format, store=True)
