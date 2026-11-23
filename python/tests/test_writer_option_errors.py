import pytest
import rars


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40"])
def test_legacy_name_limit_is_an_option_error(format):
    builder = rars.RarBuilder(version=format, level=0)
    name = "a" * (256 if format in ("rar13", "rar14") else 65536)
    builder.add_bytes(b"payload", name)
    with pytest.raises(ValueError, match="file name"):
        builder.to_bytes()


@pytest.mark.parametrize("format", ["rar15", "rar29", "rar50"])
def test_level_zero_stores(format):
    payload = b"compressible " * 1000
    builder = rars.RarBuilder(version=format, level=0)
    builder.add_bytes(payload, "file")
    info = rars.RarFile(builder.to_bytes()).getinfo("file")
    assert info.compress_size == len(payload)
    with pytest.raises(TypeError):
        rars.RarBuilder(version=format, store=True)


@pytest.mark.parametrize("settings", [
    dict(level=-1),
    dict(level=6),
    dict(recovery_percent=0),
    dict(recovery_percent=101),
    dict(version="rar29", recovery_percent=5),
    dict(encrypt_headers=True),
    dict(version="rar20", password="pw", encrypt_headers=True),
    dict(version="rar40", blake2sp=True),
    dict(volume_size=0),
    dict(comment="note", volume_size=4096),
    dict(version="rar29", resources=rars.WriterResources(max_memory_bytes=1 << 20)),
])
def test_bad_settings_are_value_errors_at_construction(settings):
    with pytest.raises(ValueError):
        rars.RarBuilder(**settings)
