import pytest
import rars


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40"])
def test_legacy_name_limit_is_an_option_error(format):
    builder = rars.RarBuilder(format=format, store=True)
    name = "a" * (256 if format in ("rar13", "rar14") else 65536)
    builder.add_bytes(b"payload", name)
    with pytest.raises(ValueError, match="file name"):
        builder.to_bytes()
