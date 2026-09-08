"""An explicit filename view must never become the rewrite identity."""
from pathlib import Path
import pytest
import rars


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40"])
def test_decoded_names_select_extract_and_preserve(tmp_path, format):
    builder = rars.RarBuilder(format=format, store=True)
    builder.add_bytes(b"payload", b"caf\x82.txt")
    data = builder.to_bytes()
    options = rars.ReadOptions(legacy_name_encoding="cp850")
    assert options.legacy_name_encoding == "cp850"
    archive = rars.RarFile.from_bytes(data, options=options)
    assert archive.namelist() == ["café.txt"]
    info = archive.getinfo("café.txt")
    assert info.orig_filename_bytes == b"caf\x82.txt"
    assert archive.read("café.txt") == b"payload"
    assert archive.read(info) == b"payload"
    assert archive.read(b"caf\x82.txt") == b"payload"
    assert Path(archive.extract("café.txt", tmp_path / "one")).name == "café.txt"
    archive.extractall(tmp_path / "all", members=["café.txt"])
    assert (tmp_path / "all" / "café.txt").read_bytes() == b"payload"
    # Passing other read limits does not forget the opened name policy.
    archive.extractall(tmp_path / "limits", options=rars.ReadOptions(max_total_output_bytes=7))
    assert (tmp_path / "limits" / "café.txt").read_bytes() == b"payload"
    rewrite = rars.RarBuilder.from_archive(archive)
    rewritten = rars.RarFile.from_bytes(rewrite.to_bytes())
    assert rewritten.infolist()[0].orig_filename_bytes == b"caf\x82.txt"


@pytest.mark.parametrize("encoding,raw,expected", [
    ("cp437", b"caf\x82", "café"), ("cp850", b"\x9b", "ø"),
    ("cp852", b"\x88", "ł"), ("cp866", b"\x80", "А"),
    ("windows-1251", b"\xc0", "А"), ("windows-1252", b"\x80", "€"),
    ("utf-8", "日本語".encode(), "日本語"),
])
def test_shared_encoding_mappings(encoding, raw, expected):
    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"x", raw)
    archive = rars.RarFile.from_bytes(builder.to_bytes(), options=rars.ReadOptions(legacy_name_encoding=encoding))
    assert archive.namelist() == [expected]


def test_invalid_options_and_undefined_bytes_fail(tmp_path):
    with pytest.raises(ValueError, match="unsupported legacy"):
        rars.ReadOptions(legacy_name_encoding="auto")
    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"x", b"bad-\x81")
    options = rars.ReadOptions(legacy_name_encoding="windows-1252")
    with pytest.raises(ValueError, match="undefined byte"):
        rars.RarFile.from_bytes(builder.to_bytes(), options=options)
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    with pytest.raises(ValueError, match="undefined byte"):
        archive.extractall(tmp_path, options=options)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("format", ["rar50", "rar70"])
def test_modern_unicode_is_not_reinterpreted(tmp_path, format):
    builder = rars.RarBuilder(format=format, store=True)
    builder.add_bytes(b"x", "café.txt")
    archive = rars.RarFile.from_bytes(builder.to_bytes(), options=rars.ReadOptions(legacy_name_encoding="cp850"))
    assert archive.namelist() == ["café.txt"]
    archive.extractall(tmp_path)
    assert (tmp_path / "café.txt").read_bytes() == b"x"


def test_legacy_unicode_and_decoded_collisions(tmp_path):
    from test_rewrite_legacy_unicode import replace_first_name, unicode_wire
    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"unicode", "first.txt")
    builder.add_bytes(b"legacy", b"caf\x82.txt")
    data = replace_first_name(builder.to_bytes(), unicode_wire("café.txt"))
    options = rars.ReadOptions(legacy_name_encoding="cp850")
    archive = rars.RarFile.from_bytes(data, options=options)
    assert archive.namelist() == ["café.txt", "café.txt"]
    with pytest.raises(ValueError, match="ambiguous"):
        archive.read("café.txt")
    assert archive.read(archive.infolist()[0]) == b"unicode"
    assert archive.read(archive.infolist()[1]) == b"legacy"
    for selected in [None, archive.infolist()]:
        out = tmp_path / ("all" if selected is None else "selected")
        with pytest.raises(ValueError, match="same decoded output path"):
            archive.extractall(out, members=selected, overwrite=True)
        assert (out / "café.txt").read_bytes() == b"unicode"
    # Selecting the Unicode entry alone must not reinterpret its UTF-8 bytes.
    archive.extract(archive.infolist()[0], tmp_path / "unicode")
    assert (tmp_path / "unicode" / "café.txt").read_bytes() == b"unicode"


@pytest.mark.parametrize("format", ["rar14", "rar29", "rar40"])
def test_volume_extraction_uses_name_policy(tmp_path, format):
    builder = rars.RarBuilder(format=format, store=True, volume_size=1024)
    payload = b"volume" * 2000
    builder.add_bytes(payload, b"caf\x82.txt")
    paths = builder.write_volumes(tmp_path / "parts.rar")
    out = tmp_path / "out"
    rars.extract_volumes(paths, out, options=rars.ReadOptions(legacy_name_encoding="cp850"))
    assert (out / "café.txt").read_bytes() == payload
