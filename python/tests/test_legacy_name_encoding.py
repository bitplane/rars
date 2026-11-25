"""An explicit filename view must never become the rewrite identity."""
from pathlib import Path
import pytest
import rars


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40"])
def test_decoded_names_select_extract_and_preserve(tmp_path, format):
    builder = rars.RarBuilder(version=format, level=0)
    builder.add_bytes(b"payload", b"caf\x82.txt")
    data = builder.to_bytes()
    options = rars.ReadOptions(legacy_name_encoding="cp850")
    assert options.legacy_name_encoding == "cp850"
    archive = rars.RarFile(data, options=options)
    assert archive.namelist() == ["café.txt"]
    info = archive.getinfo("café.txt")
    assert isinstance(info.orig_filename_bytes, bytes)
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
    rewritten = rars.RarFile(rewrite.to_bytes())
    assert rewritten.infolist()[0].orig_filename_bytes == b"caf\x82.txt"


@pytest.mark.parametrize("encoding,raw,expected", [
    ("cp437", b"caf\x82", "café"), ("cp850", b"\x9b", "ø"),
    ("cp852", b"\x88", "ł"), ("cp866", b"\x80", "А"),
    ("windows-1251", b"\xc0", "А"), ("windows-1252", b"\x80", "€"),
    ("utf-8", "日本語".encode(), "日本語"),
])
def test_shared_encoding_mappings(encoding, raw, expected):
    builder = rars.RarBuilder(version="rar29", level=0)
    builder.add_bytes(b"x", raw)
    archive = rars.RarFile(builder.to_bytes(), options=rars.ReadOptions(legacy_name_encoding=encoding))
    assert archive.namelist() == [expected]


def test_invalid_options_and_undefined_bytes_fail(tmp_path):
    with pytest.raises(ValueError, match="unsupported legacy"):
        rars.ReadOptions(legacy_name_encoding="bogus")
    builder = rars.RarBuilder(version="rar29", level=0)
    builder.add_bytes(b"x", b"bad-\x81")
    options = rars.ReadOptions(legacy_name_encoding="windows-1252")
    with pytest.raises(ValueError, match="undefined byte"):
        rars.RarFile(builder.to_bytes(), options=options)
    archive = rars.RarFile(builder.to_bytes())
    with pytest.raises(ValueError, match="undefined byte"):
        archive.extractall(tmp_path, options=options)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("format", ["rar50", "rar70"])
def test_modern_unicode_is_not_reinterpreted(tmp_path, format):
    builder = rars.RarBuilder(version=format, level=0)
    builder.add_bytes(b"x", "café.txt")
    archive = rars.RarFile(builder.to_bytes(), options=rars.ReadOptions(legacy_name_encoding="cp850"))
    assert archive.namelist() == ["café.txt"]
    archive.extractall(tmp_path)
    assert (tmp_path / "café.txt").read_bytes() == b"x"


def test_legacy_unicode_and_decoded_collisions(tmp_path):
    from test_rewrite_legacy_unicode import replace_first_name, unicode_wire
    builder = rars.RarBuilder(version="rar29", level=0)
    builder.add_bytes(b"unicode", "first.txt")
    builder.add_bytes(b"legacy", b"caf\x82.txt")
    data = replace_first_name(builder.to_bytes(), unicode_wire("café.txt"))
    options = rars.ReadOptions(legacy_name_encoding="cp850")
    archive = rars.RarFile(data, options=options)
    assert archive.namelist() == ["café.txt", "café.txt"]
    for operation in [archive.read, archive.getinfo]:
        with pytest.raises(ValueError, match="ambiguous"):
            operation("café.txt")
    with pytest.raises(ValueError, match="ambiguous"):
        archive.read_many(["café.txt"])
    assert archive.read_many([info.orig_filename_bytes for info in archive.infolist()]) == [b"unicode", b"legacy"]
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
    builder = rars.RarBuilder(version=format, level=0, volume_size=1024)
    payload = b"volume" * 2000
    builder.add_bytes(payload, b"caf\x82.txt")
    paths = builder.write(tmp_path / "parts.rar")
    out = tmp_path / "out"
    rars.RarFile(paths[0]).extractall(out, options=rars.ReadOptions(legacy_name_encoding="cp850"),
                                      volumes=paths[1:])
    assert (out / "café.txt").read_bytes() == payload


@pytest.mark.parametrize("volume_set", [False, True])
def test_detect_resolves_legacy_names(tmp_path, volume_set):
    names = [f"漫画の冒険と旅の物語/ページ{index:02}.jpg" for index in range(1, 21)]
    builder = rars.RarBuilder(version="rar29", level=0, volume_size=1024 if volume_set else None)
    payload = b"page" * 64
    cover = b"cover" * 500
    if volume_set:
        builder.add_bytes(cover, b"cover.jpg")
    for name in names:
        builder.add_bytes(payload, name.encode("cp932"))
    options = rars.ReadOptions(legacy_name_encoding="DeTeCt")
    if volume_set:
        first, *later = builder.write(tmp_path / "pages.rar")
        archive = rars.RarFile(first.read_bytes(), volumes=later, options=options)
        first_only = rars.RarFile(first.read_bytes(), options=options)
        assert first_only.legacy_name_encoding is None
        first_only.extractall(tmp_path / "override", volumes=iter(later))
    else:
        archive = rars.RarFile(builder.to_bytes(), options=options)
        raw_archive = rars.RarFile(builder.to_bytes())
        raw_archive.extractall(tmp_path / "override", options=options)
    assert archive.legacy_name_encoding == "cp932"
    assert archive.namelist() == (["cover.jpg"] + names if volume_set else names)
    archive.extractall(tmp_path / "opened")
    for name in names:
        assert (tmp_path / "opened" / name).read_bytes() == payload
        assert (tmp_path / "override" / name).read_bytes() == payload


def test_detect_ascii_names_use_the_default_view():
    builder = rars.RarBuilder(version="rar15", level=0)
    builder.add_bytes(b"page", "page01.jpg")
    archive = rars.RarFile(builder.to_bytes(), options=rars.ReadOptions(legacy_name_encoding="auto"))
    assert archive.legacy_name_encoding is None
    assert archive.namelist() == ["page01.jpg"]
