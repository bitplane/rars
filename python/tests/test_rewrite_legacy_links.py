import os
import shutil
import subprocess

import pytest
import rars

from test_rewrite_legacy import DOS_TIME


@pytest.mark.parametrize("options", [{}, {"solid": True}, {"password": "secret"}, {"password": "secret", "encrypt_headers": True, "solid": True}])
@pytest.mark.parametrize("mode", [None, 0o2750])
def test_legacy_directories_survive_edits_without_breaking_solid_data(options, mode):
    source = rars.RarBuilder(format="rar40", **options)
    source.add_bytes(b"first payload " * 200, "first", mtime=DOS_TIME)
    source.add_directory("empty", mtime=DOS_TIME, mode=mode)
    source.add_bytes(b"first payload " * 200 + b"second", "second", mtime=DOS_TIME)
    archive = rars.RarFile.from_bytes(source.to_bytes(), password=options.get("password"))
    assert archive.getinfo("empty").is_dir()
    editor = rars.RarBuilder.from_archive(archive)
    editor.rename("empty", "renamed")
    output = rars.RarFile.from_bytes(editor.to_bytes(), password=options.get("password"))
    assert output.namelist() == ["first", "renamed", "second"]
    assert output.getinfo("renamed").is_dir()
    assert output.getinfo("renamed").file_attr == archive.getinfo("empty").file_attr
    assert output.gettimes("renamed") == archive.gettimes("empty")
    assert output.read("first") == b"first payload " * 200
    assert output.read("second") == b"first payload " * 200 + b"second"
    assert output.rewrite_preservation_issues() == []
    editor.remove("first")
    output = rars.RarFile.from_bytes(editor.to_bytes(), password=options.get("password"))
    assert output.read("second") == b"first payload " * 200 + b"second"


@pytest.mark.parametrize("target", [b"missing", b"../relative-\xff", b"/absolute/target"])
@pytest.mark.parametrize("options", [{"store": True}, {"solid": True}, {"password": "secret", "encrypt_headers": True}])
def test_native_legacy_links_keep_target_bytes_through_edits(target, options):
    source = rars.RarBuilder(format="rar40", **options)
    source.add_bytes(b"first" * 200, "first")
    source.add_unix_symlink(b"link-\xff", target, mtime=DOS_TIME, mode=0o755)
    source.add_bytes(b"last" * 200, "last")
    archive = rars.RarFile.from_bytes(source.to_bytes(), password=options.get("password"))
    assert archive.readlink(b"link-\xff") == target
    editor = rars.RarBuilder.from_archive(archive)
    editor.rename(b"link-\xff", b"renamed-\xfe")
    output = rars.RarFile.from_bytes(editor.to_bytes(), password=options.get("password"))
    assert output.family == "rar15_40"
    assert output.readlink(b"renamed-\xfe") == target
    assert output.getinfo(b"renamed-\xfe").file_attr == archive.getinfo(b"link-\xff").file_attr
    assert output.gettimes(b"renamed-\xfe") == archive.gettimes(b"link-\xff")
    assert output.read("first") == b"first" * 200
    assert output.read("last") == b"last" * 200
    assert output.rewrite_preservation_issues() == []


@pytest.mark.skipif(os.name != "posix" or not shutil.which("unrar"), reason="requires Unix and unrar")
@pytest.mark.parametrize("solid", [False, True])
@pytest.mark.parametrize("links", [False, True])
@pytest.mark.parametrize("format", ["rar20", "rar40"])
def test_unrar_extracts_rewritten_legacy_directories_and_links(tmp_path, solid, links, format):
    source = rars.RarBuilder(format=format, solid=solid)
    source.add_bytes(b"payload" * 300, "file", mtime=DOS_TIME)
    source.add_directory("empty", mtime=DOS_TIME, mode=0o750)
    if links:
        source.add_unix_symlink("link", b"file", mtime=DOS_TIME)
        source.add_unix_symlink("dangling", b"missing", mtime=DOS_TIME)
    source.add_bytes(b"payload" * 300 + b"end", "last")
    editor = rars.RarBuilder.from_archive(rars.RarFile.from_bytes(source.to_bytes()))
    editor.rename("empty", "renamed")
    path = tmp_path / "archive.rar"
    editor.write(path)
    out = tmp_path / "out"
    out.mkdir()
    subprocess.run(["unrar", "x", "-idq", str(path), str(out) + "/"], check=True, capture_output=True)
    assert (out / "renamed").is_dir()
    assert (out / "renamed").stat().st_mode & 0o777 == 0o750
    if links:
        assert os.readlink(out / "link") == "file"
        assert os.readlink(out / "dangling") == "missing"
    assert (out / "last").read_bytes() == b"payload" * 300 + b"end"


@pytest.mark.parametrize("target", [b"", b"bad\0target"])
def test_invalid_native_link_target_leaves_destination_untouched(tmp_path, target):
    source = rars.RarBuilder(format="rar29", store=True)
    source.add_bytes(target, "link", mode=0o120777)
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep")
    with pytest.raises(ValueError, match="link target"):
        rars.RarBuilder.from_archive(rars.RarFile.from_bytes(source.to_bytes())).write(destination)
    assert destination.read_bytes() == b"keep"


def test_reference_legacy_directory_headers_retain_metadata():
    from test_rewrite_legacy import ROOT, headers
    # Isolate the unchanged directory records from this reference fixture;
    # its Unicode file names are outside the current preservation subset.
    data = (ROOT / "crates/rars/tests/fixtures/rar15_40/encrypted/rar4_sharpcompress_files_only.rar").read_bytes()
    blocks = [data[:7]]
    for offset, kind, flags, size in headers(data):
        if kind in [0x73, 0x7b] or (kind == 0x74 and flags & 0xe0 == 0xe0):
            blocks.append(data[offset:offset + size])
    source = rars.RarFile.from_bytes(b"".join(blocks))
    output = rars.RarFile.from_bytes(rars.RarBuilder.from_archive(source).to_bytes())
    assert len(output.infolist()) == 3
    for before, after in zip(source.infolist(), output.infolist(), strict=True):
        assert after.is_dir()
        assert after.filename == before.filename
        assert after.file_attr == before.file_attr
        assert output.gettimes(after) == source.gettimes(before)


def test_legacy_directory_payload_is_rejected_before_output(tmp_path):
    import struct
    import zlib
    from test_rewrite_legacy import headers
    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"unexpected payload", "directory")
    data = bytearray(builder.to_bytes())
    offset, _, flags, size = next(h for h in headers(data) if h[1] == 0x74)
    struct.pack_into("<H", data, offset + 3, flags | 0xe0)
    struct.pack_into("<I", data, offset + 28, 0x10)
    struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + size]) & 0xffff)
    source = rars.RarFile.from_bytes(bytes(data))
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep")
    with pytest.raises(rars.UnsupportedRarFeature):
        rars.RarBuilder.from_archive(source).write(destination)
    assert destination.read_bytes() == b"keep"
