"""Native preservation of the unpacker-20 format, including vintage input."""
import shutil
import struct
import subprocess
import zlib

import pytest
import rars

from test_rewrite_legacy import ROOT, file_metadata, headers, source_bytes, with_extended_times


@pytest.mark.parametrize("fixture", [
    "rar202/comment_nopsw.rar", "rar202/comment_psw.rar",
    "rar250/SOLID.RAR", "rar250/AUDIO.RAR", "rar250/BIGLZ.RAR",
    "rar250/AUTOREJ.RAR", "rar250/unpack20_keep_tables.rar",
    "rar250/unpack20_multiblock.rar", "rar250/unpack20_audio_text.rar",
])
def test_vintage_rar20_preserves_metadata_comments_and_payloads(tmp_path, fixture):
    path = ROOT / "crates/rars/tests/fixtures/rar15_40" / fixture
    source = rars.RarFile(path, password="password")
    editor = rars.RarBuilder.from_archive(source)
    name = source.namelist()[0]
    editor.rename(name, "renamed")
    data = editor.to_bytes()
    output = rars.RarFile.from_bytes(data, password="password")
    assert output.rewrite_preservation_issues() == []
    assert output.comment == source.comment
    assert bool(next(headers(data))[2] & 8) == bool(next(headers(path.read_bytes()))[2] & 8)
    for before, after in zip(source.namelist(), output.namelist(), strict=True):
        assert output.read(after) == source.read(before)
        assert output.getcomment(after) == source.getcomment(before)
        assert output.gettimes(after) == source.gettimes(before)
        assert output.getinfo(after).file_attr == source.getinfo(before).file_attr
        assert output.getinfo(after).is_encrypted == source.getinfo(before).is_encrypted
    for before, after in zip(file_metadata(path.read_bytes()), file_metadata(data), strict=True):
        assert after[2:] == before[2:]
        assert after[3] == 20
    if shutil.which("unrar"):
        archive = tmp_path / "rewritten.rar"
        archive.write_bytes(data)
        result = subprocess.run(["unrar", "t", "-ppassword", str(archive)], capture_output=True)
        if fixture.startswith("rar202/"):
            # Modern UnRAR reports three comment-header errors on these vintage
            # originals too; require the same diagnostics and successful data checks.
            baseline = subprocess.run(["unrar", "t", "-ppassword", str(path)], capture_output=True)
            assert result.returncode == baseline.returncode == 3
            assert result.stderr == baseline.stderr
            assert b"Total errors: 3" in result.stdout
            assert result.stdout.count(b" OK ") == baseline.stdout.count(b" OK ") == 2
        else:
            assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("damage", ["mixed", "salt", "extended", "version26"])
def test_unsupported_rar20_combinations_leave_destination_untouched(tmp_path, damage):
    data = source_bytes("rar20", store=True)
    if damage == "extended":
        data = with_extended_times(data, b"\0\0")
    else:
        data = bytearray(data)
        offset, _, flags, size = next(h for h in headers(data) if h[1] == 0x74)
        if damage in ("mixed", "version26"):
            data[offset + 24] = 29 if damage == "mixed" else 26
        else:
            data[offset + size:offset + size] = b"salt1234"
            struct.pack_into("<H", data, offset + 3, flags | 0x400)
            size += 8
            struct.pack_into("<H", data, offset + 5, size)
        struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + size]) & 0xffff)
    source = rars.RarFile.from_bytes(bytes(data))
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep")
    with pytest.raises(rars.UnsupportedRarFeature):
        rars.RarBuilder.from_archive(source).write(destination)
    assert destination.read_bytes() == b"keep"
