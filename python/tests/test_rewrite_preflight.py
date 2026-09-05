import zlib
from pathlib import Path

import pytest
import rars

from test_extract_guards import _headers, _read_vint


def archive_bytes(**options):
    builder = rars.RarBuilder(**options)
    builder.add_directory("empty", mtime=123)
    builder.add_bytes(b"payload" * 40, "file", mtime=1_700_000_002)
    return builder.to_bytes()


def test_preservation_opt_in_accepts_supported_rar5_metadata():
    source = rars.RarFile.from_bytes(archive_bytes(comment=b"comment"))
    assert source.rewrite_preservation_issues() == []
    rewritten = rars.RarBuilder.from_archive(source, preserve=True)
    rewritten.rename("file", "renamed")
    output = rars.RarFile.from_bytes(rewritten.to_bytes())
    assert output.comment == b"comment"
    assert output.namelist() == ["empty", "renamed"]
    assert output.getinfo("empty").is_dir()
    assert output.read("renamed") == b"payload" * 40


@pytest.mark.parametrize("options, feature", [
    ({"solid": True}, "solid"),
    ({"password": "secret"}, "data encryption"),
    ({"password": "secret", "encrypt_headers": True}, "header encryption"),
    ({"recovery_percent": 5}, "recovery"),
])
def test_preservation_preflight_rejects_settings_before_output(tmp_path, options, feature):
    source = rars.RarFile.from_bytes(archive_bytes(**options), password=options.get("password"))
    assert any(feature in issue for issue in source.rewrite_preservation_issues())
    destination = tmp_path / "existing.rar"
    destination.write_bytes(b"keep existing archive")
    with pytest.raises(rars.UnsupportedRarFeature, match=feature):
        rars.RarBuilder.from_archive(source, preserve=True).write(destination)
    assert destination.read_bytes() == b"keep existing archive"
    # Existing conversion remains explicit and available.
    output = rars.RarFile.from_bytes(rars.RarBuilder.from_archive(source, preserve=False).to_bytes())
    assert output.read("file") == b"payload" * 40


@pytest.mark.parametrize("damage", ["unknown", "incomplete"])
def test_skipped_extra_metadata_cannot_pass_preservation_preflight(damage):
    data = bytearray(archive_bytes(store=True))
    for crc_at, body_at, body_end in _headers(data):
        _, cursor = _read_vint(data, body_at)
        kind, cursor = _read_vint(data, cursor)
        flags, cursor = _read_vint(data, cursor)
        if kind != 2 or not flags & 1:
            continue
        extra_size, _ = _read_vint(data, cursor)
        extra_at = body_end - extra_size
        _, type_at = _read_vint(data, extra_at)
        if damage == "unknown":
            data[type_at] = 63
        else:
            data[extra_at] = 127  # Claims more bytes than this extra area holds.
        data[crc_at:crc_at + 4] = zlib.crc32(data[body_at:body_end]).to_bytes(4, "little")
        break
    source = rars.RarFile.from_bytes(bytes(data))
    assert source.read("file") == b"payload" * 40
    assert any("metadata" in issue for issue in source.rewrite_preservation_issues())
    with pytest.raises(rars.UnsupportedRarFeature, match="metadata"):
        rars.RarBuilder.from_archive(source, preserve=True)


@pytest.mark.parametrize("suffix", [b"trailing metadata", None])
def test_trailing_bytes_or_missing_end_cannot_pass_preflight(suffix):
    data = archive_bytes(store=True)
    data = data + suffix if suffix is not None else data[:_headers(data)[-1][0]]
    source = rars.RarFile.from_bytes(data)
    assert source.read("file") == b"payload" * 40
    assert source.rewrite_preservation_issues()
    with pytest.raises(rars.UnsupportedRarFeature):
        rars.RarBuilder.from_archive(source, preserve=True)


def test_legacy_preservation_is_explicitly_unimplemented():
    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"payload", "file")
    source = rars.RarFile.from_bytes(builder.to_bytes())
    assert any("legacy source format" in issue for issue in source.rewrite_preservation_issues())
    with pytest.raises(rars.UnsupportedRarFeature, match="legacy source format"):
        rars.RarBuilder.from_archive(source, preserve=True)


def test_preflight_checks_on_disk_requirements_not_creator_version():
    # The RAR7 writer may emit fully RAR5-compatible headers. Its creating
    # release cannot be inferred from these bytes and is not a preservation promise.
    compatible = rars.RarFile.from_bytes(archive_bytes(format="rar70"))
    assert compatible.rewrite_preservation_issues() == []
    fixture = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures/rar50/algorithm_version_2_stored.rar"
    future = rars.RarFile(fixture)
    assert any("source format" in issue for issue in future.rewrite_preservation_issues())
    with pytest.raises(rars.UnsupportedRarFeature, match="source format"):
        rars.RarBuilder.from_archive(future, preserve=True)


def test_preflight_accepts_supported_fractional_mtime():
    fixture = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures/rar15_40/rar420/ext_time_rar420.rar"
    converted = rars.RarBuilder.from_archive(fixture).to_bytes()
    source = rars.RarFile.from_bytes(converted)
    assert source.rewrite_preservation_issues() == []
    assert rars.RarBuilder.from_archive(source, preserve=True).to_bytes() == converted


def test_preflight_detects_volume_settings(tmp_path):
    builder = rars.RarBuilder(store=True, volume_size=128)
    builder.add_bytes(b"payload" * 100, "file")
    paths = builder.write_volumes(tmp_path / "archive.part01.rar")
    assert len(paths) > 1
    source = rars.RarFile(paths[0])
    assert any("volume" in issue for issue in source.rewrite_preservation_issues())
    with pytest.raises(rars.UnsupportedRarFeature, match="volume"):
        rars.RarBuilder.from_archive(source, preserve=True)
