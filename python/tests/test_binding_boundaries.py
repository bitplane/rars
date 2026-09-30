"""Small public API regressions for binding-only behavior."""
from pathlib import Path

import pytest
import rars

ROOT = Path(__file__).resolve().parents[2]
STORED = ROOT / "crates/rars/tests/fixtures/rar50/stored.rar"


def test_legacy_volume_name_refusal_preserves_existing_parts(tmp_path):
    builder = rars.RarBuilder(format="rar14", store=True, volume_size=1)
    builder.add_bytes(bytes(range(128)), "payload.bin")
    first = tmp_path / "archive.rar"
    second = tmp_path / "archive.r00"
    first.write_bytes(b"original first")
    second.write_bytes(b"original second")
    with pytest.raises(ValueError, match=r"\.r00 through \.r99"):
        builder.write_volumes(first)
    assert first.read_bytes() == b"original first"
    assert second.read_bytes() == b"original second"
    assert set(tmp_path.iterdir()) == {first, second}


def test_reader_context_iteration_and_info_aliases():
    with rars.RarFile(STORED) as archive:
        assert archive.sfx_offset == 0
        assert archive.family == "rar50_plus"
        infos = list(archive)
        assert [info.filename for info in infos] == archive.namelist()
        for info in infos:
            assert info.CRC == info.crc
            assert "RarInfo(" in repr(info)
            assert isinstance(info.is_dir(), bool)
            with archive.open(info) as stream:
                assert stream.read() == archive.read(info)
    with pytest.raises(RuntimeError, match="context exception"):
        with rars.RarFile(STORED):
            raise RuntimeError("context exception")


def test_reader_modes_and_noncallable_progress_are_rejected():
    with pytest.raises(NotImplementedError, match="reading"):
        rars.RarFile(STORED, mode="w")
    builder = rars.RarBuilder(store=True)
    builder.add_bytes(b"payload", "file.txt")
    with pytest.raises(ValueError, match="progress must be callable"):
        builder.to_bytes(progress=123)
    with pytest.raises(NotImplementedError, match="filter selection"):
        rars.RarBuilder(filters=[])


def test_plain_builder_removal_and_decoded_missing_name():
    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"payload", b"caf\x82.txt")
    archive = rars.RarFile.from_bytes(
        builder.to_bytes(), options=rars.ReadOptions(legacy_name_encoding="cp850")
    )
    with pytest.raises(KeyError, match="absent"):
        archive.read("absent")
    builder.remove(b"caf\x82.txt")
    assert builder.member_ids() == []


@pytest.mark.parametrize("operation", [rars.test_volumes, rars.extract_volumes])
def test_volume_path_conversion_errors(operation, tmp_path):
    args = (tmp_path,) if operation is rars.extract_volumes else ()
    with pytest.raises(ValueError, match="volume path list is empty"):
        operation([], *args)
    with pytest.raises(TypeError):
        operation([object()], *args)

    def broken_paths():
        yield STORED
        raise RuntimeError("path iterator failed")

    with pytest.raises(RuntimeError, match="path iterator failed"):
        operation(broken_paths(), *args)


@pytest.mark.parametrize("stem", ["archive.part01.rar", "archive.part.rar", "archive.partxy.RAR", "archive", "archive.RAR"])
def test_modern_volume_stems_and_roundtrip(tmp_path, stem):
    builder = rars.RarBuilder(store=True, volume_size=64)
    builder.add_bytes(b"payload" * 20, "file.txt")
    paths = builder.write_volumes(tmp_path / stem)
    base = stem.removesuffix(".rar").removesuffix(".RAR")
    if base.endswith(".part01"):
        base = base[:-7]
    assert Path(paths[0]).name == f"{base}.part01.rar"
    rars.test_volumes(paths)


@pytest.mark.parametrize("selected", [False, True])
def test_directory_only_extraction_preserves_empty_directories(tmp_path, selected):
    builder = rars.RarBuilder(store=True)
    builder.add_directory("empty")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    paths = archive.extractall(tmp_path, members=["empty"] if selected else None)
    assert [Path(p) for p in paths] == [tmp_path / "empty"]
    assert (tmp_path / "empty").is_dir()


def test_volume_extraction_directories_overwrite_and_open_failures(tmp_path):
    builder = rars.RarBuilder(store=True, volume_size=64)
    builder.add_directory("empty")
    builder.add_bytes(b"payload" * 20, "nested/file.txt")
    paths = builder.write_volumes(tmp_path / "archive.part01.rar")
    output = tmp_path / "output"
    rars.extract_volumes(paths, output)
    assert (output / "empty").is_dir()
    assert (output / "nested/file.txt").read_bytes() == b"payload" * 20
    rars.extract_volumes(paths, output, overwrite=True)
    with pytest.raises(OSError):
        rars.extract_volumes(paths, output)


def test_volume_decoded_collisions_preserve_first_file(tmp_path):
    from test_rewrite_legacy_unicode import replace_first_name, unicode_wire

    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"unicode", "first.txt")
    builder.add_bytes(b"legacy", b"caf\x82.txt")
    path = tmp_path / "source.rar"
    path.write_bytes(replace_first_name(builder.to_bytes(), unicode_wire("café.txt")))
    out = tmp_path / "output"
    with pytest.raises(ValueError, match="same decoded output path"):
        rars.extract_volumes([path], out, overwrite=True,
                             options=rars.ReadOptions(legacy_name_encoding="cp850"))
    assert (out / "café.txt").read_bytes() == b"unicode"


def test_invalid_argument_types_and_missing_output_names(tmp_path):
    with pytest.raises(TypeError):
        rars.RarFile(STORED, password=object())
    with pytest.raises(TypeError):
        rars.RarBuilder(comment=object())
    builder = rars.RarBuilder(store=True)
    with pytest.raises(TypeError):
        builder.add_bytes(b"payload", object())
    with pytest.raises(ValueError, match="no file name"):
        builder.add(Path("/"))
    builder = rars.RarBuilder(store=True, volume_size=64)
    builder.add_bytes(b"payload", "file.txt")
    with pytest.raises(ValueError, match="needs a file name"):
        builder.write_volumes(Path("/"))


@pytest.mark.parametrize("source", ["missing", "directory"])
def test_input_open_and_read_errors_are_oserrors(tmp_path, source):
    path = tmp_path / source
    if source == "directory":
        path.mkdir()
    with pytest.raises(OSError):
        rars.RarFile(path)


@pytest.mark.parametrize("method", ["getinfo", "read", "extract", "getcomment", "readlink", "gettimes"])
def test_missing_members_raise_keyerror(tmp_path, method):
    archive = rars.RarFile(STORED)
    args = ("missing", tmp_path) if method == "extract" else ("missing",)
    with pytest.raises(KeyError):
        getattr(archive, method)(*args)


def test_invalid_member_ids_are_keyerrors():
    builder = rars.RarBuilder(store=True)
    builder.add_bytes(b"payload", "file.txt")
    for identifier in [-1, 1 << 200, 100]:
        with pytest.raises(KeyError):
            builder.remove(identifier)
    assert len(builder.member_ids()) == 1


def test_member_iterator_exception_survives_selection(tmp_path):
    archive = rars.RarFile(STORED)

    def broken_members():
        raise RuntimeError("selection iterator failed")
        yield "hello.txt"

    with pytest.raises(RuntimeError, match="selection iterator failed"):
        archive.extractall(tmp_path, members=broken_members())
    assert list(tmp_path.iterdir()) == []


def test_selected_file_skips_directory_and_empty_selection(tmp_path):
    builder = rars.RarBuilder(store=True)
    builder.add_directory("unused")
    builder.add_bytes(b"payload", "selected.txt")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    assert archive.extractall(tmp_path / "none", members=[]) == []
    archive.extractall(tmp_path / "some", members=["selected.txt"])
    assert not (tmp_path / "some/unused").exists()
    assert (tmp_path / "some/selected.txt").read_bytes() == b"payload"


def test_cancelled_volume_publication_preserves_old_destination(tmp_path):
    builder = rars.RarBuilder(format="rar14", store=True, volume_size=64)
    builder.add_bytes(b"payload" * 20, "file.txt")
    cancellation = rars.CancellationToken()

    def finish(event):
        if event.phase == "writing" and event.percentage == 100:
            cancellation.cancel()

    first = tmp_path / "archive.rar"
    first.write_bytes(b"original")
    with pytest.raises(InterruptedError):
        builder.write_volumes(first, progress=finish, cancellation=cancellation)
    assert cancellation.is_cancelled()
    assert first.read_bytes() == b"original"
    assert list(tmp_path.iterdir()) == [first]


def test_readlink_refuses_regular_members():
    archive = rars.RarFile(STORED)
    with pytest.raises(rars.UnsupportedRarFeature, match="not a supported redirection"):
        archive.readlink(archive.namelist()[0])


def test_conversion_refuses_legacy_time_outside_rar5_range():
    dos_time = (127 << 25) | (12 << 21) | (31 << 16) | (23 << 11) | (59 << 5) | 29
    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"payload", "future.txt", mtime=dos_time)
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    assert archive.getinfo("future.txt").date_time[:3] == (2107, 12, 31)
    with pytest.raises(ValueError, match="RAR5 timestamp range"):
        rars.RarBuilder.from_archive(archive, preserve=False)
    retained = rars.RarFile.from_bytes(rars.RarBuilder.from_archive(archive).to_bytes())
    assert retained.getinfo("future.txt").date_time == archive.getinfo("future.txt").date_time


@pytest.mark.parametrize("host,attributes", [(3, 0o010644), (0, 0x420)])
def test_conversion_refuses_legacy_special_types(host, attributes):
    import struct
    import zlib
    from test_rewrite_legacy import headers

    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"payload", "special.txt")
    data = bytearray(builder.to_bytes())
    offset, _, _, size = next(h for h in headers(data) if h[1] == 0x74)
    data[offset + 15] = host
    struct.pack_into("<I", data, offset + 28, attributes)
    struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + size]) & 0xffff)
    archive = rars.RarFile.from_bytes(bytes(data))
    assert archive.getinfo("special.txt").file_attr == attributes
    archive.testrar()
    with pytest.raises(rars.UnsupportedRarFeature, match="special entry"):
        rars.RarBuilder.from_archive(archive, preserve=False)


def test_modern_dos_backslash_name_uses_portable_destination(tmp_path):
    from test_extract_guards import hostile_archive

    archive = rars.RarFile.from_bytes(hostile_archive(b"one\\two.txt"))
    archive.testrar()
    archive.extractall(tmp_path)
    assert (tmp_path / "one_two.txt").read_bytes() == b"owned\n"


def test_selected_extraction_skips_redirection_before_later_file(tmp_path):
    builder = rars.RarBuilder(store=True)
    builder.add_unix_symlink("link", "target")
    builder.add_bytes(b"payload", "selected")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    archive.extractall(tmp_path, members=["selected"])
    assert not (tmp_path / "link").exists()
    assert (tmp_path / "selected").read_bytes() == b"payload"


def test_explicit_none_password_and_comment_arguments_remain_optional():
    builder = rars.RarBuilder(store=True, password=None, comment=None)
    builder.add_bytes(b"payload", "file.txt")
    builder.set_file_comment("file.txt", b"comment")
    builder.set_file_comment("file.txt", None)
    archive = rars.RarFile.from_bytes(builder.to_bytes(), password=None)
    assert archive.comment is None
    assert archive.getcomment("file.txt", pwd=None) is None
    assert archive.read("file.txt", pwd=None) == b"payload"


def test_conversion_refuses_unknown_redirection_kind():
    import zlib
    from test_extract_guards import _headers, _read_vint

    builder = rars.RarBuilder(store=True)
    builder.add_unix_symlink("link", "target")
    data = bytearray(builder.to_bytes())
    changed = False
    for crc_at, body_at, body_end in _headers(data):
        _, cursor = _read_vint(data, body_at)
        kind, cursor = _read_vint(data, cursor)
        flags, cursor = _read_vint(data, cursor)
        if kind != 2 or not flags & 1:
            continue
        extra_size, cursor = _read_vint(data, cursor)
        cursor = body_end - extra_size
        while cursor < body_end:
            size, record_start = _read_vint(data, cursor)
            tag, payload_start = _read_vint(data, record_start)
            if tag == 5:
                assert data[payload_start] == 1
                data[payload_start] = 6
                data[crc_at:crc_at + 4] = zlib.crc32(data[body_at:body_end]).to_bytes(4, "little")
                changed = True
                break
            cursor = record_start + size
    assert changed
    archive = rars.RarFile.from_bytes(bytes(data))
    assert archive.namelist() == ["link"]
    with pytest.raises(rars.UnsupportedRarFeature, match="not a supported redirection"):
        archive.readlink("link")
    with pytest.raises(rars.UnsupportedRarFeature, match="special entry"):
        rars.RarBuilder.from_archive(archive, preserve=False)


def test_conversion_refuses_payload_on_legacy_directory():
    import struct
    import zlib
    from test_rewrite_legacy import headers

    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"payload", "directory")
    data = bytearray(builder.to_bytes())
    offset, _, flags, size = next(h for h in headers(data) if h[1] == 0x74)
    struct.pack_into("<H", data, offset + 3, flags | 0xe0)
    struct.pack_into("<H", data, offset, zlib.crc32(data[offset + 2:offset + size]) & 0xffff)
    archive = rars.RarFile.from_bytes(bytes(data))
    info = archive.getinfo("directory")
    assert info.is_dir()
    assert info.file_size == 7
    with pytest.raises(rars.UnsupportedRarFeature, match="special entry"):
        rars.RarBuilder.from_archive(archive, preserve=False)
