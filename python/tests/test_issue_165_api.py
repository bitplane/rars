"""Still-open Python API lines from issue 165."""

import io
from pathlib import Path

import pytest

import rars


def test_binary_file_object_is_an_archive_and_a_wrong_type_is_named():
    builder = rars.RarBuilder(format="rar50", store=True)
    builder.add_bytes(b"hello", "hello.txt")
    data = builder.to_bytes()
    opened = rars.RarFile(io.BytesIO(data))
    assert opened.read("hello.txt") == b"hello"
    assert rars.RarFile.from_bytes(io.BytesIO(data)).read(0) == b"hello"
    with pytest.raises(TypeError, match="int"):
        rars.RarFile(123)


def test_member_methods_take_an_index_options_and_password():
    builder = rars.RarBuilder(format="rar50", store=True, password=b"secret")
    builder.add_bytes(b"payload", "nested/file.txt")
    archive = rars.RarFile.from_bytes(builder.to_bytes(), password=b"secret")
    options = rars.ReadOptions()
    assert archive.read(0, pwd=b"secret", options=options) == b"payload"
    assert archive.getinfo(0, pwd=b"secret", options=options).filename.endswith("file.txt")
    assert archive.getcomment(0, pwd=b"secret", options=options) is None
    times = archive.gettimes(0, pwd=b"secret", options=options)
    assert set(times) <= {"modified", "created", "accessed"}
    assert all(isinstance(value, int) for value in times.values())


def test_progress_callbacks_run_for_extractall_testrar_and_read_many(tmp_path):
    builder = rars.RarBuilder(format="rar50", store=True)
    builder.add_bytes(b"one", "one.txt")
    builder.add_bytes(b"two", "two.txt")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    seen = []
    archive.extractall(tmp_path / "out", progress=lambda name: seen.append(("extract", name)))
    archive.testrar(progress=lambda name: seen.append(("test", name)))
    chunks = archive.read_many(["one.txt", "two.txt"], progress=lambda name, size: seen.append(("read", name, size)))
    assert chunks == [b"one", b"two"]
    assert ("extract", "one.txt") in seen
    assert ("test", "one.txt") in seen
    assert ("read", "one.txt", 3) in seen
    assert ("read", "two.txt", 3) in seen


def test_volume_progress_names_members_past_the_first_volume(tmp_path):
    payload = b"0123456789" * 40
    tail = b"abcde"
    builder = rars.RarBuilder(format="rar50", store=True, volume_size=220)
    builder.add_bytes(payload, "dir/file.bin")
    builder.add_bytes(tail, "tail.txt")
    (tmp_path / "in").mkdir()
    parts = builder.write_volumes(tmp_path / "in" / "set.part01.rar")
    assert len(parts) >= 2
    with rars.RarFile(parts[0]) as archive:
        assert "tail.txt" not in archive.namelist()
        tested = []
        archive.testrar(volumes=parts[1:], progress=lambda name: tested.append(name))
        assert tested == ["dir/file.bin", "tail.txt"]
        read = []
        chunks = archive.read_many(
            ["dir/file.bin", "tail.txt"],
            volumes=parts[1:],
            progress=lambda name, size: read.append((name, size)),
        )
    assert chunks == [payload, tail]
    assert read == [("dir/file.bin", len(payload)), ("tail.txt", len(tail))]


def test_flatten_drops_directories_and_renames_a_clash(tmp_path):
    builder = rars.RarBuilder(format="rar50", store=True)
    builder.add_bytes(b"first", "dir/readme.txt")
    builder.add_bytes(b"second", "other/readme.txt")
    builder.add_directory("dir")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    written = archive.extractall(tmp_path / "flat", flatten=True, overwrite="rename")
    names = sorted(path.name for path in written)
    assert names == ["readme(1).txt", "readme.txt"]
    assert (tmp_path / "flat" / "readme.txt").read_bytes() == b"first"
    assert (tmp_path / "flat" / "readme(1).txt").read_bytes() == b"second"
    assert not (tmp_path / "flat" / "dir").exists()
    again = archive.extractall(tmp_path / "flat2", flatten=True, overwrite="rename")
    assert sorted(Path(path).name for path in again) == names


def test_from_archive_volumes_need_options(tmp_path):
    source = rars.RarBuilder(format="rar50", store=True, volume_size=300)
    source.add_bytes(b"0123456789" * 80, "dir/file.bin")
    (tmp_path / "in").mkdir()
    parts = source.write_volumes(tmp_path / "in" / "set.part01.rar")
    with pytest.raises(ValueError, match="volumes requires options"):
        rars.RarBuilder.from_archive(parts[0], volumes=parts[1:])


def test_from_archive_options_rewrites_a_volume_set(tmp_path):
    payload = b"0123456789" * 80
    source = rars.RarBuilder(format="rar50", store=True, volume_size=300)
    source.add_bytes(payload, "dir/file.bin")
    (tmp_path / "in").mkdir()
    parts = source.write_volumes(tmp_path / "in" / "set.part01.rar")
    assert len(parts) > 1
    rewritten = rars.RarBuilder.from_archive(
        parts[0],
        volumes=parts[1:],
        options=rars.RarBuilder(format="rar50", store=True, volume_size=250),
    )
    (tmp_path / "out").mkdir()
    out = rewritten.write_volumes(tmp_path / "out" / "set.part01.rar")
    assert len(out) > 1
    with rars.RarFile(out[0]) as archive:
        assert archive.read("dir/file.bin", volumes=out[1:]) == payload
