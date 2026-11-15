import pytest
import rars


def linked_archive():
    builder = rars.RarBuilder(format="rar50", store=True)
    builder.add_bytes(b"payload", "file", mtime=10)
    builder.set_file_comment("file", b"note")
    builder.add_unix_symlink("link", "file")
    return rars.RarFile.from_bytes(builder.to_bytes())


def member_calls(archive, tmp_path):
    return {
        "getinfo": ("file", lambda m: archive.getinfo(m).filename, "file"),
        "read": ("file", lambda m: archive.read(m), b"payload"),
        "open": ("file", lambda m: archive.open(m).read(), b"payload"),
        "read_many": ("file", lambda m: archive.read_many([m]), [b"payload"]),
        "extract": ("file", lambda m: archive.extract(m, tmp_path, overwrite=True).read_bytes(), b"payload"),
        "extractall": ("file", lambda m: archive.extractall(tmp_path, members=[m], overwrite=True)[0].read_bytes(), b"payload"),
        "getcomment": ("file", lambda m: archive.getcomment(m), b"note"),
        "readlink": ("link", lambda m: archive.readlink(m), b"file"),
        "gettimes": ("file", lambda m: archive.gettimes(m)["modified"], 10_000_000_000),
    }


METHODS = ["getinfo", "read", "open", "read_many", "extract", "extractall", "getcomment", "readlink", "gettimes"]


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("kind", ["info", "str", "bytes"])
def test_every_member_method_accepts_the_same_member_kinds(tmp_path, method, kind):
    archive = linked_archive()
    name, call, expected = member_calls(archive, tmp_path)[method]
    member = {
        "info": next(info for info in archive.infolist() if info.filename == name),
        "str": name,
        "bytes": name.encode(),
    }[kind]
    assert call(member) == expected


@pytest.mark.parametrize("method", METHODS)
def test_no_member_method_selects_by_position(tmp_path, method):
    archive = linked_archive()
    _, call, _ = member_calls(archive, tmp_path)[method]
    with pytest.raises(TypeError):
        call(0)


@pytest.mark.parametrize("method", ["getcomment", "readlink", "gettimes"])
def test_metadata_reads_honour_cancellation(method):
    archive = linked_archive()
    token = rars.CancellationToken()
    token.cancel()
    member = "link" if method == "readlink" else "file"
    with pytest.raises(InterruptedError):
        getattr(archive, method)(member, options=rars.ReadOptions(cancellation=token))
    assert getattr(archive, method)(member, options=rars.ReadOptions())


@pytest.mark.parametrize("format", ["rar15", "rar20", "rar29", "rar50"])
def test_member_comments_honour_output_limits(format):
    builder = rars.RarBuilder(format=format)
    builder.add_bytes(b"payload", "file")
    builder.set_file_comment("file", b"note")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    for field in ["max_member_output_bytes", "max_total_output_bytes"]:
        assert archive.getcomment("file", options=rars.ReadOptions(**{field: 4})) == b"note"
        with pytest.raises(MemoryError):
            archive.getcomment("file", options=rars.ReadOptions(**{field: 3}))


def legacy_link(encrypt_headers):
    builder = rars.RarBuilder(format="rar40", password="right", encrypt_headers=encrypt_headers)
    builder.add_bytes(b"target", "link", mtime=10, mode=0o120777)
    return builder.to_bytes()


def test_legacy_link_targets_honour_output_limits():
    archive = rars.RarFile.from_bytes(legacy_link(False), password="right")
    assert archive.readlink("link", options=rars.ReadOptions(max_member_output_bytes=6)) == b"target"
    with pytest.raises(MemoryError):
        archive.readlink("link", options=rars.ReadOptions(max_member_output_bytes=5))


def test_readlink_takes_a_per_call_password():
    archive = rars.RarFile.from_bytes(legacy_link(False))
    with pytest.raises(rars.PasswordRequired):
        archive.readlink("link")
    assert archive.readlink("link", pwd="right") == b"target"


def test_header_encrypted_links_and_times_read_with_a_per_call_password():
    archive = rars.RarFile.from_bytes(legacy_link(True), password="right")
    with pytest.raises(rars.BadPassword):
        archive.readlink("link", pwd="wrong")
    assert archive.readlink("link", pwd="right") == b"target"
    assert archive.readlink("link") == b"target"
    plain = rars.RarFile.from_bytes(legacy_link(False))
    assert archive.gettimes("link", options=rars.ReadOptions()) == plain.gettimes("link")


@pytest.mark.parametrize("call", [
    lambda builder, info, tmp_path: builder.add(tmp_path / "source", arcname=info),
    lambda builder, info, tmp_path: builder.add_bytes(b"data", info),
    lambda builder, info, tmp_path: builder.add_directory(info),
    lambda builder, info, tmp_path: builder.add_unix_symlink(info, "target"),
    lambda builder, info, tmp_path: builder.add_unix_symlink("new-link", info),
    lambda builder, info, tmp_path: builder.rename("file", info),
], ids=["add", "add_bytes", "add_directory", "add_unix_symlink", "symlink_target", "rename"])
def test_a_rarinfo_is_not_a_new_name(tmp_path, call):
    (tmp_path / "source").write_bytes(b"data")
    archive = linked_archive()
    builder = rars.RarBuilder.from_archive(archive)
    with pytest.raises(TypeError):
        call(builder, archive.getinfo("file"), tmp_path)


def test_a_rarinfo_still_selects_an_existing_member_to_edit():
    archive = linked_archive()
    builder = rars.RarBuilder.from_archive(archive)
    builder.rename(archive.getinfo("file"), "renamed")
    builder.remove(archive.getinfo("link"))
    assert rars.RarFile.from_bytes(builder.to_bytes()).namelist() == ["renamed"]
