"""Member objects select archive entries, even when raw names are duplicated."""
import pytest
import rars

from test_extract_guards import _rewrite_name


@pytest.mark.parametrize("format", ["rar50", "rar70"])
@pytest.mark.parametrize("solid", [False, True])
def test_duplicate_member_objects_keep_payload_and_metadata_identity(tmp_path, format, solid):
    builder = rars.RarBuilder(format=format, solid=solid, level=3 if solid else 0)
    builder.add_directory("prefix")
    builder.add_bytes(b"first", "one.txt", mtime=10)
    builder.add_bytes(b"second", "two.txt", mtime=20)
    builder.set_member_comment("one.txt", b"first comment")
    builder.set_member_comment("two.txt", b"second comment")
    data = _rewrite_name(builder.to_bytes(), b"two.txt", b"one.txt")
    archive = rars.RarFile(data)
    first, second = archive.infolist()[1:]
    assert [first.member_index, second.member_index] == [1, 2]
    assert archive.getinfo("one.txt").member_index == 2
    assert archive.getinfo(first).member_index == 1
    assert archive.read("one.txt") == b"second"
    assert archive.read_many([second, first, second]) == [b"second", b"first", b"second"]
    assert archive.read_many(iter([first, "one.txt", second])) == [b"first", b"second", b"second"]
    assert archive.read_many([second, first, second], options=rars.ReadOptions(max_total_output_bytes=11)) == [b"second", b"first", b"second"]
    with pytest.raises(rars.LimitExceeded):
        archive.read_many([second, first], options=rars.ReadOptions(max_total_output_bytes=10))
    assert archive.read_many([]) == []
    with pytest.raises(IsADirectoryError):
        archive.read_many([archive.infolist()[0]])
    with pytest.raises(KeyError):
        archive.read_many([first, "missing"])
    token = rars.CancellationToken()
    token.cancel()
    for members in [[], ["missing"], [first]]:
        with pytest.raises(rars.Cancelled):
            archive.read_many(members, cancellation=token)
    for info, payload, timestamp, comment in [
        (first, b"first", 10, b"first comment"),
        (second, b"second", 20, b"second comment"),
    ]:
        assert archive.read(info) == payload
        assert archive.open(info).read() == payload
        assert archive.member_comment(info) == comment
        assert archive.getinfo(info).mtime_ns == timestamp * 1_000_000_000
        destination = tmp_path / str(info.member_index)
        assert archive.extract(info, destination).read_bytes() == payload
        assert archive.extractall(destination, members=[info], overwrite=True)[0].read_bytes() == payload
    assert archive.member_comment("one.txt") == b"second comment"
    assert archive.getinfo("one.txt").mtime_ns == 20_000_000_000
    other = rars.RarFile(data)
    for operation in [other.read, other.getinfo, other.member_comment, other.readlink]:
        with pytest.raises(ValueError, match="different archive"):
            operation(first)
    with pytest.raises(ValueError, match="different archive"):
        other.extract(first, tmp_path / "foreign")
    with pytest.raises(ValueError, match="different archive"):
        other.extractall(tmp_path / "foreign", members=[first])
    with pytest.raises(ValueError, match="different archive"):
        other.read_many([first])
    assert not (tmp_path / "foreign").exists()


def test_membership_length_and_member_equality():
    builder = rars.RarBuilder(level=0)
    builder.add_bytes(b"a", "a.txt")
    builder.add_bytes(b"b", "b.txt")
    data = builder.to_bytes()
    archive = rars.RarFile(data)
    assert len(archive) == 2
    assert "a.txt" in archive
    assert b"b.txt" in archive
    assert "missing" not in archive
    info = archive.getinfo("a.txt")
    assert info in archive
    assert info == archive.getinfo("a.txt")
    assert info in archive.infolist()
    assert hash(info) == hash(archive.getinfo("a.txt"))
    assert info != archive.getinfo("b.txt")
    assert len({info, archive.getinfo("a.txt"), archive.getinfo("b.txt")}) == 2
    other = rars.RarFile(data)
    assert info not in other
    assert info != other.getinfo("a.txt")
    assert info != "a.txt"
