"""Member objects select archive entries, even when raw names are duplicated."""
import pytest
import rars

from test_extract_guards import _rewrite_name


@pytest.mark.parametrize("format", ["rar50", "rar70"])
@pytest.mark.parametrize("solid", [False, True])
def test_duplicate_member_objects_keep_payload_and_metadata_identity(tmp_path, format, solid):
    builder = rars.RarBuilder(format=format, solid=solid, store=not solid)
    builder.add_directory("prefix")
    builder.add_bytes(b"first", "one.txt", mtime=10)
    builder.add_bytes(b"second", "two.txt", mtime=20)
    builder.set_file_comment("one.txt", b"first comment")
    builder.set_file_comment("two.txt", b"second comment")
    data = _rewrite_name(builder.to_bytes(), b"two.txt", b"one.txt")
    archive = rars.RarFile.from_bytes(data)
    first, second = archive.infolist()[1:]
    assert [first.member_index, second.member_index] == [1, 2]
    assert archive.getinfo("one.txt").member_index == 2
    assert archive.getinfo(first).member_index == 1
    assert archive.read("one.txt") == b"second"
    for info, payload, timestamp, comment in [
        (first, b"first", 10, b"first comment"),
        (second, b"second", 20, b"second comment"),
    ]:
        assert archive.read(info) == payload
        assert archive.open(info).read() == payload
        assert archive.getcomment(info) == comment
        assert archive.gettimes(info)["modified"] == timestamp * 1_000_000_000
        destination = tmp_path / str(info.member_index)
        assert archive.extract(info, destination).read_bytes() == payload
        assert archive.extractall(destination, members=[info], overwrite=True)[0].read_bytes() == payload
    assert archive.getcomment("one.txt") == b"second comment"
    assert archive.gettimes("one.txt")["modified"] == 20_000_000_000
    other = rars.RarFile.from_bytes(data)
    for operation in [other.read, other.getinfo, other.getcomment, other.gettimes, other.readlink]:
        with pytest.raises(ValueError, match="different archive"):
            operation(first)
    with pytest.raises(ValueError, match="different archive"):
        other.extract(first, tmp_path / "foreign")
    with pytest.raises(ValueError, match="different archive"):
        other.extractall(tmp_path / "foreign", members=[first])
    assert not (tmp_path / "foreign").exists()
