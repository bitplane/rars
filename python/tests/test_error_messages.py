import pytest
import rars


def archive():
    builder = rars.RarBuilder(level=0)
    builder.add_bytes(b"payload", "file.txt")
    return rars.RarFile(builder.to_bytes())


def test_a_refused_overwrite_names_the_file_and_the_way_past_it(tmp_path):
    source = archive()
    source.extractall(tmp_path)
    for extract in (lambda: source.extractall(tmp_path), lambda: source.extract("file.txt", tmp_path)):
        with pytest.raises(FileExistsError, match="overwrite=True") as raised:
            extract()
        assert str(tmp_path / "file.txt") in str(raised.value)
    assert (tmp_path / "file.txt").read_bytes() == b"payload"


def test_write_returns_every_file_it_wrote(tmp_path):
    split = rars.RarBuilder(level=0, volume_size=4096)
    split.add_bytes(bytes(range(256)) * 64, "file.bin")
    with pytest.raises(ValueError, match=r"write\(\)"):
        split.to_bytes()
    paths = split.write(tmp_path / "set.rar")
    assert len(paths) > 1
    assert paths[0] == tmp_path / "set.part01.rar"
    assert sorted(tmp_path.iterdir()) == paths
    whole = rars.RarBuilder(level=0)
    whole.add_bytes(b"payload", "file.txt")
    assert whole.write(tmp_path / "one.rar") == [tmp_path / "one.rar"]
    assert not hasattr(whole, "write_volumes")


def test_a_missing_file_is_file_not_found():
    with pytest.raises(FileNotFoundError):
        rars.RarFile("no-such-archive.rar")
