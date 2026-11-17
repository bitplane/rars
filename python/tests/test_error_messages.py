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


def test_volume_settings_and_write_methods_must_agree(tmp_path):
    split = rars.RarBuilder(level=0, volume_size=4096)
    split.add_bytes(b"payload", "file.txt")
    with pytest.raises(ValueError, match=r"write_volumes\(\)"):
        split.write(tmp_path / "one.rar")
    with pytest.raises(ValueError, match=r"write_volumes\(\)"):
        split.to_bytes()
    whole = rars.RarBuilder(level=0)
    whole.add_bytes(b"payload", "file.txt")
    with pytest.raises(ValueError, match="volume_size"):
        whole.write_volumes(tmp_path / "set.part1.rar")
    assert list(tmp_path.iterdir()) == []


def test_a_missing_file_is_file_not_found():
    with pytest.raises(FileNotFoundError):
        rars.RarFile("no-such-archive.rar")
