import pytest
import rars


FORMATS = ["rar15", "rar20", "rar29", "rar50"]
PAYLOAD = b"secret payload " * 64


def encrypted(format, compressed=True):
    builder = rars.RarBuilder(format=format, store=not compressed, password="right")
    builder.add_bytes(PAYLOAD, "file")
    return builder.to_bytes()


def calls(archive, tmp_path, pwd):
    return {
        "read": lambda: archive.read("file", pwd=pwd),
        "read_many": lambda: archive.read_many(["file"], pwd=pwd),
        "open": lambda: archive.open("file", pwd=pwd).read(),
        "extract": lambda: archive.extract("file", tmp_path / "one", pwd=pwd),
        "extractall": lambda: archive.extractall(tmp_path / "all", pwd=pwd),
        "testrar": lambda: archive.testrar(pwd=pwd),
    }


@pytest.mark.parametrize("format", FORMATS)
@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize(
    "call", ["read", "read_many", "open", "extract", "extractall", "testrar"]
)
def test_a_call_password_wins_over_the_open_password(tmp_path, format, compressed, call):
    archive = rars.RarFile.from_bytes(encrypted(format, compressed), password="right")
    with pytest.raises(rars.BadPassword):
        calls(archive, tmp_path, "wrong")[call]()
    assert archive.read("file") == PAYLOAD


@pytest.mark.parametrize("format", FORMATS)
def test_a_call_password_opens_an_archive_opened_without_one(tmp_path, format):
    archive = rars.RarFile.from_bytes(encrypted(format))
    for call in calls(archive, tmp_path, "right").values():
        call()
    assert archive.read("file", pwd="right") == PAYLOAD


def test_a_call_password_wins_in_later_volumes(tmp_path):
    builder = rars.RarBuilder(format="rar50", store=True, volume_size=4096, password="right")
    builder.add_bytes(bytes(range(256)) * 64, "large.bin")
    paths = builder.write_volumes(tmp_path / "set.part01.rar")
    archive = rars.RarFile(paths[0], password="right")
    with pytest.raises(rars.BadPassword):
        archive.read("large.bin", pwd="wrong")
    with pytest.raises(rars.BadPassword):
        archive.testrar(pwd="wrong")
    assert archive.read("large.bin") == bytes(range(256)) * 64
