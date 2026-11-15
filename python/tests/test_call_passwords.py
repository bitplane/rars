from pathlib import Path

import pytest
import rars


FORMATS = ["rar15", "rar20", "rar29", "rar50"]
PAYLOAD = b"secret payload " * 64
ENCRYPTED = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures/rar15_40/encrypted"


def encrypted(format, compressed=True):
    builder = rars.RarBuilder(format=format, store=not compressed, password="right")
    builder.add_bytes(PAYLOAD, "file")
    return builder.to_bytes()


def calls(archive, tmp_path, password):
    return {
        "read": lambda: archive.read("file", password=password),
        "read_many": lambda: archive.read_many(["file"], password=password),
        "open": lambda: archive.open("file", password=password).read(),
        "extract": lambda: archive.extract("file", tmp_path / "one", password=password),
        "extractall": lambda: archive.extractall(tmp_path / "all", password=password),
        "testrar": lambda: archive.testrar(password=password),
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
    assert archive.read("file", password="right") == PAYLOAD


def test_a_call_password_wins_in_later_volumes(tmp_path):
    builder = rars.RarBuilder(format="rar50", store=True, volume_size=4096, password="right")
    builder.add_bytes(bytes(range(256)) * 64, "large.bin")
    paths = builder.write_volumes(tmp_path / "set.part01.rar")
    archive = rars.RarFile(paths[0], password="right")
    with pytest.raises(rars.BadPassword):
        archive.read("large.bin", password="wrong")
    with pytest.raises(rars.BadPassword):
        archive.testrar(password="wrong")
    assert archive.read("large.bin") == bytes(range(256)) * 64


@pytest.mark.parametrize("name", ["header_rar300_password.rar", "header_rar420_password.rar"])
def test_a_wrong_password_on_rar4_header_encryption_raises_at_open(name):
    with pytest.raises(rars.BadPassword):
        rars.RarFile(ENCRYPTED / name, password="wrong")
    assert rars.RarFile(ENCRYPTED / name, password="password").namelist() == ["hello.txt"]


@pytest.mark.parametrize("call", [
    lambda archive, tmp_path: archive.read("file", pwd="right"),
    lambda archive, tmp_path: archive.read_many(["file"], pwd="right"),
    lambda archive, tmp_path: archive.open("file", pwd="right"),
    lambda archive, tmp_path: archive.extract("file", tmp_path, pwd="right"),
    lambda archive, tmp_path: archive.extractall(tmp_path, pwd="right"),
    lambda archive, tmp_path: archive.testrar(pwd="right"),
    lambda archive, tmp_path: archive.read_comment(pwd="right"),
    lambda archive, tmp_path: archive.getcomment("file", pwd="right"),
    lambda archive, tmp_path: archive.readlink("file", pwd="right"),
], ids=["read", "read_many", "open", "extract", "extractall", "testrar", "read_comment", "getcomment", "readlink"])
def test_the_per_call_password_keyword_is_password(tmp_path, call):
    archive = rars.RarFile.from_bytes(encrypted("rar50"))
    with pytest.raises(TypeError, match="pwd"):
        call(archive, tmp_path)
