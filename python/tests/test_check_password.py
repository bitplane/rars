from pathlib import Path
import random
import zlib

import pytest
import rars


FIXTURES = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures"


def encrypted(format, *, encrypt_headers=False):
    builder = rars.RarBuilder(format=format, password="right", encrypt_headers=encrypt_headers)
    builder.add_bytes(b"secret payload " * 64, "file.txt")
    return builder.to_bytes()


def test_a_rar5_check_value_proves_the_right_candidate():
    check = rars.check_password(encrypted("rar50"), ["wrong", "right"])
    assert check.needs_password
    assert check.correct == "right"
    assert check.undetermined == []


def test_checking_stops_at_the_first_correct_candidate():
    asked = []

    def candidates():
        for candidate in ["wrong", "right", "after"]:
            asked.append(candidate)
            yield candidate

    check = rars.check_password(encrypted("rar50"), candidates())
    assert check.correct == "right"
    assert asked == ["wrong", "right"]


@pytest.mark.parametrize("format", ["rar15", "rar20", "rar29"])
def test_rar4_file_encryption_leaves_every_candidate_undetermined(format):
    check = rars.check_password(encrypted(format), ["wrong", "right"])
    assert check.needs_password
    assert check.correct is None
    assert check.undetermined == ["wrong", "right"]
    assert check.archive.namelist() == ["file.txt"]


@pytest.mark.parametrize(
    "fixture",
    ["rar15_40/encrypted/per_file_rar300_password.rar", "rar13/README_password=password.rar"],
)
def test_winrar_file_encryption_before_rar5_is_undetermined(fixture):
    check = rars.check_password(FIXTURES / fixture, ["wrong", "password"])
    assert check.correct is None
    assert check.undetermined == ["wrong", "password"]


def test_a_zeroed_rar5_check_value_is_undetermined():
    check = rars.check_password(FIXTURES / "rar50/zeroed_password_check.rar", [b"wrong", b"secret"])
    assert check.correct is None
    assert check.undetermined == [b"wrong", b"secret"]


def test_a_rar5_check_value_rules_out_a_wrong_candidate():
    check = rars.check_password(encrypted("rar50"), ["wrong", b"also wrong"])
    assert check.correct is None
    assert check.undetermined == []
    assert check.archive.namelist() == ["file.txt"]


def test_header_encryption_opens_the_archive_with_the_correct_candidate():
    check = rars.check_password(encrypted("rar50", encrypt_headers=True), ["wrong", "right"])
    assert check.needs_password
    assert check.correct == "right"
    assert check.undetermined == []
    assert check.archive.namelist() == ["file.txt"]
    assert check.archive.read("file.txt") == b"secret payload " * 64


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(lambda: encrypted("rar50", encrypt_headers=True), id="rar50"),
        pytest.param(lambda: FIXTURES / "rar15_40/encrypted/header_rar300_password.rar", id="rar300"),
        pytest.param(lambda: FIXTURES / "rar15_40/encrypted/header_rar420_password.rar", id="rar420"),
    ],
)
def test_header_encryption_with_no_correct_candidate_has_no_archive(source):
    check = rars.check_password(source(), ["wrong", "worse"])
    assert check.needs_password
    assert check.correct is None
    assert check.undetermined == []
    assert check.archive is None


@pytest.mark.parametrize(
    "fixture, password",
    [
        ("rar15_40/encrypted/header_rar300_password.rar", "password"),
        ("rar15_40/encrypted/header_rar420_password.rar", "password"),
        ("rar50/header_encrypted.rar", "password"),
    ],
)
def test_winrar_header_encryption_finds_the_correct_candidate(fixture, password):
    check = rars.check_password(FIXTURES / fixture, ["wrong", password])
    assert check.correct == password
    assert check.archive.namelist()


@pytest.mark.parametrize("encrypt_headers", [False, True])
def test_a_later_volume_checks_the_same_as_the_first(tmp_path, encrypt_headers):
    builder = rars.RarBuilder(
        format="rar50", store=True, volume_size=4096, password="right", encrypt_headers=encrypt_headers
    )
    builder.add_bytes(random.Random(6).randbytes(20_000), "large.bin")
    paths = builder.write_volumes(tmp_path / "set.part1.rar")
    for path in [paths[0], paths[1]]:
        check = rars.check_password(path, ["wrong", "right"])
        assert check.correct == "right"
        assert check.archive.namelist() == ["large.bin"]


@pytest.mark.parametrize(
    "fixture",
    [
        "rar50/header_encrypted_stored_multivol.part2.rar",
        "rar15_40/rar300/header_encrypted_multivol_rar300.r00",
    ],
)
def test_a_later_winrar_volume_finds_the_correct_candidate(fixture):
    check = rars.check_password(FIXTURES / fixture, ["wrong", "password"])
    assert check.correct == "password"
    assert check.archive.namelist()


def test_a_later_rar4_volume_with_file_encryption_is_undetermined():
    check = rars.check_password(FIXTURES / "rar15_40/rar300/encrypted_multivol_rar300.r00", ["wrong", "password"])
    assert check.correct is None
    assert check.undetermined == ["wrong", "password"]


@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_an_unencrypted_volume_needs_no_password(format):
    builder = rars.RarBuilder(format=format)
    builder.add_bytes(b"open", "file.txt")
    check = rars.check_password(builder.to_bytes(), ["wrong", "right"])
    assert not check.needs_password
    assert check.correct is None
    assert check.undetermined == []
    assert check.archive.namelist() == ["file.txt"]


def test_a_non_rar_input_raises_not_rar_file():
    with pytest.raises(rars.NotRarFile):
        rars.check_password(b"not a rar archive", ["right"])


def zero_header_check_value(data):
    # A one-byte header size: CRC32, size, then type 4, flags, version, flags, count, salt, check.
    start = data.index(b"Rar!\x1a\x07\x01\x00") + 8
    size = data[start + 4]
    header = bytearray(data[start + 4 : start + 5 + size])
    assert header[1] == 4 and header[4] & 1
    header[-12:-4] = bytes(8)
    crc = zlib.crc32(header).to_bytes(4, "little")
    return data[:start] + crc + bytes(header) + data[start + 5 + size :]


def test_without_a_header_check_value_the_main_header_decides():
    data = zero_header_check_value(encrypted("rar50", encrypt_headers=True))
    assert rars.check_password(data, ["wrong", "right"]).correct == "right"
    check = rars.check_password(data, ["wrong"])
    assert check.correct is None
    assert check.undetermined == []
    assert check.archive is None
