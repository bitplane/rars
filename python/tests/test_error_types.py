import random

import pytest
import rars


def rar_bytes():
    builder = rars.RarBuilder(version="rar50", level=0)
    builder.add_bytes(b"payload", "file.txt")
    return builder.to_bytes()


@pytest.mark.parametrize(
    "data",
    [
        b"PK\x03\x04" + bytes(100),
        b"",
        random.Random(5).randbytes(4096),
    ],
    ids=["zip", "empty", "random"],
)
def test_input_without_a_rar_signature_is_not_a_rar_file(tmp_path, data):
    path = tmp_path / "input.bin"
    path.write_bytes(data)
    with pytest.raises(rars.NotRarFile) as raised:
        rars.RarFile(path)
    assert isinstance(raised.value, rars.Error)
    assert not isinstance(raised.value, (rars.BadRarFile, rars.UnsupportedRarFeature))
    with pytest.raises(rars.NotRarFile):
        rars.RarFile(data)


def test_a_later_volume_without_a_rar_signature_is_not_reported_as_not_a_rar_file(tmp_path):
    paths = write_set(tmp_path, "rar50")
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.Error) as raised:
            archive.testrar(volumes=[b"PK\x03\x04" + bytes(100)])
    assert not isinstance(raised.value, rars.NotRarFile)


def test_an_sfx_stub_inside_the_scan_limit_still_opens():
    stub = b"MZ" + random.Random(6).randbytes(64 * 1024)
    with rars.RarFile(stub + rar_bytes()) as archive:
        assert archive.read("file.txt") == b"payload"
        assert archive.sfx_offset == len(stub)


PAYLOAD = random.Random(22).randbytes(40_000)


def write_set(tmp_path, format):
    builder = rars.RarBuilder(version=format, level=0, volume_size=4096)
    builder.add_bytes(PAYLOAD, "large.bin")
    first = "set.part01.rar" if format == "rar50" else "set.rar"
    (tmp_path / "made").mkdir()
    paths = builder.write(tmp_path / "made" / first)
    assert len(paths) > 3
    return paths


@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_a_removed_volume_is_a_missing_volume(tmp_path, format):
    paths = write_set(tmp_path, format)
    paths[2].unlink()
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.MissingVolume) as raised:
            archive.testrar()
    assert isinstance(raised.value, rars.Error)
    assert not isinstance(raised.value, rars.BadRarFile)
    assert raised.value.volume_index == 2
    assert raised.value.path == paths[2]


def test_volumes_ending_early_is_a_missing_volume_without_a_path(tmp_path):
    paths = write_set(tmp_path, "rar50")
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.MissingVolume) as raised:
            archive.extractall(tmp_path / "out", volumes=paths[1:2])
    assert raised.value.volume_index == 2
    assert raised.value.path is None


def flip_byte(path, offset):
    data = bytearray(path.read_bytes())
    data[offset] ^= 0xFF
    path.write_bytes(bytes(data))


def test_a_corrupt_rar5_volume_is_a_checksum_error_naming_member_and_volume(tmp_path):
    paths = write_set(tmp_path, "rar50")
    flip_byte(paths[1], 2000)
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.ChecksumError) as raised:
            archive.testrar()
    assert isinstance(raised.value, rars.BadRarFile)
    assert raised.value.member == "large.bin"
    assert raised.value.volume_index == 1


@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_a_corrupt_payload_is_a_checksum_error_naming_the_member(tmp_path, format):
    builder = rars.RarBuilder(version=format, level=0)
    builder.add_bytes(PAYLOAD, "large.bin")
    path = tmp_path / "single.rar"
    path.write_bytes(builder.to_bytes())
    flip_byte(path, 20_000)
    with rars.RarFile(path) as archive:
        with pytest.raises(rars.ChecksumError) as raised:
            archive.extractall(tmp_path / "out")
    assert raised.value.member == "large.bin"


def test_a_corrupt_encrypted_rar4_member_stays_a_bad_password(tmp_path):
    builder = rars.RarBuilder(version="rar29", level=0, password="pw")
    builder.add_bytes(PAYLOAD, "large.bin")
    path = tmp_path / "encrypted.rar"
    path.write_bytes(builder.to_bytes())
    flip_byte(path, 20_000)
    with rars.RarFile(path, password="pw") as archive:
        with pytest.raises(rars.BadPassword):
            archive.testrar()


def test_a_corrupt_encrypted_rar5_member_is_a_checksum_error(tmp_path):
    builder = rars.RarBuilder(version="rar50", level=0, password="pw")
    builder.add_bytes(PAYLOAD, "large.bin")
    path = tmp_path / "encrypted.rar"
    path.write_bytes(builder.to_bytes())
    flip_byte(path, 20_000)
    with rars.RarFile(path, password="pw") as archive:
        with pytest.raises(rars.ChecksumError) as raised:
            archive.testrar()
    assert raised.value.member == "large.bin"


def test_a_refusing_limit_is_a_rars_error_not_a_memory_error():
    archive = rars.RarFile(rar_bytes())
    with pytest.raises(rars.LimitExceeded) as raised:
        archive.read("file.txt", options=rars.ReadOptions(max_member_output_bytes=1))
    assert isinstance(raised.value, rars.Error)
    assert not isinstance(raised.value, MemoryError)
    with pytest.raises(rars.LimitExceeded):
        rars.RarFile(rar_bytes(), options=rars.ReadOptions(max_header_count=1))


def test_password_errors_are_not_damage():
    builder = rars.RarBuilder(level=0, password="pw", encrypt_headers=True)
    builder.add_bytes(b"payload", "file.txt")
    data = builder.to_bytes()
    for password, error in [(None, rars.PasswordRequired), ("wrong", rars.BadPassword)]:
        with pytest.raises(error) as raised:
            rars.RarFile(data, password=password)
        assert isinstance(raised.value, rars.Error)
        assert not isinstance(raised.value, rars.BadRarFile)


# rars writes legacy sets of one member only, so only RAR 5 has a member wholly in a later volume.
@pytest.mark.parametrize("format", ["rar50", "rar70"])
def test_a_corrupt_member_wholly_in_a_later_volume_names_that_volume(tmp_path, format):
    payloads = [random.Random(index).randbytes(1500) for index in range(6)]
    builder = rars.RarBuilder(version=format, level=0, volume_size=4096)
    for index, payload in enumerate(payloads):
        builder.add_bytes(payload, f"m{index}")
    paths = builder.write(tmp_path / "set.part1.rar")
    with rars.RarFile(paths[0]) as archive:
        info = next(info for info in archive.infolist()
                    if info.volume_index > 0 and not info.is_split_before and not info.is_split_after)
    volume = paths[info.volume_index]
    data = bytearray(volume.read_bytes())
    data[data.find(payloads[int(info.filename[1:])][100:140])] ^= 0xFF
    volume.write_bytes(bytes(data))
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.ChecksumError) as raised:
            archive.testrar()
    assert raised.value.member == info.filename
    assert raised.value.volume_index == info.volume_index
    # Messages are for people, so they count as the part names do.
    assert f"in volume {info.volume_index + 1}" in str(raised.value)
