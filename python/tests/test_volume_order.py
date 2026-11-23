import random

import pytest
import rars

PAYLOAD = random.Random(31).randbytes(40_000)
FIRST = {"rar29": "set.rar", "rar50": "set.part01.rar"}


def write_set(tmp_path, format):
    builder = rars.RarBuilder(version=format, level=0, volume_size=4096)
    builder.add_bytes(PAYLOAD, "large.bin")
    (tmp_path / "made").mkdir()
    paths = builder.write(tmp_path / "made" / FIRST[format])
    assert len(paths) > 3
    return paths


def swapped(paths):
    return [paths[2], paths[1], *paths[3:]]


def read_through_open(archive, volumes):
    with archive.open("large.bin", volumes=volumes) as stream:
        return stream.read()


CALLS = {
    "extractall": lambda archive, out, volumes: archive.extractall(out, volumes=volumes),
    "extract": lambda archive, out, volumes: archive.extract("large.bin", out, volumes=volumes),
    "read": lambda archive, out, volumes: archive.read("large.bin", volumes=volumes),
    "read_many": lambda archive, out, volumes: archive.read_many(["large.bin"], volumes=volumes),
    "open": lambda archive, out, volumes: read_through_open(archive, volumes),
    "testrar": lambda archive, out, volumes: archive.testrar(volumes=volumes),
}


@pytest.mark.parametrize("format", ["rar29", "rar50"])
@pytest.mark.parametrize("call", CALLS)
def test_swapped_volumes_raise_a_volume_order_error_naming_the_volume(tmp_path, format, call):
    paths = write_set(tmp_path, format)
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.VolumeOrderError) as raised:
            CALLS[call](archive, tmp_path / "out", swapped(paths))
    assert raised.value.volume_index == 1
    assert "in volume 2" in str(raised.value)


def test_a_volume_order_error_is_a_rars_error_but_not_damage(tmp_path):
    paths = write_set(tmp_path, "rar50")
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.Error) as raised:
            archive.testrar(volumes=swapped(paths))
    assert isinstance(raised.value, rars.VolumeOrderError)
    assert not isinstance(raised.value, (rars.BadRarFile, rars.MissingVolume))


@pytest.mark.parametrize("format", ["rar29", "rar50"])
def test_listing_swapped_volumes_raises_a_volume_order_error(tmp_path, format):
    paths = write_set(tmp_path, format)
    with rars.RarFile(paths[0], volumes=swapped(paths)) as archive:
        with pytest.raises(rars.VolumeOrderError) as raised:
            archive.namelist()
    assert raised.value.volume_index == 1


def test_listing_checks_order_where_no_member_is_split(tmp_path):
    # 3943 bytes fills a 4096-byte volume exactly, so each volume holds one whole member.
    builder = rars.RarBuilder(version="rar50", level=0, volume_size=4096)
    for index in range(4):
        builder.add_bytes(bytes([index]) * 3943, f"m{index}")
    paths = builder.write(tmp_path / "set.part1.rar")
    for path in paths:
        with rars.RarFile(path, first_volume_only=True) as volume:
            assert not any(info.is_split_before or info.is_split_after for info in volume.infolist())
    with rars.RarFile(paths[0], volumes=swapped(paths)) as archive:
        with pytest.raises(rars.VolumeOrderError) as raised:
            archive.namelist()
    assert raised.value.volume_index == 1


def test_files_written_before_a_volume_order_error_are_complete_and_a_retry_succeeds(tmp_path):
    members = {f"m{index}": random.Random(index).randbytes(1500) for index in range(8)}
    builder = rars.RarBuilder(version="rar50", level=0, volume_size=4096)
    for name, data in members.items():
        builder.add_bytes(data, name)
    paths = builder.write(tmp_path / "set.part1.rar")
    out = tmp_path / "out"
    later = [paths[1], paths[3], paths[2], *paths[4:]]
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.VolumeOrderError) as raised:
            archive.extractall(out, volumes=iter(later))
        assert raised.value.volume_index == 2
        written = sorted(path.name for path in out.iterdir())
        assert written
        for name in written:
            assert (out / name).read_bytes() == members[name]
        archive.extractall(out, volumes=iter(paths[1:]), overwrite=True)
    for name, data in members.items():
        assert (out / name).read_bytes() == data


def test_volumes_recording_no_number_still_fail_on_their_checksums(tmp_path):
    builder = rars.RarBuilder(version="rar20", level=0, volume_size=4096)
    builder.add_bytes(PAYLOAD, "large.bin")
    paths = builder.write(tmp_path / "set.rar")
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.ChecksumError):
            archive.testrar(volumes=swapped(paths))
