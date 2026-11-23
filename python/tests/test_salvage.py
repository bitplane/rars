"""Reading past damage: opt-in, with every intact member delivered and each failure named."""

import random

import pytest
import rars


FORMATS = ["rar20", "rar29", "rar50"]  # RAR 1.5 to 4.x and 5 or later
MEMBERS = {
    f"m{index}.bin": random.Random(446 + index).randbytes(3000) for index in range(3)
}


def build(format, **options):
    # Stored, so each member's data is in the file as it is and can be found there.
    builder = rars.RarBuilder(version=format, level=0, **options)
    for name, data in MEMBERS.items():
        builder.add_bytes(data, name)
    return builder.to_bytes()


def flipped(archive, name):
    """The archive with one byte of `name`'s data flipped."""
    data = bytearray(archive)
    data[archive.index(MEMBERS[name]) + 1000] ^= 0xFF
    return bytes(data)


def cut_through(archive, name):
    """The archive cut short halfway through `name`'s data."""
    return archive[: archive.index(MEMBERS[name]) + 1500]


def extracted(directory):
    return {path.name: path.read_bytes() for path in directory.rglob("*") if path.is_file()}


@pytest.mark.parametrize("format", FORMATS)
def test_a_flipped_byte_in_a_middle_member_is_reported_and_the_rest_extract(tmp_path, format):
    archive = rars.RarFile(flipped(build(format), "m1.bin"))

    failed = []
    archive.testrar(on_member_error=failed.append)
    assert [(type(error), error.member) for error in failed] == [(rars.ChecksumError, "m1.bin")]

    failed = []
    written = archive.extractall(tmp_path, on_member_error=failed.append)
    assert [error.member for error in failed] == ["m1.bin"]
    assert isinstance(failed[0], rars.BadRarFile)
    assert sorted(path.name for path in written) == ["m0.bin", "m2.bin"]
    assert extracted(tmp_path) == {name: MEMBERS[name] for name in ["m0.bin", "m2.bin"]}


@pytest.mark.parametrize("format", FORMATS)
def test_an_archive_cut_through_a_member_reads_the_members_before_it(tmp_path, format):
    data = cut_through(build(format), "m1.bin")
    archive = rars.RarFile(data, salvage=True)

    assert archive.namelist() == ["m0.bin"]
    truncation = archive.truncation
    assert truncation.block is rars.TruncatedBlock.MEMBER
    assert truncation.name == b"m1.bin"
    assert truncation.started
    assert not truncation.members_complete
    assert truncation.volume_index == 0
    assert truncation.offset < len(data)
    assert "m1.bin" in str(truncation)
    archive.testrar()
    archive.extractall(tmp_path)
    assert extracted(tmp_path) == {"m0.bin": MEMBERS["m0.bin"]}


@pytest.mark.parametrize("format", ["rar50", "rar70"])
def test_an_archive_cut_in_its_recovery_record_reads_every_member(tmp_path, format):
    whole = build(format, recovery_percent=10)
    # Past the last member's data, and short of the few bytes of end block after the record.
    cut = whole[: whole.index(MEMBERS["m2.bin"]) + 3000 + 100]
    assert len(cut) < len(whole) - 100

    # The members are all there, so this needs no salvage.
    archive = rars.RarFile(cut)
    assert archive.namelist() == list(MEMBERS)
    assert archive.truncation.block is rars.TruncatedBlock.RECOVERY_RECORD
    assert archive.truncation.name is None
    assert archive.truncation.members_complete
    assert "recovery record" in str(archive.truncation)
    archive.testrar()
    archive.extractall(tmp_path)
    assert extracted(tmp_path) == MEMBERS
    assert rars.RarFile(whole).truncation is None


def write_set(tmp_path):
    builder = rars.RarBuilder(version="rar50", level=0, volume_size=4096)
    for name, data in MEMBERS.items():
        builder.add_bytes(data, name)
    builder.add_bytes(b"tail", "tail.txt")
    paths = builder.write(tmp_path / "set.part1.rar")
    assert len(paths) >= 3
    return paths


def test_a_volume_set_with_a_volume_missing_reads_both_sides_of_the_gap(tmp_path):
    paths = write_set(tmp_path)
    missing = len(paths) // 2
    paths[missing].unlink()

    # The run before the gap, its later volumes found by name until the missing one.
    before = rars.RarFile(paths[0], salvage=True)
    assert before.incomplete_members
    assert {member.missing for member in before.incomplete_members} == {rars.MissingPart.END}
    before.testrar()
    before.extractall(tmp_path / "before")

    # The run after it, starting with a volume other than the first.
    after = rars.RarFile(paths[missing + 1], volumes=paths[missing + 2 :], salvage=True)
    first = after.incomplete_members[0]
    assert first.volume_index == 0
    assert first.missing in (rars.MissingPart.START, rars.MissingPart.BOTH)
    after.testrar()
    after.extractall(tmp_path / "after")

    got = {**extracted(tmp_path / "before"), **extracted(tmp_path / "after")}
    assert got, "every member was left out"
    everything = {**MEMBERS, "tail.txt": b"tail"}
    assert all(everything[name] == data for name, data in got.items())
    left_out = {member.filename for member in before.incomplete_members + after.incomplete_members}
    assert left_out <= set(everything)
    assert not left_out & set(got)
    assert set(before.namelist()) | set(after.namelist()) == set(got)


def test_damage_raises_unless_salvage_is_asked_for(tmp_path):
    damaged = rars.RarFile(flipped(build("rar50"), "m1.bin"))
    with pytest.raises(rars.ChecksumError):
        damaged.testrar()
    with pytest.raises(rars.ChecksumError):
        damaged.extractall(tmp_path / "out")

    with pytest.raises(rars.BadRarFile):
        rars.RarFile(cut_through(build("rar50"), "m1.bin"))

    paths = write_set(tmp_path)
    paths[len(paths) // 2].unlink()
    archive = rars.RarFile(paths[0])
    assert archive.incomplete_members == []
    with pytest.raises(rars.MissingVolume):
        archive.extractall(tmp_path / "set")


def test_a_member_without_its_password_is_reported(tmp_path):
    archive = rars.RarFile(build("rar50", password="secret"))
    failed = []
    assert archive.extractall(tmp_path, on_member_error=failed.append) == []
    assert [(type(error), error.member) for error in failed] == [
        (rars.PasswordRequired, name) for name in MEMBERS
    ]


def test_raising_from_on_member_error_stops_the_call(tmp_path):
    archive = rars.RarFile(flipped(build("rar50"), "m0.bin"))

    class Stop(Exception):
        pass

    def stop(error):
        raise Stop(error.member)

    with pytest.raises(Stop, match="m0.bin"):
        archive.extractall(tmp_path, on_member_error=stop)
    assert extracted(tmp_path) == {}
    with pytest.raises(rars.ChecksumError):
        archive.testrar(on_member_error=lambda error: (_ for _ in ()).throw(error))


def test_on_member_error_reads_every_member():
    archive = rars.RarFile(build("rar50"))
    with pytest.raises(ValueError, match="members"):
        archive.extractall(members=["m0.bin"], on_member_error=print)
    with pytest.raises(ValueError, match="callable"):
        archive.testrar(on_member_error=1)
