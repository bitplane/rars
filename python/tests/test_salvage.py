"""Reading past damage: opt-in, with every intact member delivered and each failure named."""

import random
import zlib

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
def test_an_archive_cut_through_a_member_delivers_what_is_there(tmp_path, format):
    data = cut_through(build(format), "m1.bin")
    archive = rars.RarFile(data, salvage=True)

    # The cut member is listed, and gets the bytes the file still holds.
    assert archive.namelist() == ["m0.bin", "m1.bin"]
    truncation = archive.truncation
    assert truncation.block is rars.TruncatedBlock.MEMBER
    assert truncation.name == b"m1.bin"
    assert truncation.started
    assert not truncation.members_complete
    assert truncation.volume_index == 0
    assert truncation.offset < len(data)
    assert "m1.bin" in str(truncation)
    assert archive.header_damage == []

    failed = []
    assert archive.read_many(["m0.bin", "m1.bin"], on_member_error=failed.append) == [
        MEMBERS["m0.bin"],
        MEMBERS["m1.bin"][:1500],
    ]
    [error] = failed
    assert type(error) is rars.MemberCutShort
    assert isinstance(error, rars.BadRarFile)
    assert (error.member, error.packed, error.present) == ("m1.bin", 3000, 1500)
    with pytest.raises(rars.MemberCutShort):
        archive.read("m1.bin")

    failed = []
    archive.testrar(on_member_error=failed.append)
    assert [(type(error), error.member) for error in failed] == [(rars.MemberCutShort, "m1.bin")]
    with pytest.raises(rars.MemberCutShort):
        archive.testrar()

    archive.extractall(tmp_path / "plain", on_member_error=failed.append)
    assert extracted(tmp_path / "plain") == {"m0.bin": MEMBERS["m0.bin"]}
    archive.extractall(tmp_path / "kept", on_member_error=failed.append, keep_broken=True)
    assert extracted(tmp_path / "kept") == {
        "m0.bin": MEMBERS["m0.bin"],
        "m1.bin": MEMBERS["m1.bin"][:1500],
    }


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
    with pytest.raises(ValueError, match="callable"):
        archive.read("m0.bin", on_member_error=1)


def text(seed, size=60_000):
    """Word-like text, which compresses, so damage lands partway through a stream."""
    rng = random.Random(seed)
    letters = "abcdefghijklmnopqrstuvwxyz"
    words = ["".join(rng.choices(letters, k=rng.randint(2, 9))) for _ in range(400)]
    return " ".join(rng.choices(words, k=size // 5)).encode()[:size]


TEXTS = {"a.txt": text(1), "b.txt": text(2)}


def build_texts(format):
    builder = rars.RarBuilder(version=format)
    for name, data in TEXTS.items():
        builder.add_bytes(data, name)
    return builder.to_bytes()


def damaged_partway(format):
    """The archive with 16 bytes flipped halfway through b.txt's packed data, the last in the file."""
    archive = build_texts(format)
    middle = len(archive) - rars.RarFile(archive).getinfo("b.txt").compress_size // 2
    data = bytearray(archive)
    for offset in range(middle, middle + 16):
        data[offset] ^= 0x55
    return bytes(data)


def common_prefix(left, right):
    differ = (index for index, (a, b) in enumerate(zip(left, right)) if a != b)
    return next(differ, min(len(left), len(right)))


@pytest.mark.parametrize("format", FORMATS)
def test_a_member_that_fails_its_checksum_is_delivered_whole(tmp_path, format):
    data = flipped(build(format), "m1.bin")
    damaged = bytearray(MEMBERS["m1.bin"])
    damaged[1000] ^= 0xFF
    damaged = bytes(damaged)

    # Without salvage, a failed member's bytes are never handed over.
    strict = rars.RarFile(data)
    failed = []
    assert strict.read_many(list(MEMBERS), on_member_error=failed.append) == [
        MEMBERS["m0.bin"],
        b"",
        MEMBERS["m2.bin"],
    ]
    assert [(type(error), error.member) for error in failed] == [(rars.ChecksumError, "m1.bin")]
    with pytest.raises(rars.ChecksumError):
        strict.read("m1.bin")

    archive = rars.RarFile(data, salvage=True)
    assert archive.header_damage == []
    failed = []
    assert archive.read_many(list(MEMBERS), on_member_error=failed.append) == [
        MEMBERS["m0.bin"],
        damaged,
        MEMBERS["m2.bin"],
    ]
    assert [(type(error), error.member) for error in failed] == [(rars.ChecksumError, "m1.bin")]
    failed = []
    assert archive.open("m1.bin", on_member_error=failed.append).read() == damaged
    assert [error.member for error in failed] == ["m1.bin"]
    # With nowhere to report to, reading still raises.
    with pytest.raises(rars.ChecksumError):
        archive.read("m1.bin")

    failed = []
    archive.testrar(on_member_error=failed.append)
    assert [(type(error), error.member) for error in failed] == [(rars.ChecksumError, "m1.bin")]

    failed = []
    written = archive.extractall(tmp_path / "plain", on_member_error=failed.append)
    assert sorted(path.name for path in written) == ["m0.bin", "m2.bin"]
    assert [error.member for error in failed] == ["m1.bin"]

    failed = []
    written = archive.extractall(tmp_path / "kept", on_member_error=failed.append, keep_broken=True)
    assert sorted(path.name for path in written) == sorted(MEMBERS)
    assert extracted(tmp_path / "kept") == {**MEMBERS, "m1.bin": damaged}
    assert [(type(error), error.member) for error in failed] == [(rars.ChecksumError, "m1.bin")]


@pytest.mark.parametrize("format", FORMATS)
def test_a_member_damaged_partway_delivers_what_decoded_before_the_damage(tmp_path, format):
    data = damaged_partway(format)
    original = TEXTS["b.txt"]

    strict = rars.RarFile(data)
    with pytest.raises(rars.BadRarFile):
        strict.read("b.txt")
    failed = []
    assert strict.read_many(list(TEXTS), on_member_error=failed.append) == [TEXTS["a.txt"], b""]
    assert [error.member for error in failed] == ["b.txt"]

    archive = rars.RarFile(data, salvage=True)
    failed = []
    got = archive.read("b.txt", on_member_error=failed.append)
    [error] = failed
    assert isinstance(error, rars.BadRarFile)
    assert error.member == "b.txt"
    # Up to the damage the bytes are the member's own; past it, what the decoder made of it.
    assert got != original
    assert len(got) <= len(original)
    assert common_prefix(got, original) > len(original) // 8

    failed = []
    archive.testrar(on_member_error=failed.append)
    assert [(type(failure), failure.member) for failure in failed] == [(type(error), "b.txt")]

    failed = []
    archive.extractall(tmp_path, on_member_error=failed.append, keep_broken=True)
    assert extracted(tmp_path) == {"a.txt": TEXTS["a.txt"], "b.txt": got}
    assert [failure.member for failure in failed] == ["b.txt"]


@pytest.mark.parametrize("format", FORMATS)
def test_a_damaged_header_is_read_past_and_listed(tmp_path, format):
    whole = build(format)
    data = bytearray(whole)
    data[whole.index(b"m1.bin")] ^= 0x20  # M1.bin now, and the header fails its checksum
    data = bytes(data)

    with pytest.raises(rars.BadRarFile):
        rars.RarFile(data)

    archive = rars.RarFile(data, salvage=True)
    assert archive.namelist() == ["m0.bin", "M1.bin", "m2.bin"]
    [damage] = archive.header_damage
    assert damage.kind is rars.HeaderDamageKind.CHECKSUM
    assert damage.offset == whole.index(MEMBERS["m0.bin"]) + 3000
    assert damage.volume_index == 0
    assert "checksum" in str(damage)

    # The member's data is whole, so it reads and verifies.
    failed = []
    assert archive.read_many(archive.namelist(), on_member_error=failed.append) == list(
        MEMBERS.values()
    )
    assert failed == []
    archive.testrar()
    archive.extractall(tmp_path)
    assert extracted(tmp_path) == {
        "m0.bin": MEMBERS["m0.bin"],
        "M1.bin": MEMBERS["m1.bin"],
        "m2.bin": MEMBERS["m2.bin"],
    }


def test_a_member_that_runs_past_its_declared_size_gets_its_declared_bytes():
    data = bytearray(build_texts("rar29"))
    # A RAR 2.9 file header: 32 fixed bytes, then the name.
    head = data.index(b"b.txt") - 32
    assert data[head + 2] == 0x74
    data[head + 11 : head + 15] = (1000).to_bytes(4, "little")
    size = int.from_bytes(data[head + 5 : head + 7], "little")
    crc = zlib.crc32(data[head + 2 : head + size]) & 0xFFFF
    data[head : head + 2] = crc.to_bytes(2, "little")
    data = bytes(data)

    with pytest.raises(rars.BadRarFile) as raised:
        rars.RarFile(data).read("b.txt")
    assert not isinstance(raised.value, rars.MemberRanPastDeclaredSize)

    archive = rars.RarFile(data, salvage=True)
    assert archive.header_damage == []
    failed = []
    assert archive.read("b.txt", on_member_error=failed.append) == TEXTS["b.txt"][:1000]
    [error] = failed
    assert type(error) is rars.MemberRanPastDeclaredSize
    assert (error.member, error.declared) == ("b.txt", 1000)


def test_keep_broken_needs_salvage_and_a_report(tmp_path):
    data = flipped(build("rar50"), "m1.bin")
    with pytest.raises(ValueError, match="salvage"):
        rars.RarFile(data).extractall(tmp_path, on_member_error=print, keep_broken=True)
    with pytest.raises(ValueError, match="on_member_error"):
        rars.RarFile(data, salvage=True).extractall(tmp_path, keep_broken=True)
    assert extracted(tmp_path) == {}


def test_keep_broken_keeps_nothing_of_a_member_without_its_password(tmp_path):
    archive = rars.RarFile(build("rar50", password="secret"), salvage=True)
    failed = []
    assert archive.extractall(tmp_path, on_member_error=failed.append, keep_broken=True) == []
    assert [type(error) for error in failed] == [rars.PasswordRequired] * len(MEMBERS)
    assert extracted(tmp_path) == {}


def test_reading_a_member_in_a_later_volume_refuses_on_member_error(tmp_path):
    archive = rars.RarFile(write_set(tmp_path)[0], salvage=True)
    with pytest.raises(ValueError, match="later volume"):
        archive.read("tail.txt", on_member_error=print)
    assert archive.read("tail.txt") == b"tail"
