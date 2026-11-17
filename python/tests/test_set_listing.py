from pathlib import Path
import random
import shutil
import zlib

import pytest
import rars


def times(info):
    return info.mtime_ns, info.birthtime_ns, info.atime_ns


FIXTURES = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures"

MEMBERS = {
    "head.txt": b"head",
    "large.bin": random.Random(22).randbytes(40_000),
    "after.bin": random.Random(23).randbytes(12_000),
    "tail.bin": random.Random(24).randbytes(6_000),
}
LATER = ["after.bin", "tail.bin"]


def write_set(tmp_path, **options):
    builder = rars.RarBuilder(version="rar50", level=0, volume_size=4096, **options)
    for name, data in MEMBERS.items():
        builder.add_bytes(data, name)
    (tmp_path / "made").mkdir()
    paths = builder.write(tmp_path / "made" / "set.part01.rar")
    assert len(paths) > 3
    return paths


def write_legacy_set(tmp_path, format, first, **options):
    builder = rars.RarBuilder(version=format, level=0, volume_size=4096, **options)
    builder.add_bytes(MEMBERS["large.bin"], "large.bin")
    (tmp_path / "made").mkdir()
    paths = builder.write(tmp_path / "made" / first)
    assert len(paths) > 3
    return paths


def test_namelist_lists_every_member_of_the_set_once(tmp_path):
    paths = write_set(tmp_path)
    with rars.RarFile(paths[0]) as archive:
        names = archive.namelist()
        written = archive.extractall(tmp_path / "out")
        assert [info.filename for info in archive] == names
        assert [info.filename for info in archive.infolist()] == names
    assert names == list(MEMBERS)
    assert [Path(p).name for p in written] == names


@pytest.mark.parametrize(
    "format, first",
    [
        ("rar13", "set.rar"),
        ("rar15", "set.rar"),
        ("rar20", "set.rar"),
        ("rar29", "set.rar"),
        ("rar29", "set.part01.rar"),
    ],
)
def test_a_legacy_split_member_is_listed_once_and_whole(tmp_path, format, first):
    paths = write_legacy_set(tmp_path, format, first)
    with rars.RarFile(paths[0]) as archive:
        [info] = archive.infolist()
        written = archive.extractall(tmp_path / "out")
    assert [Path(p).name for p in written] == [info.filename] == ["large.bin"]
    assert info.file_size == info.compress_size == len(MEMBERS["large.bin"])
    if format != "rar13":
        assert info.CRC == zlib.crc32(MEMBERS["large.bin"])


@pytest.mark.parametrize(
    "first",
    [
        "rar15_40/rar300/multivol_oldnaming_rar300.rar",
        "rar15_40/rar300/multivol_newnaming_rar300.part01.rar",
        "rar15_40/rar154/random.rar",
        "rar50/encrypted_members_multivol.part1.rar",
    ],
)
def test_namelist_matches_what_extractall_writes_from_winrar_sets(tmp_path, first):
    password = "password" if "encrypted" in first else None
    with rars.RarFile(FIXTURES / first, password=password) as archive:
        names = archive.namelist()
        written = archive.extractall(tmp_path / "out")
        for info in archive.infolist():
            data = (tmp_path / "out" / info.filename).read_bytes()
            assert info.file_size == len(data)
            # An encrypted RAR 5 member stores its CRC keyed by the password.
            if not info.is_encrypted:
                assert info.CRC == zlib.crc32(data)
    assert [Path(p).name for p in written] == names


def test_every_member_has_its_whole_sizes_and_crc(tmp_path):
    paths = write_set(tmp_path)
    with rars.RarFile(paths[0]) as archive:
        infos = {info.filename: info for info in archive.infolist()}
    for name, data in MEMBERS.items():
        assert infos[name].file_size == infos[name].compress_size == len(data)
        assert infos[name].CRC == zlib.crc32(data)
    assert infos["head.txt"].volume_index == 0
    assert infos["after.bin"].volume_index > 0


def test_members_starting_in_later_volumes_can_be_selected(tmp_path):
    paths = write_set(tmp_path)
    with rars.RarFile(paths[0]) as archive:
        for name in LATER:
            assert archive.read(name) == MEMBERS[name]
            assert archive.open(name).read() == MEMBERS[name]
            assert archive.read(archive.getinfo(name)) == MEMBERS[name]
            written = archive.extract(name, tmp_path / "one")
            assert Path(written).read_bytes() == MEMBERS[name]
        assert archive.read_many(["tail.bin", "head.txt", "after.bin"]) == [
            MEMBERS["tail.bin"],
            MEMBERS["head.txt"],
            MEMBERS["after.bin"],
        ]
        written = archive.extractall(tmp_path / "some", members=["after.bin"])
    assert [Path(p).name for p in written] == ["after.bin"]
    assert [p.name for p in (tmp_path / "some").iterdir()] == ["after.bin"]


def test_a_later_member_reads_only_as_far_as_it_ends(tmp_path):
    paths = write_set(tmp_path)
    with rars.RarFile(paths[0]) as archive:
        after = archive.getinfo("after.bin")
    ends = next(
        index
        for index, path in enumerate(paths)
        if any(
            info.filename == "after.bin" and not info.is_split_after
            for info in rars.RarFile(path, first_volume_only=True).infolist()
        )
    )
    assert after.volume_index < ends < len(paths) - 1

    def volumes():
        yield from paths[1 : ends + 1]
        raise AssertionError("pulled past the last selected member")

    with rars.RarFile(paths[0]) as archive:
        assert archive.read("after.bin", volumes=volumes()) == MEMBERS["after.bin"]


def test_metadata_of_a_later_member_comes_from_its_own_volume(tmp_path):
    paths = write_set(tmp_path)
    with rars.RarFile(paths[0]) as archive:
        assert times(archive.getinfo("tail.bin")) == times(archive.getinfo("head.txt"))
        assert archive.member_comment("tail.bin") is None


def test_a_rarinfo_from_the_first_volume_still_selects_its_member(tmp_path):
    paths = write_set(tmp_path)
    with rars.RarFile(paths[0]) as archive:
        head = archive.getinfo("head.txt")
        assert archive.namelist() == list(MEMBERS)
        assert archive.read(head) == MEMBERS["head.txt"]
        assert archive.infolist()[head.member_index].filename == "head.txt"


def test_opening_a_set_does_not_look_for_later_volumes(tmp_path):
    paths = write_set(tmp_path)
    later = tmp_path / "later"
    later.mkdir()
    arriving = [Path(shutil.move(path, later / path.name)) for path in paths[1:]]
    with rars.RarFile(paths[0]) as archive:
        assert archive.read("head.txt") == MEMBERS["head.txt"]
        assert archive.getinfo("large.bin").is_split_after
        archive.testrar(volumes=iter(arriving))
        written = archive.extractall(tmp_path / "out", volumes=iter(arriving))
    assert [Path(p).name for p in written] == list(MEMBERS)


def test_a_missing_middle_volume_is_named_by_the_listing(tmp_path):
    paths = write_set(tmp_path)
    paths[2].unlink()
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.MissingVolume, match=paths[2].name) as raised:
            archive.namelist()
        assert raised.value.volume_index == 2
        assert raised.value.path == paths[2]
        with pytest.raises(rars.MissingVolume):
            archive.read("tail.bin")


def test_first_volume_only_lists_just_the_first_volume(tmp_path):
    paths = write_set(tmp_path)
    with rars.RarFile(paths[0], first_volume_only=True) as archive:
        assert archive.namelist() == ["head.txt", "large.bin"]
        assert archive.read("large.bin") == MEMBERS["large.bin"]
        with pytest.raises(KeyError, match="first_volume_only"):
            archive.read("after.bin")


def test_a_set_opened_from_bytes_lists_only_its_first_volume(tmp_path):
    paths = write_set(tmp_path)
    with rars.RarFile(paths[0].read_bytes()) as archive:
        assert archive.namelist() == ["head.txt", "large.bin"]
        with pytest.raises(KeyError, match="volumes="):
            archive.read("after.bin")


@pytest.mark.parametrize("as_bytes", [False, True])
def test_a_set_given_its_volumes_lists_and_reads_them(tmp_path, as_bytes):
    paths = write_set(tmp_path)
    later = [path.read_bytes() if as_bytes else path for path in paths[1:]]
    with rars.RarFile(paths[0].read_bytes(), volumes=later) as archive:
        assert archive.namelist() == list(MEMBERS)
        assert archive.read("after.bin") == MEMBERS["after.bin"]
        assert archive.read("large.bin") == MEMBERS["large.bin"]


def test_a_one_shot_iterator_is_refused_as_opening_volumes(tmp_path):
    paths = write_set(tmp_path)
    with pytest.raises(TypeError, match="list or tuple"):
        rars.RarFile(paths[0], volumes=iter(paths[1:]))


def test_listing_never_reads_packed_data(tmp_path):
    paths = write_set(tmp_path)
    with rars.RarFile(paths[0]) as archive:
        before = archive.infolist()
    middles = [
        path
        for path in paths[1:]
        if all(i.is_split_before and i.is_split_after for i in rars.RarFile(path, first_volume_only=True).infolist())
    ]
    assert len(middles) > 3
    for path in middles:
        data = bytearray(path.read_bytes())
        # A middle volume is one member's packed data between its headers and end record.
        data[1000:3000] = bytes(2000)
        path.write_bytes(bytes(data))
    with rars.RarFile(paths[0]) as archive:
        after = archive.infolist()
        with pytest.raises(rars.ChecksumError):
            archive.testrar()
    assert [(i.filename, i.file_size, i.CRC) for i in after] == [
        (i.filename, i.file_size, i.CRC) for i in before
    ]


def read_bytes_so_far():
    for line in Path("/proc/self/io").read_text().splitlines():
        if line.startswith("rchar:"):
            return int(line.split()[1])


@pytest.mark.skipif(not Path("/proc/self/io").exists(), reason="needs Linux read counters")
def test_listing_a_large_set_reads_headers_only(tmp_path):
    builder = rars.RarBuilder(version="rar50", level=0, volume_size=1 << 20)
    for index in range(4):
        builder.add_bytes(random.Random(index).randbytes(3 << 20), f"{index}.bin")
    (tmp_path / "made").mkdir()
    paths = builder.write(tmp_path / "made" / "big.part01.rar")
    with rars.RarFile(paths[0]) as archive:
        start = read_bytes_so_far()
        assert len(archive.namelist()) == 4
        read = read_bytes_so_far() - start
    assert read < sum(path.stat().st_size for path in paths) / 50


def test_a_header_encrypted_set_lists_with_its_password(tmp_path):
    paths = write_set(tmp_path, password="secret", encrypt_headers=True)
    with rars.RarFile(paths[0], password="secret") as archive:
        assert archive.namelist() == list(MEMBERS)
        assert archive.read("tail.bin") == MEMBERS["tail.bin"]


@pytest.mark.parametrize(
    "first, name",
    [
        ("rar50/header_encrypted_stored_multivol.part1.rar", "stored_4k.bin"),
        ("rar15_40/rar300/header_encrypted_multivol_rar300.rar", "bigtext_64k.bin"),
        ("rar15_40/rar300/header_encrypted_newnaming_rar300.part01.rar", "bigtext_64k.bin"),
    ],
)
def test_a_header_encrypted_winrar_set_lists_across_volumes(tmp_path, first, name):
    with rars.RarFile(FIXTURES / first, password="password") as archive:
        [info] = archive.infolist()
        written = archive.extractall(tmp_path / "out")
    data = Path(written[0]).read_bytes()
    assert info.filename == name
    assert info.file_size == len(data)
    assert info.CRC == zlib.crc32(data)
