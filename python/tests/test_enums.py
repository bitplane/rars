import pickle
from pathlib import Path

import pytest
import rars

STORED = Path(__file__).resolve().parents[2] / "crates/rars/tests/fixtures/rar50/stored.rar"


@pytest.mark.parametrize(
    "member, value",
    [
        (rars.ArchiveVersion.RAR29, "rar29"),
        (rars.ArchiveFamily.RAR50_PLUS, "rar50_plus"),
        (rars.VolumeNaming.PART, "part"),
        (rars.AttributeKind.UNIX, "unix"),
        (rars.ProgressPhase.EXTRACTING, "extracting"),
    ],
)
def test_members_stand_in_for_the_strings_they_replace(member, value):
    assert member == value
    assert isinstance(member, str)
    assert str(member) == f"{member}" == value
    assert {member} == {value}
    assert {value: 1}[member] == 1
    assert type(member)(value) is member
    assert pickle.loads(pickle.dumps(member)) is member
    assert type(member).__module__ == "rars"


def test_module_constants_are_archive_versions():
    for version in rars.ArchiveVersion:
        assert getattr(rars, version.name) is version


def test_reads_report_enum_members():
    with rars.RarFile(STORED) as archive:
        assert archive.family is rars.ArchiveFamily.RAR50_PLUS
        assert archive.volume_naming is rars.VolumeNaming.PART
        assert {info.family for info in archive.infolist()} == {rars.ArchiveFamily.RAR50_PLUS}
        events = []
        archive.read(archive.namelist()[0], progress=events.append)
    assert {event.phase for event in events} == {rars.ProgressPhase.READING}
    assert all(type(event.phase) is rars.ProgressPhase for event in events)


@pytest.mark.parametrize("format", [rars.ArchiveVersion.RAR29, "rar29"])
def test_builder_takes_a_version_or_its_string(format):
    builder = rars.RarBuilder(format, level=0)
    builder.add_bytes(b"payload", "member")
    archive = rars.RarFile(builder.to_bytes())
    assert archive.family is rars.ArchiveFamily.RAR15_40
    assert archive.infolist()[0].family is rars.ArchiveFamily.RAR15_40
