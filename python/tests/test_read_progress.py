import random

import pytest
import rars


PAYLOAD = random.Random(5).randbytes(300_000)


def single_archive():
    builder = rars.RarBuilder(version="rar50", level=3)
    builder.add_bytes(PAYLOAD, "large.bin")
    builder.add_bytes(b"small", "small.txt")
    builder.add_directory("empty")
    return rars.RarFile(builder.to_bytes())


def test_extractall_reports_bytes_written_against_a_known_total(tmp_path):
    events = []
    single_archive().extractall(tmp_path, progress=events.append)

    assert events
    assert {event.phase for event in events} == {"extracting"}
    assert events[-1].completed == events[-1].total == len(PAYLOAD) + 5
    assert events[-1].percentage == 100.0
    assert events[-1].volume_number is None
    assert all(a.completed <= b.completed for a, b in zip(events, events[1:]))


def write_set(tmp_path):
    builder = rars.RarBuilder(version="rar50", level=0, volume_size=64 * 1024)
    builder.add_bytes(PAYLOAD, "large.bin")
    builder.add_bytes(b"small", "small.txt")
    tmp_path.mkdir(exist_ok=True)
    return builder.write_volumes(tmp_path / "set.part01.rar")


def test_a_set_from_a_generator_claims_no_total_before_its_last_volume(tmp_path):
    paths = write_set(tmp_path)
    assert len(paths) > 3
    events = []

    def later_volumes():
        for path in paths[1:]:
            yield path

    def record(event):
        events.append((event.volume_number, event.total, event.percentage, event.completed))

    with rars.RarFile(paths[0]) as archive:
        archive.testrar(progress=record, volumes=later_volumes())

    before_last = [event for event in events if event[0] < len(paths)]
    assert before_last
    assert all(total == 0 and percentage is None for _, total, percentage, _ in before_last)
    volumes = [volume for volume, *_ in events]
    assert volumes == sorted(volumes)
    assert volumes[0] == 1
    assert events[-1] == (len(paths), len(PAYLOAD) + 5, 100.0, len(PAYLOAD) + 5)


class Stop(Exception):
    pass


def test_a_raising_callback_stops_extraction_and_reaches_the_caller(tmp_path):
    def stop(event):
        raise Stop("enough")

    paths = write_set(tmp_path / "made")
    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(Stop, match="enough"):
            archive.extractall(tmp_path / "out", progress=stop)

    assert not (tmp_path / "out" / "large.bin").exists()


def test_a_callback_raising_on_the_finished_event_still_reaches_the_caller():
    def stop(event):
        if event.completed == event.total and event.percentage == 100.0:
            raise Stop("at the end")

    with pytest.raises(Stop, match="at the end"):
        single_archive().read_many(["large.bin"], progress=stop)


@pytest.mark.parametrize(
    "call, phase, total",
    [
        (lambda archive, progress: archive.read_many(["small.txt", "large.bin"], progress=progress), "reading", len(PAYLOAD) + 5),
        (lambda archive, progress: archive.read("small.txt", progress=progress), "reading", 5),
        (lambda archive, progress: archive.testrar(progress=progress), "testing", len(PAYLOAD) + 5),
    ],
)
def test_reads_and_tests_report_their_phase_against_the_members_they_decode(call, phase, total):
    events = []

    call(single_archive(), events.append)

    assert {event.phase for event in events} == {phase}
    assert all(event.total == total for event in events)
    assert events[-1].completed == total


def test_read_many_with_progress_returns_the_same_bytes_in_request_order():
    archive = single_archive()
    data = archive.read_many(["small.txt", "large.bin", "small.txt"], progress=lambda event: None)

    assert data == [b"small", PAYLOAD, b"small"]


def test_a_selection_on_a_set_counts_only_the_selected_member(tmp_path):
    paths = write_set(tmp_path / "made")
    events = []

    with rars.RarFile(paths[0]) as archive:
        archive.extractall(
            tmp_path / "out",
            members=["large.bin"],
            progress=events.append,
        )

    assert events[-1].completed == events[-1].total == len(PAYLOAD)
    assert events[-1].entry_name == b"large.bin"


def test_progress_must_be_callable():
    with pytest.raises(ValueError, match="progress must be callable"):
        single_archive().read("small.txt", progress=3)


def test_read_options_no_longer_carry_progress_or_cancellation():
    with pytest.raises(TypeError):
        rars.ReadOptions(progress=print)
    with pytest.raises(TypeError):
        rars.ReadOptions(cancellation=rars.CancellationToken())


def test_read_many_on_a_set_counts_a_member_after_a_split_one(tmp_path):
    paths = write_set(tmp_path / "made")
    events = []

    with rars.RarFile(paths[0]) as archive:
        data = archive.read_many(
            ["small.txt", "large.bin"], progress=events.append
        )

    assert data == [b"small", PAYLOAD]
    assert {event.phase for event in events} == {"reading"}
    assert events[-1].completed == events[-1].total == len(PAYLOAD) + 5
    assert events[-1].total_entries == 2


def test_a_set_found_by_name_knows_its_total_from_the_first_event(tmp_path):
    paths = write_set(tmp_path / "made")
    events = []

    with rars.RarFile(paths[0]) as archive:
        archive.extractall(tmp_path / "out", progress=events.append)

    assert all(event.total == len(PAYLOAD) + 5 for event in events)
    assert events[0].percentage is not None
    assert events[0].total_entries == 2


def test_a_set_given_as_a_list_knows_its_total_from_the_first_event(tmp_path):
    paths = write_set(tmp_path / "made")
    events = []

    with rars.RarFile(paths[0].read_bytes()) as archive:
        archive.testrar(
            progress=events.append,
            volumes=[path.read_bytes() for path in paths[1:]],
        )

    assert all(event.total == len(PAYLOAD) + 5 for event in events)


def test_a_set_with_a_volume_still_missing_falls_back_to_an_unknown_total(tmp_path):
    paths = write_set(tmp_path / "made")
    paths[-1].unlink()
    events = []

    with rars.RarFile(paths[0]) as archive:
        with pytest.raises(rars.MissingVolume):
            archive.testrar(progress=events.append)

    assert events
    assert all(event.total == 0 and event.percentage is None for event in events)
