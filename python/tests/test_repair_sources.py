import io

import pytest
import rars


def recoverable(damage_header=False):
    builder = rars.RarBuilder(version="rar50", level=0, recovery_percent=10)
    builder.add_bytes(bytes(range(256)) * 2000, "file")
    data = bytearray(builder.to_bytes())
    if damage_header:
        data[8] ^= 1  # Main-header CRC: only the raw recovery fallback can read it.
    else:
        middle = len(data) // 2
        for index in range(middle, middle + 64):
            data[index] ^= 0xFF
    return bytes(data)


def report_fields(report):
    return (
        report.changed,
        report.data_repaired,
        report.available_recovery_shards,
        report.expected_recovery_shards,
    )


@pytest.mark.parametrize("damage_header", [False, True])
def test_repair_reads_paths_file_objects_and_bytes_alike(tmp_path, damage_header):
    data = recoverable(damage_header)
    expected = rars.repair(data)
    assert expected.report.data_repaired
    path = tmp_path / "damaged.rar"
    path.write_bytes(data)
    sources = [
        lambda: data,
        lambda: path,
        lambda: str(path),
        lambda: path.open("rb"),
        lambda: io.BytesIO(data),
    ]
    output = tmp_path / "repaired.rar"
    for source in sources:
        opened = source()
        result = rars.repair(opened)
        assert result.data == expected.data
        assert report_fields(result.report) == report_fields(expected.report)

        written = rars.repair(source(), output=output, overwrite=True)
        assert written.data is None
        assert output.read_bytes() == expected.data
        assert report_fields(written.report) == report_fields(expected.report)
        if hasattr(opened, "close"):
            opened.close()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["damaged.rar", "repaired.rar"]
    assert rars.RarFile(expected.data).read("file") == bytes(range(256)) * 2000
