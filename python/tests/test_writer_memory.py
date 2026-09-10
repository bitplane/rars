import pytest
import rars


@pytest.mark.parametrize("format", ["rar50", "rar70"])
@pytest.mark.parametrize("store,solid,recovery", [(True, False, None), (False, False, None), (False, True, 10)])
def test_writer_memory_preserves_output(format, store, solid, recovery):
    options = dict(format=format, store=store, solid=solid, recovery_percent=recovery)
    plain = rars.RarBuilder(**options)
    limited = rars.RarBuilder(**options, max_memory_bytes=256 << 20)
    for builder in (plain, limited):
        builder.add_bytes(b"payload" * 1024, "member")
    expected = plain.to_bytes()
    for _ in range(2):
        actual = limited.to_bytes()
        assert actual == expected
        assert rars.RarFile.from_bytes(actual).read("member") == b"payload" * 1024


def test_writer_memory_failure_preserves_destination(tmp_path):
    builder = rars.RarBuilder(format="rar50", store=True, max_memory_bytes=1024)
    builder.add_bytes(b"payload" * 1024, "member")
    destination = tmp_path / "archive.rar"
    destination.write_bytes(b"original")
    for _ in range(3):
        with pytest.raises(MemoryError):
            builder.to_bytes()
        with pytest.raises(MemoryError):
            builder.write(destination)
        assert destination.read_bytes() == b"original"
        assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("format", ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40"])
def test_legacy_writer_refuses_memory_policy(format):
    builder = rars.RarBuilder(format=format, store=True, max_memory_bytes=0)
    builder.add_bytes(b"payload", "member")
    with pytest.raises(rars.UnsupportedRarFeature):
        builder.to_bytes()


@pytest.mark.parametrize("encrypt_headers", [False, True])
def test_encrypted_recovery_and_volume_output_obey_memory_policy(tmp_path, encrypt_headers):
    options = dict(format="rar50", store=True, password="secret",
                   encrypt_headers=encrypt_headers, recovery_percent=10,
                   max_memory_bytes=32 << 20)
    builder = rars.RarBuilder(**options)
    builder.add_bytes(b"payload" * 1024, "member")
    archive = rars.RarFile.from_bytes(builder.to_bytes(), password="secret")
    assert archive.read("member") == b"payload" * 1024
    builder = rars.RarBuilder(**options, volume_size=2048)
    builder.add_bytes(b"payload" * 1024, "member")
    parts = builder.write_volumes(tmp_path / "set.part1.rar")
    assert len(parts) > 1
    rars.test_volumes(parts, password="secret")
    output = tmp_path / "extracted"
    rars.extract_volumes(parts, output, password="secret")
    assert (output / "member").read_bytes() == b"payload" * 1024
