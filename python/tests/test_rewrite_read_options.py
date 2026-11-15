import pytest
import rars


def legacy_archive():
    builder = rars.RarBuilder(format="rar29", store=True)
    builder.add_bytes(b"payload", b"caf\x82.txt")
    return builder.to_bytes()


def test_conversion_decodes_legacy_names_as_asked(tmp_path):
    path = tmp_path / "legacy.rar"
    path.write_bytes(legacy_archive())
    options = rars.ReadOptions(legacy_name_encoding="cp850")
    rewrite = rars.RarBuilder.from_archive(path, options=options, preserve=False)
    rewritten = rars.RarFile.from_bytes(rewrite.to_bytes())
    assert rewritten.infolist()[0].orig_filename_bytes == "café.txt".encode()
    assert rewritten.read("café.txt") == b"payload"


def payload_archive():
    builder = rars.RarBuilder(compression=1)
    builder.add_bytes(b"payload" * 100, "payload.txt")
    return builder.to_bytes()


@pytest.mark.parametrize("preserve", [True, False])
def test_limits_apply_while_the_source_is_read(preserve):
    tight = rars.ReadOptions(max_member_output_bytes=10)
    rewrite = rars.RarBuilder.from_archive(payload_archive(), options=tight, preserve=preserve)
    with pytest.raises(MemoryError):
        rewrite.to_bytes()


def test_cancellation_applies_while_the_source_is_read():
    token = rars.CancellationToken()
    options = rars.ReadOptions(cancellation=token)
    rewrite = rars.RarBuilder.from_archive(payload_archive(), options=options)
    token.cancel()
    with pytest.raises(InterruptedError):
        rewrite.to_bytes()


def test_options_override_those_a_rarfile_was_opened_with():
    tight = rars.ReadOptions(max_member_output_bytes=10)
    opened_tight = rars.RarFile.from_bytes(payload_archive(), options=tight)
    with pytest.raises(MemoryError):
        rars.RarBuilder.from_archive(opened_tight).to_bytes()

    loose = rars.RarBuilder.from_archive(opened_tight, options=rars.ReadOptions())
    assert rars.RarFile.from_bytes(loose.to_bytes()).read("payload.txt") == b"payload" * 100

    opened = rars.RarFile.from_bytes(payload_archive())
    with pytest.raises(MemoryError):
        rars.RarBuilder.from_archive(opened, options=tight).to_bytes()


@pytest.mark.parametrize("format", ["rar29", "rar50"])
@pytest.mark.parametrize("where", ["archive", "member"])
def test_limits_apply_to_comments_read_from_the_source(format, where):
    builder = rars.RarBuilder(format=format, comment=b"long comment" if where == "archive" else None)
    builder.add_bytes(b"x", "x")
    if where == "member":
        builder.set_file_comment("x", b"long comment")
    tight = rars.ReadOptions(max_member_output_bytes=4)
    with pytest.raises(MemoryError):
        rars.RarBuilder.from_archive(builder.to_bytes(), options=tight)
