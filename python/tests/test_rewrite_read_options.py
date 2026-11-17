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
    rewritten = rars.RarFile(rewrite.to_bytes())
    assert rewritten.infolist()[0].orig_filename_bytes == "café.txt".encode()
    assert rewritten.read("café.txt") == b"payload"


def payload_archive():
    builder = rars.RarBuilder(level=1)
    builder.add_bytes(b"payload" * 100, "payload.txt")
    return builder.to_bytes()


@pytest.mark.parametrize("preserve", [True, False])
def test_limits_apply_while_the_source_is_read(preserve):
    tight = rars.ReadOptions(max_member_output_bytes=10)
    rewrite = rars.RarBuilder.from_archive(payload_archive(), options=tight, preserve=preserve)
    with pytest.raises(MemoryError):
        rewrite.to_bytes()


def test_each_call_that_reads_the_source_takes_its_own_cancellation():
    cancelled = rars.CancellationToken()
    cancelled.cancel()
    with pytest.raises(rars.Cancelled):
        rars.RarBuilder.from_archive(payload_archive(), cancellation=cancelled)
    live = rars.CancellationToken()
    rewrite = rars.RarBuilder.from_archive(payload_archive(), cancellation=live)
    live.cancel()
    # from_archive's token ended with that call; staging follows the write's.
    assert rars.RarFile(rewrite.to_bytes()).read("payload.txt") == b"payload" * 100
    with pytest.raises(rars.Cancelled):
        rewrite.to_bytes(cancellation=cancelled)


def test_a_rarfile_opened_with_a_token_does_not_stop_a_later_rewrite():
    token = rars.CancellationToken()
    opened = rars.RarFile(payload_archive(), cancellation=token)
    token.cancel()
    rewrite = rars.RarBuilder.from_archive(opened)
    assert rars.RarFile(rewrite.to_bytes()).read("payload.txt") == b"payload" * 100


def test_options_override_those_a_rarfile_was_opened_with():
    tight = rars.ReadOptions(max_member_output_bytes=10)
    opened_tight = rars.RarFile(payload_archive(), options=tight)
    with pytest.raises(MemoryError):
        rars.RarBuilder.from_archive(opened_tight).to_bytes()

    loose = rars.RarBuilder.from_archive(opened_tight, options=rars.ReadOptions())
    assert rars.RarFile(loose.to_bytes()).read("payload.txt") == b"payload" * 100

    opened = rars.RarFile(payload_archive())
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
