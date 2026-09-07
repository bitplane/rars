import pytest
import rars


FORMATS = ["rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70"]


def make_archive(format="rar50", solid=False):
    builder = rars.RarBuilder(
        format=format, solid=solid, store=not solid or format in ("rar50", "rar70")
    )
    builder.add_bytes(b"first", "first")
    builder.add_bytes(b"second!", "second")
    builder.add_bytes(b"end", "last")
    return rars.RarFile.from_bytes(builder.to_bytes())


@pytest.mark.parametrize("format", FORMATS)
@pytest.mark.parametrize("method", ["read", "open", "extract", "extractall", "testrar"])
def test_member_limits_apply_before_publication_and_do_not_change_defaults(tmp_path, format, method):
    archive = make_archive(format)
    options = rars.ReadOptions(max_member_output_bytes=4)
    target = tmp_path / "first"
    target.write_bytes(b"keep")
    with pytest.raises(MemoryError):
        if method in ("read", "open"):
            getattr(archive, method)("first", options=options)
        elif method == "extract":
            archive.extract("first", tmp_path, overwrite=True, options=options)
        elif method == "extractall":
            archive.extractall(tmp_path, overwrite=True, options=options)
        else:
            archive.testrar(options=options)
    assert target.read_bytes() == b"keep"
    assert list(tmp_path.iterdir()) == [target]
    assert archive.read("first") == b"first"
    archive.testrar()


@pytest.mark.parametrize("format", FORMATS)
@pytest.mark.parametrize("solid", [False, True])
def test_total_budget_counts_solid_dependencies_and_resets_per_call(tmp_path, format, solid):
    archive = make_archive(format, solid)
    required = 15 if solid else 3
    options = rars.ReadOptions(max_total_output_bytes=required)
    for _ in range(2):
        assert archive.read("last", options=options) == b"end"
        assert archive.open("last", options=options).read() == b"end"
    too_small = rars.ReadOptions(max_total_output_bytes=required - 1)
    with pytest.raises(MemoryError):
        archive.read("last", options=too_small)
    with pytest.raises(MemoryError):
        archive.extractall(tmp_path, members=["last"], options=too_small)
    assert list(tmp_path.iterdir()) == []
    assert archive.extractall(tmp_path, members=["last"], options=options) == [tmp_path / "last"]
    assert (tmp_path / "last").read_bytes() == b"end"
    with pytest.raises(MemoryError):
        archive.testrar(options=rars.ReadOptions(max_total_output_bytes=14))
    archive.testrar(options=rars.ReadOptions(max_total_output_bytes=15))


@pytest.mark.parametrize("method", ["read", "open", "extract", "extractall", "testrar"])
@pytest.mark.parametrize("empty_selection", [False, True])
def test_cancelled_reader_operations_do_no_output_work(tmp_path, method, empty_selection):
    archive = make_archive()
    token = rars.CancellationToken()
    options = rars.ReadOptions(cancellation=token)
    assert options.cancellation is not None
    token.cancel()
    assert options.cancellation.is_cancelled()
    name = "missing" if empty_selection else "first"
    with pytest.raises(InterruptedError):
        if method in ("read", "open"):
            getattr(archive, method)(name, options=options)
        elif method == "extract":
            archive.extract(name, tmp_path, options=options)
        elif method == "extractall":
            archive.extractall(tmp_path, members=[] if empty_selection else None, options=options)
        else:
            archive.testrar(options=options)
    assert list(tmp_path.iterdir()) == []
    assert archive.read("first") == b"first"


def test_options_are_immutable_reusable_and_preserve_password_handling():
    builder = rars.RarBuilder(password="secret")
    builder.add_bytes(b"encrypted payload", "file")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    token = rars.CancellationToken()
    options = rars.ReadOptions(cancellation=token, max_total_output_bytes=17)
    assert options.max_total_output_bytes == 17
    assert options.max_member_output_bytes is None
    with pytest.raises(AttributeError):
        options.max_total_output_bytes = 100
    with pytest.raises(rars.PasswordRequired):
        archive.read("file", options=options)
    assert archive.read("file", pwd="secret", options=options) == b"encrypted payload"
    archive.testrar(pwd="secret", options=options)
    assert not token.is_cancelled()
    for value in [-1, 2**64]:
        with pytest.raises(OverflowError):
            rars.ReadOptions(max_total_output_bytes=value)


@pytest.mark.parametrize("format", ["rar50", "rar70"])
def test_rar5_dictionary_policy_and_streaming_decode_option(format):
    builder = rars.RarBuilder(format=format)
    payload = b"repeated text\n" * 1000
    builder.add_bytes(payload, "file")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    refused = rars.ReadOptions(rar50_dictionary_size_limit=0)
    with pytest.raises(MemoryError):
        archive.read("file", options=refused)
    with pytest.raises(MemoryError):
        archive.testrar(options=refused)
    streaming = rars.ReadOptions(rar50_buffered_decode_limit=0)
    assert archive.read("file", options=streaming) == payload
    archive.testrar(options=streaming)


@pytest.mark.parametrize("format", FORMATS)
def test_selected_extraction_keeps_empty_files_and_completed_prefixes(tmp_path, format):
    builder = rars.RarBuilder(format=format, store=True)
    builder.add_bytes(b"", "empty")
    builder.add_bytes(b"first", "first")
    builder.add_bytes(b"second", "second")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    zero = rars.ReadOptions(max_total_output_bytes=0)
    assert archive.extract("empty", tmp_path, options=zero) == tmp_path / "empty"
    assert (tmp_path / "empty").read_bytes() == b""
    with pytest.raises(MemoryError):
        archive.extractall(tmp_path, members=["first", "second"],
                           options=rars.ReadOptions(max_total_output_bytes=5))
    assert (tmp_path / "first").read_bytes() == b"first"
    assert not (tmp_path / "second").exists()
