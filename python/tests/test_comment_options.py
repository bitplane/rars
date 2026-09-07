import pytest
import rars

from test_read_options import FORMATS
from test_rewrite_legacy_comment_encryption import encrypted_comment_source


@pytest.mark.parametrize("format", FORMATS)
@pytest.mark.parametrize("comment", [None, b"", b"archive comment\xff"])
def test_comment_policies_keep_defaults_and_reset_budgets(format, comment):
    builder = rars.RarBuilder(format=format, comment=comment)
    builder.add_bytes(b"payload", "file")
    archive = rars.RarFile.from_bytes(builder.to_bytes())
    assert archive.comment == comment
    assert archive.read_comment() == comment
    size = len(comment or b"")
    options = rars.ReadOptions(max_member_output_bytes=size, max_total_output_bytes=size)
    for _ in range(2):
        assert archive.read_comment(options=options) == comment
    if size:
        for field in ["max_member_output_bytes", "max_total_output_bytes"]:
            with pytest.raises(MemoryError):
                archive.read_comment(options=rars.ReadOptions(**{field: size - 1}))
    token = rars.CancellationToken()
    token.cancel()
    with pytest.raises(InterruptedError):
        archive.read_comment(options=rars.ReadOptions(cancellation=token))
    assert archive.comment == comment
    assert archive.read_comment() == comment
    assert archive.read("file") == b"payload"


@pytest.mark.parametrize("password", [None, "wrong", "password"])
def test_comment_password_override_is_per_call_and_limits_precede_decryption(password):
    archive = rars.RarFile.from_bytes(encrypted_comment_source(), password=password)
    expected = b"secret archive comment"
    with pytest.raises(MemoryError):
        archive.read_comment(options=rars.ReadOptions(max_member_output_bytes=0))
    options = rars.ReadOptions(max_total_output_bytes=len(expected))
    assert archive.read_comment(pwd=b"password", options=options) == expected
    if password == "password":
        assert archive.comment == expected
        assert archive.read_comment(options=options) == expected
        with pytest.raises((rars.BadPassword, rars.BadRarFile)):
            archive.read_comment(pwd="wrong", options=options)
        assert archive.comment == expected
    else:
        error = rars.PasswordRequired if password is None else (rars.BadPassword, rars.BadRarFile)
        with pytest.raises(error):
            archive.read_comment(options=options)
        with pytest.raises(error):
            _ = archive.comment
