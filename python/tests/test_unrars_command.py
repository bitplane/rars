"""The `unrars` command that the package installs, run as a subprocess.

It runs the standalone binary's code, so where the binary is available
(`RARS_UNRARS_BIN`, which scripts/test-python-bindings.py sets) every run is
compared with it: exit code, stdout and stderr byte for byte, and the files
written.
"""
import os
import shutil
import signal
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest
import rars

PAYLOADS = {
    "alpha.txt": b"alpha\n" * 50,
    "nested/beta.bin": bytes(range(256)) * 64,
    "nested/deeper/empty.txt": b"",
}


def installed_unrars() -> str:
    scripts = sysconfig.get_path("scripts")
    found = shutil.which("unrars", path=scripts)
    assert found, f"pip install rars should put unrars in {scripts}"
    return found


def standalone_unrars() -> str | None:
    return os.environ.get("RARS_UNRARS_BIN") or None


def make_archive(path: Path, version: str = "rar50", level: int = 3) -> None:
    builder = rars.RarBuilder(version=version, level=level)
    for name, data in PAYLOADS.items():
        builder.add_bytes(data, name, mtime=1_700_000_000)
    builder.write(path)


def run(program: str, args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [program, *args],
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
    )


def tree(root: Path) -> dict[str, bytes | None]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes() if path.is_file() else None
        for path in sorted(root.rglob("*"))
    }


def run_both(tmp_path: Path, archive: bytes, args: list[str]):
    """Runs the installed command, and the binary when there is one, each in a
    directory holding `a.rar`, and checks they agree. Returns the installed
    command's result and the files it left beside the archive."""
    results = []
    for name, program in (("installed", installed_unrars()), ("binary", standalone_unrars())):
        if program is None:
            continue
        cwd = tmp_path / name
        cwd.mkdir()
        (cwd / "a.rar").write_bytes(archive)
        result = run(program, args, cwd)
        (cwd / "a.rar").unlink()
        results.append((result, tree(cwd)))
    installed, *binary = results
    for result, files in binary:
        assert installed[0].returncode == result.returncode
        assert installed[0].stdout == result.stdout
        assert installed[0].stderr == result.stderr
        assert installed[1] == files
    return installed


@pytest.fixture(params=["rar50", "rar29", "rar15"])
def archive(request, tmp_path) -> bytes:
    path = tmp_path / f"{request.param}.rar"
    make_archive(path, request.param)
    return path.read_bytes()


def test_test_command(tmp_path, archive):
    result, _ = run_both(tmp_path, archive, ["t", "a.rar"])
    assert result.returncode == 0, result.stderr
    assert b"All OK" in result.stdout


def test_extract_command(tmp_path, archive):
    result, files = run_both(tmp_path, archive, ["x", "-y", "a.rar", "out/"])
    assert result.returncode == 0, result.stderr
    written = {name[len("out/"):]: data for name, data in files.items() if data is not None}
    assert written == PAYLOADS


@pytest.mark.parametrize("command", ["l", "lt", "lb"])
def test_list_commands(tmp_path, archive, command):
    result, _ = run_both(tmp_path, archive, [command, "a.rar"])
    assert result.returncode == 0, result.stderr
    for name in PAYLOADS:
        assert os.path.basename(name).encode() in result.stdout


def test_print_command_is_byte_exact(tmp_path, archive):
    result, _ = run_both(tmp_path, archive, ["p", "-inul", "a.rar", "nested/beta.bin"])
    assert result.returncode == 0, result.stderr
    assert result.stdout == PAYLOADS["nested/beta.bin"]
    assert result.stderr == b""


def test_print_command_with_messages(tmp_path, archive):
    result, _ = run_both(tmp_path, archive, ["p", "a.rar", "alpha.txt"])
    assert result.returncode == 0, result.stderr
    assert PAYLOADS["alpha.txt"] in result.stdout


@pytest.mark.parametrize(
    "args, code",
    [
        ([], 0),
        (["q", "a.rar"], 7),
        (["t", "missing.rar"], None),
        (["x", "a.rar", "no-such-member", "out/"], 10),
    ],
)
def test_exit_codes(tmp_path, args, code):
    path = tmp_path / "made.rar"
    make_archive(path)
    result, _ = run_both(tmp_path, path.read_bytes(), args)
    if code is not None:
        assert result.returncode == code
    else:
        assert result.returncode != 0
    assert b"Traceback" not in result.stderr


def test_damaged_archive_exit_code(tmp_path):
    path = tmp_path / "made.rar"
    make_archive(path, level=0)
    data = bytearray(path.read_bytes())
    offset = data.index(PAYLOADS["nested/beta.bin"][:64])
    data[offset + 10] ^= 0xFF
    result, _ = run_both(tmp_path, bytes(data), ["t", "a.rar"])
    assert result.returncode == 3
    assert b"Traceback" not in result.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_ctrl_c_stops_without_a_traceback(tmp_path):
    # Larger than a pipe holds, so the command blocks writing until it is read.
    builder = rars.RarBuilder(level=0)
    builder.add_bytes(os.urandom(4 << 20), "big.bin")
    builder.write(tmp_path / "a.rar")
    process = subprocess.Popen(
        [installed_unrars(), "p", "-inul", "a.rar"],
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.stdout.read(4096)
        process.send_signal(signal.SIGINT)
        process.stdout.close()
        stderr = process.stderr.read()
        assert process.wait(timeout=60) == -signal.SIGINT
    finally:
        process.kill()
        process.wait()
    assert b"Traceback" not in stderr
    assert b"KeyboardInterrupt" not in stderr
