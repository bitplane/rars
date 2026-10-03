"""Focused Unix CLI password regressions using actual controlling terminals."""
import errno
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import time
import tempfile
import termios


def run_terminal(binary, arguments, password=None):
    pid, master = pty.fork()
    if pid == 0:
        os.execv(binary, [binary, *arguments])
    output = bytearray()
    sent = False
    status = None
    reaped = False
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.1)
            if readable:
                try:
                    block = os.read(master, 8192)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not block:
                    break
                output.extend(block)
            if password is not None and b"password: " in output and not sent:
                # rpassword prints its prompt before disabling echo. Check the
                # terminal state even without new output: disabling echo itself
                # produces no bytes on the master.
                if not termios.tcgetattr(master)[3] & termios.ECHO:
                    os.write(master, password + b"\n")
                    sent = True
            if not reaped:
                done, candidate = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = candidate
                    reaped = True
        else:
            raise AssertionError(f"password prompt timed out: {bytes(output)!r}")
        if not reaped:
            _, status = os.waitpid(pid, 0)
            reaped = True
        code = os.waitstatus_to_exitcode(status)
        return code, bytes(output), sent
    finally:
        os.close(master)
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass


def prompted(binary, fixture, password, expected_code):
    code, output, sent = run_terminal(binary, ["--threads", "1", "--progress", "never", "test", str(fixture)], password)
    assert sent, output
    assert code == expected_code, (code, output)
    if expected_code == 0:
        assert b"OK hello.txt" in output, output
    assert password + b"\r\n" not in output, "password was echoed"


def prompt_readiness_regression():
    # Deliberately separate prompt publication from echo suppression to expose
    # the ordering that was intermittently hit under CI scheduling.
    child = """
import sys, termios, time
print('password: ', end='', flush=True)
time.sleep(0.2)
settings = termios.tcgetattr(0)
settings[3] &= ~termios.ECHO
termios.tcsetattr(0, termios.TCSANOW, settings)
assert sys.stdin.readline() == 'terminal-secret\\n'
"""
    code, output, sent = run_terminal(sys.executable, ["-c", child], b"terminal-secret")
    assert sent and code == 0, (code, output, sent)
    assert b"terminal-secret" not in output, "harness sent input before echo was disabled"


def progress_suite(binary, root):
    with tempfile.TemporaryDirectory(prefix="cli-progress-", dir=root / "target") as name:
        directory = Path(name)
        source = directory / "input"
        source.write_bytes(b"payload" * 100)
        for version in ["rar15", "rar50"]:
            archive = directory / f"{version}.rar"
            code, output, _ = run_terminal(binary, ["--threads", "1", "--progress", "always", "add", "--format", version, "--store", str(archive), str(source)])
            assert code == 0, (code, output)
            assert archive.is_file()
            result = subprocess.run([binary, "--threads", "1", "test", str(archive)], capture_output=True, timeout=15)
            assert result.returncode == 0, result.stderr
    print("terminal progress creation and verification passed")


def main():
    binary = os.path.abspath(sys.argv[1])
    root = Path(__file__).resolve().parent.parent
    if len(sys.argv) > 2 and sys.argv[2] == "progress":
        progress_suite(binary, root)
        return
    fixtures = root / "crates/rars/tests/fixtures/rar15_40/encrypted"
    prompt_readiness_regression()
    header = fixtures / "header_rar300_password.rar"
    prompted(binary, header, b"password", 0)
    wrong = subprocess.run([binary, "--threads", "1", "test", "--password", "wrong-password", str(header)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    assert wrong.returncode != 0
    # Legacy header encryption has no independent password verifier. Prompted
    # retries must preserve the same error class as an explicit password.
    prompted(binary, header, b"wrong-password", wrong.returncode)
    prompted(binary, fixtures / "per_file_rar300_password.rar", b"password", 0)
    # stdin is a terminal, but this isolated session deliberately has no /dev/tty.
    for fixture in [header, fixtures / "per_file_rar300_password.rar"]:
        master, slave = pty.openpty()
        try:
            result = subprocess.run(
                [binary, "--threads", "1", "test", str(fixture)],
                stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, timeout=15,
            )
            assert result.returncode == 1, (result.returncode, result.stderr)
        finally:
            os.close(master)
            os.close(slave)
    print("controlling-terminal success/retry/wrong-password and unavailable-terminal cases passed")


if __name__ == "__main__":
    main()
