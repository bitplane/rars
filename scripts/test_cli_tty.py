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


def prompted(binary, fixture, password, expected_code):
    pid, master = pty.fork()
    if pid == 0:
        os.execv(binary, [binary, "--threads", "1", "--progress", "never", "test", str(fixture)])
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
                if b"password: " in output and not sent:
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
        assert sent, bytes(output)
        assert code == expected_code, (code, bytes(output))
        if expected_code == 0:
            assert b"OK hello.txt" in output, bytes(output)
        assert password + b"\r\n" not in output, "password was echoed"
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


def main():
    binary = os.path.abspath(sys.argv[1])
    root = Path(__file__).resolve().parent.parent
    fixtures = root / "crates/rars/tests/fixtures/rar15_40/encrypted"
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
