#!/usr/bin/env python3
"""Build and smoke-test the PyO3 bindings in an isolated virtualenv."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, env=env, check=True)


def venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def create_venv(path: Path, keep: bool) -> Path:
    if path.exists() and not keep:
        shutil.rmtree(path)
    if not path.exists():
        run([sys.executable, "-m", "venv", str(path)])
    return venv_python(path)


def install_dev_tools(python: Path) -> None:
    uv = shutil.which("uv")
    if uv:
        run([uv, "pip", "install", "--python", str(python), "maturin>=1.8,<2", "pytest"])
    else:
        run([str(python), "-m", "pip", "install", "--upgrade", "pip"])
        run([str(python), "-m", "pip", "install", "maturin>=1.8,<2", "pytest"])


def smoke_script() -> str:
    fixture = ROOT / "crates/rars/tests/fixtures/rar50/stored.rar"
    return f"""
from pathlib import Path
import tempfile
import rars

archive = rars.RarFile(Path({str(fixture)!r}))
names = archive.namelist()
assert names, "fixture should contain at least one member"
archive.testrar()
first = archive.read(names[0])
assert isinstance(first, bytes)

builder = rars.RarBuilder(format="rar50", store=True)
builder.add_bytes(b"alpha", "alpha.txt")
builder.add_bytes(b"beta", "nested/beta.txt")
rebuilt = rars.RarFile.from_bytes(builder.to_bytes())
assert rebuilt.namelist() == ["alpha.txt", "nested/beta.txt"]
assert rebuilt.read("alpha.txt") == b"alpha"
assert rebuilt.read(b"nested/beta.txt") == b"beta"

with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp)
    rebuilt.extractall(out)
    assert (out / "alpha.txt").read_bytes() == b"alpha"
    assert (out / "nested/beta.txt").read_bytes() == b"beta"
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--venv",
        type=Path,
        # Under target/, not the system temp directory: this is a few hundred
        # megabytes of maturin and pytest, and /tmp is a tmpfs on most Linux
        # installs, so the default would spend that much RAM.
        default=ROOT / "target/python-bindings-venv",
        help="virtualenv path to create/use",
    )
    parser.add_argument(
        "--keep-venv",
        action="store_true",
        help="reuse an existing virtualenv instead of recreating it",
    )
    parser.add_argument(
        "--skip-pytest",
        action="store_true",
        help="run only the inline smoke test",
    )
    args = parser.parse_args()

    python = create_venv(args.venv, args.keep_venv)
    install_dev_tools(python)

    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(args.venv)
    env["PATH"] = f"{python.parent}{os.pathsep}{env['PATH']}"

    run(
        [
            str(python),
            "-m",
            "maturin",
            "develop",
            "--manifest-path",
            "crates/rars-python/Cargo.toml",
            "--features",
            "extension-module",
        ],
        env=env,
    )
    if not args.skip_pytest:
        # --basetemp keeps pytest's tmp_path fixtures off /tmp too.
        run(
            [
                str(python),
                "-m",
                "pytest",
                "python/tests",
                "--basetemp",
                str(ROOT / "target/pytest-tmp"),
            ],
            env=env,
        )
    run([str(python), "-c", smoke_script()], env=env)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
