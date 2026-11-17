#!/usr/bin/env python3
"""Keep non-Cargo release metadata aligned with the Cargo workspace."""

from pathlib import Path
import os
import re
import subprocess
import sys


def replace_once(path: Path, pattern: str, replacement: str, description: str) -> None:
    text = path.read_text()
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(f"could not find {description} in {path}")
    path.write_text(updated)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: sync-release-version.py VERSION")

    version = sys.argv[1]
    root = Path(__file__).resolve().parents[1]
    replace_once(
        root / "pyproject.toml",
        r'^(version = ")[^"]+("\s*)$',
        rf"\g<1>{version}\g<2>",
        "[project] version",
    )
    replace_once(
        root / ".github/workflows/release.yml",
        r'^(\s*default: "v)[^"]+("\s*)$',
        rf"\g<1>{version}\g<2>",
        "release workflow default ref",
    )
    # The independent reader consumer has its own lockfile, which cargo-release
    # does not touch. CI checks it with --locked.
    replace_once(
        root / "scripts/reader-consumer/Cargo.lock",
        r'^(name = "rars"\nversion = ")[^"]+(")$',
        rf"\g<1>{version}\g<2>",
        "reader consumer rars lock entry",
    )

    # Producer records contain the library version, including inside recovery
    # parity and the legacy volume fingerprints. Refresh the byte fixtures once, after cargo-release has bumped
    # rars, so the version-only release commit still passes the golden tests.
    if os.environ.get("CRATE_NAME") == "rars" and os.environ.get("DRY_RUN") != "true":
        subprocess.run(
            [
                "cargo",
                "test",
                "-p",
                "rars",
                "--test",
                "rar50_golden",
                "--test",
                "legacy_compressed_volumes",
                "--locked",
            ],
            cwd=root,
            env={**os.environ, "RARS_BLESS_GOLDEN": "1"},
            check=True,
        )


if __name__ == "__main__":
    main()
