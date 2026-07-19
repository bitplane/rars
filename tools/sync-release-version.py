#!/usr/bin/env python3
"""Keep non-Cargo release metadata aligned with the Cargo workspace."""

from pathlib import Path
import re
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


if __name__ == "__main__":
    main()
