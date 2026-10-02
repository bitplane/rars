#!/usr/bin/env python3
"""Print the wasm-bindgen CLI version matching the locked crate (Python 3.10+)."""
from pathlib import Path
import re

lock = (Path(__file__).resolve().parents[1] / "Cargo.lock").read_text(encoding="utf-8")
match = re.search(r'^name = "wasm-bindgen"\nversion = "([^"\n]+)"$', lock, re.MULTILINE)
if match is None:
    raise SystemExit("Cargo.lock does not contain a wasm-bindgen version")
print(match[1])
